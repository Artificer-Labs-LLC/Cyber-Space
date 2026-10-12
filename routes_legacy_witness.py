"""Legacy witness routes (ART-40), ported from 73a08c2's log routes.

The migrate / cancel / withdraw paths stay the 409 stub in
routes_legacy_migrate. These routes make a window migration verifiable by
a second node: a signed head, a per-name proof, an observe mark, and an
import that checks the witness rules before it writes.

Check order on every write (import-legacy, observe) is bucket, then
signature, then weak_reason, then write. The bucket step runs first, so a
refused request still consumes a token.

Buckets are keyed on client_source (ratesrc.source):

  head / proof / witnessed     per IP, plus a global ceiling >= 10x
  observe / import-legacy      per IP and per log_id, global >= 10x

import-legacy does not charge the shared src:auth bucket. A 1x
import-legacy:global is not used; the global ceiling is 10x the per-source
cap so one source cannot fill it for everyone.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

from fastapi import APIRouter, HTTPException, Query, Request

import core
import legacy_witness as lw
import ratesrc
import window_open
from fed import ed25519 as _ed

router = APIRouter()

# Per-IP caps follow 73a08c2's read/auth limits. Globals are ceilings only.
HEAD_PER_IP = 240
HEAD_GLOBAL = 2400
PROOF_PER_IP = 120
PROOF_GLOBAL = 1200
WITNESSED_PER_IP = 120
WITNESSED_GLOBAL = 1200
OBSERVE_PER_IP = 120
OBSERVE_PER_LOG = 120
OBSERVE_GLOBAL = 1200
IMPORT_PER_SOURCE = 60
IMPORT_PER_LOG = 60
IMPORT_GLOBAL = 600

assert HEAD_GLOBAL >= 10 * HEAD_PER_IP
assert PROOF_GLOBAL >= 10 * PROOF_PER_IP
assert WITNESSED_GLOBAL >= 10 * WITNESSED_PER_IP
assert OBSERVE_GLOBAL >= 10 * OBSERVE_PER_IP
assert OBSERVE_GLOBAL >= 10 * OBSERVE_PER_LOG
assert IMPORT_GLOBAL >= 10 * IMPORT_PER_SOURCE
assert IMPORT_GLOBAL >= 10 * IMPORT_PER_LOG

IMPORT_FORMAT = "cyberspace-legacy-import/v1"
_proof_cache: dict = {}


def charge_head(src: str) -> None:
    core._check_rate(f"legacy-log:head:{src}", limit=HEAD_PER_IP)
    core._check_rate("legacy-log:head:global", limit=HEAD_GLOBAL)


def charge_proof(src: str) -> None:
    core._check_rate(f"legacy-log:proof:{src}", limit=PROOF_PER_IP)
    core._check_rate("legacy-log:proof:global", limit=PROOF_GLOBAL)


def charge_witnessed(src: str) -> None:
    core._check_rate(f"legacy-log:witnessed:{src}", limit=WITNESSED_PER_IP)
    core._check_rate("legacy-log:witnessed:global", limit=WITNESSED_GLOBAL)


def charge_observe_source(src: str) -> None:
    core._check_rate(f"legacy-log:observe:{src}", limit=OBSERVE_PER_IP)


def charge_observe_scoped(log_id: str) -> None:
    core._check_rate(f"legacy-log:observe:log:{log_id}", limit=OBSERVE_PER_LOG)
    core._check_rate("legacy-log:observe:global", limit=OBSERVE_GLOBAL)


def charge_import_source(src: str) -> None:
    core._check_rate(f"import-legacy:{src}", limit=IMPORT_PER_SOURCE)


def charge_import_scoped(log_id: str) -> None:
    core._check_rate(f"import-legacy:log:{log_id}", limit=IMPORT_PER_LOG)
    core._check_rate("import-legacy:global", limit=IMPORT_GLOBAL)


def pinned():
    """(log_id, WitnessSet) from the environment, or None when unset.

    Read at request time so a node can pin Genesis's witnesses without a
    code change. Unpinned import/observe answer 503 after the bucket step.
    """
    raw = os.environ.get("CYBERNET_GENESIS_WITNESSES", "").strip()
    log_id = os.environ.get("CYBERNET_GENESIS_LOG_ID", "").strip().lower()
    if not raw or len(log_id) != 64:
        return None
    pubs = [p.strip() for p in raw.split(",") if p.strip()]
    try:
        threshold = int(os.environ.get("CYBERNET_GENESIS_WITNESS_THRESHOLD", "1"))
        return log_id, lw.WitnessSet(threshold, pubs)
    except (TypeError, ValueError):
        return None


def witnessed_inception_ok(ident: dict, pub: str) -> bool:
    """The presented key is the cutover's k0, not a fresh key over an old proof."""
    return ident.get("k0_pub") == pub


def import_message(name: str, log_id: str, public_key: str, proof: dict) -> bytes:
    digest = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return (
        f"{IMPORT_FORMAT}\nname={name}\nlog_id={log_id}\n"
        f"pub={public_key}\nproof_sha256={digest}"
    ).encode()


def _window_fields(entries: list) -> tuple:
    kinds = [e["kind"] for e in entries]
    o = kinds.index("window-open") + 1 if "window-open" in kinds else None
    c = kinds.index("window-close") + 1 if "window-close" in kinds else None
    state = "closed" if c else ("open" if o else "unopened")
    return o, c, state


def _signed_view(name: str | None):
    """Signed head plus span for the local log, or None when it cannot
    answer (empty log, or no hold for `name`). Cached per (log, seq, name)
    so a proof poll does not re-sign every hit."""
    with core._db_lock, core._db() as conn:
        log_id, entries = window_open.export_log(conn)
        hop_rows = window_open.export_hop_rows(conn)
    if not entries:
        return None
    if name is not None and not any(e["kind"] == "hold" and e.get("name") == name for e in entries):
        return None
    key = (log_id, entries[-1]["seq"], name)
    cached = _proof_cache.get(key)
    if cached is not None:
        return cached
    pub = core._NODE_PUB.lower()
    wset = lw.WitnessSet(1, [pub])
    o, c, state = _window_fields(entries)
    head = {
        "log_id": log_id,
        "witness_set": wset.id,
        "seq": len(entries),
        "head_hash": entries[-1]["entry_hash"],
        "window_open_seq": o,
        "window_close_seq": c,
        "window_state": state,
    }

    def _sign(msg, sk=core._NODE_PRIV, pk=pub):
        return pk, _ed.sign(msg, bytes.fromhex(sk), bytes.fromhex(pk)).hex()

    body = {"head": lw.sign_head(head, [_sign]), "span": [lw.full(e) for e in entries],
            "hops": hop_rows}
    _proof_cache[key] = body
    return body


def _import_log_id(data: dict) -> str:
    log_id = data.get("log_id")
    if isinstance(log_id, str) and log_id.strip():
        return log_id.strip().lower()
    proof = data.get("proof")
    if isinstance(proof, dict):
        signed = proof.get("head")
        inner = signed.get("head") if isinstance(signed, dict) else None
        if isinstance(inner, dict) and isinstance(inner.get("log_id"), str):
            return inner["log_id"].strip().lower()
    return "missing"


@router.get("/api/v1/legacy-log/head")
def legacy_log_head(request: Request):
    charge_head(ratesrc.source(request))
    body = _signed_view(None)
    if body is None:
        raise HTTPException(status_code=404, detail="legacy log is empty")
    return body["head"]


@router.get("/api/v1/legacy-log/proof")
def legacy_log_proof(request: Request, name: str = Query(max_length=32)):
    charge_proof(ratesrc.source(request))
    body = _signed_view((name or "").strip().lower())
    if body is None:
        raise HTTPException(status_code=404, detail="no witnessed hold for this name")
    return body


@router.get("/api/v1/legacy-log/witnessed")
def legacy_log_witnessed(request: Request):
    """Marks this node has stored. 200 with an empty list when nothing has
    been observed yet, including when the witness set is not pinned: the
    read must not depend on Genesis's DB being the only copy."""
    charge_witnessed(ratesrc.source(request))
    with core._db_lock, core._db() as conn:
        window_open.init_schema(conn)
        rows = conn.execute(
            "SELECT log_id, seq, head_hash, seen_at FROM legacy_observed_heads ORDER BY seen_at, seq"
        ).fetchall()
    return {"marks": [{"log_id": r[0], "seq": r[1], "head_hash": r[2], "seen_at": r[3]} for r in rows]}


@router.post("/api/v1/legacy-log/observe")
async def legacy_log_observe(request: Request):
    src = ratesrc.source(request)
    charge_observe_source(src)
    try:
        data = await request.json()
    except Exception:
        charge_observe_scoped("malformed")
        raise HTTPException(status_code=400, detail="body is not JSON")
    if not isinstance(data, dict):
        charge_observe_scoped("malformed")
        raise HTTPException(status_code=400, detail="body is not an object")
    signed = data.get("head")
    log_id = "missing"
    if isinstance(signed, dict) and isinstance(signed.get("head"), dict):
        lid = signed["head"].get("log_id")
        if isinstance(lid, str) and lid.strip():
            log_id = lid.strip().lower()
    charge_observe_scoped(log_id)

    def verify():
        pin = pinned()
        if pin is None:
            raise HTTPException(status_code=503, detail="legacy observe is not pinned on this node")
        pinned_log, wset = pin
        if log_id != pinned_log:
            raise HTTPException(status_code=400, detail="head is for another log")
        try:
            h = lw.verify_head(signed, wset, pinned_log)
        except lw.WitnessRefused as e:
            raise HTTPException(status_code=400, detail=str(e))
        for s in signed.get("signatures") or []:
            w = s.get("witness") if isinstance(s, dict) else None
            if not isinstance(w, str):
                continue
            why = lw.witness_key_admitted(w)
            if why:
                raise HTTPException(status_code=400, detail=f"Refused (weak key): {why}.")
        data["_head"] = h

    def write():
        h = data.get("_head")
        if not h:
            return {"status": "unwritten"}
        with core._db_lock, core._db() as conn:
            window_open.init_schema(conn)
            conn.execute(
                """INSERT OR IGNORE INTO legacy_observed_heads
                   (log_id, seq, head_hash, seen_at) VALUES (?,?,?,?)""",
                (h["log_id"], h["seq"], h["head_hash"], int(time.time())))
        return {"status": "observed", "log_id": h["log_id"], "seq": h["seq"]}

    return window_open.run_admission(verify, write)


@router.post("/api/v1/agents/import-legacy")
async def import_legacy(request: Request):
    src = ratesrc.source(request)
    # Per-source bucket before the body is parsed. Not src:auth:{src}: that
    # bucket is shared with every challenge-burning route, and charging it
    # here would let one filled auth bucket refuse every import.
    charge_import_source(src)
    try:
        data = await request.json()
    except Exception:
        charge_import_scoped("malformed")
        raise HTTPException(status_code=400, detail="body is not JSON")
    if not isinstance(data, dict):
        charge_import_scoped("malformed")
        raise HTTPException(status_code=400, detail="body is not an object")
    log_id = _import_log_id(data)
    charge_import_scoped(log_id)

    def verify():
        pin = pinned()
        if pin is None:
            raise HTTPException(status_code=503, detail="legacy import is not pinned on this node")
        pinned_log, wset = pin
        if log_id in ("missing", "malformed") or log_id != pinned_log:
            raise HTTPException(status_code=400, detail="log_id is not the log this node pins")
        name = data.get("name")
        proof = data.get("proof")
        if not isinstance(name, str) or core.NAME_RE.fullmatch(name) is None:
            raise HTTPException(status_code=400, detail="name is not a legacy name")
        try:
            pub = lw.normalize_pub(data.get("public_key") or "")
            sig = (data.get("signature") or "").strip().lower()
            if len(sig) != 128:
                raise ValueError("sig")
            bytes.fromhex(sig)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="public_key or signature is malformed")
        if not isinstance(proof, dict):
            raise HTTPException(status_code=400, detail="proof is not an object")
        msg = import_message(name, log_id, pub, proof)
        if not _ed.checkvalid(bytes.fromhex(sig), msg, bytes.fromhex(pub)):
            raise HTTPException(status_code=400, detail="signature does not verify")
        why = window_open.weak_reason(pub)
        if why:
            raise HTTPException(status_code=400, detail=f"Refused (weak key): {why}.")
        try:
            _h, _entries, ident = lw.check_identity(proof, name, wset, pinned_log)
        except lw.WitnessRefused as e:
            raise HTTPException(status_code=400, detail=str(e))
        if not witnessed_inception_ok(ident, pub):
            raise HTTPException(
                status_code=400,
                detail="presented key is not the witnessed inception key")
        data["_ident"] = ident
        data["_pub"] = pub
        data["_name"] = name

    def write():
        ident = data.get("_ident")
        if not ident:
            return {"status": "unwritten"}
        with core._db_lock, core._db() as conn:
            window_open.init_schema(conn)
            conn.execute(
                """INSERT INTO legacy_imports
                   (name, log_id, k0_pub, public_key, head_seq, imported_at)
                   VALUES (?,?,?,?,?,?)""",
                (data["_name"], log_id, ident["k0_pub"], data["_pub"],
                 ident["head_seq"], int(time.time())))
        return {"status": "imported", "name": data["_name"], "log_id": log_id,
                "k0_pub": ident["k0_pub"], "head_seq": ident["head_seq"],
                "late": ident["late"]}

    return window_open.run_admission(verify, write)
