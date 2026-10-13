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
import threading
import time

from fastapi import APIRouter, HTTPException, Query, Request

import core
import legacy_witness as lw
import ratesrc
import window_open
from fed import ed25519 as _ed

router = APIRouter()
# READ deploy (oracle/legacy-log-read-only): the mounted router carries ONLY
# GET /legacy-log/head and GET /legacy-log/proof. /witnessed, /observe and
# /agents/import-legacy stay in the code on write_router, which app.py does
# NOT include; tests that exercise them mount it on their own app.
write_router = APIRouter()

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


IMPORT_CERTS_PER_SOURCE = 60 * 66 * 4


def charge_import_certs(src: str, n: int) -> None:
    """Per-source bucket scaled by cert count, charged before any per-hop
    verify (hop_certs.verify_hops calls this with the row count)."""
    for _ in range(max(1, int(n))):
        core._check_rate(f"import-legacy:certs:{src}", limit=IMPORT_CERTS_PER_SOURCE)


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


_view_lock = threading.Lock()      # single-flight: one builder per log seq
_view_cache: dict = {}             # top seq -> (log_id, entries, body-without-name)


def _read_conn():
    """A plain SQLite read connection, NOT under core._db_lock: a read takes
    only SQLite's shared lock for the ~15 ms row copy, so GET /head and
    /proof never hold the process-wide write lock (writers wait on SQLite's
    busy timeout for at most that copy)."""
    return core._db()


def _top_seq():
    conn = _read_conn()
    try:
        row = conn.execute("SELECT MAX(seq) FROM legacy_migration_log").fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    return row[0] if row else None


def _build(top):
    """Raw rows are copied in one read transaction (no core._db_lock); the proof walk (entry dicts,
    roots, full(), signing) runs outside it. Built once per log seq."""
    conn = _read_conn()
    try:
        conn.execute("BEGIN")                       # one consistent snapshot
        log_id, entries = window_open.export_log(conn)
        hop_rows = window_open.export_hop_rows(conn)
        leaves = window_open.export_bound_leaves(conn)
        conn.execute("COMMIT")
    finally:
        conn.close()
    if not entries:
        return None
    import hop_certs
    roots = {"hops_root": lw.hops_root(hop_rows), "bound_root": hop_certs.bound_root(leaves),
             "v1_frozen_root": hop_certs.v1_frozen_root(hop_rows)}
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
        **roots,
    }

    def _sign(msg, sk=core._NODE_PRIV, pk=pub):
        return pk, _ed.sign(msg, bytes.fromhex(sk), bytes.fromhex(pk)).hex()

    holds = {e.get("name") for e in entries if e["kind"] == "hold"}
    return holds, {"head": lw.sign_head(head, [_sign]), "span": [lw.full(e) for e in entries],
                   "hops": hop_rows, "bound": leaves}


def _signed_view(name: str | None):
    """Signed head plus span for the local log, or None when it cannot
    answer (empty log, or no hold for `name`). Built once per log seq
    (single-flight), shared across names; core._db_lock is never taken."""
    top = _top_seq()
    if top is None:
        return None
    built = _view_cache.get(top)
    if built is None:
        with _view_lock:
            built = _view_cache.get(top)
            if built is None:
                built = _build(top)
                if built is None:
                    return None
                _view_cache.clear()
                _view_cache[top] = built
    holds, body = built
    if name is not None and name not in holds:
        return None
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


_abuild = None


async def _view(name):
    """Event-loop side: cached views answer without a worker thread; a miss
    runs ONE build at a time in the threadpool while other requests await
    (holding no thread), so a /proof burst cannot starve other routes."""
    global _abuild
    import asyncio
    from starlette.concurrency import run_in_threadpool
    loop = asyncio.get_running_loop()
    if _abuild is None or _abuild[0] is not loop:
        _abuild = (loop, asyncio.Lock())
    top = await run_in_threadpool(_top_seq)
    built = _view_cache.get(top)
    if built is not None:
        holds, body = built
        return None if (name is not None and name not in holds) else body
    async with _abuild[1]:
        return await run_in_threadpool(_signed_view, name)


@router.get("/api/v1/legacy-log/head")
async def legacy_log_head(request: Request):
    charge_head(ratesrc.source(request))
    body = await _view(None)
    if body is None:
        raise HTTPException(status_code=404, detail="legacy log is empty")
    return unwitnessed_head(body["head"])


def unwitnessed_head(signed: dict) -> dict:
    """Genesis-only signed head, explicitly unwitnessed: no cosign and no
    threshold fields. Node B's import refuses it (no threshold cosign)."""
    return {"head": signed["head"], "signatures": signed["signatures"],
            "witnessed": False, "status": "unwitnessed"}


def unwitnessed_proof(body: dict) -> dict:
    """The /proof body: span, hops, bound and the unwitnessed head; nothing
    else from the cached view (no cosign / threshold fields)."""
    return {"head": unwitnessed_head(body["head"]), "span": body["span"], "hops": body["hops"],
            "bound": body["bound"], "witnessed": False, "status": "unwitnessed"}


@router.get("/api/v1/legacy-log/proof")
async def legacy_log_proof(request: Request, name: str = Query(max_length=32)):
    charge_proof(ratesrc.source(request))
    body = await _view((name or "").strip().lower())
    if body is None:
        raise HTTPException(status_code=404, detail="no hold for this name in the legacy log")
    return unwitnessed_proof(body)


@write_router.get("/api/v1/legacy-log/witnessed")
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


@write_router.post("/api/v1/legacy-log/observe")
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


@write_router.post("/api/v1/agents/import-legacy")
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
            _h, _entries, ident = lw.check_identity(proof, name, wset, pinned_log,
                                                 charge=lambda n: charge_import_certs(src, n))
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
