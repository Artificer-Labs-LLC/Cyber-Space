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

import contextlib
import hashlib
import json
import os
import time

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

import core
import head_level as hl
import hop_certs
import legacy_level_wiring as wiring
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


# Pre-verify budget: 30 s of key-check/verify CPU per source per 60 s
# window, in units of one cert (2 libsodium key checks + 1 verify =
# hop_certs.CERT_COST_US, measured). Only the per-cert charge was
# re-derived for the libsodium fast path.
PREVERIFY_BUDGET_US = 30_000_000


def import_certs_per_source(cert_cost_us: int) -> int:
    return PREVERIFY_BUDGET_US // cert_cost_us


IMPORT_CERTS_PER_SOURCE = import_certs_per_source(hop_certs.CERT_COST_US)
# Global per-window cap across all sources: 10x one source.
IMPORT_CERTS_GLOBAL = 10 * IMPORT_CERTS_PER_SOURCE


def charge_import_certs(src: str, cost_us: int) -> None:
    """Per-source and global pre-verify buckets, charged in whole certs
    (cost_us / CERT_COST_US) before any key check or verify runs."""
    for _ in range(max(1, -(-int(cost_us) // hop_certs.CERT_COST_US))):
        core._check_rate(f"import-legacy:certs:{src}", limit=IMPORT_CERTS_PER_SOURCE)
        core._check_rate("import-legacy:certs:global", limit=IMPORT_CERTS_GLOBAL)


async def admit(verify, write):
    """Bulwark: key checks / per-hop verify run off the event loop, so a
    long import does not stall other routes."""
    return await run_in_threadpool(window_open.run_admission, verify, write)


def charge_import_scoped(log_id: str) -> None:
    core._check_rate(f"import-legacy:log:{log_id}", limit=IMPORT_PER_LOG)
    core._check_rate("import-legacy:global", limit=IMPORT_GLOBAL)


class WeakPinnedWitness(ValueError):
    """A pinned witness key fails weak_reason: the whole pin is refused."""


# Bulwark/Cipher 8360b0c8 item 1(a): weak_reason runs once per pin config
# (raw keys, log_id, threshold) at load, against wset.pubs, never per
# request entry. A refused config is cached as refused (None).
_PIN_CACHE: dict = {}


def _load_pin(raw: str, log_id: str, threshold):
    key = (raw, log_id, threshold)
    if key not in _PIN_CACHE:
        try:
            wset = lw.load_witness_set(raw, threshold)
            for pub in wset.pubs:
                if lw.witness_key_admitted(pub):
                    raise WeakPinnedWitness(pub)
            _PIN_CACHE[key] = (log_id, wset)
        except (TypeError, ValueError):
            _PIN_CACHE[key] = None
    return _PIN_CACHE[key]


def pinned():
    """(log_id, WitnessSet) from the environment, or None when unset.

    Read at request time so a node can pin Genesis's witnesses without a
    code change. Unpinned import/observe answer 503 after the bucket step.
    """
    raw = os.environ.get("CYBERNET_GENESIS_WITNESSES", "").strip()
    log_id = os.environ.get("CYBERNET_GENESIS_LOG_ID", "").strip().lower()
    if not raw or len(log_id) != 64:
        return None
    # No default: an unset/invalid threshold, a duplicate key, the Genesis
    # node key in the set or a weak pinned key is refused at load (fail
    # closed, 503).
    return _load_pin(raw, log_id, os.environ.get("CYBERNET_GENESIS_WITNESS_THRESHOLD"))


_GENESIS_OK: dict = {}


def genesis_level_pub():
    """The pinned Genesis key for head_level, weak_reason checked once."""
    pub = lw.genesis_node_pub()
    if pub is None:
        return None
    if pub not in _GENESIS_OK:
        _GENESIS_OK[pub] = lw.HEX64_RE.fullmatch(pub) is not None and lw.witness_key_admitted(pub) is None
    return pub if _GENESIS_OK[pub] else None


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
        leaves = window_open.export_bound_leaves(conn)
        orphans = window_open.export_orphan_leaves(conn)
        roots = window_open.head_roots(conn)
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
        **roots,
    }

    def _sign(msg, sk=core._NODE_PRIV, pk=pub):
        return pk, _ed.sign(msg, bytes.fromhex(sk), bytes.fromhex(pk)).hex()

    body = {"head": lw.sign_head(head, [_sign]), "span": [lw.full(e) for e in entries],
            "hops": hop_rows, "bound": leaves, "orphans": orphans}
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
        wiring.init_schema(conn)
        contested = conn.execute(
            "SELECT log_id, seq, head_hash_a, head_hash_b, seen_at FROM legacy_contested_heads"
            " ORDER BY seen_at, seq").fetchall()
    bad = {(r[0], r[1]) for r in contested}
    # A contested (log_id, seq) is shown once, as evidence, never as marks.
    return {"marks": [{"log_id": r[0], "seq": r[1], "head_hash": r[2], "seen_at": r[3]}
                      for r in rows if (r[0], r[1]) not in bad],
            "contested": [{"log_id": r[0], "seq": r[1], "head_hashes": [r[2], r[3]], "seen_at": r[4]}
                          for r in contested]}


@contextlib.contextmanager
def _locked_conn():
    with core._db_lock, core._db() as conn:
        window_open.init_schema(conn)
        yield conn


@router.post("/api/v1/legacy-log/observe")
async def legacy_log_observe(request: Request):
    src = ratesrc.source(request)
    charge_observe_source(src)
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body is not JSON")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="body is not an object")
    signed = data.get("head")
    log_id = "missing"
    if isinstance(signed, dict) and isinstance(signed.get("head"), dict):
        lid = signed["head"].get("log_id")
        if isinstance(lid, str) and lid.strip():
            log_id = lid.strip().lower()

    def verify():
        pin = pinned()
        if pin is None:
            raise HTTPException(status_code=503, detail="legacy observe is not pinned on this node")
        pinned_log, wset = pin
        if log_id != pinned_log:
            raise HTTPException(status_code=400, detail="head is for another log")
        # Pinned keys passed weak_reason at pin load; the request path runs
        # the typed signatures pre-check, then checkvalid once per witness.
        try:                                # transport caps first: 0 hashes, 0 verifies
            wiring.precheck_level(data.get("level"))
        except hl.Refused as e:
            raise HTTPException(status_code=400, detail=f"{type(e).__name__}: {e}")
        try:
            wiring.precheck_signatures(signed, wset)
        except lw.WitnessRefused as e:
            raise HTTPException(status_code=400, detail=f"{type(e).__name__}: {e}")
        # Bulwark 8078a11 #3: the per-log and global budgets are charged only
        # once the typed pre-check passes, so junk from one source (charged
        # to its own per-IP bucket above) cannot exhaust an honest head's.
        charge_observe_scoped(log_id)
        try:
            vhead = wiring.verify_legacy(signed, wset, pinned_log, sig_ok=lw.checkvalid_ok)
        except lw.WitnessRefused as e:
            raise HTTPException(status_code=400, detail=f"{type(e).__name__}: {e}")
        data["_head"] = vhead

    def write():
        # ART-42 wiring cut: every head_level check (mark rebuilt from the
        # root, cheap_head, cosigns, mapping, chain extension, fork) runs in
        # legacy_level_wiring.observe before any row is written.
        vhead = data.get("_head")
        if vhead is None:
            return {"status": "unwritten"}
        genesis_pub = genesis_level_pub()
        try:
            pins = hl.load_pins(os.environ.get("CYBERNET_WITNESS_PINS", ""), genesis_pub or "",
                                lw.checkvalid_ok, os.path.join(core._DB_DIR, "witness-pins.state.json"))
            # Bulwark 8078a11 #1: the lock is held only to read, then to
            # re-check and write; every verify runs between, off the lock.
            return wiring.observe_split(_locked_conn, vhead, data.get("level"), genesis_pub, pins,
                                        lw.checkvalid_ok)
        except wiring.LevelNotBound as e:
            raise HTTPException(status_code=503, detail=str(e))
        except wiring.LogContested as e:
            raise HTTPException(status_code=409, detail=str(e))
        except wiring.MarksChanged as e:
            # marks moved while we verified off the lock: nothing written, retry
            raise HTTPException(status_code=409, detail=f"MarksChanged: {e}")
        except hl.Refused as e:
            raise HTTPException(status_code=400, detail=f"{type(e).__name__}: {e}")

    return await admit(verify, write)


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
            _h, _entries, ident = lw.check_identity(proof, name, wset, pinned_log,
                                                 charge=lambda n: charge_import_certs(src, n),
                                                 sender=src)
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

    return await admit(verify, write)
