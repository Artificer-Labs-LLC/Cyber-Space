#!/usr/bin/env python3
"""Pin-rotation v2 belt, item3 (split from test_pin_rotation_v2.py)."""
from pinrot_common import *  # noqa: F401,F403
from pinrot_common import _round_k, _flat_nf, _flat_doc, _ed, _fed_env  # noqa: F401

# ================================================================ item 3
print("item 3: evidence store capped, charged before write", flush=True)


# Minted once and replayed into both the real and the mutant run (the store
# is emptied between runs and none of these names is pinned), so the file
# pays for 256 signatures once, not twice.
_tag = secrets.token_hex(2)
_senders = [pub(seed()) for _ in range(4)]
FLOOD = []
for i in range(128):
    _nm = f"junk{_tag}{i}"
    _k = seed()
    _prev = secrets.token_hex(32)
    FLOOD.append([nf.mint_cert(_nm, _k, pub(seed()), 1, _prev, issued_at=ISSUED),
                  nf.mint_cert(_nm, _k, pub(seed()), 1, _prev, issued_at=ISSUED)])


def run_flood(stop_over_cap=False):
    """stop_over_cap is only used for the mutant run: once the store has
    grown past the cap the row has already failed, so the rest of the flood
    is not replayed (keeps the file far under the suite timeout)."""
    before = db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    log0 = db("SELECT COUNT(*) FROM name_pin_log")[0][0]
    con0 = db("SELECT COUNT(*) FROM name_contested")[0][0]
    t_flood = next_round()
    for i, pair in enumerate(FLOOD):
        ingest(pair, sender=_senders[i % 4], now=t_flood + i)
        if stop_over_cap and (db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
                              - before) > 4 * nf.EVIDENCE_PER_SENDER:
            break
    after = db("SELECT COUNT(*) FROM name_cert_evidence")[0][0]
    grown = after - before
    return (grown <= 4 * nf.EVIDENCE_PER_SENDER and after <= nf.EVIDENCE_GLOBAL
            and db("SELECT COUNT(*) FROM name_pin_log")[0][0] == log0
            and db("SELECT COUNT(*) FROM name_contested")[0][0] == con0), grown


with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_cert_evidence")
(real, g_real) = run_flood()
check(f"128 POSTs of junk pairs: store <= cap ({g_real}), no contested, no pin log",
      real, g_real)
with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_cert_evidence")
with patched(nf, "evidence_has_room", lambda *a: True):
    (mut, g_mut) = run_flood(stop_over_cap=True)
mutant("evidence store uncapped", "junk flood stays under cap", real, mut)
with core._db_lock, core._db() as c:
    c.execute("DELETE FROM name_cert_evidence")
ttl_ok = True
with core._db_lock, core._db() as c:
    c.execute("INSERT INTO name_cert_evidence (name, sender, cert_hash, cert,"
              " recorded_ts) VALUES ('old','s','h1','{}',?)",
              (time.time() - nf.EVIDENCE_TTL_SEC - 5,))
    nf._prune(c, time.time())
    ttl_ok = c.execute("SELECT COUNT(*) FROM name_cert_evidence").fetchone()[0] == 0
check("evidence expires after EVIDENCE_TTL_SEC", ttl_ok)


finish()
