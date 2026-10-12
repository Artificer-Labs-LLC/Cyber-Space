"""Resolver freeze on equivocating threshold heads (board 8:39 PM).

Freeze, don't pick. A resolver holding two FULLY verified threshold heads
at the same seq answers "contested" for every name whose binding differs
between them, and falls back to the last head its witnesses agreed on for
everything else it cannot take from the pair; names identical in both
heads keep resolving.

A second head counts only after full threshold verification, in order:
intake caps (per sender, per seq), charge, then off the event loop:
witness-cosign/v1 tag, lw.verify_head (in-set, strict majority, Genesis
never counts; libsodium via hop_certs), bound leaves vs bound_root.
Nothing about a head is recorded before it verifies.
"""
from __future__ import annotations

import asyncio
from collections import Counter

import hop_certs as hc
import legacy_witness as lw

COSIGN_FORMAT = "witness-cosign/v1"
MARK_FORMAT = "witness-mark/v1"
PER_SENDER = 8          # submissions per sender per seq window
PER_SEQ = 16            # submissions per seq, all senders


def sodium_sig_ok(pub_hex, msg, sig_hex) -> bool:
    """libsodium only: canonical decode, is_valid_point, crypto_sign verify."""
    return hc.verify_path(pub_hex, msg, sig_hex, sender="freeze")


class Freeze:
    def __init__(self, wset, log_id, per_sender=PER_SENDER, per_seq=PER_SEQ, charge=None):
        self.wset, self.log_id = wset, log_id
        self.per_sender, self.per_seq = per_sender, per_seq
        self.charge = charge or (lambda sender: None)
        self.by_sender, self.by_seq = Counter(), Counter()
        self.heads = {}            # seq -> {head_hash: bindings}
        self.verifies = 0

    # ---------------------------------------------------------------- intake
    def verify(self, sub) -> dict | None:
        """bindings {name: pub} of a fully verified threshold head, else None."""
        self.verifies += 1
        if not isinstance(sub, dict) or sub.get("format") != COSIGN_FORMAT:
            return None
        try:
            h = lw.verify_head(sub["head"], self.wset, self.log_id, sig_ok=sodium_sig_ok)
            leaves = sub["bound"]
            if hc.bound_root(leaves) != h["bound_root"]:
                return None
            return {"seq": h["seq"], "head_hash": h["head_hash"],
                    "bindings": {n: hc.norm(p) for n, p in leaves}}
        except (lw.WitnessRefused, KeyError, TypeError, ValueError, AttributeError):
            return None

    def admit(self, sender, sub) -> str:
        seq = sub.get("head", {}).get("head", {}).get("seq") if isinstance(sub, dict) else None
        if type(seq) is not int:
            return "refused: malformed"
        if self.by_sender[(sender, seq)] >= self.per_sender or self.by_seq[seq] >= self.per_seq:
            return "refused: intake cap"
        self.by_sender[(sender, seq)] += 1
        self.by_seq[seq] += 1
        self.charge(sender)                         # charged before it is checked
        return "ok"

    def record(self, v) -> None:
        self.heads.setdefault(v["seq"], {})[v["head_hash"]] = v["bindings"]

    def submit(self, sender, sub) -> str:
        why = self.admit(sender, sub)
        if why != "ok":
            return why
        v = self.verify(sub)
        if v is None:
            return "refused: not a verified threshold head"
        self.record(v)
        return "contested" if len(self.heads[v["seq"]]) > 1 else "accepted"

    async def submit_async(self, sender, sub) -> str:
        """Verify off the event loop."""
        why = self.admit(sender, sub)
        if why != "ok":
            return why
        v = await asyncio.to_thread(self.verify, sub)
        if v is None:
            return "refused: not a verified threshold head"
        self.record(v)
        return "contested" if len(self.heads[v["seq"]]) > 1 else "accepted"

    # ---------------------------------------------------------------- resolve
    def agreed(self):
        """Bindings of the last seq with exactly one verified head."""
        for seq in sorted(self.heads, reverse=True):
            if len(self.heads[seq]) == 1:
                return next(iter(self.heads[seq].values()))
        return {}

    def resolve(self, name):
        top = max(self.heads) if self.heads else None
        if top is not None and len(self.heads[top]) > 1:
            vals = {b.get(name) for b in self.heads[top].values()}
            if len(vals) > 1:
                return "contested"
            v = vals.pop()
            if v is not None:
                return v
        return self.agreed().get(name)
