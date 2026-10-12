#!/usr/bin/env python3
"""Window-open witness kinds, split 9/9: resolver freeze on equivocating
threshold heads (board 8:39 PM). Freeze, don't pick. Every mutant here is
killed by a row in this file."""
import asyncio
import time

import head_freeze as hf
import hop_certs as hc
from wok_common import check, finish, keypair, lw, record_mutant, sign_with

W = [keypair(bytes([0x90 + j]) * 32) for j in range(3)]
OUT = [keypair(bytes([0x98 + j]) * 32) for j in range(2)]
WSET = lw.WitnessSet(2, W)
LOG = "fe" * 32
K0, K1, K2, KM, KP = (keypair(bytes([0x80 + j]) * 32) for j in range(5))


def sub(seq, hh, leaves, signers, fmt=hf.COSIGN_FORMAT, wset=WSET):
    h = {"log_id": LOG, "witness_set": wset.id, "seq": seq, "head_hash": hh,
         "window_open_seq": 1, "window_close_seq": 2, "window_state": "closed",
         **{k: "00" * 32 for k in lw.HEAD_ROOT_FIELDS}}
    h["bound_root"] = hc.bound_root(leaves)
    return {"format": fmt, "head": lw.sign_head(h, [lambda m, _p=p: (_p, sign_with(_p, m)) for p in signers]),
            "bound": leaves}


H0 = sub(1, "a0" * 32, [["n", K0], ["m", KM], ["p", KP]], W[:2])
HA = sub(2, "a1" * 32, [["n", K1], ["m", KM]], W[:2])
HB = sub(2, "a2" * 32, [["n", K2], ["m", KM]], W[1:])          # W[1] signs both


def fresh():
    return hf.Freeze(WSET, LOG)


def equivocation(f=None):
    f = f or fresh()
    f.submit("s1", H0)
    f.submit("s1", HA)
    f.submit("s2", HB)
    return f


f = equivocation()
real_eq = f.resolve("n") == "contested" and f.resolve("m") == KM and f.resolve("p") == KP
check("(freeze) heads binding N to K1 and K2 at one seq: N 'contested'; identical M and "
      "fallback-only P still resolve", real_eq, (f.resolve("n"), f.resolve("m"), f.resolve("p")))


class FirstSeen(hf.Freeze):
    def record(self, v):
        self.heads.setdefault(v["seq"], {})
        if not self.heads[v["seq"]]:
            self.heads[v["seq"]][v["head_hash"]] = v["bindings"]


m1 = equivocation(FirstSeen(WSET, LOG))
record_mutant("use the first head seen", "(freeze) N contested", real_eq, m1.resolve("n") != "contested")

# ---------------------------------------------------------------- junk second heads change nothing
forged = sub(2, "a2" * 32, [["n", K2], ["m", KM]], W[1:])
forged["head"]["signatures"] = [dict(s, sig="00" * 64) for s in forged["head"]["signatures"]]
outset = sub(2, "a3" * 32, [["n", K2], ["m", KM]], [])
outset["head"] = lw.sign_head(outset["head"]["head"], [lambda m, _p=p: (_p, sign_with(_p, m)) for p in OUT])
relabel = dict(HB, format=hf.MARK_FORMAT)


def junk(F=hf.Freeze):
    out = []
    for j in (forged, outset, relabel):
        g = F(WSET, LOG)
        g.submit("s1", H0)
        g.submit("s1", HA)
        r = g.submit("evil", j)
        out.append((r, g.resolve("n")))
    return out


jr = junk()
real_j = all(r.startswith("refused") and n == K1 for r, n in jr)
check("(freeze) forged / out-of-set / relabeled-mark second head: refused, N still resolves to K1",
      real_j, jr)


class FreezeFirst(hf.Freeze):
    def submit(self, sender, sub_):
        why = self.admit(sender, sub_)
        if why != "ok":
            return why
        try:
            h = sub_["head"]["head"]
            self.record({"seq": h["seq"], "head_hash": h["head_hash"],
                         "bindings": {n: hc.norm(p) for n, p in sub_["bound"]}})
        except (KeyError, TypeError):
            pass
        return "accepted" if self.verify(sub_) else "refused"


mj = junk(FreezeFirst)
record_mutant("freeze before verifying", "(freeze) junk second head changes nothing", real_j,
              any(n == "contested" for _, n in mj))

# ---------------------------------------------------------------- flood: capped verifies, charged first
order = []
g = hf.Freeze(WSET, LOG, charge=lambda s: order.append(("charge", g.verifies)))
for _ in range(10_000):
    g.submit("flood", forged)
check(f"(flood) 10k submissions from one sender at one seq: {g.verifies} verifies <= cap {hf.PER_SENDER}",
      g.verifies == hf.PER_SENDER, g.verifies)
check("(flood) every verify was charged before it ran",
      len(order) == g.verifies and all(v == i for i, (_, v) in enumerate(order)), order[:3])
g2 = hf.Freeze(WSET, LOG)
for i in range(1000):
    g2.submit(f"s{i}", forged)
check(f"(flood) 1000 senders at one seq: {g2.verifies} verifies <= per-seq cap {hf.PER_SEQ}",
      g2.verifies == hf.PER_SEQ, g2.verifies)


# ---------------------------------------------------------------- off the event loop
async def loop_row():
    g3 = hf.Freeze(WSET, LOG)
    ticks = 0
    done = False

    async def ticker():
        nonlocal ticks
        while not done:
            ticks += 1
            await asyncio.sleep(0.001)
    t = asyncio.create_task(ticker())
    real_v = g3.verify

    def slow(s):
        time.sleep(0.5)
        return real_v(s)
    g3.verify = slow
    r = await g3.submit_async("s", H0)
    done = True
    await t
    return r, ticks


lr, ticks = asyncio.run(loop_row())
check("(loop) verify runs off the event loop (loop kept ticking during a 0.5 s verify)",
      lr == "accepted" and ticks > 50, (lr, ticks))

finish("freeze")
