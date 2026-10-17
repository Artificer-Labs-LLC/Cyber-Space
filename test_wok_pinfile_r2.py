"""Pin-file format r2 (Loom, ART-42 bdba9b29; Villhaze 1e762099).
Each row is a named assertion. A row that raises anything other than its
asserted outcome is reported as ERROR, not as a failed assertion, so a
mutant only counts as killed when a row's assertion fails."""
import hashlib, os, struct, sys, tempfile, time, traceback
from nacl.signing import SigningKey, VerifyKey
import head_level as hl

R = []
CALLS = [0]
def sig_ok(pub, msg, sig):
    CALLS[0] += 1
    try:
        VerifyKey(bytes.fromhex(pub)).verify(msg, bytes.fromhex(sig)); return True
    except Exception:
        return False

def K(i):
    k = SigningKey(hashlib.sha256(b"wok-pin-r2-%d" % i).digest()); return k, k.verify_key.encode().hex()
gen, GEN = K(0); f1, F1 = K(1); f2, F2 = K(2); o1, O1 = K(3); x, X = K(5)
s0, S0 = K(10); s1, S1 = K(11); s2, S2 = K(12)
SIGNERS = (S0, S1, S2); THR = 2
LID = hl.log_id_of(GEN)
OP_FLEET = b"\x01" * 32; OP_A = b"\x0a" * 32; OP_X = b"\x0b" * 32
ROOT = b"\xab" * 32; PROOT = b"\xcd" * 32; MARK = (5, PROOT)
D = tempfile.mkdtemp()
ISSUED = 1_700_000_000

def ent(seq, prev, op, oid, cls=0, pub=None, size=0, ref=b"ART-42/1e762099", signer_ks=((0, s0), (1, s1))):
    pubb = hl.ZERO32 if pub is None else bytes.fromhex(pub)
    body = hl.ENTRY_HEAD.pack(seq, prev, op, oid, cls, pubb, size, ISSUED + seq) + bytes([len(ref)]) + ref
    sigs = bytes([len(signer_ks)]) + b"".join(bytes([i]) + k.sign(hl.PIN_MAGIC_V2 + body).signature for i, k in signer_ks)
    return body + sigs

def chain(specs):
    """specs: list of dicts of ent() kwargs (without seq/prev); returns entry bytes list."""
    out, prev = [], hl.ZERO32
    for n, s in enumerate(specs, 1):
        e = ent(n, prev, **s); out.append(e); prev = hashlib.sha256(e).digest()
    return out

def pfile(entries, lid=LID, extra=b""):
    return hl.PIN_MAGIC_V2 + lid + struct.pack(">I", len(entries)) + b"".join(entries) + extra

BASE = [dict(op=1, oid=OP_FLEET, cls=1), dict(op=1, oid=OP_A, cls=2), dict(op=2, oid=OP_FLEET, pub=F1)]
def parse(data, prefix=(0, None), thr=THR): return hl.parse_pins_v2(data, GEN, sig_ok, SIGNERS, thr, prefix)
def load(path, st, signers=SIGNERS, thr=THR): return hl.load_pins_v2(path, GEN, sig_ok, st, signers, thr)
def wfile(name, data):
    p = os.path.join(D, name); open(p, "wb").write(data); return p

def refusal(fn):
    """Returns the Refused message, or None if fn() returned. Other
    exceptions propagate (-> ERROR, never counted as an assertion)."""
    try: fn(); return None
    except hl.Refused as e: return str(e)
def refused0(fn, why):
    CALLS[0] = 0; r = refusal(fn); return r is not None and why in r and CALLS[0] == 0

def head(mode, op=None, size=7):
    op = (OP_FLEET if mode == 1 else hl.ZERO32) if op is None else op
    return hl.pack_head(mode, LID, size, ROOT, MARK[0], MARK[1], op, ISSUED + 100)
def gsig(b): return gen.sign(b).signature.hex()
def cos(ks, b):
    body = b[b.index(b"\n") + 1:]
    return [{"pub": k.verify_key.encode().hex(), "sig": k.sign(hl.COSIGN_PREFIX + body).signature.hex()} for k in ks]
# b1b88de: verify_head takes only a VerifiedMark. Build the stored mark (5, PROOT)
# the only legal way, as test_wok_level.py does: a Genesis-signed root head of size 5.
MARK_ROOT_HEAD = hl.pack_head(0, LID, MARK[0], MARK[1], 0, hl.ZERO32, hl.ZERO32, 1_700_000_000)
VMARK = hl.root_mark(MARK_ROOT_HEAD, gen.sign(MARK_ROOT_HEAD).signature.hex(), GEN, [], parse(pfile([])), sig_ok)[1]
def level(b, cs, pins):
    try: return hl.verify_head(b, gsig(b), GEN, cs, pins, sig_ok, mark=VMARK)[0]
    except hl.Refused as e: return "refused: " + str(e)

# ---- rows ----
def row1_empty():
    empty = parse(pfile([]))
    def ld(*a, **k):
        try: return load(*a, **k)
        except hl.Refused as e: return "refused: " + str(e)   # fail-closed means None, not a refusal
    ph = ld(wfile("r1.bin", pfile(chain(BASE))), os.path.join(D, "r1s"), signers=None, thr=None)  # compiled placeholder
    ph0 = ld(wfile("r1b.bin", pfile(chain(BASE))), os.path.join(D, "r1t"), thr=0)
    b0, b1 = head(0), head(1)
    return (empty["keys"] == {} and ph is None and ph0 is None
            and level(b0, cos([f1, f2], b0), empty) == "unwitnessed"
            and level(b0, cos([f1, f2], b0), ph) == "unwitnessed"
            and level(b1, cos([f1], b1), empty).startswith("refused"))

def row2_rewrite():
    st = os.path.join(D, "r2s"); p = os.path.join(D, "r2.bin")
    good = chain(BASE)
    open(p, "wb").write(pfile(good)); load(p, st)
    alt = chain(BASE[:1] + [dict(op=1, oid=OP_X, cls=2)] + BASE[2:])   # rewrites entry 2 (chain re-hashed)
    open(p, "wb").write(pfile(alt))
    r = refusal(lambda: load(p, st))
    return r is not None and "rollback" in r

def row3_drop():
    st = os.path.join(D, "r3s"); p = os.path.join(D, "r3.bin")
    good = chain(BASE)
    open(p, "wb").write(pfile(good)); load(p, st)
    open(p, "wb").write(pfile(good[:2]))
    r = refusal(lambda: load(p, st))
    return r is not None and "rollback" in r

def row4_retire():
    pins = parse(pfile(chain(BASE + [dict(op=3, oid=OP_FLEET, pub=F1, size=10)])))
    before, at, after = head(1, size=7), head(1, size=10), head(1, size=11)
    return (level(before, cos([f1], before), pins) == "single-operator"
            and level(at, cos([f1], at), pins) == "single-operator"
            and level(after, cos([f1], after), pins).startswith("refused")
            and level(head(0, size=11), cos([f1], head(0, size=11)), pins) == "unwitnessed")

def row5_readd():
    specs = BASE + [dict(op=3, oid=OP_FLEET, pub=F1, size=10), dict(op=2, oid=OP_FLEET, pub=F1, size=20)]
    return refused0(lambda: parse(pfile(chain(specs))), "retired key re-added")

def row6_empty_ref():
    specs = BASE[:2] + [dict(op=2, oid=OP_FLEET, pub=F1, ref=b"")]
    return refused0(lambda: parse(pfile(chain(specs))), "ruling_ref")

def row7_key_before_op():
    specs = [dict(op=1, oid=OP_A, cls=2), dict(op=2, oid=OP_FLEET, pub=F1)]
    return refused0(lambda: parse(pfile(chain(specs))), "before add-operator")

def row8_triple():
    specs = [dict(op=1, oid=OP_FLEET, cls=1, signer_ks=((0, s0), (0, s0), (0, s0)))]
    return refused0(lambda: parse(pfile(chain(specs))), "unsorted or duplicate")

def row9_network():
    pins = parse(pfile(chain(BASE)))
    rogue = pfile(chain([dict(op=1, oid=OP_X, cls=2), dict(op=2, oid=OP_X, pub=X)]))
    b = head(1)
    resp = {"head": b, "genesis_sig": gsig(b), "cosigns": cos([f1, x], b), "pins": rogue}
    try: lv = hl.verify_head_response(resp, GEN, pins, sig_ok, mark=VMARK)[0]
    except hl.Refused as e: lv = "refused: " + str(e)
    # a URL-shaped path that also exists on disk, so dropping the guard loads it (an assertion, not an OSError)
    os.makedirs(os.path.join(D, "https:"), exist_ok=True); wfile("https:/pins", rogue)
    url = refusal(lambda: load(os.path.join(D, "https://pins"), os.path.join(D, "r9s")))
    return lv == "single-operator" and url is not None and "local path" in url

GOLDEN_SPECS = [dict(op=1, oid=OP_FLEET, cls=1), dict(op=1, oid=OP_A, cls=2), dict(op=2, oid=OP_A, pub=O1, size=3)]
def row10_golden():
    data = pfile(chain(GOLDEN_SPECS))
    pins = parse(data)
    b = head(2)
    return (data.hex() == GOLDEN_HEX and pins["last"][0] == 3
            and set(pins["ops"]) == {OP_FLEET, OP_A} and set(pins["keys"]) == {O1}
            and level(b, cos([o1], b), pins) == "independent")

def row11_one_sig():
    specs = [dict(op=1, oid=OP_FLEET, cls=1, signer_ks=((0, s0),))]
    return refused0(lambda: parse(pfile(chain(specs))), "too few")

def row12_oor():
    specs = [dict(op=1, oid=OP_FLEET, cls=1, signer_ks=((0, s0), (7, s1)))]
    return refused0(lambda: parse(pfile(chain(specs))), "out of range")

def row_extend_ok():
    st = os.path.join(D, "rxs"); p = os.path.join(D, "rx.bin")
    good = chain(BASE + [dict(op=2, oid=OP_A, pub=O1)])
    open(p, "wb").write(pfile(good[:3])); load(p, st)
    open(p, "wb").write(pfile(good)); pins = load(p, st)
    return set(pins["keys"]) == {F1, O1} and pins["last"][0] == 4

def row_sig_calls():
    specs = [dict(op=1, oid=OP_FLEET, cls=1, signer_ks=((0, s0), (1, s1), (2, s2)))]
    CALLS[0] = 0; parse(pfile(chain(specs))); return CALLS[0] == THR

def row_cheap_first():
    # a bad signature on entry 1 and a structural error on entry 2: refused for structure, 0 verifies
    e = chain(BASE[:2]); bad = e[0][:-1] + bytes([e[0][-1] ^ 1])
    return refused0(lambda: parse(pfile([bad, e[1]], extra=b"\x00")), "")

def row_caps():
    big = hl.PIN_MAGIC_V2 + LID + struct.pack(">I", 257)
    ops = [dict(op=1, oid=bytes([i]) * 32, cls=1) for i in range(1, 18)]
    keys = [dict(op=1, oid=OP_FLEET, cls=1)] + [dict(op=2, oid=OP_FLEET, pub=K(200 + i)[1]) for i in range(5)]
    return (refused0(lambda: parse(big), "too many entries")
            and refused0(lambda: parse(pfile(chain(ops))), "too many operators")
            and refused0(lambda: parse(pfile(chain(keys))), "too many live keys"))

def row_genesis_and_op():
    return (refused0(lambda: parse(pfile(chain(BASE[:1] + [dict(op=2, oid=OP_FLEET, pub=GEN)]))), "Genesis")
            and refused0(lambda: parse(pfile(chain([dict(op=4, oid=OP_FLEET, cls=1)]))), "unknown op")
            and refused0(lambda: parse(pfile(chain(BASE), extra=b"\x00")), "trailing"))

V = 10
RETIRED_AT_V = BASE + [dict(op=3, oid=OP_FLEET, pub=F1, size=V)]
def row_valid_to_boundary_at():
    pins = parse(pfile(chain(RETIRED_AT_V))); b = head(1, size=V)
    return level(b, cos([f1], b), pins) == "single-operator"
def row_valid_to_boundary_past():
    pins = parse(pfile(chain(RETIRED_AT_V))); b = head(1, size=V + 1)
    return level(b, cos([f1], b), pins).startswith("refused: marker 'single-operator' but cosigns give 'unwitnessed'")

def row_fc_r2():
    # Lodestar's first-contact rule with an r2 pin file loaded (fleet key live)
    pins = parse(pfile(chain(BASE)))
    bad = hl.pack_head(1, LID, 7, ROOT, 5, PROOT, OP_FLEET, ISSUED)
    ok = hl.pack_head(1, LID, 7, ROOT, 0, hl.ZERO32, OP_FLEET, ISSUED)
    CALLS[0] = 0
    try: hl.verify_head(bad, gsig(bad), GEN, cos([f1], bad), pins, sig_ok, mark=None); r = None
    except hl.Refused as e: r = e
    zero = CALLS[0] == 0
    lv = hl.verify_head(ok, gsig(ok), GEN, cos([f1], ok), pins, sig_ok, mark=None)[0]
    return isinstance(r, hl.FirstContactRefused) and zero and lv == "single-operator"

ROWS = [
    ("(1) empty shipped file / placeholder + fleet cosigns: unwitnessed", row1_empty),
    ("(2) file rewriting entry 2 refused after entry 3 loaded", row2_rewrite),
    ("(3) dropping the last entry refused", row3_drop),
    ("(4) retire-key: counts up to valid_to, not past it", row4_retire),
    ("(5) re-adding a retired key refused, 0 verifies", row5_readd),
    ("(6) empty ruling_ref refused, 0 verifies", row6_empty_ref),
    ("(7) add-key without add-operator refused, 0 verifies", row7_key_before_op),
    ("(8) three copies of one signer's sig fail threshold 2, 0 verifies", row8_triple),
    ("(9) pin file carried on /head ignored; network path refused", row9_network),
    ("(10) golden vector: 3 entries, one fleet + one outside operator", row10_golden),
    ("(11) threshold 2 with one valid sig refused, 0 verifies", row11_one_sig),
    ("(12) out-of-range signer_index refused, 0 verifies", row12_oor),
    ("(13a) row_valid_to_boundary: key retired at valid_to=V counts for a head at V", row_valid_to_boundary_at),
    ("(13b) row_valid_to_boundary: same key does not count for a head at V+1", row_valid_to_boundary_past),
    ("(FC-r2) first contact with an r2 pin file: nonzero prev refused 0 verifies; prev 0 labelled", row_fc_r2),
    ("(x) honest extension of the accepted chain loads", row_extend_ok),
    ("(x) exactly threshold-many verifies per entry", row_sig_calls),
    ("(x) structural refusal before any verify", row_cheap_first),
    ("(x) n_entries>256 / >16 operators / >4 live keys refused, 0 verifies", row_caps),
    ("(x) Genesis key / unknown op / trailing bytes refused, 0 verifies", row_genesis_and_op),
]
# sha256 seeds 'wok-pin-r2-%d'; signers 10,11 sign; issued_at 1700000000+seq.
GOLDEN_HEX = (
    "637962657273706163652d7769746e6573732d70696e732f76320a4200f917733dd0f16abdf5ffbbc68f188c993ad13d"
    "9e67a732c16dcc272b22b500000003000000000000000100000000000000000000000000000000000000000000000000"
    "000000000000000101010101010101010101010101010101010101010101010101010101010101010100000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000006553f1010f4152542d3432"
    "2f31653736323039390200ea92cd8c52c909eaa5df7dafaa57771b38d84cac6d803e90e3b8846bd0251731adbc61af0f"
    "3ebaede0281f9f0898792454c3e6a81ab8b42c0d6a7cb0660a790701864fd007abb4d26cc0418c6de4bac58a2bf44a5b"
    "37d0b6f702cf2bee179d38e896b95c771507e7ee62dafc7cabe6895692f2abf41d9b83f7a34f5423193a090b00000000"
    "00000002104d93b9f0ccd28d22f2d17a74a34589ac8ad6879fe3c0bb8076146998582af7010a0a0a0a0a0a0a0a0a0a0a"
    "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a020000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000006553f1020f4152542d34322f31653736323039390200ee1328d506b4d57d"
    "8f3e7a4fa77c81b3a19a545cefb0a7d2e991008e94fa442a179281a77e2db902710ff684bd5396d1a4570e88d2e7a10c"
    "581cf11c54327502017372b9697a573a57a9a8e9fd8b717e927878749036f51ae097b382811e3efab7f1ef0802bdc41e"
    "677f49241b2886d76246fc8dfed8f3bb2da2abb8b3206e440600000000000000032c887533c5805a9520214b43fde1b1"
    "2face3aca632749fff871022b906c9742c020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
    "0a0a00db711b67175a14ddb202d8a8c237cf0a6083dedc90e7e76a3976f8c4d32baa2e00000000000000030000000065"
    "53f1030f4152542d34322f31653736323039390200f703773f8bf9edfa63da79e7de149540ab3008e0dfac4cdb87554d"
    "e6bfb2f8087ce165a002208622a9900b96e30da67b909263600c306cafe23abc938316cf04017e50a33580b12757f1c8"
    "dea80967b3121dbf22cf3008efaff9e276a0cca76b5b621e110b1013d879deee27be02bde781b3497f498eb5750774c6"
    "5928ba679d03"
)
if "--emit-golden" in sys.argv:
    print(pfile(chain(GOLDEN_SPECS)).hex()); raise SystemExit(0)

fails = errors = 0
for n, f in ROWS:
    try:
        ok = bool(f()); print(("  ok   " if ok else "  FAIL ") + n); fails += not ok
    except Exception as e:
        errors += 1; print(f"  ERROR {n}: {type(e).__name__}: {e}")
print(f"pinfile_r2: {len(ROWS) - fails - errors} passed, {fails} failed, {errors} errored")
raise SystemExit(1 if fails or errors else 0)
