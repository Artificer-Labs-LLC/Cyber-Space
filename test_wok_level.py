"""Head witness level + pin file (board conditions 1-4, Research Board
10:46 designs, 10:47 amendments). Conditional on Villhaze's single-operator
ruling; head_level.py is parameterized."""
import hashlib, json, os, struct, tempfile, time
from unittest import mock
import ast
from nacl.signing import SigningKey, VerifyKey
import head_level as hl

T0 = time.time()
R = []
def check(name, ok):
    R.append((name, bool(ok))); print(("  ok  " if ok else "  FAIL") + " " + name)

CALLS = [0]
def sig_ok(pub, msg, sig):
    CALLS[0] += 1
    try:
        VerifyKey(bytes.fromhex(pub)).verify(msg, bytes.fromhex(sig)); return True
    except Exception:
        return False

def K(i):
    k = SigningKey(hashlib.sha256(b"wok-level-%d" % i).digest()); return k, k.verify_key.encode().hex()
gen, GEN = K(0); f1, F1 = K(1); f2, F2 = K(2); o1, O1 = K(3); o1b, O1B = K(4); x, X = K(5)
s0, S0 = K(10); s1, S1 = K(11); s2, S2 = K(12)
SIGNERS = (S0, S1, S2); THR = 2
LID = hl.log_id_of(GEN)
OP_FLEET = b"\x01" * 32; OP_A = b"\x0a" * 32; OP_X = b"\x0b" * 32
ROOT = b"\xab" * 32; PROOT = b"\xcd" * 32
MARK = (5, PROOT)

def entry(op, cls, keys):
    out = op + bytes([cls, len(keys)])
    for pub, vf, vt in keys: out += bytes.fromhex(pub) + struct.pack(">QQ", vf, vt)
    return out
def pinfile(ops, version=3, signer_ks=((0, s0), (1, s1)), lid=LID, extra=b"", nops=None):
    body = hl.PIN_MAGIC + lid + struct.pack(">QQ", version, 1_700_000_000) + bytes([len(ops) if nops is None else nops])
    for op, cls, keys in ops: body += entry(op, cls, sorted(keys))
    sigs = bytes([len(signer_ks)]) + b"".join(bytes([i]) + k.sign(body).signature for i, k in signer_ks)
    return body + sigs + extra
OPS = sorted([(OP_FLEET, 1, [(F1, 0, 10**9), (F2, 0, 10**9)]),
              (OP_A, 2, [(O1, 0, 10**9), (O1B, 0, 10**9)])])
D = tempfile.mkdtemp()
def parse(data): return hl.parse_pins(data, GEN, sig_ok, SIGNERS, THR)
PINS = parse(pinfile(OPS))

def head(mode, op=None, mark=MARK, size=7):
    op = (OP_FLEET if mode == 1 else hl.ZERO32) if op is None else op
    return hl.pack_head(mode, LID, size, ROOT, mark[0], mark[1], op, 1_700_000_100)
def gsig(blob): return gen.sign(blob).signature.hex()
def cos(keys, blob):
    body = blob[blob.index(b"\n") + 1:]
    return [{"pub": k.verify_key.encode().hex(), "sig": k.sign(hl.COSIGN_PREFIX + body).signature.hex()} for k in keys]
def ver(blob, cs, pins=None, **kw):
    return hl.verify_head(blob, gsig(blob), GEN, cs, PINS if pins is None else pins, sig_ok, mark=MARK, **kw)
def refused(fn):
    try: fn(); return False
    except hl.Refused: return True
def zero_calls(fn):
    CALLS[0] = 0; r = refused(fn); return r and CALLS[0] == 0

def refused_as(cls, fn):
    """Row assertion: fn raises exactly a `cls` refusal with 0 verify calls.
    Any other exception (IndexError etc.) is a FAILED assertion here, never
    a pass and never something the harness counts."""
    CALLS[0] = 0
    try: fn(); return False
    except Exception as e: return isinstance(e, cls) and CALLS[0] == 0

# ---- Lodestar / board condition 1-2 ----
def row_tags():
    if len(set(hl.TAGS.values())) != 3: return False
    for a in range(3):
        b = head(a)
        for t in range(3):
            if t == a: continue
            relab = hl.TAGS[hl.MODES[t]] + b[len(hl.TAGS[hl.MODES[a]]):]
            if not refused(lambda: hl.verify_head(relab, gsig(b), GEN, [], PINS, sig_ok, mark=MARK)): return False
    return True
def row_mode_range(): return zero_calls(lambda: ver(hl.TAGS["independent"] + bytes([3]) + head(2)[len(hl.TAGS["independent"]) + 1:], []))
def row_opzero():
    return all(zero_calls(lambda m=m: ver(head(m, op=OP_A), [])) for m in (0, 2)) and zero_calls(lambda: ver(head(1, op=hl.ZERO32), []))
def row_indep_fleet_only(): b = head(2); return refused(lambda: ver(b, cos([f1, f2], b)))
def row_single_outside(): b = head(1); return refused(lambda: ver(b, cos([f1, o1], b)))
def row_accept():
    b0, b1, b2 = head(0), head(1), head(2)
    return (ver(b0, [])[0] == "unwitnessed" and ver(b1, cos([f1], b1))[0] == "single-operator"
            and ver(b2, cos([f1, o1], b2))[0] == "independent")
def row_single_wrong_op(): b = head(1, op=OP_A); return _refused_typed(hl.OperatorMismatch, lambda: ver(b, cos([f1], b)))
def row_logid(): b = hl.pack_head(0, b"\x00" * 32, 7, ROOT, 5, PROOT, hl.ZERO32, 1); return zero_calls(lambda: ver(b, []))
# ---- condition 3/4 ----
def row_cap():
    b = head(2)
    junk = [{"pub": "%064x" % i, "sig": "00" * 64} for i in range(10000)]
    CALLS[0] = 0
    lvl, calls = ver(b, junk + cos([f1, o1], b))
    return lvl == "independent" and calls <= 2 and CALLS[0] == 1 + calls
def row_resp_list():
    b = head(1); resp = {"head": b, "pins": {X: "outside-x"}, "cosigns": cos([f1, x], b)}
    try: return ver(resp["head"], resp["cosigns"])[0] == "single-operator"
    except hl.Refused: return False
def row_per_operator():
    b = head(2)
    try: ver(b, cos([o1, o1b], b), ruling={"min_outside_operators": 2}); return False
    except hl.Refused as e: return "give 'single-operator'" in str(e) or "give 'unwitnessed'" in str(e)
# ---- Bulwark ----
def malformed(i):
    k = i % 5
    if k == 0: return hl.TAGS["unwitnessed"] + head(2)[len(hl.TAGS["independent"]):]
    if k == 1: return hl.TAGS["independent"] + bytes([7]) + head(2)[len(hl.TAGS["independent"]) + 1:]
    if k == 2: return head(0, op=bytes([i % 255 + 1]) * 32)
    if k == 3: return head(0, mark=(i, PROOT))
    return head(2)[:-1 - (i % 9)]
def row_bulwark():
    CALLS[0] = 0
    n = sum(refused(lambda i=i: hl.verify_head(malformed(i), "00" * 64, GEN, [], PINS, sig_ok, mark=MARK)) for i in range(10000))
    return n == 10000 and CALLS[0] == 0
def row_prev_mismatch(): return zero_calls(lambda: ver(head(0, mark=(6, PROOT)), []))
# ---- golden vectors ----
GOLD = {}
def row_golden():
    got = {hl.MODES[m]: hashlib.sha256(head(m)).hexdigest() for m in range(3)}
    GOLD.update(got)
    exp = GOLDEN
    return got == exp and len(head(0)) == len(hl.TAGS["unwitnessed"]) + 153
# ---- Loom pin file ----
def row_pin_ok(): return set(PINS["keys"]) == {F1, F2, O1, O1B}
def row_pin_dup_across():
    ops = sorted([(OP_FLEET, 1, [(F1, 0, 9)]), (OP_A, 2, [(F1, 0, 9)])]); return zero_calls(lambda: parse(pinfile(ops)))
def row_pin_genesis(): return zero_calls(lambda: parse(pinfile([(OP_FLEET, 1, [(GEN, 0, 9)])])))
def row_pin_unsorted_ops():
    data = pinfile([(OP_A, 2, [(O1, 0, 9)])])  # build then swap order manually
    body = hl.PIN_MAGIC + LID + struct.pack(">QQ", 3, 1) + bytes([2]) + entry(OP_A, 2, [(O1, 0, 9)]) + entry(OP_FLEET, 1, [(F1, 0, 9)])
    return zero_calls(lambda: parse(body + b"\x00"))
def row_pin_dup_op():
    body = hl.PIN_MAGIC + LID + struct.pack(">QQ", 3, 1) + bytes([2]) + entry(OP_A, 2, [(O1, 0, 9)]) + entry(OP_A, 2, [(O1B, 0, 9)])
    return zero_calls(lambda: parse(body + b"\x00"))
def row_pin_unsorted_keys():
    ks = sorted([(F1, 0, 9), (F2, 0, 9)], reverse=True)
    body = hl.PIN_MAGIC + LID + struct.pack(">QQ", 3, 1) + bytes([1]) + entry(OP_FLEET, 1, ks)
    return zero_calls(lambda: parse(body + b"\x00"))
def row_pin_trailing(): return zero_calls(lambda: parse(pinfile(OPS, extra=b"\x00")))
def row_pin_limits():
    many = [(bytes([i]) * 32, 1, [(K(100 + i)[1], 0, 9)]) for i in range(1, 18)]
    fivek = [(OP_FLEET, 1, [(K(200 + i)[1], 0, 9) for i in range(5)])]
    return zero_calls(lambda: parse(pinfile(many))) and zero_calls(lambda: parse(pinfile(fivek)))
def row_pin_weak():
    small = "0100000000000000000000000000000000000000000000000000000000000000"
    return zero_calls(lambda: parse(pinfile([(OP_FLEET, 1, [(small, 0, 9)])])))
def row_pin_rollback():
    st = os.path.join(D, "state.json"); p = os.path.join(D, "p.bin")
    open(p, "wb").write(pinfile(OPS, version=5)); hl.load_pins(p, GEN, sig_ok, st, SIGNERS, THR)
    open(p, "wb").write(pinfile(OPS, version=4))
    return refused(lambda: hl.load_pins(p, GEN, sig_ok, st, SIGNERS, THR)) and json.load(open(st))["pin_version"] == 5
def row_pin_local(): return refused(lambda: hl.load_pins("https://x/pins", GEN, sig_ok, os.path.join(D, "s2"), SIGNERS, THR))
def row_pin_badsig():
    body_ks = ((0, s0), (1, s2))  # s2 signs as index 1 -> wrong key
    return refused(lambda: parse(pinfile(OPS, signer_ks=body_ks)))
# ---- 10:47 amendments ----
def row_failclosed():
    p = os.path.join(D, "p3.bin"); open(p, "wb").write(pinfile(OPS))
    pins = hl.load_pins(p, GEN, sig_ok, os.path.join(D, "s3"))        # compiled placeholder
    pins0 = hl.load_pins(p, GEN, sig_ok, os.path.join(D, "s4"), SIGNERS, 0)
    b0, b1 = head(0), head(1)
    return (pins is None and pins0 is None
            and hl.verify_head(b0, gsig(b0), GEN, cos([f1, o1], b0), pins, sig_ok, mark=MARK)[0] == "unwitnessed"
            and refused(lambda: hl.verify_head(b1, gsig(b1), GEN, cos([f1], b1), pins, sig_ok, mark=MARK)))
def row_triple():
    return refused(lambda: parse(pinfile(OPS, signer_ks=((0, s0), (0, s0), (0, s0)))))
def row_oor():
    # Cipher 5157a264: index == len(signers) refused AS out of range, 0 verifies
    n = len(SIGNERS)
    return (refused_as(hl.SignerIndexOutOfRange, lambda: parse(pinfile(OPS, signer_ks=((0, s0), (n, s1)))))
            and refused_as(hl.SignerIndexOutOfRange, lambda: parse(pinfile(OPS, signer_ks=((0, s0), (7, s1))))))
def row_thr_one():
    # Cipher 5157a264: threshold 2, exactly one VALID signature -> refused
    # (TooFewSignatures) before any verify. Control: the same one signature
    # loads at threshold 1, so the refusal is the count, not the signature.
    one = pinfile(OPS, signer_ks=((0, s0),))
    ctl = hl.parse_pins(one, GEN, sig_ok, SIGNERS, 1)["version"] == 3
    return THR == 2 and ctl and refused_as(hl.TooFewSignatures, lambda: parse(one))
def row_tag_mode():
    # single-operator tag over a mode-2 body (and the reverse): typed refusal, 0 verifies
    b1, b2 = head(1), head(2)
    t1, t2 = hl.TAGS["single-operator"], hl.TAGS["independent"]
    a = t1 + b2[len(t2):]
    c = t2 + b1[len(t1):]
    b0 = head(0)
    d = t1 + b0[len(hl.TAGS["unwitnessed"]):]      # Lodestar 2bdecf9c item 3: tag single-operator, mode 0x00
    return (d[len(t1)] == 0x00
            and refused_as(hl.TagModeMismatch, lambda: hl.verify_head(d, gsig(d), GEN, cos([f1], d), PINS, sig_ok, mark=MARK))
            and refused_as(hl.TagModeMismatch, lambda: hl.verify_head(a, gsig(a), GEN, [], PINS, sig_ok, mark=MARK))
            and refused_as(hl.TagModeMismatch, lambda: hl.verify_head(c, gsig(c), GEN, [], PINS, sig_ok, mark=MARK)))
OP_F2 = b"\x02" * 32
f3, F3 = K(6)
PINS2 = parse(pinfile(sorted([(OP_FLEET, 1, [(F1, 0, 10**9)]), (OP_F2, 1, [(F3, 0, 10**9)]),
                              (OP_A, 2, [(O1, 0, 10**9)])])))
def row_single_two_fleet():
    # head names OP_FLEET but OP_F2 also cosigns: operator_id must EQUAL the cosigner
    b = head(1, op=OP_FLEET)
    ok_one = ver(b, cos([f1], b), pins=PINS2)[0] == "single-operator"
    return ok_one and _refused_typed(hl.OperatorMismatch, lambda: ver(b, cos([f1, f3], b), pins=PINS2))
def row_op_x_names_y():
    # Lodestar 2bdecf9c item 4: single-operator head whose VALID cosigns all
    # come from operator X (OP_FLEET) but whose body names operator Y.
    # Y = another pinned fleet operator, an outside operator, an unpinned id.
    for y in (OP_F2, OP_A, OP_X):
        b = head(1, op=y)
        cs = cos([f1], b)
        if not all(sig_ok(c["pub"], hl.COSIGN_PREFIX + b[len(hl.TAGS["single-operator"]):], c["sig"]) for c in cs):
            return False                                   # cosigns really are valid
        if not _refused_typed(hl.OperatorMismatch, lambda: ver(b, cs, pins=PINS2)): return False
    b = head(1, op=OP_FLEET)                               # control: X names X
    return ver(b, cos([f1], b), pins=PINS2)[0] == "single-operator"
def _refused_typed(cls, fn):
    try: fn(); return False
    except Exception as e: return isinstance(e, cls)
def _fc(b, **kw):
    return hl.verify_head(b, gsig(b), GEN, [], PINS, sig_ok, mark=None, **kw)
def row_first_contact_default():
    # Villhaze ART-29 4b2e3f59: with no mark stored, a first contact is
    # accepted ONLY at the root. Nonzero prev_size -> FirstContactRefused,
    # 0 verifies; prev_* is never skipped silently. Control: the root head
    # (prev_size 0, prev_root empty) is accepted.
    bad, ok = head(0, mark=(5, PROOT)), head(0, mark=(0, hl.ZERO32))
    bad1 = head(0, mark=(1, hl.ZERO32))
    return (refused_as(hl.FirstContactRefused, lambda: _fc(bad))
            and refused_as(hl.FirstContactRefused, lambda: _fc(bad1))
            and _fc(ok)[0] == "unwitnessed")
def row_first_contact_prev_root():
    # Lodestar rider (ART-42 e802b3a5), adopted by Villhaze ART-29 4b2e3f59:
    # prev_size 0 beside a non-empty prev_root is a history claim by another
    # name -> FirstContactRefused, 0 verifies. Control: the same head with
    # prev_root empty is accepted, so the refusal is the prev_root.
    probes = [head(m, mark=(0, r)) for m in (0, 1, 2)
              for r in (PROOT, b"\x00" * 31 + b"\x01", b"\x01" + b"\x00" * 31)]
    ok = head(0, mark=(0, hl.ZERO32))
    return (all(refused_as(hl.FirstContactRefused, lambda b=b: _fc(b)) for b in probes)
            and _fc(ok)[0] == "unwitnessed")
TOFU_TOKENS = ("tofu", "first_contact", "trust_on_first_use")
def tofu_switch_hits(src, fname="<src>"):
    """Any trust-on-first-use switch/branch/label in head_level source:
    grep (case-insensitive 'tofu' anywhere, comments included) plus AST
    (identifiers, attributes, args, keywords, string constants carrying a
    TOFU/first-contact-policy token)."""
    hits = [f"{fname}:{i}:grep" for i, line in enumerate(src.splitlines(), 1) if "tofu" in line.lower()]
    for n in ast.walk(ast.parse(src, fname)):
        names = []
        if isinstance(n, ast.Name): names.append(n.id)
        elif isinstance(n, ast.Attribute): names.append(n.attr)
        elif isinstance(n, ast.arg): names.append(n.arg)
        elif isinstance(n, ast.keyword) and n.arg: names.append(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.ClassDef)): names.append(n.name)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str): names.append(n.value)
        for v in names:
            if any(t in v.lower() for t in TOFU_TOKENS):
                hits.append(f"{fname}:{getattr(n, 'lineno', 0)}:{v[:40]}")
    return hits
def _hl_src():
    return open(hl.__file__).read()
OLD_SWITCH_SHAPES = (
    'FIRST_CONTACT = "refuse_nonzero_prev"\nFIRST_CONTACT_CHOICES = ("refuse_nonzero_prev", "tofu")\n',
    'def f(mark, psize):\n    if mark is None and POLICY == "tofu":\n        return 1\n',
    'def f(h):\n    return {"first_contact_policy": h}\n',
    'def verify_head(blob, out=None, trust_on_first_use=False):\n    pass\n',
)
def row_no_tofu_switch():
    # Villhaze ART-29 4b2e3f59 item 3: the dormant TOFU switch does not ship.
    # Production head_level.py carries no TOFU switch, branch, or label; any
    # future change goes through the written-ruling path (ART-29 1e762099).
    # Self-probe: the scanner flags each historical switch shape and is
    # clean on a plain root-only check.
    src = _hl_src()
    probe = all(tofu_switch_hits(s_) for s_ in OLD_SWITCH_SHAPES)
    clean = not tofu_switch_hits("def f(mark, psize):\n    if mark is None and psize != 0:\n        raise E\n")
    sig = (list(hl.cheap_head.__code__.co_varnames[:hl.cheap_head.__code__.co_argcount]) == ["blob", "log_id", "mark"]
           and "out" not in hl.verify_head.__code__.co_varnames[:hl.verify_head.__code__.co_argcount])
    return probe and clean and sig and tofu_switch_hits(src, "head_level.py") == []
def override_calls(src, fname="<src>"):
    """Calls to parse_pins/load_pins that pass signers/threshold (keyword or
    extra positional). Production code must have none (Cipher 5157a264)."""
    base = {"parse_pins": 3, "load_pins": 4}
    hits = []
    for n in ast.walk(ast.parse(src, fname)):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name in base and (len(n.args) > base[name] or any(k.arg in ("signers", "threshold") or k.arg is None for k in n.keywords)):
                hits.append(f"{fname}:{n.lineno}")
    return hits
def production_files():
    root = os.path.dirname(os.path.abspath(hl.__file__))
    import subprocess
    try:
        ls = subprocess.run(["git", "-C", root, "ls-files", "*.py"], capture_output=True, text=True, check=True).stdout.split()
        return [os.path.join(root, f) for f in ls
                if not os.path.basename(f).startswith("test_") and os.path.basename(f) != "head_level.py"]
    except Exception:
        pass
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if not d.startswith(".") and d not in ("venv", ".venv", "node_modules", "__pycache__")]
        for f in fn:
            if f.endswith(".py") and not f.startswith("test_") and f != "head_level.py":
                out.append(os.path.join(dp, f))
    return out
def row_no_prod_override():
    hits = []
    for p in production_files():
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try: hits += override_calls(open(p).read(), p)
            except SyntaxError: hits.append(p + ":unparseable")
    # inside head_level, only load_pins -> parse_pins forwards them
    hl_hits = override_calls(open(hl.__file__).read(), "head_level.py")
    # self-check: the scanner flags each override shape
    probe = all(override_calls(s_) for s_ in ("hl.parse_pins(d, g, s, ('aa',), 1)",
                                             "parse_pins(d, g, s, threshold=1)",
                                             "hl.load_pins(p, g, s, st, signers=x)",
                                             "hl.load_pins(p, g, s, st, **kw)"))
    clean = not override_calls("hl.parse_pins(d, g, s); hl.load_pins(p, g, s, st)")
    return len(production_files()) > 0 and hits == [] and len(hl_hits) == 1 and probe and clean
def row_sig_calls():
    CALLS[0] = 0; parse(pinfile(OPS, signer_ks=((0, s0), (1, s1), (2, s2)))); return CALLS[0] <= THR

ROWS = [
    ("(L1) three distinct tags; a head under one tag fails under the other two", row_tags),
    ("(L1) mode byte 3 refused, 0 verifies", row_mode_range),
    ("(L1) operator_id non-zero in modes 0/2 (and zero in mode 1) refused, 0 verifies", row_opzero),
    ("(L1) log_id != SHA-256(Genesis pub) refused, 0 verifies", row_logid),
    ("(L2) marked independent with only fleet cosigns: refused", row_indep_fleet_only),
    ("(L2) marked single-operator with an outside cosign: refused", row_single_outside),
    ("(L2) agreeing heads accepted at each level", row_accept),
    ("(L2) single-operator operator_id != cosigning fleet operator: refused", row_single_wrong_op),
    ("(L3) 10,000 unknown + 2 valid cosigns: <= 2 cosign verifies, right level", row_cap),
    ("(L4) response carrying its own list with an extra key: still single-operator", row_resp_list),
    ("(L4) two outside keys of one operator count once", row_per_operator),
    ("(B) 10,000 malformed heads: 0 verify calls", row_bulwark),
    ("(B) prev_* != stored mark refused, 0 verifies", row_prev_mismatch),
    ("(G) golden vector per mode", row_golden),
    ("(P) valid signed pin file loads", row_pin_ok),
    ("(P) duplicate pubkey across operators refused, 0 verifies", row_pin_dup_across),
    ("(P) Genesis key in the pin file refused, 0 verifies", row_pin_genesis),
    ("(P) unsorted operators refused, 0 verifies", row_pin_unsorted_ops),
    ("(P) duplicate operator refused, 0 verifies", row_pin_dup_op),
    ("(P) unsorted keys refused, 0 verifies", row_pin_unsorted_keys),
    ("(P) trailing bytes refused, 0 verifies", row_pin_trailing),
    ("(P) n_ops > 16 / n_keys > 4 refused, 0 verifies", row_pin_limits),
    ("(P) small-order key refused (sodium_key_ok), 0 verifies", row_pin_weak),
    ("(P) pin_version rollback refused; highest stored", row_pin_rollback),
    ("(P) network path refused (local only)", row_pin_local),
    ("(P) signature by the wrong signer refused", row_pin_badsig),
    ("(a) placeholder / threshold 0: no pin file, valid fleet cosign still rates unwitnessed", row_failclosed),
    ("(b) three copies of one signer's sig fail threshold 2", row_triple),
    ("(b) at most threshold-many pin verifies", row_sig_calls),
    ("(C1) threshold 2 with one valid signature refused (TooFewSignatures), 0 verifies", row_thr_one),
    ("(C2) out-of-range signer index: typed SignerIndexOutOfRange, 0 verifies, never IndexError", row_oor),
    ("(L5) tag/mode mismatch both ways: typed TagModeMismatch, 0 verifies", row_tag_mode),
    ("(L5) single-operator with a second fleet operator cosigning: OperatorMismatch", row_single_two_fleet),
    ("(L4) single-operator head: valid cosigns from operator X, body names Y -> OperatorMismatch (Y fleet/outside/unpinned)", row_op_x_names_y),
    ("(FC) first contact root-only (ART-29 4b2e3f59): nonzero prev_size refused (FirstContactRefused), 0 verifies; root head accepted", row_first_contact_default),
    ("(FC-R) first contact prev_size 0 + non-empty prev_root refused (FirstContactRefused), 0 verifies (Lodestar e802b3a5 rider)", row_first_contact_prev_root),
    ("(FC-S) no TOFU switch/branch/label in production head_level.py (grep + AST; changes via ART-29 1e762099)", row_no_tofu_switch),
    ("(C3) no production caller overrides parse_pins/load_pins signers/threshold (AST scan)", row_no_prod_override),
]
# sha256 of tag||body for head(m): Genesis seed sha256("wok-level-0"), size 7,
# root ab*32, prev (5, cd*32), operator 01*32 in mode 1, issued 1700000100.
GOLDEN = {"unwitnessed": "9ab2e70114e26c0c95e6ebd8edd212c9ecb3f3e73e35e71ee667240a845520d8",
          "single-operator": "e1b96d513e9cb5b435d86d954de55590e3a736d4609b57783a9605f70c1f9231",
          "independent": "48755ca0153517cfe446fdd48cdb1eb99f143589620d5031d2512413b23afab4"}
for n, f in ROWS: check(n, f())

ORIG = hl.verify_head; ORIG_PARSE = hl.parse_pins; ORIG_CHEAP = hl.cheap_head
def trust_marker(blob, gs, gp, cs, pins, so, mark=None, ruling=hl.RULING):
    h = hl.cheap_head(blob, hl.log_id_of(gp), mark); so(gp, blob, gs); return h["level"], 0
def verify_all(blob, gs, gp, cs, pins, so, mark=None, ruling=hl.RULING):
    for c in cs: so(c["pub"], b"", c["sig"])
    return ORIG(blob, gs, gp, cs, pins, so, mark, ruling)
def from_response(blob, gs, gp, cs, pins, so, mark=None, ruling=hl.RULING):
    p = {"keys": dict(pins["keys"])}; p["keys"][X] = {"op": OP_X, "class": 2, "from": 0, "to": 10**9}
    return ORIG(blob, gs, gp, cs, p, so, mark, ruling)
def per_key(blob, gs, gp, cs, pins, so, mark=None, ruling=hl.RULING):
    p = {"keys": {k: dict(v, op=bytes.fromhex(k)) for k, v in pins["keys"].items()}}
    return ORIG(blob, gs, gp, cs, p, so, mark, ruling)
def checks_after(blob, gs, gp, cs, pins, so, mark=None, ruling=hl.RULING):
    so(gp, blob, gs); return ORIG(blob, gs, gp, cs, pins, so, mark, ruling)
def _mut_src(old, new, fn):
    """Source mutant of head_level. The mutant module shares head_level's
    Refused classes, so rows see the same exception types; no rows or
    helpers are redefined for mutants."""
    src = open(hl.__file__).read(); assert src.count(old) == 1, old
    ns = {"__name__": "head_level_mut"}; exec(compile(src.replace(old, new), "mut", "exec"), ns)
    for n in ("Refused", "TagModeMismatch", "OperatorMismatch", "SignerIndexOutOfRange", "TooFewSignatures", "FirstContactRefused"):
        ns[n] = getattr(hl, n)
    return ns[fn]
def mut_parse(old, new):
    f = _mut_src(old, new, "parse_pins")
    return lambda data, gp, so, signers=None, threshold=None: f(data, gp, so, signers, threshold)
def mut_verify(old, new):
    f = _mut_src(old, new, "verify_head")
    return lambda *a, **k: f(*a, **k)
def src_mutant(old, new):
    """Production-source mutant written to a temp file; hl.__file__ points
    at it for the duration of the mutant run (rows that read source see it)."""
    src = open(hl.__file__).read(); assert src.count(old) == 1, old
    p = os.path.join(D, "head_level_mut_%d.py" % time.time_ns()); open(p, "w").write(src.replace(old, new))
    return mock.patch.object(hl, "__file__", p)
def _thr_after():
    """Mutant: the count check moved after the verify loop (verifies first)."""
    src = open(hl.__file__).read()
    chk = '    if len(sigs) < threshold:\n        raise TooFewSignatures("too few pin signatures")\n'
    tail = '    return {"log_id": lid, "version": version'
    assert src.count(chk) == 1 and src.count(tail) == 1
    src = src.replace(chk, "").replace(tail, chk + tail)
    ns = {"__name__": "head_level_mut"}; exec(compile(src, "mut", "exec"), ns)
    for n in ("Refused", "TagModeMismatch", "OperatorMismatch", "SignerIndexOutOfRange", "TooFewSignatures", "FirstContactRefused"):
        ns[n] = getattr(hl, n)
    f = ns["parse_pins"]
    return lambda data, gp, so, signers=None, threshold=None: f(data, gp, so, signers, threshold)
mut_dupacross = mut_parse('            if pub in seen:\n                raise Refused', '            if False:\n                raise Refused')
mut_trailing = mut_parse('    if p != len(data):\n        raise Refused("trailing bytes")', '    pass')
def run_mut(row, patches):
    """KILLED only when the named row returns False (its own assertion
    fails). Any exception escaping the row is ERROR, never a kill."""
    import contextlib
    with contextlib.ExitStack() as st:
        for p in patches: st.enter_context(p)
        try: return "KILLED" if row() is False else "SURVIVED"
        except Exception as e: return f"ERROR({type(e).__name__})"
def rollback_skip(path, gp, so, state, signers=None, threshold=None):
    return ORIG_LOAD(path, gp, so, state + ".fresh%d" % time.time_ns(), signers, threshold)
ORIG_LOAD = hl.load_pins
SHARED = dict(hl.TAGS); SHARED["independent"] = SHARED["single-operator"]
def placeholder_accepts(signers=None, threshold=None): return False
def pins_any(data, gp, so, signers=None, threshold=None):
    # empty compiled signer set treated as "accept any file": every
    # signature is accepted, against the test signer table
    return ORIG_PARSE(data, gp, lambda *a: True, SIGNERS, THR)
MUT = [
    ("two levels share one tag", row_tags, [mock.patch.dict(hl.TAGS, SHARED)]),
    ("verifier trusts the marker", row_indep_fleet_only, [mock.patch.object(hl, "verify_head", trust_marker)]),
    ("every cosign is verified", row_cap, [mock.patch.object(hl, "verify_head", verify_all)]),
    ("pin list taken from the response", row_resp_list, [mock.patch.object(hl, "verify_head", from_response)]),
    ("independence counted per key, not operator", row_per_operator, [mock.patch.object(hl, "verify_head", per_key)]),
    ("cheap checks moved after verify", row_bulwark, [mock.patch.object(hl, "verify_head", checks_after)]),
    ("no duplicate-pubkey-across-operators check", row_pin_dup_across, [mock.patch.object(hl, "parse_pins", mut_dupacross)]),
    ("trailing bytes accepted", row_pin_trailing, [mock.patch.object(hl, "parse_pins", mut_trailing)]),
    ("rollback state ignored", row_pin_rollback, [mock.patch.object(hl, "load_pins", rollback_skip)]),
    ("placeholder = empty signer set accepting any file", row_failclosed, [mock.patch.object(hl, "placeholder", placeholder_accepts), mock.patch.object(hl, "parse_pins", pins_any)]),
    ("sigs counted without de-duplicating by index", row_triple, [mock.patch.object(hl, "parse_pins", mut_parse('    if idx != sorted(set(idx)):\n        raise Refused', '    if False:\n        raise Refused'))]),
    ("threshold-count check removed", row_thr_one, [mock.patch.object(hl, "parse_pins", mut_parse('    if len(sigs) < threshold:\n        raise TooFewSignatures', '    if False:\n        raise TooFewSignatures'))]),
    ("signer-index range check removed", row_oor, [mock.patch.object(hl, "parse_pins", mut_parse('    if any(i >= len(signers) for i in idx):\n        raise SignerIndexOutOfRange', '    if False:\n        raise SignerIndexOutOfRange'))]),
    ("tag/mode check removed", row_tag_mode, [mock.patch.object(hl, "cheap_head", _mut_src('    if MODES[mode] != m:\n        raise TagModeMismatch', '    if False:\n        raise TagModeMismatch', "cheap_head"))]),
    ("operator_id checked by membership, not equality", row_single_two_fleet, [mock.patch.object(hl, "verify_head", mut_verify('fleet_ops != {h["operator_id"]}', 'h["operator_id"] not in fleet_ops'))]),
    ("operator_id check removed (X cosigns, body names Y)", row_op_x_names_y, [mock.patch.object(hl, "verify_head", mut_verify('    if level == "single-operator" and fleet_ops != {h["operator_id"]}:', '    if False:'))]),
    ("threshold count checked only after verifying", row_thr_one, [mock.patch.object(hl, "parse_pins", _thr_after())]),
    ("first contact skips prev_size silently", row_first_contact_default, [mock.patch.object(hl, "cheap_head", _mut_src('        if psize != 0:\n            raise FirstContactRefused', '        if False:\n            raise FirstContactRefused', "cheap_head"))]),
    ("first contact without prev_root check (Lodestar rider dropped)", row_first_contact_prev_root, [mock.patch.object(hl, "cheap_head", _mut_src('        if proot != ZERO32:\n            raise FirstContactRefused', '        if False:\n            raise FirstContactRefused', "cheap_head"))]),
    ("first-contact branch removed (any prev_* accepted with no mark)", row_first_contact_default, [mock.patch.object(hl, "cheap_head", _mut_src('    if mark is None:                        # ART-29 4b2e3f59: root only', '    if False:', "cheap_head"))]),
    ("dormant TOFU switch reintroduced (default refuse)", row_no_tofu_switch, [src_mutant('class FirstContactRefused(Refused):', 'FIRST_CONTACT = "refuse_nonzero_prev"\nFIRST_CONTACT_CHOICES = ("refuse_nonzero_prev", "tofu")\n\n\nclass FirstContactRefused(Refused):')]),
    ("TOFU branch reintroduced in cheap_head", row_no_tofu_switch, [src_mutant('    if mark is None:                        # ART-29 4b2e3f59: root only', '    if mark is None and globals().get("POLICY") == "tofu":\n        pass\n    elif mark is None:')]),
    ("first-contact policy label reintroduced", row_no_tofu_switch, [src_mutant('            "operator_id": op, "issued_at": issued}', '            "operator_id": op, "issued_at": issued, "first_contact_policy": None}')]),
    ("operator_id check removed", row_single_wrong_op, [mock.patch.object(hl, "verify_head", mut_verify('    if level == "single-operator" and fleet_ops != {h["operator_id"]}:', '    if False:'))]),
]
table = []
for name, row, patches in MUT:
    real = row()
    res = run_mut(row, patches)
    table.append((name, row.__name__, real, res)); check(f"MUTANT {name}: real passes and named row fails", real and res == "KILLED")
print("mutant table (kill = named row fails its own assertion; exceptions are ERROR):\n  mutant | row | real passes | result")
for n, r, a, b in table: print(f"  {n} | {r} | {a} | {b}")
print("golden sha256(signed head bytes):", json.dumps(GOLD))
fails = sum(1 for _, ok in R if not ok)
print(f"wok_level: {len(R) - fails} passed, {fails} failed ({time.time() - T0:.1f}s)")
raise SystemExit(1 if fails else 0)
