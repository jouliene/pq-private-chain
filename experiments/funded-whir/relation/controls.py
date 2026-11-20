"""Exercise the registered Goldilocks transfer matrices on synthetic, non-wallet openings."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend as f


def sponge(params, message):
    """Numeric reference independent of the sparse polynomial emitter."""
    p = f.P
    initial, internal, diagonal, final = params

    def external(s):
        result = []
        for off in range(0, 12, 4):
            a, b, c, d = s[off:off+4]
            result.extend([2*a + 3*b + c + d, a + 2*b + 3*c + d,
                           a + b + 2*c + 3*d, 3*a + b + c + 2*d])
        sums = [sum(result[j::4]) for j in range(4)]
        return [(v + sums[i % 4]) % p for i, v in enumerate(result)]

    def full(s, constants):
        for i in range(0, 48, 12):
            s = external([pow((v+k) % p, 7, p) for v, k in zip(s, constants[i:i+12])])
        return s

    msg = message + [1]
    msg += [0] * (-len(msg) % 8)
    s = [0]*12
    for start in range(0, len(msg), 8):
        s[:8] = [(a+b) % p for a,b in zip(s[:8], msg[start:start+8])]
        s = full(external(s), initial)
        for k in internal:
            s[0] = pow((s[0]+k) % p, 7, p)
            t = sum(s)
            s = [(t+v*d) % p for v,d in zip(s, diagonal)]
        s = full(s, final)
    return s[:4]


def fixture(profile):
    w = f.blank(profile)
    def digest(i):
        return [i*4+j+1 for j in range(4)]
    w.update(header=list(range(45)), depth=1, fee=3 if profile == "MNG1" else 0,
             asset_id=digest(88), ct_digest=digest(100), auth_key=list(range(1,9)))
    for i, note in enumerate(w["inputs"]):
        note.update(ask=digest(i+1), nk=digest(i+4), rho=digest(i+7), raw=digest(i+10),
                    value=12 if i == 0 or profile == "MNG1" else 0,
                    token=7 if i == 0 or profile == "MNG1" else 0, dummy=i == 1 and profile == "SLG1")
    for i, out in enumerate(w["outputs"]):
        out.update(pk=digest(i+15), raw=digest(i+50), value=0 if i==0 else (21 if profile=="MNG1" else 12),
                   token=3 if i==0 else (11 if profile=="MNG1" else 4))
    return w


def projection(params, w, *, tree):
    """Recompute commitments and public outputs after changes, including deliberately invalid economics."""
    def h(tag, *words):
        return sponge(params, [tag] + [v for part in words for v in part])

    def opened(n, raw):
        return h(f.OPEN, w["asset_id"] if n["token"] else [0]*4, [n["token"]], raw)

    inputs, nfs = [], []
    for n in w["inputs"]:
        op = opened(n, n["raw"])
        pk = h(f.PK, h(f.AK, n['ask']), n['nk'])
        inputs.append(h(f.CM, h(f.NOTE, pk, n["rho"], op), [n["value"]]))
        nfs.append(h(f.NF_DUMMY if n["dummy"] else f.NF, n["nk"], n["rho"], op))
    if tree:
        leaves = [*inputs, [0]*4, [0]*4]
        leaves.sort(key=lambda d: struct.pack("<4Q", *d))
        for cm, n in zip(inputs, w["inputs"]):
            pos = leaves.index(cm)
            n.update(siblings=[leaves[:pos]+leaves[pos+1:]], positions=[pos])
        w["header"][13:17] = sponge(params, sum(leaves, []))
    cms = []
    for i, n in enumerate(w["outputs"]):
        raw = n["raw"] if w["suite"] == "MNG1" else h(f.SWAP_OPEN, w["auth_key"], n["raw"])
        rho = h(f.RHO, *nfs, [i])
        cms.extend(h(f.CM, h(f.NOTE, n["pk"], rho, opened(n, raw)), [n["value"]]))
    w["public"] = (sponge(params, w["header"]) + [w["header"][4]] + sum(nfs, []) + cms +
                   [w["fee"]] + w["ct_digest"] + ([0]*4+[w["delta"]] if w["suite"] == "MNG1" else w["auth_key"]))


def independent_matrix(path, z):
    """Evaluate every row from the registered public artifact, without importing the gadget evaluator."""
    raw = path.read_bytes()
    assert raw[:8] == f.MAGIC
    public, cols, rows = struct.unpack_from("<III", raw, 8)
    assert len(z) == cols and z[0] == 1 and all(0 <= v < f.P for v in z)
    off = 20
    for _ in range(rows):
        sides = []
        for _ in range(3):
            count, = struct.unpack_from("<I", raw, off)
            off += 4
            val = 0
            last = -1
            for col, k in struct.iter_unpack("<IQ", memoryview(raw)[off:off+count*12]):
                assert last < col < cols and 0 < k < f.P
                last = col
                val += z[col]*k
            off += count*12
            sides.append(val % f.P)
        a, b, c = sides
        if (a*b-c) % f.P:
            return False
    assert off == len(raw)
    return True


def check_funded(profile, source, matrix, w):
    """Wallet-side: compare a real opened note assignment to the frozen matrix without serializing secrets."""
    params = f.constants(source)
    with matrix.open("rb") as stream:
        head = stream.read(20)
    with matrix.open("rb") as stream:
        import hashlib
        registered = hashlib.file_digest(stream, "sha256").hexdigest()
    column_hash = sha256(head)
    class Sink:
        def write(self, block):
            column_hash.update(block)
    good = f.compile_relation(profile, params, w, Sink())
    assert not good.failures and column_hash.hexdigest() == registered and independent_matrix(matrix, good.z)
    intact = f.compile_relation(profile, params, w)
    assert not intact.failures and intact.z == good.z
    # Column 0 is ONE, then all PIs, then the 45 header wires. The very next
    # private column is a bit of the public height decomposition. Bypass the
    # compiler and give the registered matrix a field element 2 for that bit.
    malformed = good.z[:]
    height_bit = 1 + f.PUBLIC[profile] + 45
    assert malformed[height_bit] in (0, 1)
    malformed[height_bit] = 2
    assert not independent_matrix(matrix, malformed)
    return dict(matrix_sha256=registered, identical_matrix_on_populated_assignment=True,
                positive_registered_rows=True, deterministic_fresh_assignment=True,
                nonboolean_auxiliary_rejected_by_fixed_matrix=True)


def run(profile, source, matrix):
    params = f.constants(source)
    w = fixture(profile)
    projection(params, w, tree=True)
    base_checks = check_funded(profile, source, matrix, w)
    results = {}

    def check(label, mutation, expect, *, republish=False, tree=False):
        case = f.copy.deepcopy(w)
        mutation(case)
        if republish:
            projection(params, case, tree=tree)
        c = f.compile_relation(profile, params, case)
        assert expect in c.failures, label
        # Each negative is a FULL assignment. Evaluate it against the registered matrix bytes.
        assert not independent_matrix(matrix, c.z), label
        results[label] = True

    check("wrong_spending_key", lambda v:v["inputs"][0]["ask"].__setitem__(0, 773), "path position or membership", republish=True)
    check("wrong_sibling", lambda v:v["inputs"][0]["siblings"][0][0].__setitem__(0, 654), "path position or membership")
    check("invalid_position", lambda v:v["inputs"][0]["positions"].__setitem__(0, 4), "path position or membership")
    check("depth_above_20", lambda v:v.update(depth=21), "shared depth")
    check("dummy_with_funds", lambda v:v["inputs"][0].update(dummy=True), "dummy balances", republish=True)
    check("non_boolean_dummy", lambda v:v["inputs"][0].update(dummy=2), "dummy flag", republish=True)
    check("native_overspend", lambda v:v["outputs"][0].update(value=1), "native conservation", republish=True)
    check("mint_without_authority", lambda v:v["outputs"][0].update(token=4), "token conservation", republish=True)
    check("native_range", lambda v:v["outputs"][0].update(value=1<<62), "note ranges", republish=True)
    check("token_range", lambda v:v["outputs"][0].update(token=1<<62), "note ranges", republish=True)
    check("asset_limb_range", lambda v:v["asset_id"].__setitem__(1, 1<<63), "asset and policy", republish=True, tree=True)
    check("wrong_asset_for_funded_note", lambda v:v["asset_id"].__setitem__(0, 37), "path position or membership", republish=True)
    check("positive_tokens_with_zero_id", lambda v:v.update(asset_id=[0]*4), "zero token tag", republish=True, tree=True)
    check("repeated_nullifier", lambda v:v["inputs"].__setitem__(1, f.copy.deepcopy(v["inputs"][0])),
          "funded input and distinct nullifiers", republish=True, tree=True)
    check("unapproved_fee", lambda v:v.update(fee=1), "asset and policy", republish=True)
    check("altered_ciphertext_statement", lambda v:v["public"].__setitem__(22, 1), "asset and policy")
    check("altered_output_commitment", lambda v:v["public"].__setitem__(13, 1), "published output")
    check("altered_public_nullifier", lambda v:v["public"].__setitem__(5, 1), "published nullifier")
    check("altered_anchor", lambda v:v["public"].__setitem__(0, 1), "header")
    check("height_range", lambda v:v["header"].__setitem__(4, 1<<32), "header", republish=True)
    if profile == "MNG1":
        check("nonzero_delta", lambda v:v.update(delta=1), "asset and policy", republish=True)
        check("nonzero_public_id", lambda v:v["public"].__setitem__(26, 1), "asset and policy")
    else:
        check("altered_bound_key", lambda v:v["public"].__setitem__(26, 42), "published output")
        check("key_word_range", lambda v:v["auth_key"].__setitem__(1, 1<<32), "asset and policy", republish=True)
        def reverse(v):
            v["inputs"].reverse()
        check("first_leg_slot_dummy", reverse, "funded input and distinct nullifiers", republish=True, tree=True)

    def unused_tag(v):
        for note in [*v["inputs"], *v["outputs"]]:
            note["token"] = 0
    check("unused_nonzero_hidden_asset", unused_tag, "zero token tag", republish=True, tree=True)

    large = fixture(profile)
    large["asset_id"] = [(1 << 63) - 1] * 4
    large["header"][4] = (1 << 32) - 1
    for note in large["inputs"]:
        note.update(dummy=False, value=(1 << 62) - 1, token=(1 << 62) - 1)
    for i, note in enumerate(large["outputs"]):
        note.update(value=(1 << 62) - 1 - i * large["fee"], token=(1 << 62) - 1)
    projection(params, large, tree=True)
    high = f.compile_relation(profile, params, large)
    assert not high.failures and independent_matrix(matrix, high.z)
    for i in range(f.PUBLIC[profile]):
        alias = list(w["public"])
        alias[i] = f.P
        try:
            f.Circuit(alias, params)
        except ValueError as e:
            assert str(e) == "noncanonical witness field"
        else:
            raise AssertionError("noncanonical public field")
    return dict(profile=profile, **base_checks, valid_max_limb_and_lane_values=True,
                all_public_columns_reject_noncanonical_wire=f.PUBLIC[profile],
                negative_registered_assignments=results)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("profile", choices=f.PUBLIC)
    p.add_argument("constants", type=Path)
    p.add_argument("matrix", type=Path)
    a = p.parse_args()
    print(json.dumps(run(a.profile, a.constants, a.matrix), sort_keys=True, indent=2))
