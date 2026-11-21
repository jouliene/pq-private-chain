"""Full geometry with the published synthetic depth-20 SLG1 relation and fresh masks."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lattice-spend/pivot"))
import check


def packed(seq):
    return struct.pack(f"<{len(seq)}Q", *seq)


def run(binary, shape, constants):
    f = check.f
    params = f.constants(constants)
    receipts = bytes(i % 251 for i in range(3584))
    w = check.fixture("SLG1")
    w["ct_digest"] = check.pc.receipt_digest(params, receipts)
    leaves = [check.input_leaf(params, w, note) for note in w["inputs"]]
    w["depth"] = 20
    old, _ = check.synthetic_paths(params, leaves, check.parent_old, 20)
    w["header"][13:17] = check.decode(old)
    check.projection(params, w, tree=False)
    aux, paths = check.synthetic_paths(params, leaves, check.v.parent, 20)
    for note, path in zip(w["inputs"], paths, strict=True):
        note.update(path)
    w["public"].extend(check.decode(aux))
    circuit = check.v.compile_full("SLG1", params, w)
    if circuit.failures:
        raise ValueError("fixture constraint error")
    public = hashlib.sha256(b"FTL1/synthetic/proof-test/v1\0" + receipts).digest() + packed(w["public"])

    def invoke(role, request):
        return subprocess.run([binary, role, shape], input=request, capture_output=True, timeout=240)

    start = time.monotonic()
    result = invoke("prove", public + packed(circuit.z[39:]))
    if result.returncode:
        raise RuntimeError(result.stderr.decode())
    proof = result.stdout
    proving = time.monotonic() - start
    start = time.monotonic()
    result = invoke("verify", public + proof)
    elapsed = time.monotonic() - start
    if result.returncode or result.stdout:
        raise RuntimeError(result.stderr.decode())
    request = public + proof

    def flip(blob, at):
        changed = bytearray(blob)
        changed[at] ^= 1
        return changed

    controls = {
        "context": flip(request, 0),
        "public_statement": flip(request, 32),
        "auxiliary_root": flip(request, 32 + 34 * 8),
        "root_commitment": flip(request, 336),
        "degree_digest": flip(request, 400),
        "broadcast_digest": flip(request, 464),
        "opening_salt": flip(request, 528),
        "opening_share": flip(request, 560),
        "noncanonical_opening": request[:560] + packed([f.P]) + request[568:],
        "multiproof": flip(request, 528 + 32 * (32 + 533 * 8)),
        "degree_tail": flip(request, len(request) - 44800 - 30888),
        "polynomial_tail": flip(request, len(request) - 44800),
        "linear_tail": flip(request, len(request) - 1),
        "trailing": request + bytes(1),
        "truncated": request[:-1],
    }
    for name, bad in controls.items():
        if invoke("verify", bad).returncode == 0:
            raise RuntimeError(f"accepted mutation: {name}")
    wrong = list(circuit.z[39:])
    wrong[-1] = (wrong[-1] + 1) % f.P
    if invoke("prove", public + packed(wrong)).returncode == 0:
        raise RuntimeError("accepted inconsistent private assignment")
    return dict(synthetic_full_depth=True, proof_bytes=len(proof), proof_wall_s=round(proving, 3),
                public_verify_wall_s=round(elapsed, 3), rejected_public_controls=list(controls),
                rejected_invalid_assignment=True)


if __name__ == "__main__":
    print(json.dumps(run(*map(Path, sys.argv[1:])), indent=2))
