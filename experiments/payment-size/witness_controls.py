"""Exercise the unchanged complete prover with well-formed, semantically invalid inputs.

Only the repository's deterministic, intentionally public arithmetic fixture enters
this harness. The independently generated private payment samples use private_smoke.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def words(values):
    return struct.pack("<" + "Q" * len(values), *values)


def packet(statement, witness):
    buf = bytearray(struct.pack("<BBH", 2, 2, 0))
    for note in witness["inputs"]:
        buf.extend(words(note["note"] + note["key"] + note["origin"] + [note["index"]]))
        buf.extend(struct.pack("<HH", 40, 0))
        for sibling in note["siblings"]:
            buf.extend(words(sibling))
    for output in witness["outputs"]:
        buf.extend(words(output))
    if len(buf) != 5996:
        raise ValueError("unexpected public witness shape")
    return struct.pack("<8sHHI", b"CPPRV004", 4, 0, len(statement)) + statement + struct.pack("<I", len(buf)) + buf


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--approve-installation", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    common = module("psize_common", ROOT / "scripts/common.py")
    inst = common.load_installation(args.installation, args.approve_installation)
    source = Path(inst["source_root"])
    target = Path(inst["workspace"]) / "target/release/compact-all-payments-v3"
    common.need(inst["pins"][str(target)] == common.sha(target), "approved complete prover")
    ref = module("psize_public_ref", source / "experiments/compact-all-payments-v3/reference.py")
    bundle, _ = ref.linked()
    common.need(hashlib.sha256(ref.canonical(bundle)).hexdigest() == "9d8dde618ce9ce60579d23549f552ff104ccfb8023a5fbdee0fbb1dfa8c95a95", "public fixture identity")
    original = bundle["fixtures"][2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for case in ["valid", "owner", "second_path", "index_at_count", "nullifier", "output_commitment", "balance_only", "out_of_range"]:
        w = copy.deepcopy(original["witness"])
        s = ref.r.parse(bytes.fromhex(original["statement_hex"]))
        if case == "owner":
            w["inputs"][0]["key"][0] ^= 1
        elif case == "second_path":
            w["inputs"][1]["siblings"][39][0] ^= 1
        elif case == "index_at_count":
            w["inputs"][1]["index"] = s["count"]
        elif case == "nullifier":
            s["nullifiers"][1][0] ^= 1
        elif case == "output_commitment":
            w["outputs"][1][19] ^= 1
        elif case == "balance_only":
            w["outputs"][1][1] += 1
            ref.r.refresh(s, w)
        elif case == "out_of_range":
            w["outputs"][1][1] = ref.r.MAX + 1
            ref.r.refresh(s, w)
        encoded = ref.r.encode(s)
        common.need(ref.r.parse(encoded) == s, "canonical control statement")
        failures = ref.r.relation(s, w)
        common.need(bool(failures) == (case != "valid"), "independent semantic check")
        if case == "balance_only":
            common.need(failures == ["integer balance"], "isolated balance discriminator")
        artifacts = output / case
        proc, stdout, stderr = common.run_private([str(target), "prove-private", str(artifacts)],
            cwd=source, env=inst["proof_environment"], seconds=60, data=packet(encoded, w))
        common.need(proc["wrapper_exit"] == 0 and not proc["timeout"], "normal worker lifecycle")
        if case == "valid":
            common.need(proc["process_exit"] == 0 and not stderr and json.loads(stdout)["genuine_proof_created"]
                        and (artifacts / "proof.bin").is_file(), "positive witness execution")
        else:
            common.need(proc["process_exit"] == 1 and not stdout and stderr == b"PRIVATE_CALLER_ERROR:Input\n"
                        and not artifacts.exists(), "invalid witness rejected with no proof")
        results.append(dict(case=case, independent_arithmetic_failures=failures, worker_exit=proc["process_exit"]))
    common.hashes(inst["pins"])
    common.save(output / "RESULT.json", dict(passed=True, scope="Public arithmetic controls on actual prover; receipt/spending established separately by fresh private cycles",
                installation_sha256=args.approve_installation, rows=results))
    print(json.dumps(results))


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
