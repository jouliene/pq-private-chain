"""Price the selected accelerator on a public sequence of 96 genuine CP03 proofs."""
import argparse
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
ARCHIVE_SHA = "29541085933138adb13e11fb1f91b247b03f8c20e10d68c978d6d7034ecfccc4"

def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("archive", type=Path)
    path = args.parse_args().archive
    with path.open("rb") as handle:
        assert hashlib.file_digest(handle, "sha256").hexdigest() == ARCHIVE_SHA
    spec = spec_from_file_location("review_tree_counts", HERE.parent / "review/merkle_work.py")
    review = module_from_spec(spec)
    spec.loader.exec_module(review)
    totals = []
    input_bytes = 0
    prefix = "full01-public-closure/"
    with tarfile.open(path) as archive:
        manifest = json.load(archive.extractfile(prefix + "closure.json"))
        for i in range(96):
            key = f"rolling-{i:03d}"
            entry = manifest["bodies"][key]
            body = archive.extractfile(prefix+entry["path"]).read()
            assert hashlib.sha256(body).hexdigest() == entry["sha256"] and len(body) == entry["bytes"]
            counts = dict(review.read_trees(body))
            totals.append(sum(v for k,v in counts.items() if k!="fixed"))
            input_bytes += len(body)
    capacity = {str(po2): (1<<po2)//200 for po2 in (14,17,18)}
    total = sum(totals)
    print(json.dumps({"archive_sha256":ARCHIVE_SHA,"public_sample":"rolling-000..095",
        "history_ordered_proofs":len(totals), "total_body_bytes":input_bytes,
        "per_payment_nonfixed_permutations_min_mean_max":[min(totals),total/len(totals),max(totals)],
        "workload_nonfixed_permutations": total, "permutations_per_body":totals,
        "risc0_scheduled_trace_rows_at_200_per_state_before_rounding":total*200,
        "max_states_per_keccak_seal":capacity,
        "minimum_accelerator_seals_ideal_cross_payment_batching":{k:(total+c-1)//c for k,c in capacity.items()}},
        indent=2,sort_keys=True))

if __name__ == "__main__":
    main()
