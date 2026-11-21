"""Check the non-native lift inside each released one-seed funded role."""
import argparse
import json
from pathlib import Path
import resource
import shutil
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent


def verify_role(name):
    import check
    import lift
    import funded_check
    import released_roles

    expected = json.loads((HERE / "SHAPES.json").read_text())
    previous_check = check.full

    def with_lift(suite, params, witness, programs, receipts):
        result = previous_check(suite, params, witness, programs, receipts)
        assignment = check.e.compile_program(suite, params, witness, True)
        start = time.process_time()
        actual = lift.Census(programs[1], assignment.z).result()
        if actual != expected[suite] or assignment.failures:
            raise ValueError("funded lift differs from the registered shape")
        print(f"lift_cpu_s {name} {time.process_time()-start:.3f}", file=sys.stderr)
        funded_check.check(name, suite, params, witness)
        return result

    check.full = with_lift
    try:
        released_roles.worker(name)
    finally:
        check.full = previous_check


def run(args):
    source = HERE.parents[1] / "packed-tcith/encoding"
    sys.path.insert(0, str(source))
    import funded

    # Keep the released launcher's original namespace, read-only mounts and output checks.
    # Stage its worker together with the mandatory additional arithmetic check.
    with tempfile.TemporaryDirectory(prefix="lattice-role-code-") as tmp:
        stage = Path(tmp)
        for name in ("check.py", "encoding.py", "packed.py"):
            shutil.copyfile(source / name, stage / name)
        shutil.copyfile(source / "funded.py", stage / "released_roles.py")
        for name in ("pivot.py", "funded_check.py"):
            shutil.copyfile(HERE.parent / "pivot" / name, stage / name)
        for name in ("lift.py", "SHAPES.json"):
            shutil.copyfile(HERE / name, stage / name)
        shutil.copyfile(Path(__file__), stage / "funded.py")
        funded.HERE = stage
        result = funded.run(args)
    return {name: {"released_proof_verified": item["released_proof_verified"],
                   "selected_funded_inputs_and_receipts_checked": item["ordered_receipt_hash_matches"],
                   "complete_integer_lift_checked": True,
                   "fixed_parent_funded_assignment_and_shared_spent_rule_checked": True} for name, item in result.items()}


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if not __debug__:
        raise SystemExit("enable assertions")
    if sys.argv[1:2] == ["--worker"]:
        sys.path.insert(0, str(HERE))
        verify_role(sys.argv[2])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for key in ("home", "capture", "constants"):
            parser.add_argument(key, type=Path)
        print(json.dumps(run(parser.parse_args()), indent=2, sort_keys=True))
