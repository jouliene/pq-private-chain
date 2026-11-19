"""Check a public walkthrough capture without a wallet, prior node database or privileged checkpoint."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
from audit_db import audit_db
from chain import Chain
from network_oracle import best, decode, examine
from runtime import config
from run import Resources


def replay(capture, runtime, roots, rewards):
    result = json.loads((capture / "RESULT.json").read_bytes())
    joined = result["winning"]
    fork = result["reorg"]
    common = joined.index(fork["common"]) + 1
    losing = joined[:common] + fork["detached"]
    assert joined[common:] == fork["attached"] and (len(joined), len(losing), common) == (15, 14, 4)
    bank = {p.stem: p.read_bytes() for p in (capture / "blocks").glob("*.bin")}
    assert set(bank) == set(joined) | set(losing)
    assert all(decode(b)["id"].hex() == bid for bid, b in bank.items())
    branches = {name: examine([bank[bid] for bid in bids], roots, rewards)
                for name, bids in [("selected", joined), ("detached", losing)]}
    selected = branches["selected"]
    assert best(branches.values()) is selected and selected["body_B"] == result["archive_B"]
    assert selected["payments"] == 3 and branches["detached"]["payments"] == 4
    assert [selected[k] for k in ("spent","fees","issued")] == [6,9,1500]
    assert [branches["detached"][k] for k in ("spent","fees","issued")] == [8,12,1400]
    resources = Resources(config(runtime))
    try:
        with tempfile.TemporaryDirectory(prefix="pqdev-public-replay-") as tmp:
            db = Path(tmp) / "public.sqlite"
            ledger = Chain(db, resources.backend)
            try:
                assert ledger.status()["issued"] == ledger.status()["height"] == 0
                for ids, expected in [(losing, branches["detached"]), (joined[common:], selected)]:
                    for bid in ids:
                        ledger.accept(bank[bid])
                    state = ledger.status()
                    for name in ("tip","height","anchor","issued","fees","spent","work"):
                        assert state[name] == expected[name]
                assert state["deep_replays"] >= 1
            finally:
                ledger.close()
            checked = audit_db(db, roots, rewards)
            assert checked["selected"]["tip"] == joined[-1] and checked["raw_block_objects"] == len(bank)
    finally:
        resources.close()
    return dict(public_capture_sha256=hashlib.sha256((capture / "RESULT.json").read_bytes()).hexdigest(),
                decoded_public_objects=len(bank), replayed_from_genesis=True,
                registered_verifier=True, deep_replays=state["deep_replays"], common_height=common,
                selected_occupancies=checked["heights_by_occupancy"],
                branches={n:{k:v for k,v in data.items() if k!="headers"} for n,data in branches.items()})


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("capture","runtime","reference","reward"):
        p.add_argument(key,type=lambda x:Path(x).resolve())
    a = p.parse_args()
    print(json.dumps(replay(a.capture,a.runtime,a.reference,a.reward),indent=2,sort_keys=True))
