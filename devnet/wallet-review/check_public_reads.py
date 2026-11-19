"""Recreate each measured real prefix from public blocks and trace the selected database reads."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent)]
from measure_sql import measure
from private_compare import decode
from chain import Chain
from runtime import config
from run import Resources


def check(capture,runtime):
    data=json.loads((capture/"WALLET.json").read_bytes())
    results={}
    resources=Resources(config(runtime))
    try:
        with tempfile.TemporaryDirectory(prefix="pqwallet-public-reads-") as t:
            for arm in ("small","large"):
                record=data["scale"][arm]
                ids=record["archive"]["order"]
                h=record["base_height"]
                assert h==(4 if arm=="small" else 40) and len(ids)==h+3
                reports={}
                for label,height in [("base",h),("one_empty",h+1),("one_payment",h+3)]:
                    db=Path(t)/f"{arm}-{label}.sqlite"
                    ledger=Chain(db,resources.backend)
                    try:
                        for ident in ids[:height]:
                            raw=(capture/"blocks"/(ident+".bin")).read_bytes()
                            assert decode(raw)["id"].hex()==ident
                            ledger.accept(raw)
                        assert ledger.status()["tip"]==ids[height-1]
                    finally:
                        ledger.close()
                    reports[label]=measure(db)
                results[arm]=reports
    finally:
        resources.close()
    return dict(roles="actual selected SQLite history service, full native public block validation during fixture preparation",
                receipt_bytes="actual pread64 transfer on the main DB file; warm OS page cache, independently measured physical process input",
                branches=results)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture",type=Path)
    p.add_argument("runtime",type=Path)
    args=p.parse_args()
    print(json.dumps(check(args.capture,args.runtime),indent=2,sort_keys=True))
