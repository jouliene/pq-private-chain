"""Create one optional archival APV2 proof after all source blocks have been directly included."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/"devnet"))
import chain
import runtime
from run import Resources

CAPTURE=ROOT/"devnet/evidence/author"


def selected():
    data=json.loads((CAPTURE/"RESULT.json").read_bytes())
    rows=[]
    for height,h in enumerate(data["winning"],1):
        raw=(CAPTURE/"blocks"/(h+".bin")).read_bytes()
        assert chain.block_id(raw).hex()==h
        blk=chain.decode_block(raw)
        for idx,p in enumerate(blk.packets):
            rows.append((height,idx,p))
    assert [(h,i) for h,i,_ in rows]==[(3,0),(4,0),(4,1)]
    return rows


def run(args):
    root=args.out
    root.mkdir(exist_ok=False,parents=True)
    rows=selected()
    group=[p for _,_,p in rows]
    res=Resources(runtime.config(args.runtime))
    try:
        slots=[res.backend.verify(p)[0] for p in group]
        build=res.role("detached3",["builder","/keys","3"])
        assert build.get()==b"READY"
        start=time.monotonic()
        raw=build.call(*group)
        took=time.monotonic()-start
        assert res.backend.verify(raw)==slots
        (root/"certificate.bin").write_bytes(raw)
        result=dict(source_result_sha256=hashlib.sha256((CAPTURE/"RESULT.json").read_bytes()).hexdigest(),
                    approval_profile_sha256=res.a.profile_sha,installation_sha256=res.a.binary_sha,
                    certificate_sha256=hashlib.sha256(raw).hexdigest(),certificate_B=len(raw),
                    elapsed_after_ready_s=took,individual_slots=[dict(height=h,offset=i,anchor_height=s.height,
                    packet_sha256=hashlib.sha256(p).hexdigest(),packet_B=len(p)) for (h,i,p),s in zip(rows,slots,strict=True)],
                    builder=res.finish("detached3"),checked_equal_ordered_slots=True)
        (root/"BUILD.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    finally:
        res.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    run(p.parse_args())
