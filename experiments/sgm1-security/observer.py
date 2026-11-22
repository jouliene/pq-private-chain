"""Measure public equality tests on registered, previously validated SGM1 frames."""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent / "sgm1-admission"))
from packets import parse


def compare(a, b):
    left, right = parse(a), parse(b)
    def overlap(field):
        return len({v for leg in left for v in getattr(leg.body, field)} &
                   {v for leg in right for v in getattr(leg.body, field)})
    return dict(wire_B=[len(a),len(b)], same_wire=a==b,
                same_fees=[l.body.fee for l in left]==[r.body.fee for r in right],
                same_anchor=left[0].body.anchor==right[0].body.anchor,
                same_role_sequence=[l.body.role for l in left]==[r.body.role for r in right],
                shared_nullifiers=overlap("nfs"), shared_commitments=overlap("cms"),
                shared_receipts=overlap("receipts"))


def observe(public):
    def op(n):
        return (public / f"op-{n:02}.bin").read_bytes()
    result = dict(identical_retransmission=compare(op(1),op(1)),
                  different_ordinary_same_wave=compare(op(1),op(2)),
                  intentional_conflict_against_first_pair=compare((public/"conflict.bin").read_bytes(),op(10)),
                  first_receipt_then_onward=compare(op(1),op(11)),
                  same_two_swap_wallets_later_wave=compare(op(10),op(20)))
    assert result["different_ordinary_same_wave"]["same_fees"]
    assert result["different_ordinary_same_wave"]["same_anchor"]
    assert result["intentional_conflict_against_first_pair"]["shared_nullifiers"] >= 1
    return result


if __name__ == "__main__":
    print(json.dumps(observe(Path(sys.argv[1])), indent=2))
