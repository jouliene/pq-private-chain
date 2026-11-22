"""Price the actual mixed-field wire format at fixed parameters."""
import json
from math import ceil,comb,log2


def size(width,ell):
    pack,opens,leaves,eta = 112,88,2048,75
    trace = 3*ell+5
    rows = ceil((width + 16*trace)/pack)
    parts = dict(columns=(rows+32+eta)*opens*2,
                 siblings=opens*(leaves.bit_length()-1)*64, salts=opens*32,
                 R_completion=pack*eta*2, Q=(2*pack+opens)*32, digests=128, trace=trace*32)
    return dict(width=width,ell=ell,rows=rows,parts=parts,proof_bytes=sum(parts.values()))


def report():
    ret = {
        "linked_segment":size(81412,17), "funded_only_2x40":size(3723978,22),
        "complete_payment_uncompiled_wire_inventory":size(3904227,22),
        "interactive_exponents":{
            "row":256-log2(17), "DECS":16*75-log2(comb(2048,201)),
            "LCS_opening":log2(comb(2048,88))-log2(comb(311,88)), "LCS_mix":256}}
    p = ret["complete_payment_uncompiled_wire_inventory"]["proof_bytes"]
    ret["conditional_wire_bytes"] = {"ordinary":3990+p,"one_signed_leg":33918+p,
                                     "two_leg_bundle":67856+2*p}
    return ret


if __name__ == "__main__":
    print(json.dumps(report(),indent=2))
