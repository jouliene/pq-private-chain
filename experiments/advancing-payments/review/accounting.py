"""Check the scenario geometry against actual packet bytes and observed role CPU."""
from fractions import Fraction
import argparse
import json
from math import isclose
from pathlib import Path

YEAR = 365*86400
OFFER = 100_000_000
PROFILES = {"low":([85,10,4,1],Fraction(1)),"busy":([5,10,15,70],Fraction(1,9))}


def inspect(directory,roles_path):
    report = json.loads((directory/"RESULT.json").read_bytes())
    trace = json.loads((directory/"TRACE.json").read_bytes())
    roles = json.loads(roles_path.read_bytes())
    widths = {}
    for block in trace["blocks"].values():
        if block["packet"] is None:
            assert block["size"]==152
            continue
        packet = (directory/"packets"/(block["packet"]+".bin")).read_bytes()
        width = packet[4]
        size = len(packet)
        assert size == 9+int.from_bytes(packet[5:9],"little")+width*3584
        assert block["size"]==size+152
        assert widths.setdefault(width,size)==size
    assert set(widths)=={1,2,3,4}
    for k,size in widths.items():
        entry = roles["widths"][str(k)]
        assert [entry[q] for q in ["packet","ciphertexts","preinclusion","acks","block","relay"]]==[
            size,k*3584,k*(widths[1]+4),32*k,size+152,size+156]
    meters = report["roles"]
    def ops(names,op,key):
        return [m[key] for name,role in meters.items() if name in names
                for m in role["meters"] if m["operation"]==op]
    builder_cpu, builder_wall = {},{}
    for k in [2,3,4]:
        names = [n for n in meters if n.startswith(f"builder{k}")]
        samples = ops(names,"builder_aggregate","cpu_s")
        times = ops(names,"builder_aggregate","elapsed_s")
        builder_cpu[k] = sum(samples)/len(samples)
        builder_wall[k] = sum(times)/len(times)
        assert len(samples)==(4 if k==4 else 1)
        assert len(ops(names,"builder_setup","elapsed_s"))==(2 if k==4 else 1)
    lower_bound = min(Fraction(size+152,width) for width,size in widths.items())
    result = []
    comp = lambda a,b:isclose(float(a),float(b),rel_tol=1e-12,abs_tol=1e-8)
    for s in roles["scenarios"]:
        weights,empties = PROFILES[s["mix"]]
        share = Fraction(str(s["inclusion"]))
        mean_width = sum((i+1)*v for i,v in enumerate(weights))/Fraction(100)
        included = OFFER*share
        paid = included/mean_width
        all_blocks = paid*(1+empties)
        mix_packet = sum(widths[i+1]*v for i,v in enumerate(weights))/Fraction(100)
        body = paid*mix_packet+152*all_blocks
        stream = body+4*all_blocks
        intakes = OFFER*(4+widths[1])
        cpu = sum(weights[i-1]*builder_cpu[i] for i in builder_cpu)/100*float(paid)/YEAR
        service = sum(weights[i-1]*builder_wall[i] for i in builder_wall)/100*float(paid)/YEAR
        vals = {"mean_width":mean_width,"expected_paid_blocks":paid,
                "expected_blocks":all_blocks,"complete_canonical_block_bytes":body,
                "peer_one_copy_stream_bytes":stream,"wallet_to_ingress_bytes":intakes,
                "uniform_eight_block_seconds":8*YEAR/all_blocks,"builder_cpu_s_per_s":cpu,
                "serial_builder_service_s_per_s":service,"real_indexes_minimum_new_payload_B":128*included,
                "one_year_common_receipt_rows_B":3648*included,"one_year_common_nfs_B":64*included}
        for key,v in vals.items():
            assert comp(s[key],v), key
        for tb in [1,5]:
            assert comp(s["days_to_archive_TB"][str(tb)],365*tb*10**12/body)
            assert comp(s["one_archive_max_offers_per_year"][str(tb)],OFFER*tb*10**12/body)
        result.append(dict(mix=s["mix"],included=int(included),archive_TB=float(body/10**12),
                           relay_one_copy_TB=float(stream/10**12),uniform_eight_blocks_s=float(8*YEAR/all_blocks),
                           all_full_width_archive_minimum_TB=float(included*lower_bound/(10**12)),
                           builder_wall_per_s=service))
    return dict(packet_B=widths,archive_bytes_per_included_payment_lower_bound=float(lower_bound),
                scenarios=result,wallet_uploaded_TB=OFFER*(4+widths[1])/10**12,
                busy_origins=report["busy"]["synchronized_prepared_payments"])


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",type=Path)
    p.add_argument("roles",type=Path)
    a=p.parse_args()
    print(json.dumps(inspect(a.directory,a.roles),sort_keys=True,indent=2))
