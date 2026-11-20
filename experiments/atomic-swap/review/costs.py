"""Cross-check serialized sizes, accepted upload and independently logged verifier work."""
import argparse
import json
import statistics
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from swaps import decode_pair, hash_bytes


def check(public,audit,measure):
    doc=json.loads((public/'RUN.json').read_bytes())
    raw=(public/'SWAP.bin').read_bytes()
    ledger=json.loads(audit.read_bytes())
    measured=json.loads(measure.read_bytes())
    left,right=decode_pair(raw)
    sizes=measured['wire']
    legs=[len(f)-17195 for f in (left,right)]
    proofs=[n-3593 for n in legs]
    rpc_bytes=8+len(b'{"op":"submit"}')+len(raw)
    negotiation=doc['negotiation_B']
    assert negotiation==dict(terms=3358,offer_A=legs[0],offer_B=legs[1],auth_A=17088,auth_B=17088)
    assert sizes['one_copy_each_negotiation_file_B']==sum(negotiation.values())
    assert hash_bytes(raw).hex()==measured['bundle_sha256']==doc['swap']['bundle_sha256']
    assert sizes['proofs_B']==proofs and sizes['complete_legs_B']==legs
    assert sizes['final_signatures_B']==34176 and sizes['four_ciphertexts_B']==7168
    assert sizes['submission_bundle_B']==doc['swap']['packet_B']==len(raw)
    assert doc['swap']['upload']['transport']['request_B']==rpc_bytes==sizes['rpc_submit_request_B']
    assert sizes['block_incremental_over_empty_B']==len(raw)-5
    assert sizes['whole_two_frame_block_B']==len(raw)+217==ledger['economics']['measured_bundle_block_B']
    assert sizes['aggregate_fee_native_units']==3 and sizes['physical_payment_slots']==2
    for key in ('cold','warm_process_including_one_warmup'):
        group=measured[key]
        count=1 if key=='cold' else 6
        assert len(group['calls'])==count
        for c in group['calls']:
            stages=c['stage']
            assert set(stages)=={'leg0_proof','leg0_signature','leg1_proof','leg1_signature'}
            assert sum(x['cpu_s'] for x in stages.values())==c['native_verification_cpu_s']
            assert c['pair_wall_s']>0 and c['native_verification_cpu_s']>0
            assert c['ipc_to_verifier_B']==sum(legs)+2*(1+32+32+17088)+16
            assert c['ipc_from_verifier_B']==2*(3789+1)+16
        assert group['total_cpu_through_shutdown_s']>=group['parent_cpu_through_shutdown_s']
    warm=measured['warm_process_including_one_warmup']['calls'][1:]
    assert measured['warm_measured_pairs']==len(warm)==5
    assert measured['warm_median_pair_wall_s']==statistics.median(t['pair_wall_s'] for t in warm)
    wallet={}
    for i,who in enumerate(('wallet_A','wallet_B')):
        r=doc['swap'][who]
        assert r['fee']==(3 if i==0 else 0) and r['packet_B']==legs[i]
        assert r['proving_wall_s']>0 and r['prover_cpu_s']>0 and r['prover_role_peak_rss_KiB']>0
        wallet[who]={k:r[k] for k in ('proving_wall_s','prover_cpu_s','prover_role_peak_rss_KiB','real_inputs','fee')}
    return dict(checked_negotiation_one_copy_B=sum(negotiation.values()),upload_B=len(raw),rpc_upload_B=rpc_bytes,
                block_incremental_B=len(raw)-5,whole_mined_block_B=len(raw)+217,proof_B=proofs,
                receipt_B=7168,signatures_B=34176,physical_frame_B=[len(left),len(right)],wallets=wallet,
                fresh_verifier_process_wall_s=measured['cold']['launch_through_shutdown_wall_s'],
                warm_median_joint_verification_wall_s=measured['warm_median_pair_wall_s'],
                warm_median_joint_parent_and_native_cpu_s=measured['warm_median_parent_plus_native_pair_cpu_s'],
                warm_peak_native_KiB=measured['warm_peak_native_process_KiB'])


if __name__=='__main__':
    if not __debug__: sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for x in ('public','audit','measurement'):p.add_argument(x,type=Path)
    a=p.parse_args()
    print(json.dumps(check(a.public,a.audit,a.measurement),sort_keys=True,indent=2))
