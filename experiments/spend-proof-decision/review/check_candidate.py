"""Verify historical funding event proofs, issuer authorizations and isolated fixture accounting."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'experiments/managed-assets/review'))
from chain_audit import advance_asset
from events import BURN, Reader, ast1

NETWORK=sha256(b'K384/isolated-network/v1').digest()


def check(pub,baseline,node,roots,approval):
    oldkey=baseline/'registered/managed.vk'
    assert sha256(oldkey.read_bytes()).hexdigest()=='1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d'
    role=ast1.Role(baseline/'native',approval,['verify','/keys'],oldkey.parent)
    try:
        r=Reader(role,roots,NETWORK,node)
        prior={}; seen=set(); events=[]
        for name,op,delta,stock in (('issue0',1,70,70),('issue1',2,300,300),('mint',3,40,340),('burn',4,BURN+10,330)):
            raw=(pub/(name+'.bin')).read_bytes()
            e=r.packet(raw)
            assert e.op==op and e.delta==delta and e.fee==3 and not set(e.nullifiers)&seen
            seen.update(e.nullifiers)
            nxt=advance_asset(prior.get(e.asset),e,1)
            assert nxt.supply==stock
            prior[e.asset]=nxt
            events.append(dict(label=name,txid=e.txid.hex(),asset=e.asset.hex(),outstanding=nxt.supply,revision=nxt.revision))
        assert len(prior)==2
        checks=r.verify_sigs()
        role.close()
    finally:
        role.abort()
    trial=json.loads((pub/'RESULT.json').read_bytes())
    assert trial['fixed_supply']==70 and trial['managed_supply']==330
    assert trial['inputs_ordinary_and_both_legs']==[2,1,1]
    assert (trial['backup_to_forward_fixed'],trial['backup_to_forward_managed'])==(7,30)
    assert all(trial[k] for k in ('isolated_registry_issuer_signed_register_and_mint','four_receipts_checked_before_signatures',
                                  'both_altered_authorizations_rejected','changed_public_fee_rejected','corrupt_ordinary_proof_rejected',
                                  'tampered_receipt_rejected','old_verifier_rejected_retagged_candidate'))
    metrics={}
    for k,real in (('ordinary',2),('leg0',1),('leg1',1)):
        sample=trial['meters'][k+'_prove']
        prove,=[m for m in sample['native'] if m['operation']=='compact_prove']
        assert sample['call_wall_s'][-1]>0 and prove['cpu_s']>0 and prove['peak_rss_kib']>0
        setup,=[m for m in sample['native'] if m['operation']=='wallet_setup']
        metrics[k]=dict(positive_real_inputs=real,prove_rpc_wall_s=sample['call_wall_s'][-1],
                        first_proof_metered_native_cpu_s=setup['cpu_s']+prove['cpu_s'],
                        setup_only_cpu_s=setup['cpu_s'],proof_only_cpu_s=prove['cpu_s'],proof_only_wall_s=prove['elapsed_s'],
                        peak_process_KiB=prove['peak_rss_kib'],process_including_setup_and_teardown_wall_s=sample['complete_process_wall_s'])
    signers=[]
    for side in (0,1):
        sample=trial['meters']['sign'+str(side)]
        sig,=[m for m in sample['native'] if m['operation']=='swap_sign']
        signers.append(dict(side=side,call_wall_s=sample['call_wall_s'][-1],cpu_s=sig['cpu_s'],peak_process_KiB=sig['peak_rss_kib']))
    return dict(independent_registered_funding_proofs=4,independent_issuer_signatures=checks['valid_public_signatures'],
                changed_issuer_authorizations_rejected=len(checks['mutated_binding_rejections']),authenticated_funding_events=events,
                declared_private_fixture=dict(real_inputs=[2,1,1],backups_forwarded=[7,30],old_verifier_onward_B=trial['old_managed_onward_B']),
                prover_roles=metrics,swap_final_authorizations=signers,isolated_network=NETWORK.hex(),synthetic_height=1)


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('public','baseline','node','roots'):p.add_argument(n,type=Path)
    p.add_argument('baseline_sha')
    a=p.parse_args();print(json.dumps(check(a.public,a.baseline,a.node,a.roots,a.baseline_sha),indent=2,sort_keys=True))
