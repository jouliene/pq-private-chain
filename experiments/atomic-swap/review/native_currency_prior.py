"""Feed the captured history and controls to an empty installation of the preceding public node revision."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from admission import ancestry,rejected

FIELDS=('tip','height','work','anchor','fees','issued','spent','spent_set_sha256','notes')


def exercise(dep,public,directory,require_published_elf):
    assert not directory.exists()
    directory.mkdir(mode=0o700)
    prior_modules={'chain.py':'029afef113db8691053910afe6af5fce4282914eb243480c4c5ccb79f46c92ca',
                   'swap_ledger.py':'3b4f47a46e92df3ba8ed4d1150a69f54ca37e65e4973027707b541c54ea23535',
                   'swap_wire.py':'0c1fdd12aaeda2613d21e83cee772507fb8d38db2c5f38a5b66fccacbe24c66f',
                   'managed_ledger.py':'0dc97699a13057b9d1a940e7571dfc4153a3868d572084640a320e28fd55611f',
                   'managed_ops.py':'c80f8d1c99ec3272d79bcc97256fa16fc6d13ddd7e270a3d97021229047b367d'}
    for name,digest in prior_modules.items():
        assert sha256((dep/'devnet'/name).read_bytes()).hexdigest()==digest
    mng=sha256((dep/'runtime/native').read_bytes()).hexdigest()
    slg=sha256((dep/'swap-runtime/native').read_bytes()).hexdigest()
    same=(mng,slg)==('360fa89587ec7dd6d349516ad26ccc29178c32e82f583568fc38c9520f59d8f5','46ee4c569abe6eea973843713444a759075534de169fa3a6177f0f869973cc1a')
    if require_published_elf:
        assert same
    assert (mng,slg)==tuple((dep/'devnet'/f).read_text().strip() for f in ('approved-native.sha256','approved-swap-native.sha256'))
    assert sha256((dep/'keys/managed.vk').read_bytes()).hexdigest()=='1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d'
    assert sha256((dep/'swap-keys/swap.vk').read_bytes()).hexdigest()=='0527447637fa2f34d9585606501c4a55883c0ceaf58adb2d3e9834c66ab19837'
    sys.path.insert(0,str(dep/'devnet'))
    import chain
    import runtime
    from run import Resources
    from swap_wire import split
    run=json.loads((public/'RUN.json').read_bytes())
    raw=(public/'SWAP.bin').read_bytes();frames=split(raw)
    controls=run['controls']
    reasons={'incomplete':'incomplete atomic swap','missing-first':'incomplete atomic swap','changed-terms':'invalid swap authorization',
             'changed-payer':'swap fee payer','expired':'swap expired','ordinary-conflict':'spent nullifier'}
    assert set(controls)==set(reasons)
    cases={}
    for name,reason in reasons.items():
        item=controls[name]
        payload=(public/'controls'/(name+'.bin')).read_bytes()
        assert sha256(payload).hexdigest()==item['sha256'] and item['reason']==reason and item['unchanged']
        cases[name]=payload
    assert cases['incomplete']==frames[0] and cases['missing-first']==frames[1] and cases['expired']==cases['ordinary-conflict']==raw
    visited=set(); snapshots={}; rejected_names=[]
    def reject_case(name,ledger):
        at=ledger.status(); req=controls[name]
        assert (at['tip'],at['fees'],at['spent'])==(req['tip'],req['fees'],req['spent'])
        rejected(ledger,lambda:ledger.offer(cases[name]),reasons[name])
        rejected_names.append(name)
    with ExitStack() as stack:
        resources=Resources(runtime.config(dep/'runtime'))
        stack.callback(resources.close)
        ledger=chain.Chain(directory/'history.sqlite',resources.backend)
        stack.callback(ledger.close)
        assert ledger.status()['tip']==run['genesis'] and ledger.pending()==[]
        for name in ('funded','common','swap_included','native_respent','expiry_branch','before_reorg','swap_detached','swap_restored','final'):
            expected=run['tips'][name]
            for bid,block in ancestry(public,expected['tip'],run['genesis']):
                if bid not in visited:
                    ledger.accept(block)
                    visited.add(bid)
            tip=ledger.status()
            assert all(tip[k]==expected[k] for k in FIELDS),(name,tip,expected)
            snapshots[name]={k:tip[k] for k in ('tip','height','fees','spent')}
            if name=='common':
                pk=bytes.fromhex(run['miner_keys']['miner-a'])
                for c in ('incomplete','missing-first','changed-terms','changed-payer'):
                    reject_case(c,ledger)
                rejected(ledger,lambda:ledger.template(pk,[frames[0]]),'incomplete atomic swap')
                rejected(ledger,lambda:ledger.template(pk,[frames[1],frames[0]]),'unmatched atomic swap')
                template=ledger.template(pk,frames)
                assert template[213]==2 and int.from_bytes(template[109:117],'little')==103
            if name=='expiry_branch':
                reject_case('expired',ledger)
        assert len(visited)==len(list((public/'blocks').glob('*.bin')))
        other=chain.Chain(directory/'early-conflict.sqlite',resources.backend)
        stack.callback(other.close)
        for bid,block in ancestry(public,controls['ordinary-conflict']['tip'],run['genesis']):
            assert other.accept(block)['tip']==bid
        reject_case('ordinary-conflict',other)
    return dict(preceding_public_revision='998b39809b4464a9901161530d60f670b9bfaa7a',old_MNG1_sha256=mng,old_SLG1_sha256=slg,
                published_x86_64_binaries_byte_identical=same,historical_consensus_module_digests=prior_modules,
                all_public_blocks=len(visited),physical_block_template_slots=2,actual_reorganization_checkpoints=snapshots,
                public_control_rejections=rejected_names,half_and_reversed_block_templates_rejected=True)


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('previous_deployment','public','new_directory'):
        p.add_argument(name,type=lambda x:Path(x).resolve())
    p.add_argument('--require-published-elf',action='store_true')
    a=p.parse_args()
    print(json.dumps(exercise(a.previous_deployment,a.public,a.new_directory,a.require_published_elf),sort_keys=True,indent=2))
