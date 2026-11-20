"""Replay selected public blocks into disposable validators; exercise fee, conflict and expiry boundaries."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys


def ancestry(public,tip,genesis):
    block=[]
    while tip!=genesis:
        raw=(public/'blocks'/(tip+'.bin')).read_bytes()
        block.append((tip,raw))
        tip=raw[41:73].hex()
    return reversed(block)


def fingerprint(db):
    s=db.status()
    return [s[k] for k in ('height','tip','notes','spent','fees','issued','anchor')],tuple(db.pending())


def rejected(db,fn,reason):
    before=fingerprint(db)
    try:
        fn()
    except ValueError as e:
        assert str(e)==reason,(str(e),reason)
    else:
        raise AssertionError('unexpected acceptance')
    assert fingerprint(db)==before


def exercise(dep,public,replay,dest):
    doc=json.loads((public/'RUN.json').read_bytes())
    audit=json.loads(replay.read_bytes())
    dest.mkdir(mode=0o700,exist_ok=False)
    # Load only the candidate's public node path. No wallet or negotiation directory is mounted.
    sys.path.insert(0,str(dep/'devnet'))
    import chain
    import runtime
    from run import Resources
    raw=(public/'SWAP.bin').read_bytes()
    size,=struct.unpack_from('<I',raw,5)
    left,right=raw[9:9+size],raw[13+size:]
    assert len(right)==int.from_bytes(raw[9+size:13+size],'little')
    cfg=runtime.config(dep/'runtime')
    pins={row['role']:row for row in audit['registered']}
    assert cfg.binary_sha==pins['MNG1']['approved_binary'] and cfg.profile_sha==pins['MNG1']['registered_vk']
    genesis=doc['genesis']
    event=doc['ordinary']['competing-ordinary']['tx']
    ordinary=(public/'packets'/(event+'.bin')).read_bytes()
    pk=next(ancestry(public,doc['tips']['common']['tip'],genesis))[1][77:109]
    common=doc['tips']['common']['tip']
    eid=doc['swap']['expiry']
    selected=audit['selected']
    results={}
    for name,last in [('winning',selected['tip']),('expiry',doc['tips']['expiry_branch']['tip'])]:
        resources=Resources(cfg)
        try:
            ledger=chain.Chain(dest/(name+'.sqlite'),resources.backend)
            try:
                assert ledger.status()['tip']==genesis and ledger.pending()==[]
                for tid,block in ancestry(public,last,genesis):
                    live=ledger.status()
                    if name=='winning' and live['tip']==common:
                        rejected(ledger,lambda:ledger.offer(left),'incomplete atomic swap')
                        rejected(ledger,lambda:ledger.template(pk,[left]),'incomplete atomic swap')
                        rejected(ledger,lambda:ledger.template(pk,[right,left]),'unmatched atomic swap')
                        rejected(ledger,lambda:ledger.template(pk,[left,right,left,right,left]),'block capacity')
                        template=ledger.template(pk,[left,right])
                        assert template[213]==2 and int.from_bytes(template[109:117],'little')==103
                        prefix=[]
                        for item in doc.get('capacity_fixture',[]):
                            packet=(public/'capacity'/item['file']).read_bytes()
                            actual=ledger.offer(packet)
                            assert actual['id']==sha256(packet).hexdigest()==item['sha256'] and not actual['duplicate']
                            prefix.append(packet)
                        assert not prefix or len(prefix)==3
                        assert ledger.offer(raw)['duplicate'] is False
                        assert ledger.offer(raw)['duplicate'] is True
                        rejected(ledger,lambda:ledger.offer(ordinary),'pool conflict')
                        assert ledger.pending()==[sha256(x).hexdigest() for x in (*prefix,raw)]
                        if prefix:
                            assert chain.decode_block(ledger.template(pk)+bytes(8)).packets==tuple(prefix)
                            results['three_ordinary_then_pair']=dict(queued_physical_slots=5,proposed_slots=3,
                                                                    held_together_until_next_block=True)
                    if name=='expiry' and live['tip']==common:
                        assert ledger.offer(ordinary)['id']==event
                        rejected(ledger,lambda:ledger.offer(raw),'pool conflict')
                        assert ledger.pending()==[event]
                    if name=='expiry' and live['height']==eid-1:
                        # The production template bypasses mempool membership and validates actual candidate effects.
                        assert ledger.template(pk,[left,right])[213]==2
                    outcome=ledger.accept(block)
                    assert outcome['selected'] and outcome['tip']==tid
                if name=='winning':
                    tip=ledger.status()
                    assert all(tip[k]==selected[k] for k in ('height','tip','fees','issued','notes','spent','anchor','spent_set_sha256'))
                    rejected(ledger,lambda:ledger.offer(ordinary),'anchor age' if tip['height']+1-
                             int.from_bytes(ordinary[-3584-248+32:-3584-248+36],'little')>8 else 'spent nullifier')
                else:
                    assert ledger.status()['height']==eid
                    rejected(ledger,lambda:ledger.offer(raw),'swap expired')
                    rejected(ledger,lambda:ledger.template(pk,[left,right]),'swap expired')
                results[name]=dict(blocks=ledger.status()['height'],tip=ledger.status()['tip'],fees=ledger.status()['fees'])
            finally:
                ledger.close()
        finally:
            resources.close()
    return dict(replays=results,both_orders_of_pool_conflict=True,isolated_and_reordered_frames_rejected=True,
                four_slot_ceiling=True,inclusive_expiry_height=eid,first_rejected_candidate_height=eid+1,
                unchanged_state_and_mempool_on_rejections=True)


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('deployment','public','audit','empty_directory'):
        p.add_argument(n,type=lambda s:Path(s).resolve())
    a=p.parse_args()
    print(json.dumps(exercise(a.deployment,a.public,a.audit,a.empty_directory),indent=2,sort_keys=True))
