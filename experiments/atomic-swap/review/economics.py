"""Reconcile disclosed fixture directions with independently verified public branch effects."""
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from swaps import decode_pair, hash_bytes


def balances(rows):
    return {owner:dict(native=vals['native'],assets={k:v for k,v in vals.items() if k!='native' and v})
            for owner,vals in rows.items()}


def economics(public,states,blocks,winner,reader,miner_file=None):
    doc=json.loads((public/'RUN.json').read_bytes())
    f,u=doc['asset_ids']['fixed'],doc['asset_ids']['managed']
    assert f!=u and doc['network']==reader.network.hex() and doc['genesis']==states[winner].ids[0].hex()
    # Payer, payee, native paid to the payee, private token payment, and public signed supply change.
    plan={'fixed':('miner-a','miner-a',0,70,f,70),'managed':('miner-b','miner-b',0,300,u,300),
          'mint':('miner-b','miner-b',0,40,u,40),'fund-burn':('miner-b','burner',3,10,u,0),
          'burn':('burner','burner',0,0,u,-10),'fixed-funding':('miner-a','alice',20,15,f,0),
          'usd-funding':('miner-b','bob',18,80,u,0),'fee-alice':('miner-a','alice',9,0,'',0),
          'fee-bob':('miner-a','bob',9,0,'',0),'competing-ordinary':('bob','rival',0,5,u,0),
          'respend-a':('alice','forward',0,30,u,0),'respend-b':('bob','forward',0,7,f,0)}
    assert set(plan)==set(doc['ordinary'])
    by_tx={bytes.fromhex(entry['tx']):name for name,entry in doc['ordinary'].items()}
    assert len(by_tx)==len(plan)
    frames=decode_pair((public/'SWAP.bin').read_bytes())
    ids=[hash_bytes(x) for x in frames]
    group_id=hash_bytes((public/'SWAP.bin').read_bytes())
    assert reader.groups[group_id]['leg_txids']==list(map(bytes.hex,ids))
    rec=doc['swap']
    assert rec['frame_ids']==list(map(bytes.hex,ids)) and rec['bundle_sha256']==group_id.hex()
    for i,n in enumerate(('a','b')):
        by_tx[ids[i]]='swap-'+n
    plan.update({'swap-a':('alice','bob',0,7,f,0),'swap-b':('bob','alice',0,30,u,0)})
    inventory=set()
    for path in (public/'packets').glob('*.bin'):
        raw=path.read_bytes()
        pid=hash_bytes(raw)
        assert path.name==pid.hex()+'.bin' and pid in by_tx
        inventory.add(pid)
        if pid not in ids:
            entry=doc['ordinary'][by_tx[pid]]
            assert len(raw)==entry['packet_B'] and entry['fee']==reader.legacy.events[pid].fee
    assert inventory==set(by_tx)
    keys=doc.get('miner_keys')
    if miner_file:
        source=json.loads(miner_file.read_bytes())
        assert keys is None or keys==source
        keys=source
    assert set(keys)=={'miner-a','miner-b','miner-c'} and keys['miner-a']==keys['miner-c']!=keys['miner-b']
    miner={bytes.fromhex(keys[v]):v for v in ('miner-a','miner-b')}
    assert {b.miner for b in blocks.values()}<=miner.keys()
    stages=doc['tips']
    assert set(stages)=={'funded','common','swap_included','expiry_branch','before_reorg','swap_detached','swap_restored','final'}
    st={k:states[bytes.fromhex(v['tip'])] for k,v in stages.items()}
    assert st['final'] is states[winner]
    snapshots={}
    for label,state in st.items():
        summary=state.summary()
        assert all(stages[label][k]==summary[k] for k in ('tip','height','work','anchor','issued','fees','spent','notes','spent_set_sha256'))
        assert stages[label]['header']==state.header.hex()
        assert state.supply()==doc['registries'][label]
        assert state.assets[bytes.fromhex(f)].supply==70 and state.assets[bytes.fromhex(u)].supply==330
        rows={name:Counter() for name in (set(miner.values())|{'burner','alice','bob','forward','rival'})}
        for bid in state.ids[1:]:
            block=blocks[bid]
            for event in block.slots:
                label_=by_tx[event.txid]
                payer,payee,native,quantity,asset,minted=plan[label_]
                delta=(1<<62)-event.delta if event.op==4 else event.delta
                assert delta==minted
                if minted:
                    assert event.asset.hex()==asset
                rows[payer]['native']-=event.fee+native
                rows[payee]['native']+=native
                if asset:
                    rows[payer][asset]+=minted-quantity
                    rows[payee][asset]+=quantity
                assert min(rows[payer].values())>=0
            rows[miner[block.miner]]['native']+=block.amount
        expected=balances(rows)
        assert sum(v['native'] for v in expected.values())==summary['issued']
        assert all(sum(v['assets'].get(tag,0) for v in expected.values())==s for tag,s in [(u,330),(f,70)])
        for actor,row in doc['balances'][label].items():
            assert expected[actor.removesuffix('-restored')]==row,(label,actor)
        snapshots[label]={'height':summary['height'],'fees':summary['fees'],'balances':expected}
    # Displacements concern both entire legs, the related fee credit, and both parties' nullifiers.
    orig=bytes.fromhex(doc['ordinary']['competing-ordinary']['tx'])
    ordinary=reader.legacy.events[orig]
    assert set(ordinary.nullifiers)&set(reader.frames[ids[1]].effect.nullifiers)
    assert not set(ordinary.nullifiers)&set(reader.frames[ids[0]].effect.nullifiers)
    for label in ('swap_included','before_reorg','swap_restored','final'):
        assert all(i in st[label].locations for i in ids) and orig not in st[label].locations
    for label in ('common','expiry_branch','swap_detached'):
        assert all(i not in st[label].locations for i in ids)
    assert orig in st['swap_detached'].locations
    assert st['swap_included'].fees-st['common'].fees==st['swap_detached'].fees-st['common'].fees==3
    assert len(st['swap_included'].spent)-len(st['common'].spent)==4
    assert len(st['swap_detached'].spent)-len(st['common'].spent)==2
    b=blocks[st['final'].locations[ids[0]]]
    assert b.id==st['final'].locations[ids[1]] and b.height==doc['moving']['inclusion_height']
    assert doc['moving']['before_first_leg']<doc['moving']['after_second_leg']<b.height
    assert doc['peer_pids_preserved'] and doc['fresh_node']==dict(initial_height=0,final_height=len(st['final'].ids)-1,winning_tip=winner.hex())
    assert doc['gross_miner_credits']==st['final'].rewards
    errors={'incomplete':'incomplete atomic swap','changed-terms':'invalid swap authorization',
            'expired':'swap expired','ordinary-conflict':'spent nullifier'}
    assert set(doc['controls'])==set(errors)
    denied={}
    for name,expected in errors.items():
        log=doc['controls'][name]
        raw=(public/'controls'/(name+'.bin')).read_bytes()
        ref=states[bytes.fromhex(log['tip'])]
        assert hash_bytes(raw).hex()==log['sha256'] and log['reason']==expected and log['unchanged']
        assert log['fees']==ref.fees and log['spent']==len(ref.spent)
        if name=='incomplete':
            assert raw==frames[0]
        elif name=='changed-terms':
            changed=decode_pair(raw)
            for old,new in zip(frames,changed,strict=True):
                assert len(old)==len(new) and old[:43]==new[:43] and old[75:]==new[75:] and old[43:75]!=new[43:75]
            assert changed[0][43:75]==changed[1][43:75]
        elif name=='expired':
            assert hash_bytes(raw)==group_id and len(ref.ids)>doc['swap']['expiry']
            assert all(set(reader.frames[x].effect.nullifiers).isdisjoint(ref.spent) for x in ids)
        else:
            assert hash_bytes(raw)==group_id and orig in ref.locations
            assert set(reader.frames[ids[1]].effect.nullifiers)&ref.spent.keys()
        denied[name]=expected
    assert doc['checks']['abort']['state']=='aborted' and doc['checks']['short_delivery']=='wallet cannot open'
    return dict(snapshots=snapshots,public_negative_controls=denied,ordinary_packets=len(doc['ordinary']),winning_swap_group=group_id.hex(),
                conflict_on_second_participant=True,funded_fixed_supply=70,funded_managed_supply=330,
                measured_bundle_block_B=len((public/'blocks'/(b.id.hex()+'.bin')).read_bytes()))
