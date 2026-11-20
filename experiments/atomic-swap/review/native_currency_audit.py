"""Rebuild every fork, complete exchange, reward, and fee using the previously released MNG1/SLG1 verifiers."""
import argparse
from collections import Counter
from contextlib import ExitStack
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from audit import MANAGED_VK,SWAP_VK,HistoricalReader,Reader,ast1,database,group_rows,mount,read_graph,selected_summary
from economics import balances
from swaps import ZERO,decode_pair,hash_bytes

NETWORK=bytes.fromhex('7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac')
OLD_MANAGED='360fa89587ec7dd6d349516ad26ccc29178c32e82f583568fc38c9520f59d8f5'
OLD_SWAP='46ee4c569abe6eea973843713444a759075534de169fa3a6177f0f869973cc1a'

def check_money(doc, states, blocks, reader, labels, legs):
    managed, fixed = doc['asset_ids']['managed'],doc['asset_ids']['substitute']
    assert managed != fixed and set(doc['asset_ids'])=={'managed','substitute'}
    # Participant-disclosed directions and quantities, separately reconciled with local spendable rows.
    plan = {
        'managed':('miner-b','miner-b',0,managed,100,100), 'fixed':('miner-a','miner-a',0,fixed,8,8),
        'usd-funding':('miner-b','alice',0,managed,100,0), 'native-funding':('miner-a','bob',25,None,0,0),
        'substitute-funding':('miner-a','bob',0,fixed,8,0),
        'respend-a':('alice','forward',5,None,0,0), 'competing-ordinary':('bob','rival',2,None,0,0)}
    assert set(labels)==set(plan)
    txplan={tx:plan[label] for label,tx in labels.items()}
    txplan.update({legs[0]:('alice','bob',0,managed,20,0),legs[1]:('bob','alice',8,None,0,0)})
    keys=doc['miner_keys']
    assert set(keys)=={'miner-a','miner-b','miner-c'} and keys['miner-a']==keys['miner-c']!=keys['miner-b']
    miners={bytes.fromhex(keys[name]):name for name in ('miner-a','miner-b')}
    assert set(b.miner for b in blocks.values())==set(miners)
    stages=('funded','common','swap_included','native_respent','expiry_branch','before_reorg','swap_detached','swap_restored','final')
    assert set(states)==set(stages)
    owners=('alice','bob','forward','rival','miner-a','miner-b')
    records={}
    assert doc['ordinary']['respend-a']['real_inputs']==1
    paid=reader.legacy.events[labels['respend-a']]
    rival=reader.legacy.events[labels['competing-ordinary']]
    assert paid.op==rival.op==0 and paid.delta==rival.delta==0
    f0,f1=(reader.frames[tx].effect for tx in legs)
    assert len(set(f1.nullifiers)&set(rival.nullifiers))==1 and not set(f0.nullifiers)&set(rival.nullifiers)
    for name in stages:
        state=states[name]
        money={owner:Counter() for owner in owners}
        for bid in state.ids[1:]:
            b=blocks[bid]
            for event in b.slots:
                payer,receiver,native,asset,tokens,delta=txplan[event.txid]
                assert event.delta==delta and (not delta or event.asset.hex()==asset)
                money[payer]['native']-=native+event.fee
                money[receiver]['native']+=native
                if asset:
                    money[payer][asset]+=delta-tokens
                    money[receiver][asset]+=tokens
                assert min(money[payer].values())>=0
            money[miners[b.miner]]['native']+=b.amount
        holdings=balances(money)
        for owner,row in doc['balances'][name].items():
            assert row==holdings[owner.removesuffix('-restored')],(owner,name)
        assert sum(row['native'] for row in holdings.values())==100*(len(state.ids)-1)
        for tag,total in [(managed,100),(fixed,8)]:
            assert state.assets[bytes.fromhex(tag)].supply==total==sum(row['assets'].get(tag,0) for row in holdings.values())
        early=name in ('funded','common','expiry_branch')
        detached=name=='swap_detached'
        swapped=not (early or detached)
        onward=swapped and name!='swap_included'
        assert all((x in state.locations)==swapped for x in legs)
        assert (paid.txid in state.locations)==onward and (rival.txid in state.locations)==detached
        assert state.fees==15+3*(int(swapped)+int(onward)+int(detached))
        assert len(state.spent)==10+4*swapped+2*onward+2*detached
        # Both branch-specific spends are seen on their own branch only.
        assert all((nf in state.spent)==swapped for nf in f0.nullifiers)
        assert all((nf in state.spent)==onward for nf in paid.nullifiers)
        existing={v[0] for v in state.outs}
        assert all((cm in existing)==swapped for cm in (*f0.commitments,*f1.commitments))
        assert all((cm in existing)==onward for cm in paid.commitments)
        records[name]=dict(height=len(state.ids)-1,tip=state.ids[-1].hex(),logical_fees=state.fees,credited_to_miners=state.rewards,
                           issued=100*(len(state.ids)-1),balances=holdings)
    assert records['funded']['balances']['alice']==dict(native=0,assets={managed:100})
    assert records['swap_included']['balances']['alice']==dict(native=8,assets={managed:80})
    assert records['final']['balances']['alice']==dict(native=0,assets={managed:80})
    assert records['final']['balances']['forward']==dict(native=5,assets={})
    assert records['final']['balances']['bob']==dict(native=14,assets={fixed:8,managed:20})
    assert doc['gross_miner_credits']==states['final'].rewards and doc['peer_pids_preserved']
    assert doc['fresh_node']==dict(initial_height=0,final_height=len(states['final'].ids)-1,winning_tip=states['final'].ids[-1].hex())
    common=states['common']; successful=states['swap_included']; final=states['final']
    assert successful.ids[:-1]==common.ids
    assert final.locations[legs[0]]==final.locations[legs[1]]==successful.ids[-1]
    sb=blocks[successful.ids[-1]]; ob=blocks[final.locations[paid.txid]]
    assert [e.txid for e in sb.slots]==legs and [e.txid for e in ob.slots]==[paid.txid]
    assert sb.amount==ob.amount==103 and ob.parent==sb.id
    for changed in ('before_reorg','swap_detached','swap_restored'):
        assert common.ids==states[changed].ids[:len(common.ids)]
    assert states['before_reorg'].ids not in (states['swap_detached'].ids,states['swap_restored'].ids)
    assert len(states['before_reorg'].ids)<len(states['swap_detached'].ids)<len(states['swap_restored'].ids)
    assert states['before_reorg'].ids==states['swap_restored'].ids[:len(states['before_reorg'].ids)]
    assert states['swap_detached'].ids[len(common.ids)]!=sb.id
    return dict(snapshots=records,ordinary_reference_tx=paid.txid.hex(),one_input_ordinary_reported=doc['ordinary']['respend-a']['real_inputs']==1,
                changed_tip_after_rollback=states['swap_detached'].ids[-1].hex(),
                swap_fee=sb.amount-100,ordinary_fee=ob.amount-100,winning_fee_total=final.fees,
                rival_branch_fee_total=states['swap_detached'].fees,losing_empty_fee_total=states['expiry_branch'].fees,
                recovered_swap_outputs=4,recovered_dependent_outputs=2,ordinary_conflicts_only_with_fee_payer=True)


def audit(args):
    assert hash_bytes(b'AST1/PoW/network/v1\0'+bytes.fromhex(ast1.VK)+ast1.RULES)==NETWORK
    doc=json.loads((args.public/'RUN.json').read_bytes())
    with ExitStack() as stack:
        ordinary,pin_m=mount(stack,args.deployment,'MNG1','managed.vk',MANAGED_VK)
        swap,pin_s=mount(stack,args.deployment,'SLG1','swap.vk',SWAP_VK,'swap-')
        published_elf=(pin_m['approved_binary'],pin_s['approved_binary'])==(OLD_MANAGED,OLD_SWAP)
        if args.require_published_elf:
            assert published_elf
        reader=Reader(HistoricalReader(ordinary,args.helpers/'roots',NETWORK,args.node),swap)
        states,blocks,tips,best=read_graph(args.public,reader,args.helpers)
        final=states[best]
        assert doc['network']==NETWORK.hex() and doc['genesis']==final.ids[0].hex()
        submitted=(args.public/'SWAP.bin').read_bytes()
        ident=hash_bytes(submitted)
        ids=[hash_bytes(f) for f in decode_pair(submitted)]
        group=reader.groups[ident]
        assert len(reader.groups)==1 and group['payer']==1 and group['fee_by_leg']==[0,3]
        assert group['leg_txids']==list(map(bytes.hex,ids))
        assert doc['swap']['bundle_sha256']==ident.hex() and doc['swap']['frame_ids']==group['leg_txids']
        occurrences=group_rows(reader,blocks)
        assert len(occurrences)==1
        by_name={name:bytes.fromhex(entry['tx']) for name,entry in doc['ordinary'].items()}
        assert len(set(by_name.values()))==len(by_name) and set(by_name.values())==set(reader.legacy.events)
        packets={}
        for path in (args.public/'packets').glob('*.bin'):
            raw=path.read_bytes()
            tx=hash_bytes(raw)
            assert path.name==tx.hex()+'.bin' and tx not in packets
            packets[tx]=raw
        assert set(packets)==set(by_name.values())|set(ids) and [packets[i] for i in ids]==list(decode_pair(submitted))
        for name,tx in by_name.items():
            ev=reader.legacy.events[tx]
            assert doc['ordinary'][name]['packet_B']==len(packets[tx]) and doc['ordinary'][name]['fee']==ev.fee==3
        snapshots={label:states[bytes.fromhex(head['tip'])] for label,head in doc['tips'].items()}
        assert snapshots['final'] is final
        for stage,state in snapshots.items():
            r=selected_summary(state,reader)
            assert state.supply()==doc['registries'][stage] and doc['tips'][stage]['header']==state.header.hex()
            assert all(r[k]==doc['tips'][stage][k] for k in ('tip','height','anchor','work','issued','fees','notes','spent','spent_set_sha256'))
        monetary=check_money(doc,snapshots,blocks,reader,by_name,ids)
        signatures=reader.verify_independent(args.node)
        controls=reader.public_controls()
        if reader.legacy.sigs:
            import subprocess
            from swaps import MANAGED
            items=list(dict.fromkeys(reader.legacy.sigs))
            assert subprocess.check_output([args.node,MANAGED/'verify_slh.mjs'],input=b''.join(items))==b'1'*len(items)
        verdict=dict(network=NETWORK.hex(),genesis=final.ids[0].hex(),all_public_blocks=len(blocks),
                     branch_tip_count=len(tips),selected=selected_summary(final,reader),swap=group,economics=monetary,
                     released_verifier_key_and_local_binary_approvals=[pin_m,pin_s],published_x86_64_binaries_byte_identical=published_elf,public_receipt_and_ordinary_role_controls=controls,
                     independent_joint_signature_checks=signatures,historical_proofs=reader.legacy.counts,
                     independent_issuer_signatures=len(set(reader.legacy.sigs)),swap_leg_native_proofs=reader.proof_calls,
                     databases=[database(path,final,occurrences) for path in args.db])
        if args.observations:
            from observe_swap import reconcile
            verdict['observed_peers']=reconcile(args.observations,states,best)
        ordinary.close()
        swap.close()
        return verdict


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for field in ('public','deployment','helpers','node'):
        p.add_argument('--'+field,required=True,type=Path)
    p.add_argument('--db',action='append',type=Path,default=[])
    p.add_argument('--observations',type=Path)
    p.add_argument('--require-published-elf',action='store_true')
    print(json.dumps(audit(p.parse_args()),indent=2,sort_keys=True))
