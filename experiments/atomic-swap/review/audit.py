"""Reconstruct all SWP1 fork states from the public raw bytes and registered verifier roles."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from swaps import Reader, MANAGED, ZERO, ast1, hash_bytes, decode_pair
from chain_audit import Snapshot, advance_asset, compare_db, read_block
from events import Reader as HistoricalReader

SWAP_VK = "0527447637fa2f34d9585606501c4a55883c0ceaf58adb2d3e9834c66ab19837"
MANAGED_VK = "1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d"


def extend(parent,block,reader,roots):
    assert block.parent==parent.ids[-1] and block.height==len(parent.ids)
    swaps=reader.validate_block(block.slots,block.height)
    assert len(block.slots)<=4
    supply=parent.assets.copy()
    changes=list(parent.changes)
    spent=parent.spent.copy()
    locations=parent.locations.copy()
    outputs=list(parent.outs)
    commitments={row[0] for row in outputs}
    event_assets=set()
    for event in block.slots:
        assert 1<=block.height-event.born<=8 and parent.anchors[event.born]==event.anchor
        assert event.txid not in locations
        assert set(event.nullifiers).isdisjoint(spent) and set(event.commitments).isdisjoint(commitments)
        if event.op:
            assert event.asset not in event_assets
            event_assets.add(event.asset)
            record=advance_asset(supply.get(event.asset),event,block.height)
            supply[event.asset]=record
            changes.append(record.row(event.asset))
        locations[event.txid]=block.id
        spent.update((nf,block.height) for nf in event.nullifiers)
        commitments.update(event.commitments)
        outputs.extend((cm,block.height,event.receipts[i*1792:(i+1)*1792],None) for i,cm in enumerate(event.commitments))
    assert block.reward not in commitments
    outputs.append((block.reward,block.height,None,block.reward_record))
    fee=sum(event.fee for event in block.slots)
    assert fee==3*(len(block.slots)-swaps) and block.amount==100+fee
    fees=parent.fees+fee
    rewards=parent.rewards+block.amount
    assert rewards==100*block.height+fees
    assert len(outputs)==block.height+2*len(locations) and len(spent)==2*len(locations)
    state=ast1.counted_hash(b'dev-state',reader.network,parent.header[36:68],ast1.U64.pack(len(outputs)),
                            ast1.U64.pack(block.height*100),ast1.U64.pack(fees),block.reward_record,
                            b''.join(e.transition() for e in block.slots))
    assert state==block.state
    root=ast1.reference(roots,[str(len(outputs))],b''.join(row[0] for row in outputs))[0].split()[2]
    assert root==block.root.hex()
    header=parent.anchors[-1]+ast1.U32.pack(block.height)+state+ast1.counted_hash(b'dev-seal',reader.network,block.id)+block.root
    anchor=ast1.header_id(roots,header)
    return Snapshot(parent.ids+(block.id,),parent.anchors+(anchor,),header,tuple(outputs),spent,locations,supply,
                    tuple(changes),fees,rewards)


def read_graph(public,reader,helpers):
    net=reader.network
    gid=hash_bytes(b'AST1/PoW/genesis/v1\0'+net)
    header=bytes(36)+ast1.counted_hash(b'dev-genesis-state',net)+ast1.counted_hash(b'dev-genesis-body',net)+ZERO
    states={gid:Snapshot((gid,),(ast1.header_id(helpers/'roots',header),),header,(),{},{},{},(),0,0)}
    by_id={}
    for p in sorted((public/'blocks').glob('*.bin')):
        ident=bytes.fromhex(p.stem)
        assert p.stem==ident.hex() and ident not in by_id
        by_id[ident]=read_block(p.read_bytes(),ident,net,reader)
    assert by_id
    blocks=sorted(by_id.values(),key=lambda b:(b.height,b.id))
    for block in blocks:
        states[block.id]=extend(states[block.parent],block,reader,helpers/'roots')
    for start in range(0,len(blocks),128):
        batch=blocks[start:start+128]
        actual=ast1.reference(helpers/'rewards',[],b''.join(b.reward_record for b in batch))
        assert actual==[b.reward.hex() for b in batch]
    tips=set(by_id)-{b.parent for b in blocks}
    winner=min(tips,key=lambda k:(-by_id[k].height,k))
    return states,by_id,tips,winner


def group_rows(reader,blocks):
    rows={}
    for block in blocks.values():
        for i,e in enumerate(block.slots):
            f=reader.frames.get(e.txid)
            if f is not None and f.side==0:
                other=block.slots[i+1]
                g=next(k for k,v in reader.groups.items() if v['leg_txids']==[e.txid.hex(),other.txid.hex()])
                rows[g,block.id]=i
    return rows


def database(path,state,groups):
    checks=compare_db(path,state)
    db=sqlite3.connect(path.resolve(strict=True).as_uri()+'?mode=ro',uri=True)
    try:
        actual=db.execute("SELECT g.id,g.bid,g.idx FROM swap_archive g JOIN sel ON sel.id=g.bid").fetchall()
        assert sorted(actual)==sorted((g,bid,i) for (g,bid),i in groups.items() if bid in state.ids)
    finally:
        db.close()
    return checks | dict(selected_swaps=len(actual))


def mount(stack,dep,leaf,key_name,digest,fold=''):
    vk=(dep/(fold+'keys')/key_name).read_bytes()
    assert hash_bytes(vk).hex()==digest
    mount=Path(stack.enter_context(tempfile.TemporaryDirectory()))
    (mount/key_name).write_bytes(vk)
    binary=dep/(fold+'runtime')/'native'
    approved=(dep/'devnet'/('approved-'+fold+'native.sha256')).read_text().strip()
    assert hash_bytes(binary.read_bytes()).hex()==approved
    role=ast1.Role(binary,approved,['verify','/keys'],mount)
    stack.callback(role.abort)
    return role,dict(role=leaf,registered_vk=digest,approved_binary=approved)


def selected_summary(state,reader):
    summary=state.summary()
    # txloc indexes physical frames. The two frame identifiers name one exchange.
    physical=sum(t in reader.frames for t in state.locations)
    assert physical%2==0
    summary['physical_payments_and_legs']=summary.pop('payments')
    summary['atomic_swaps']=physical//2
    summary['logical_payments']=len(state.locations)-physical//2
    assert summary['logical_payments']*3==summary['fees']
    return summary


def audit(args):
    net=hash_bytes(b'AST1/PoW/network/v1\0'+bytes.fromhex(ast1.VK)+ast1.RULES)
    assert net.hex()=='7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac'
    with ExitStack() as stack:
        rmanaged,managed_pin=mount(stack,args.deployment,'MNG1','managed.vk',MANAGED_VK)
        rswap,swap_pin=mount(stack,args.deployment,'SLG1','swap.vk',SWAP_VK,'swap-')
        roles={'MNG1':rmanaged,'SLG1':rswap}
        pins=[managed_pin,swap_pin]
        ast=None
        if args.legacy:
            oldrole,pin=mount(stack,args.legacy,'AST1','asset.vk',ast1.VK)
            roles['AST1']=oldrole
            pins.append(pin)
            ast=ast1.Reader(oldrole,args.helpers/'roots',net)
        old=HistoricalReader(rmanaged,args.helpers/'roots',net,args.node,ast)
        reader=Reader(old,rswap)
        states,blocks,tips,winner=read_graph(args.public,reader,args.helpers)
        groups=group_rows(reader,blocks)
        sigs=reader.verify_independent(args.node)
        proof_controls=reader.public_controls()
        result=dict(network=net.hex(),genesis=states[winner].ids[0].hex(),blocks=len(blocks),
                    selected=selected_summary(states[winner],reader),tips=[selected_summary(states[k],reader) for k in sorted(tips)],
                    swap_groups=list(reader.groups.values()),signature_checks=sigs,proof_controls=proof_controls,legacy_calls=old.counts,
                    swap_leg_proof_checks=reader.proof_calls,registered=pins,
                    databases=[database(p,states[winner],groups) for p in args.db])
        from economics import economics
        result['economics']=economics(args.public,states,blocks,winner,reader,args.miner_keys)
        if args.observations:
            from observe_swap import reconcile
            result['public_peer_observations']=reconcile(args.observations,states,winner)
        if old.sigs:
            import subprocess
            messages=list(dict.fromkeys(old.sigs))
            verdicts=subprocess.check_output([args.node,MANAGED/'verify_slh.mjs'],input=b''.join(messages),timeout=60)
            assert verdicts==b'1'*len(messages)
            result['independent_issuer_signatures']=len(messages)
        result['role_meters']={n:r.close() for n,r in roles.items()}
        return result


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('public','deployment','helpers','node'):
        p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--miner-keys',type=Path,help='public reward key map for a pre-schema capture')
    p.add_argument('--observations',type=Path)
    p.add_argument('--legacy',type=Path,help='AST1 approved installation for histories with original direct packets')
    p.add_argument('--db',type=Path,action='append',default=[])
    print(json.dumps(audit(p.parse_args()),indent=2,sort_keys=True))
