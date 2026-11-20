"""Independent complete MNG1 proof, PoW, asset-event and selected-database replay."""
import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from events import Reader, BURN, MAX, ZERO, ast1


@dataclass(frozen=True)
class Registration:
    mode: str
    authority: bytes
    supply: int
    height: int
    tx: bytes
    revision: int

    def row(self, asset):
        return (asset,self.revision,self.mode,self.authority,self.supply,self.height,self.tx)

    def public(self, asset):
        return dict(id=asset.hex(),mode=self.mode,authority=self.authority.hex(),supply=self.supply,
                    height=self.height,tx=self.tx.hex(),sequence=self.revision)


def advance_asset(prior,e,height):
    if e.op in (1,2):
        assert prior is None and e.sequence==0 and e.prior==ZERO
        return Registration('fixed' if e.op==1 else 'managed',e.issuer,e.delta,height,e.txid,1)
    assert prior and prior.mode=='managed'
    if e.op==3:
        assert (e.issuer,e.sequence,e.prior)==(prior.authority,prior.revision,prior.tx)
        supply = prior.supply+e.delta
    else:
        assert e.op==4
        supply = prior.supply-(e.delta-BURN)
    assert 0<=supply<=MAX
    return Registration(prior.mode,prior.authority,supply,height,e.txid,prior.revision+1)


@dataclass
class Snapshot:
    ids: tuple
    anchors: tuple
    header: bytes
    outs: tuple
    spent: dict
    locations: dict
    assets: dict
    changes: tuple
    fees: int
    rewards: int

    def supply(self):
        return {key.hex():v.public(key) for key,v in sorted(self.assets.items())}

    def summary(self):
        height = len(self.ids)-1
        return dict(tip=self.ids[-1].hex(),height=height,work=height*(1<<22),anchor=self.anchors[-1].hex(),
                    funded_root=self.header[-32:].hex(),issued=100*height,fees=self.fees,miner_credits=self.rewards,
                    notes=len(self.outs),spent=len(self.spent),spent_set_sha256=ast1.sha(b''.join(sorted(self.spent))).hex(),
                    payments=len(self.locations),total_supply_events=len(self.changes),registry=self.supply())


def read_block(raw,bid,network,reader):
    assert 222<=len(raw)<=222+4*(262144+4)
    assert raw[:41]==b'ASTPOW01'+network+bytes([22])
    assert ast1.sha(b'PQDEV1/work\0'+ast1.sha(b'PQDEV1/template\0'+raw[:-8])+raw[-8:])==bid
    assert int.from_bytes(bid,'big')<1<<234
    parent, h, miner = raw[41:73],ast1.U32.unpack_from(raw,73)[0],raw[77:109]
    reward,state,root = (raw[i:i+32] for i in (117,149,181))
    assert all(ast1.field(x) for x in (miner,reward,state,root)) and ZERO not in (miner,reward)
    amount = ast1.U64.unpack_from(raw,109)[0]
    end,ptr,count,slots = len(raw)-8,214,raw[213],[]
    assert count<=4
    for _ in range(count):
        assert ptr+4<=end
        length=ast1.U32.unpack_from(raw,ptr)[0]
        ptr+=4
        assert 0<length<=min(262144,end-ptr)
        slots.append(reader.packet(raw[ptr:ptr+length]))
        ptr+=length
    assert ptr==end and amount==100+sum(e.fee for e in slots)
    context=ast1.sha(b'PQDEV1/reward-context\0'+network+parent+ast1.U32.pack(h)+miner+ast1.sha(raw[213:end]))
    return ast1.Block(bid,parent,h,miner,amount,reward,state,root,context,tuple(slots))


def append(parent,b,network,roots):
    assert b.parent==parent.ids[-1] and b.height==len(parent.ids)
    outs,spent,loc = list(parent.outs),parent.spent.copy(),parent.locations.copy()
    assets,changes = parent.assets.copy(),list(parent.changes)
    cms = {r[0] for r in outs}
    active = set()
    for e in b.slots:
        assert 1<=b.height-e.born<=8 and parent.anchors[e.born]==e.anchor
        assert e.txid not in loc and set(e.nullifiers).isdisjoint(spent) and set(e.commitments).isdisjoint(cms)
        if e.op:
            assert e.asset not in active
            active.add(e.asset)
            record = advance_asset(assets.get(e.asset),e,b.height)
            assets[e.asset]=record
            changes.append(record.row(e.asset))
        loc[e.txid]=b.id
        spent.update((nf,b.height) for nf in e.nullifiers)
        cms.update(e.commitments)
        outs.extend((cm,b.height,e.receipts[i*1792:(i+1)*1792],None) for i,cm in enumerate(e.commitments))
    assert b.reward not in cms
    outs.append((b.reward,b.height,None,b.reward_record))
    fees=parent.fees+sum(e.fee for e in b.slots)
    rewards=parent.rewards+b.amount
    assert rewards==100*b.height+fees and fees==3*len(loc) and len(outs)==b.height+2*len(loc) and len(spent)==2*len(loc)
    state=ast1.counted_hash(b'dev-state',network,parent.header[36:68],ast1.U64.pack(len(outs)),ast1.U64.pack(b.height*100),
                            ast1.U64.pack(fees),b.reward_record,b''.join(e.transition() for e in b.slots))
    assert state==b.state
    leaves=b''.join(r[0] for r in outs)
    assert ast1.reference(roots,[str(len(outs))],leaves)[0].split()[2]==b.root.hex()
    header=parent.anchors[-1]+ast1.U32.pack(b.height)+state+ast1.counted_hash(b'dev-seal',network,b.id)+b.root
    return Snapshot(parent.ids+(b.id,),parent.anchors+(ast1.header_id(roots,header),),header,tuple(outs),spent,
                    loc,assets,tuple(changes),fees,rewards)


def compare_db(path,state):
    db=sqlite3.connect(path.resolve(strict=True).as_uri()+'?mode=ro',uri=True)
    try:
        assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
        assert db.execute('SELECT h,id FROM sel ORDER BY h').fetchall()==list(enumerate(state.ids))
        assert db.execute('SELECT pos,cm,h,ct,reward FROM outs ORDER BY pos').fetchall()==[(i,*r) for i,r in enumerate(state.outs)]
        assert dict(db.execute('SELECT nf,h FROM spent'))==state.spent
        loc = db.execute('SELECT tx,bid FROM txloc JOIN sel ON bid=id').fetchall()
        assert len(loc)==len(state.locations) and dict(loc)==state.locations
        assert db.execute('SELECT id,sequence,mode,authority,supply,h,tx FROM assets ORDER BY id,sequence').fetchall()==sorted(state.changes)
        assert db.execute('SELECT ap,header,n,fees FROM blocks WHERE id=?',(state.ids[-1],)).fetchone()==(
            state.anchors[-1],state.header,len(state.outs),state.fees)
    finally:
        db.close()
    return dict(height=len(state.ids)-1,outputs=len(state.outs),payments=len(state.locations),supply_events=len(state.changes))


def audit(public,reader,helpers):
    net=reader.network
    gid=ast1.sha(b'AST1/PoW/genesis/v1\0'+net)
    header=bytes(36)+ast1.counted_hash(b'dev-genesis-state',net)+ast1.counted_hash(b'dev-genesis-body',net)+ZERO
    states={gid:Snapshot((gid,),(ast1.header_id(helpers/'roots',header),),header,(),{},{},{},(),0,0)}
    blocks={}
    for file in sorted((public/'blocks').glob('*.bin')):
        bid=bytes.fromhex(file.stem)
        assert file.stem==bid.hex() and bid not in blocks
        blocks[bid]=read_block(file.read_bytes(),bid,net,reader)
    assert blocks
    for bid,b in sorted(blocks.items(),key=lambda t:(t[1].height,t[0])):
        states[bid]=append(states[b.parent],b,net,helpers/'roots')
    ordered=list(blocks.values())
    for start in range(0,len(ordered),128):
        sub=ordered[start:start+128]
        assert ast1.reference(helpers/'rewards',[],b''.join(b.reward_record for b in sub))==[b.reward.hex() for b in sub]
    included=set(reader.events)
    wire={}
    for file in sorted((public/'packets').glob('*.bin')):
        raw=file.read_bytes()
        e=reader.packet(raw)
        assert file.stem==e.txid.hex()
        wire[e.txid]=dict(tx=file.stem,operation=e.op,outer_B=len(raw),inner_B=len(raw)-(0 if e.legacy else 6)-(17160 if e.op in (2,3) else 0),
                          legacy=e.legacy,fee=e.fee,delta=(e.delta if e.op!=4 else BURN-e.delta),public_asset=e.asset.hex())
    assert included<=wire.keys()
    terminals=set(blocks)-{b.parent for b in blocks.values()}
    winner=min(terminals,key=lambda bid:(-blocks[bid].height,bid))
    report=dict(network=net.hex(),genesis=gid.hex(),blocks=len(blocks),packets=list(wire.values()),native_calls=reader.counts,
                selected=states[winner].summary(),tips=[states[k].summary() for k in sorted(terminals)],
                signed_wire_count_before_controls=reader.counts['signature'])
    return report,states,blocks,winner


def controls(public,reader,states,run):
    result={}
    for name,reason in [('duplicate-mint','stale issuer state'),('unregistered-authority','wrong issuer authority'),
                        ('mint-fixed','immutable fixed supply'),('duplicate-burn','spent nullifier')]:
        record=run['controls'][name]
        path=public/'controls'/(name+'.bin')
        raw=path.read_bytes()
        assert record['unchanged'] and record['reason']==reason and ast1.sha(raw).hex()==record['packet_sha256']
        e=reader.packet(raw)
        base='loser' if name=='duplicate-burn' else 'common'
        state=states[bytes.fromhex(run['tips'][base]['tip'])]
        reg=state.assets[e.asset]
        if name=='duplicate-mint':
            assert e.op==3 and e.txid in state.locations and (e.sequence,e.prior)!=(reg.revision,reg.tx)
        elif name=='unregistered-authority':
            assert e.op==3 and reg.mode=='managed' and e.issuer!=reg.authority
        elif name=='mint-fixed':
            assert e.op==3 and reg.mode=='fixed'
        else:
            assert e.op==4 and e.txid in state.locations and set(e.nullifiers)<=state.spent.keys()
        result[name]=dict(tx=e.txid.hex(),checked_branch=base,independent_reason=reason,positive_inner_proof=True,
                          public_signature_checked=e.op in (2,3))
    return result


def main():
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('public','binary','vk','helpers','node'):
        p.add_argument('--'+name,required=True,type=lambda s:Path(s).resolve(strict=True))
    p.add_argument('--approve-binary',required=True)
    p.add_argument('--approve-vk',required=True)
    p.add_argument('--legacy-binary',type=lambda s:Path(s).resolve(strict=True))
    p.add_argument('--legacy-vk',type=lambda s:Path(s).resolve(strict=True))
    p.add_argument('--approve-legacy-binary')
    p.add_argument('--db',action='append',default=[],type=Path)
    p.add_argument('--observations',type=Path)
    a=p.parse_args()
    vk=a.vk.read_bytes()
    assert ast1.sha(vk).hex()==a.approve_vk=='1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d'
    network=ast1.sha(b'AST1/PoW/network/v1\0'+bytes.fromhex(ast1.VK)+ast1.RULES)
    assert network.hex()=='7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac'
    run=json.loads((a.public/'RUN.json').read_bytes())
    with ExitStack() as stack:
        mounted=stack.enter_context(tempfile.TemporaryDirectory())
        legacy=None
        if any((a.legacy_binary,a.legacy_vk,a.approve_legacy_binary)):
            assert all((a.legacy_binary,a.legacy_vk,a.approve_legacy_binary))
            old_key=a.legacy_vk.read_bytes()
            assert ast1.sha(old_key).hex()==ast1.VK
            key_dir=stack.enter_context(tempfile.TemporaryDirectory())
            (Path(key_dir)/'asset.vk').write_bytes(old_key)
            oldrole=ast1.Role(a.legacy_binary,a.approve_legacy_binary,['verify','/keys'],key_dir)
            stack.callback(oldrole.abort)
            legacy=ast1.Reader(oldrole,a.helpers/'roots',network)
        (Path(mounted)/'managed.vk').write_bytes(vk)
        role=ast1.Role(a.binary,a.approve_binary,['verify','/keys'],mounted)
        try:
            reader=Reader(role,a.helpers/'roots',network,a.node,legacy)
            report,states,blocks,winner=audit(a.public,reader,a.helpers)
            report['policy_controls']=controls(a.public,reader,states,run)
            report['signature_checks']=reader.verify_sigs()
            report['native_meters']=role.close()
            if legacy:
                report['legacy_meters']=legacy.role.close()
        finally:
            role.abort()
    from monetary import reconcile
    from payout import check as check_payout
    report['monetary']=reconcile(run,reader,states,blocks,winner,observations=a.observations)
    report['redemption']=check_payout(run,states,reader,a.observations)
    report['binary_sha256']=a.approve_binary
    report['vk_sha256']=a.approve_vk
    report['databases']=[compare_db(f,states[winner]) for f in a.db]
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__=='__main__':
    main()
