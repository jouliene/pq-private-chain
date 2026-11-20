"""Rebuild the public funding prefix and old swap extension; optionally reopen the actual notes from test seeds."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile

HERE=Path(__file__).resolve().parent
EXPERIMENTS=HERE.parents[1]
sys.path.insert(0,str(EXPERIMENTS/'atomic-swap/review'))
from audit import HistoricalReader, MANAGED_VK, Reader, SWAP_VK, mount, read_graph
from swaps import decode_pair
sys.path.insert(0,str(HERE))
from public import split as split_funded

NET=bytes.fromhex('7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac')
GEN=sha256(b'AST1/PoW/genesis/v1\0'+NET).digest()
ZERO=bytes(32)


def block_hash(raw):
    return sha256(b'PQDEV1/work\0'+sha256(b'PQDEV1/template\0'+raw[:-8]).digest()+raw[-8:]).digest()


def check(events,blocks,deployment,helpers,node,home=None,write_prefix=None):
    ext=(events/'released-swap.block').read_bytes();bid=block_hash(ext)
    _,candidate_legs,_=split_funded((events/'candidate.swap').read_bytes(),True)
    parent=bytes(ext[41:73])
    if write_prefix:
        write_prefix.mkdir(parents=True,exist_ok=False)
    with ExitStack() as stack:
        scratch=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        (scratch/'blocks').mkdir()
        (scratch/'blocks'/(bid.hex()+'.bin')).write_bytes(ext)
        cur=parent;anc=[]
        while cur!=GEN:
            raw=(blocks/(cur.hex()+'.bin')).read_bytes()
            assert block_hash(raw)==cur and cur not in anc
            anc.append(cur)
            (scratch/'blocks'/(cur.hex()+'.bin')).write_bytes(raw)
            if write_prefix:
                (write_prefix/(cur.hex()+'.bin')).write_bytes(raw)
            cur=raw[41:73]
        m,mp=mount(stack,deployment,'MNG1','managed.vk',MANAGED_VK)
        s,sp=mount(stack,deployment,'SLG1','swap.vk',SWAP_VK,'swap-')
        legacy=HistoricalReader(m,helpers/'roots',NET,node)
        reader=Reader(legacy,s)
        states,decoded,tips,winner=read_graph(scratch,reader,helpers)
        assert tips=={bid} and bid==winner
        common=states[parent];settled=states[bid]
        old_bundle=(events/'released.swap').read_bytes()
        frames=decode_pair(old_bundle)
        fx=decoded[bid].slots
        assert [x.txid for x in fx]==[sha256(f).digest() for f in frames]
        assert settled.fees==common.fees+3 and decoded[bid].amount==103
        ordinary=legacy.packet(b'MSP1\1\0'+(events/'ordinary.released').read_bytes())
        onward=legacy.packet((events/'restored-onward.transfer').read_bytes())
        for event,snapshot in ((ordinary,common),(onward,settled)):
            assert event.op==0 and event.fee==3 and event.delta==0 and event.asset==ZERO
            assert event.anchor==snapshot.anchors[event.born] and set(event.nullifiers).isdisjoint(snapshot.spent)
        assert onward.born==len(settled.ids)-1
        assert not any(x in settled.locations for x in (onward.txid,ordinary.txid))
        results=dict(ancestor_blocks_from_genesis=len(anc),inherited_anchor=common.anchors[-1].hex(),
                     common_tip=parent.hex(),independently_verified_release_extension=bid.hex(),
                     selected_released_swap_inclusion_height=len(settled.ids)-1,
                     managed_funded_supplies=common.supply(),swap_fee_and_credit=[3,103],
                     independently_verified_native_spend_from_swap_anchor=onward.txid.hex(),
                     onward_recorded_as='verified and admitted to old mempool by fixture',
                     settled_extension_publicly_verified=True)
        if home:
            spec=importlib.util.spec_from_file_location('reproduction_seed_actor',EXPERIMENTS/'stranger-swap/review/wallet.py')
            wallet=importlib.util.module_from_spec(spec);spec.loader.exec_module(wallet)
            owners=[]
            for who in ('miner-a','alice','bob'):
                seed=home/'wallets'/who/'seed' if who=='miner-a' else home/'owner-backups'/who/'seed'
                role,_=wallet.restore_role(stack,seed,deployment)
                owners.append(role)
            legs=candidate_legs
            opened_inputs=[]
            for role,event in zip(owners,(ordinary,*fx),strict=True):
                found=[]
                for cm,_,ct,reward in common.outs:
                    origin=cm+ct if ct else reward[:72]+bytes(8)+reward[72:]
                    op=role.call(b'D'+origin)
                    if op[:3]==b'HIT' and op[3:35] in event.nullifiers:
                        assert len(op)==84
                        native,token,asset=struct.unpack_from('<QQ32s',op,35)
                        assert native+token>0
                        found.append(dict(native=native,token=token,asset='native' if asset==ZERO else 'managed'))
                        assert asset==ZERO or common.supply()[asset.hex()]['mode']=='managed'
                opened_inputs.append(found)
            assert [len(v) for v in opened_inputs]==[2,1,1]
            assert opened_inputs[1]==[dict(native=0,token=100,asset='managed')]
            assert opened_inputs[2]==[dict(native=25,token=0,asset='native')]
            seller,buyer=owners[1:];seen=[]
            for side,(event,leg) in enumerate(zip(fx,legs,strict=True)):
                assert event.receipts==leg[-3584:]
                for j in (0,1):
                    origin=event.commitments[j]+event.receipts[j*1792:(j+1)*1792]
                    receiving=buyer if (side==0)==(j==0) else seller
                    wrong=seller if receiving is buyer else buyer
                    op=receiving.call(b'D'+origin)
                    assert len(op)==84 and op[:3]==b'HIT' and wrong.call(b'D'+origin)==b'MISS'
                    native,token,asset=struct.unpack_from('<QQ32s',op,35)
                    assert (asset.hex() in common.supply()) if token else (asset==ZERO)
                    if side==1 and j==0:
                        assert op[3:35] in onward.nullifiers
                    seen.append((native,token))
            assert seen==[(0,20),(0,80),(8,0),(14,0)]
            live_matches=[]
            for cm,_,ct,reward in settled.outs:
                origin=cm+ct if ct else reward[:72]+bytes(8)+reward[72:]
                op=seller.call(b'D'+origin)
                if op[:3]==b'HIT' and op[3:35] in onward.nullifiers and op[3:35] not in settled.spent:
                    live_matches.append((cm,*struct.unpack_from('<QQ32s',op,35)))
            assert live_matches==[(fx[1].commitments[0],8,0,ZERO)]
            payouts=[];changes=[]
            for j,cm in enumerate(onward.commitments):
                origin=cm+onward.receipts[j*1792:(j+1)*1792]
                op=buyer.call(b'D'+origin)
                if op[:3]==b'HIT':
                    native,token,asset=struct.unpack_from('<QQ32s',op,35)
                    assert (native,token,asset)==(5,0,ZERO)
                    payouts.append(j)
                own=seller.call(b'D'+origin)
                if own[:3]==b'HIT':
                    assert struct.unpack_from('<QQ32s',own,35)==(0,0,ZERO)
                    changes.append(j)
            assert len(payouts)==len(changes)==1 and payouts!=changes
            results.update(real_funded_source_counts=[len(v) for v in opened_inputs],funded_private_checks=opened_inputs,
                           exact_swap_outputs_native_and_token=seen,restored_source8_matched_onward_public_nullifier=True,
                           actual_beneficiary_opened5=True,exact_live_recovered_funded_source_count=len(live_matches),
                           restored_change_native_and_token=[0,0],ordinary_fee=onward.fee)
            for role in owners:
                role.close()
        m.close();s.close()
        return results


if __name__=='__main__':
    if not __debug__:raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('events','blocks','deployment','helpers','node'):
        p.add_argument(k,type=Path)
    p.add_argument('--private-home',type=Path);p.add_argument('--write-prefix',type=Path)
    a=p.parse_args();print(json.dumps(check(a.events,a.blocks,a.deployment,a.helpers,a.node,a.private_home,a.write_prefix),
                                     sort_keys=True,indent=2))
