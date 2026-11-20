"""Check restored wallet origins and subsequent spend nullifiers in a private disposable home."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from swaps import ZERO, hash_bytes


def dbread(path):
    return closing(sqlite3.connect(path.resolve(strict=True).as_uri()+'?mode=ro',uri=True))


def block_packets(raw):
    cursor=214
    for _ in range(raw[213]):
        n,=struct.unpack_from('<I',raw,cursor)
        cursor+=4
        yield raw[cursor:cursor+n]
        cursor+=n
    assert cursor==len(raw)-8


def effects(raw):
    if raw[:5]==b'SWF1\x01':
        inner=raw[17195:]
        count=34
    elif raw[:5]==b'MSP1\x01':
        inner=raw[17166:] if raw[5] in (2,3) else raw[6:]
        count=31
    else:
        assert raw[:5]==b'AST1\x01'
        inner=raw
        count=31
    end=9+int.from_bytes(inner[5:9],'little')
    assert end+3584==len(inner)
    declared,=struct.unpack_from('<Q',inner,end-(count+1)*8)
    assert declared==count
    pi=inner[end-count*8:end]
    return (pi[40:72],pi[72:104]),(pi[104:136],pi[136:168])


def check(home,summary):
    report=json.loads(summary.read_bytes())
    winner=report['selected']
    root=home/'public/blocks'
    tip=winner['tip']
    packets={}
    while tip!=report['genesis']:
        raw=(root/(tip+'.bin')).read_bytes()
        for p in block_packets(raw):
            pid=hash_bytes(p)
            assert pid not in packets
            packets[pid]=p
        tip=raw[41:73].hex()
    groups=[row for row in report['swap_groups'] if all(bytes.fromhex(tx) in packets for tx in row['leg_txids'])]
    assert len(groups)==1
    swap=groups[0]
    registry={r['mode']:bytes.fromhex(x) for x,r in winner['registry'].items()}
    assert set(registry)=={'fixed','managed'}
    paths=sorted((home/'wallets').glob('*/mng1-wallet-state.sqlite'))
    assert paths
    detail=[]
    for side,(sent,taken,supply,quantity,change,change_native) in enumerate([
            ('fixed','managed',7,30,8,17),('managed','fixed',30,7,50,18)]):
        outgoing,incoming=(bytes.fromhex(swap['leg_txids'][direction]) for direction in (side,1-side))
        receive_cm=effects(packets[incoming])[1][0]
        change_cm=effects(packets[outgoing])[1][1]
        input_nfs=effects(packets[outgoing])[0]
        found=set()
        for path in paths:
            with dbread(path) as c:
                hit=c.execute("SELECT nf,amount,asset,token,kind,creator,spender FROM owned WHERE cm=?",(receive_cm,)).fetchone()
                if hit is None or hit[-1] is None:
                    continue
                nf,n,aid,t,kind,creator,after=hit
                if after not in packets:
                    continue
                assert (n,aid,t,kind,creator)==(0,registry[taken],quantity,'incoming',incoming)
                after_wire=packets[after]
                assert after_wire[:6]==b'MSP1\x01\x00'
                public_spends=effects(after_wire)[0]
                assert nf in public_spends
                inputs=c.execute("SELECT nf,asset,token,amount FROM owned WHERE spender=?",(after,)).fetchall()
                assert len(inputs)==2 and {i[0] for i in inputs}==set(public_spends)
                native_only,=[i for i in inputs if i[0]!=nf]
                assert native_only[1:3]==(ZERO,0) and native_only[3]>=3
                outgoing_inputs=c.execute("SELECT nf,asset,token,amount FROM owned WHERE spender=?",(outgoing,)).fetchall()
                assert outgoing_inputs and all(i[0] in input_nfs for i in outgoing_inputs)
                assert sum(i[2] for i in outgoing_inputs)==change+supply
                assert sum(i[3] for i in outgoing_inputs)==change_native+(3 if side==0 else 0)
                assert all(i[1]==registry[sent] for i in outgoing_inputs if i[2])
                out=c.execute("SELECT amount,asset,token,kind,creator FROM owned WHERE cm=?",(change_cm,)).fetchone()
                assert out==(change_native,registry[sent],change,'change',outgoing)
                owner,=c.execute("SELECT owner FROM identity").fetchone()
                found.add(owner)
        assert len(found)==1
        detail.append((next(iter(found)),dict(gave_asset_mode=sent,received_asset_mode=taken,gave_tokens=supply,
                     received_and_respent_tokens=quantity,native_change=change_native,token_change=change,
                     received_native=0,ordinary_inputs=2,ordinary_native_only_fee_inputs=1)))
    assert detail[0][0]!=detail[1][0]
    return dict(two_distinct_restored_wallet_owners=True,winning_bundle=swap['id'],
                exact_external_swap_outputs_consumed=2,exact_own_change_outputs_matched=2,
                wallets=[case for _,case in detail])


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('home',type=Path)
    p.add_argument('audit',type=Path)
    args=p.parse_args()
    print(json.dumps(check(args.home,args.audit),indent=2,sort_keys=True))
