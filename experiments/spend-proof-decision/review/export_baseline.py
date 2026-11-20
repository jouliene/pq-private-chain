"""Export two complete public payloads and participant-disclosed timing aggregates from a fresh SWP1 run."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys


def capture(home,out):
    out.mkdir(mode=0o700,exist_ok=False)
    public=home/'public'
    run=json.loads((public/'RUN.json').read_bytes())
    selected=run['ordinary']['respend-a']
    tx=selected['tx']
    assert selected['operation']=='transfer' and selected['fee']==3 and selected['real_inputs']==2
    ordinary=(public/'packets'/(tx+'.bin')).read_bytes()
    assert ordinary[:6]==b'MSP1\x01\x00' and sha256(ordinary).hexdigest()==tx and len(ordinary)==selected['packet_B']
    with sqlite3.connect((home/'wallets/alice-restored/mng1-intents.sqlite').resolve(strict=True).as_uri()+'?mode=ro',uri=True) as db:
        row,=db.execute('SELECT accounting,prove_s FROM attempts WHERE tx=? AND intent=?',(tx,'respend-a')).fetchall()
    own=json.loads(row[0])
    assert own['token_amount']==30 and own['real_inputs']==2 and own['fee']==3 and not own['issue_supply']
    assert own['token_input_total']==own['token_amount']+own['token_change']
    assert own['input_total']==own['amount']+own['fee']+own['change']
    swap=(public/'SWAP.bin').read_bytes()
    assert sha256(swap).hexdigest()==run['swap']['bundle_sha256'] and len(swap)==run['swap']['packet_B']
    fields=('fee','real_inputs','prover_cpu_s','prover_role_peak_rss_KiB')
    wallet=dict(ordinary=dict(proving_wall_s=row[1],**{k:own[k] for k in fields}),
                swap=[{k:run['swap'][name][k] for k in ('proving_wall_s',*fields)} for name in ('wallet_A','wallet_B')])
    assert all(item['prover_cpu_s']>0 and item['prover_role_peak_rss_KiB']>0 and item['proving_wall_s']>0
               for item in (wallet['ordinary'],*wallet['swap']))
    selected_tip=run['tips']['final']
    head=selected_tip['tip']
    included={}
    ids=[tx,*run['swap']['frame_ids']]
    while head!=run['genesis']:
        raw=(public/'blocks'/(head+'.bin')).read_bytes()
        h=int.from_bytes(raw[73:77],'little')
        pos=214
        for idx in range(raw[213]):
            n=int.from_bytes(raw[pos:pos+4],'little')
            payload=raw[pos+4:pos+4+n]
            pos+=4+n
            key=sha256(payload).hexdigest()
            if key in ids:
                assert key not in included
                included[key]=dict(height=h,block=head,index=idx)
        assert pos==len(raw)-8
        head=raw[41:73].hex()
    assert set(included)==set(ids)
    a,b=(included[x] for x in ids[1:])
    assert a['height']==b['height']==run['moving']['inclusion_height'] and a['index']+1==b['index']
    assert included[tx]['height']>a['height']
    info=dict(baseline='3f08bff0089096d7fb27279bc0d444006e9147ce',network=run['network'],
              run_sha256=sha256((public/'RUN.json').read_bytes()).hexdigest(),wallet=wallet,
              final_selected_tip=selected_tip['tip'],final_selected_height=selected_tip['height'],
              final_fees=selected_tip['fees'],genesis=run['genesis'],included=included,
              ordinary_tx=tx,swap_bundle=run['swap']['bundle_sha256'],swap_frame_ids=ids[1:],swap_height=a['height'])
    (out/'ordinary.bin').write_bytes(ordinary)
    (out/'swap.bin').write_bytes(swap)
    (out/'funded-receipt.json').write_text(json.dumps(info,sort_keys=True,indent=2)+'\n')
    return info


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('home',type=Path);p.add_argument('new_public',type=Path)
    a=p.parse_args();print(json.dumps(capture(a.home,a.new_public),sort_keys=True))
