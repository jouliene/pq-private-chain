"""Mine the source branch with the original public C implementation and new wallet keys."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "partial-fills"))
from prepare import HISTORIC_TIP, agree, cli, load_lab, need


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def capture(lab, node, fixture, start=1):
    status = lab.status(node)
    ids = lab.request(node, 'selected', start=start, limit=128)[0]
    need(len(ids) == status['height']-start+1, "incomplete selected range")
    for ident in ids:
        target = fixture/'blocks'/(ident+'.bin')
        if not target.is_file():
            raw = lab.request(node, 'block', id=ident)[1]
            from chain import block_id
            need(block_id(raw).hex()==ident, "wrong original body")
            target.write_bytes(raw)
    return ids


def copy_database(source, destination):
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro', uri=True)) as original:
        with closing(sqlite3.connect(destination)) as frozen:
            original.backup(frozen)


def prepare(out):
    home, fixture = out/'source', out/'fixture'
    (fixture/'blocks').mkdir(parents=True)
    (fixture/'records').mkdir()
    lab = load_lab(home)
    from chain import GENESIS, block_id, decode_block
    try:
        lab.start(manual=True)
        parent = bytes.fromhex(HISTORIC_TIP)
        prefix = []
        while parent != GENESIS:
            raw = (out/'history/public/blocks'/(parent.hex()+'.bin')).read_bytes()
            need(block_id(raw)==parent,"public prefix")
            prefix.append(raw)
            parent = decode_block(raw).parent
        for raw in reversed(prefix):
            lab.request('a','publish',raw)
        agree(lab,HISTORIC_TIP)
        # These wallets are never scanned in the funding process. Only an exported public
        # address is given to the paying wallet. Fresh recovery roles mount just their own seed.
        for owner in ('offline','payee'):
            lab.new_wallet(owner)
            lab.backup(owner, out/(owner+'.backup'))
            lab.export_address(owner, out/(owner+'.addr'))
        mined = lab.mine('a',2,pay_to='miner-a')
        agree(lab,mined['tip'])
        sent = cli(home,'a','send','miner-a','@'+str(out/'offline.addr'),17,'native',0,'--intent','fund-before-snapshot')
        funding = lab.mine('a',1,pay_to='miner-a')
        agree(lab,funding['tip'])
        frame = decode_block(lab.request('a','block',id=funding['tip'])[1]).packets
        need(len(frame)==1 and frame[0].startswith(b'MSP3') and hashlib.sha256(frame[0]).hexdigest()==sent['tx'],
             'original funded C receipt')
        for node, peers in (('c',[]),('a',['b']),('b',['a'])):
            lab.links(node,peers)
        base = lab.mine('a',1,pay_to='miner-a')
        agree(lab,base['tip'],nodes='ab')
        # Two separate live databases reached this selected base by ordinary peer admission.
        for node in 'ab':
            copy_database(home/'nodes'/node/'chain.sqlite',out/(node+'-base.sqlite'))
        suffix = lab.mine('a',1,pay_to='miner-a')
        agree(lab,suffix['tip'],nodes='ab')
        main = capture(lab,'a',fixture)
        case = dict(genesis=GENESIS.hex(), prefix=HISTORIC_TIP, funding=sent['tx'], funding_block=funding['tip'],
                    fork_height=funding['height'], base=base['tip'], base_height=base['height'],
                    usable=suffix['tip'], first_main=main)
        need(lab.status('c')['tip']==funding['tip'], 'isolated fork parent')
        save(fixture/'case.json',case)
        print(json.dumps({k:case[k] for k in ('base','base_height','funding_block','usable')}),flush=True)
    finally:
        lab.stop()


if __name__=='__main__':
    os.umask(0o077)
    prepare(Path(sys.argv[1]).resolve())
