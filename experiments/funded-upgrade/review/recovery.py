"""Check the original backup against both native wallet roles; export only aggregate fixture facts."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

from_public_path = Path(__file__).resolve().parent
sys.path.insert(0, str(from_public_path))
from public import PINS, ast1, hash_bytes
from wallet_joins import dbread, block_packets


def effects(packet):
    if packet[:5] in (b'SWF1\x01', b'SWF2\x01'):
        inner, count = packet[17195:], 34
    elif packet[:5] in (b'MSP1\x01', b'MSP2\x01'):
        inner, count = packet[17166:] if packet[5] in (2,3) else packet[6:], 31
    else:
        assert packet[:5] == b'AST1\x01'
        inner, count = packet, 31
    end = 9 + int.from_bytes(inner[5:9], 'little')
    assert end + 3584 == len(inner)
    assert struct.unpack_from('<Q', inner, end - (count+1)*8)[0] == count
    pi = inner[end-8*count:end]
    return (pi[40:72],pi[72:104]), ((pi[104:136],inner[end:end+1792]), (pi[136:168],inner[end+1792:]))


def winner(public, tip):
    path = []
    while (public/'blocks'/(tip+'.bin')).is_file():
        block = (public/'blocks'/(tip+'.bin')).read_bytes()
        assert hash_bytes(b'PQDEV1/work\0'+hash_bytes(b'PQDEV1/template\0'+block[:-8])+block[-8:]).hex() == tip
        path.append((int.from_bytes(block[73:77], 'little'), block[77:109], tuple(block_packets(block))))
        tip = block[41:73].hex()
    return path[::-1]


def restore(home, actor, suite, blocks, before):
    backup = home/'owner-backups'/actor
    assert not backup.is_symlink() and backup.stat().st_size == 32 and not backup.stat().st_mode & 0o077
    name, vk_pin, prefix = PINS[suite]
    deployment = home/'deployment'
    keys = deployment/(prefix+'keys')
    assert hash_bytes((keys/name).read_bytes()).hex() == vk_pin
    binary = deployment/(prefix+'runtime')/'native'
    approved = (deployment/'devnet'/('approved-'+prefix+'native.sha256')).read_text().strip()
    assert hash_bytes(binary.read_bytes()).hex() == approved
    with tempfile.TemporaryDirectory() as empty:
        private = Path(empty)
        shutil.copyfile(backup, private/'seed')
        (private/'seed').chmod(0o600)
        role = ast1.Role(binary, approved, ['wallet','/keys','/private/seed','restore'], keys, private=private)
        try:
            addr = role.get()
            assert len(addr) == 1601
            found = []
            for height, miner, packets in blocks:
                if height >= before:
                    break
                # A reward is public and recoverable by its owner key. Neither fixture recipient is a miner.
                assert addr[1:33] != miner
                for packet in packets:
                    for cm, ciphertext in effects(packet)[1]:
                        row = role.call(b'D'+cm+ciphertext)
                        if row == b'MISS':
                            continue
                        assert len(row) == 84 and row[:3] == b'HIT'
                        n, t, aid, kind = struct.unpack('<QQ32sB', row[35:])
                        if n or t:
                            found.append((cm,row[3:35],n,t,aid,kind,hash_bytes(packet)))
            role.close()
            return found
        finally:
            role.abort()


def inspect(home):
    public = home/'public'
    run = json.loads((public/'RUN.json').read_bytes())
    chain = winner(public, run['tips']['final']['tip'])
    assert [h for h,_,_ in chain] == list(range(1,len(chain)+1))
    asset = bytes.fromhex(run['asset_ids']['managed'])
    def tx(label):
        ident = run['ordinary'][label]['tx']
        raw = (public/'packets'/(ident+'.bin')).read_bytes()
        assert hash_bytes(raw).hex() == ident
        return raw
    used = {}
    for actor, funding, spends, expected, height in (
            ('offline','fund-offline',('restored-a-to-b',),(20,12,asset),16),
            ('conflict','fund-conflict',('a-conflict','b-conflict'),(20,0,bytes(32)),13)):
        with_a = restore(home, actor, 'MNG1', chain, height)
        with_b = restore(home, actor, 'MNG2', chain, height)
        assert with_a == with_b and len(with_a) == 1
        cm, nf, n, t, aid, kind, creator = with_b[0]
        assert (n,t,aid) == expected and creator == hash_bytes(tx(funding))
        assert kind == 2 and cm in [c for c,_ in effects(tx(funding))[1]]
        for spend in spends:
            raw = tx(spend)
            assert nf in effects(raw)[0]
            assert run['ordinary'][spend]['real_inputs'] == 1
        used[actor] = dict(original_backup_B=32, accepted_roles=2, matching_owned_positive_notes=1,
                           source_native=n, source_tokens=t, exact_spends_checked=len(spends))
    # The forward wallet uses its own live store. Its only actual input came from the restored wallet's B payment.
    onward, back = tx('b-to-b'), tx('restored-a-to-b')
    with dbread(home/'wallets/forward/mng1-wallet-state.sqlite') as db:
        rows = db.execute('SELECT cm,nf,amount,token,asset,kind,creator FROM owned WHERE spender=?',
                          (hash_bytes(onward),)).fetchall()
    assert len(rows) == 1
    cm,nf,n,t,aid,kind,creator = rows[0]
    assert (n,t,aid,kind,creator) == (12,8,asset,'incoming',hash_bytes(back))
    assert cm in {c for c,_ in effects(back)[1]} and nf in effects(onward)[0]
    return dict(seed_and_selected_public_history=used, recipient_onward=dict(source_native=n,source_tokens=t,
                actual_funded_inputs=1,source_and_spend_matched=True))


if __name__ == '__main__':
    if not __debug__:
        sys.exit('run with Python assertions enabled')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('home', type=Path)
    print(json.dumps(inspect(p.parse_args().home.resolve()), indent=2, sort_keys=True))
