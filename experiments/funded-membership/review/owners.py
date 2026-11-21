"""Independently match disclosed funded receipts to actual spend nullifiers, one backup per role."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]/'funded-upgrade/review'))
from recovery import ast1, effects as earlier, hash_bytes, winner


def effects(raw):
    if raw[:5] not in (b'MSP3\x01', b'SWF3\x01'):
        return earlier(raw)
    if raw[:4] == b'SWF3':
        leg, words = raw[17195:], 35
    else:
        leg, words = (raw[17166:] if raw[5] in (2,3) else raw[6:]), 32
    end = 9 + int.from_bytes(leg[5:9], 'little')
    assert len(leg) == end + 3584
    assert struct.unpack_from('<Q', leg, end-(words+1)*8)[0] == words
    pi = leg[end-words*8:end]
    return (pi[40:72],pi[72:104]), ((pi[104:136],leg[end:end+1792]), (pi[136:168],leg[end+1792:]))


def scan(deployment, backup, blocks):
    keys = deployment/'c-keys'
    assert (keys/'managed.vk').read_bytes() == (HERE.parent/'registry/managed.vk').read_bytes()
    binary = deployment/'c-runtime/native'
    pin = (deployment/'devnet/approved-c-native.sha256').read_text().strip()
    assert backup.is_file() and not backup.is_symlink() and backup.stat().st_size == 32
    assert backup.stat().st_mode & 0o077 == 0
    seen, spent = {}, {}
    with TemporaryDirectory() as directory:
        private = Path(directory)
        shutil.copyfile(backup, private/'seed')
        (private/'seed').chmod(0o600)
        role = ast1.Role(binary, pin, ['wallet','/keys','/private/seed','restore'], keys, private=private)
        try:
            address = role.get()
            assert len(address) == 1601
            for height, miner, packets in blocks:
                assert miner != address[1:33]
                for packet in packets:
                    txid = hash_bytes(packet)
                    nfs, outputs = effects(packet)
                    for nf in nfs:
                        if nf in seen:
                            assert nf not in spent
                            spent[nf] = txid
                    for cm, ciphertext in outputs:
                        result = role.call(b'D' + cm + ciphertext)
                        if result == b'MISS':
                            continue
                        assert result[:3] == b'HIT' and len(result) == 84
                        n,t,aid,_ = struct.unpack('<QQ32sB', result[35:])
                        if n or t:
                            nf = result[3:35]
                            assert nf not in seen
                            seen[nf] = (height,n,t,aid,txid)
            role.close()
        finally:
            role.abort()
    return seen, spent


def audit(public, deployment, payer_backup, recipient_backup):
    run = json.loads((public/'RUN.json').read_bytes())
    chain = winner(public, run['tips']['final']['tip'])
    assert [h for h,_,_ in chain] == list(range(1,34))
    asset = bytes.fromhex(run['asset_ids']['managed'])
    def tx(name):
        return bytes.fromhex(run['operations'][name]['tx'])

    def check(backup, expected):
        seen, spent = scan(deployment, backup, chain)
        assert len(seen) == len(expected)
        by_height = {}
        for nf,(height,n,t,aid,creation) in seen.items():
            assert height not in by_height
            exp_n,exp_t,creator,consumer = expected[height]
            assert (n,t,aid) == (exp_n,exp_t,asset)
            if creator:
                assert creation == tx(creator)
            if consumer:
                assert spent[nf] == tx(consumer)
            else:
                assert nf not in spent
            by_height[height] = nf
        assert by_height.keys() == expected.keys()
        return by_height

    funded = check(payer_backup, {12:(20,12,None,'paid'), 13:(14,16,None,'paid'), 25:(3,3,'paid',None)})
    original_notes = {funded[12],funded[13]}
    for raw in ((public/'controls/legacy-b.bin').read_bytes(),
                (public/'packets'/(tx('alternate').hex()+'.bin')).read_bytes()):
        assert set(effects(raw)[0]) == original_notes
    check(recipient_backup, {25:(28,25,'paid','onward'),26:(5,9,'onward','final'),33:(1,8,'final',None)})
    return dict(backup_B_per_role=32, funded_real_inputs_in_each_of_three_distinct_payments=2,
                historical_note_amounts=[[20,12],[14,16]], payer_remaining=[3,3],
                recipient_first_note=[28,25], recipient_subsequent_real_spend_heights=[26,33],
                recipient_final_change=[1,8])


if __name__ == '__main__':
    if not __debug__:
        sys.exit('run with Python assertions enabled')
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('public','deployment','payer_backup','recipient_backup'):
        p.add_argument(arg, type=Path)
    print(json.dumps(audit(**vars(p.parse_args())), indent=2, sort_keys=True))
