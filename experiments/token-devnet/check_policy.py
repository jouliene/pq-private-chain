"""Check the public operator policy against fixed positive and incompatible configuration fixtures."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'advancing-payments')]
from policy import load
from runtime import checked_keys
from wire import canonical, digest

RULES = struct.pack('<BBBIQ', 22, 8, 4, 8, 100)


def rejected(action, message):
    try:
        action()
    except ValueError as err:
        if str(err) == message:
            return
        raise
    raise AssertionError('incompatible configuration accepted')


def check(public, operator_pin):
    raw = (public/'genesis.bin').read_bytes()
    expected = json.loads((public/'RUN.json').read_bytes())['fresh_genesis']
    with TemporaryDirectory() as temp:
        root = Path(temp)
        record, approval = root/'genesis.bin', root/'approved-genesis.sha256'
        record.write_bytes(raw)
        approval.write_text(operator_pin)
        def read():
            return load(root,RULES,digest,canonical)
        net,gid,_,header = read()
        assert net.hex()==expected['network'] and gid.hex()==expected['genesis'] and header.hex()==expected['header']
        approval.write_text('00'*32)
        rejected(read,'unapproved founding inventory')
        for offset, reason in [(8, 'unapproved founding inventory'), (40, 'unapproved founding inventory'),
                               (136, 'invalid founding allocation'), (144, 'invalid founding allocation')]:
            changed = bytearray(raw)
            changed[offset] ^= 1
            record.write_bytes(changed)
            approval.write_text(sha256(changed).hexdigest())
            rejected(read,reason)
        keys = root/'keys'
        keys.mkdir()
        vk = HERE.parent/'token-profile/candidate/registry/token.vk'
        installed = keys/'token.vk'
        installed.write_bytes(vk.read_bytes())
        assert checked_keys(keys) == keys.resolve()
        installed.write_bytes((HERE/'comparison/evidence/tkq1.vk').read_bytes())
        rejected(lambda:checked_keys(keys),'unapproved TKN1 verifier')
    return dict(approved_network=net.hex(), rejected=['other operator pin','other declared verifier','other asset',
                                                      'different native founding','different token founding','TKQ1 verifier directory'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('public',type=Path)
    p.add_argument('--approve-genesis',required=True)
    args=p.parse_args()
    print(json.dumps(check(args.public,args.approve_genesis),indent=2))
