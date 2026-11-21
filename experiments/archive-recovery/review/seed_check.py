"""Check the restored wallet's two real inputs using one seed and captured public blocks."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'funded-upgrade/review'))
from recovery import PINS, ast1, effects, hash_bytes, winner


def audit(public, deployment, backup, tip):
    chain = winner(public, tip)
    assert [h for h,_,_ in chain] == list(range(1, len(chain) + 1))
    assert backup.is_file() and not backup.is_symlink()
    assert backup.stat().st_size == 32 and backup.stat().st_mode & 0o077 == 0
    name, pinned, prefix = PINS['MNG2']
    keys = deployment / (prefix + 'keys')
    binary = deployment / (prefix + 'runtime/native')
    assert hash_bytes((keys / name).read_bytes()).hex() == pinned
    approved = (deployment / 'devnet' / ('approved-' + prefix + 'native.sha256')).read_text().strip()
    observed = []
    remaining = {}
    consumed = []
    with TemporaryDirectory() as temporary:
        private = Path(temporary)
        seed = private / 'seed'
        shutil.copyfile(backup, seed)
        seed.chmod(0o600)
        role = ast1.Role(binary, approved, ['wallet', '/keys', '/private/seed', 'restore'], keys, private=private)
        try:
            address = role.get()
            assert len(address) == 1601
            for h, miner, frames in chain:
                assert miner != address[1:33]
                for frame in frames:
                    nfs, rows = effects(frame)
                    spent = [remaining.pop(nf) for nf in nfs if nf in remaining]
                    if spent:
                        consumed.append((h, frame[:4], spent))
                    for cm, ct in rows:
                        answer = role.call(b'D' + cm + ct)
                        if answer == b'MISS':
                            continue
                        assert len(answer) == 84 and answer[:3] == b'HIT'
                        nf = answer[3:35]
                        native, tokens, asset, kind = struct.unpack('<QQ32sB', answer[35:])
                        if native or tokens:
                            assert nf not in remaining
                            row = (h, frame[:4], native, tokens, asset)
                            observed.append(row)
                            remaining[nf] = row
            role.close()
        finally:
            role.abort()
    assert len(consumed) == 1
    spend_height, suite, inputs = consumed[0]
    assert suite == b'MSP2' and len(inputs) == 2
    assert sorted(inputs) == sorted(observed[:2])
    assert [(h, k, n, q) for h,k,n,q,_ in observed] == [
        (12, b'MSP1', 20, 12), (13, b'MSP2', 14, 16), (spend_height, b'MSP2', 3, 3)]
    assert len({row[-1] for row in observed}) == 1 and observed[0][-1] != bytes(32)
    assert list(remaining.values()) == [observed[-1]]
    assert len(chain) > spend_height
    return dict(restored_seed_B=32, historical_native=[20,14], historical_managed=[12,16],
                exact_selected_nullifiers_from_scan=len(inputs), fresh_spend_height=spend_height,
                later_selected_blocks=len(chain)-spend_height, unspent_native=3, unspent_managed=3)


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Python assertions must be enabled')
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('public','deployment','backup'):
        p.add_argument(arg, type=Path)
    p.add_argument('tip', help='independently replayed winning tip')
    print(json.dumps(audit(**vars(p.parse_args())), sort_keys=True, indent=2))
