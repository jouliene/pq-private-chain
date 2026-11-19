"""Independent PoW, monetary, anchor, receipt and full-tree replay of two public D8 histories."""
import argparse
from hashlib import sha256, sha3_256
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'experiments/advancing-payments/review'))
from public_chain import P, ZERO, counted_hash, reference

PROFILE = bytes.fromhex('5d6cfc6ccff5792e4899799124b2fb1e7dac50f727825c4886485dc01a564ce8')
NET = sha256(b'D8/network/v1\0' + PROFILE + struct.pack('<BBBIQ', 22, 8, 4, 8, 100)).digest()
GENESIS = sha256(b'PQDEV1/genesis\0' + NET).digest()


def u32(value):
    return struct.pack('<I', value)


def u64(value):
    return struct.pack('<Q', value)


def effect(pi, receipts):
    assert len(pi) == 208 and len(receipts) == 3584
    fields = struct.unpack('<26Q', pi)
    assert all(v < P for v in fields) and fields[21] == 3
    return pi[:32] + u32(fields[4]) + pi[40:176] + receipts


def sid(data):
    assert len(data) == 3756
    return sha3_256(b'D8/payment/v1\0' + NET + data).digest()


def public_packet(packet):
    assert len(packet) == 143187 and packet[:5] == b'DLF1\x01'
    size = int.from_bytes(packet[5:9], 'little')
    assert size == 139594
    pos = 9 + size
    pi = packet[pos - 208:pos]
    assert packet[pos - 216:pos - 208] == u64(26)
    return effect(pi, packet[pos:]), pi[-32:]


def dissect(raw, roots):
    assert raw[:8] == b'D8POW001' and raw[8:40] == NET and raw[40] == 22
    count = raw[213]
    assert count <= 4 and len(raw) >= 222
    i = 214
    ids, effects, receipts, digests = [], [], [], []
    for _ in range(count):
        length, = struct.unpack_from('<I', raw, i)
        packet = raw[i + 4:i + 4 + length]
        row, digest = public_packet(packet)
        ids.append(sid(row))
        effects.append(row)
        receipts.append(row[172:])
        digests.append(digest.hex())
        i += 4 + length
    assert i + 8 == len(raw)
    if digests:
        assert reference(roots, ['--ciphertext-digests'], b''.join(receipts)) == digests
    vector = bytes([count]) + b''.join(ids)
    core = raw[:213] + vector + raw[-8:]
    return decode_core(core, effects, len(raw))


def decode_core(core, effects, transport_size):
    assert (len(core) == 222 + core[213] * 32 and core[:8] == b'D8POW001'
            and core[8:40] == NET and core[40] == 22 and core[213] <= 4)
    vector = core[213:-8]
    ids = [core[i:i+32] for i in range(214, len(core)-8, 32)]
    assert ids == [sid(row) for row in effects]
    template = sha256(b'D8/core/v1\0' + core[:-8]).digest()
    bid = sha256(b'PQDEV1/work\0' + template + core[-8:]).digest()
    assert int.from_bytes(bid, 'big') < 2**234
    parent = core[41:73]
    height = int.from_bytes(core[73:77], 'little')
    context = sha256(b'PQDEV1/reward-context\0' + NET + parent + u32(height) + core[77:109] + sha256(vector).digest()).digest()
    opening = context + core[77:117]
    return dict(id=bid, parent=parent, h=height, reward=int.from_bytes(core[109:117], 'little'),
                opened_reward=opening, reward_cm=core[117:149], state=core[149:181], root=core[181:213],
                rows=effects, sids=ids, raw_B=transport_size, core_B=len(core))


def evaluate(records, roots, rewards):
    assert [b['reward_cm'].hex() for b in records] == reference(rewards, [], b''.join(b['opened_reward'] for b in records))
    state = counted_hash(b'dev-genesis-state', NET)
    def anchor(header):
        return bytes.fromhex(reference(roots, ['--header-ids'], header)[0].split()[1])
    anchors = [anchor(ZERO + u32(0) + state + counted_hash(b'dev-genesis-body', NET) + ZERO)]
    tip, fees = GENESIS, 0
    nfs, cms, leaves, each_root = set(), set(), [], {}
    paid = []
    for h, b in enumerate(records, 1):
        assert h == b['h'] and b['parent'] == tip and b['reward'] == 100 + 3 * len(b['rows'])
        transitions = []
        for row, tx in zip(b['rows'], b['sids'], strict=True):
            born = int.from_bytes(row[32:36], 'little')
            assert 1 <= h - born <= 8 and anchors[born] == row[:32] and row[164:172] == u64(3)
            spent = (row[36:68], row[68:100])
            made = (row[100:132], row[132:164])
            assert len(set(spent)) == len(set(made)) == 2 and nfs.isdisjoint(spent) and cms.isdisjoint(made) and ZERO not in made
            nfs.update(spent); cms.update(made); leaves.extend(made)
            transitions.append(row[36:172]); paid.append(tx.hex()); fees += 3
        cm = b['reward_cm']
        assert cm not in cms and cm != ZERO
        leaves.append(cm); cms.add(cm)
        state = counted_hash(b'dev-state', NET, state, u64(len(leaves)), u64(100 * h), u64(fees),
                             b['opened_reward'] + cm, b''.join(transitions))
        assert state == b['state']
        each_root[len(leaves)] = b['root'].hex()
        tip = b['id']
        anchors.append(anchor(anchors[-1] + u32(h) + state + counted_hash(b'dev-seal', NET, tip) + b['root']))
    expected = list(each_root.values())
    actual = reference(roots, [str(n) for n in each_root], b''.join(leaves))
    assert [r.split()[2] for r in actual] == expected
    return dict(tip=tip.hex(), height=len(records), work=len(records) * (1 << 22), root=expected[-1],
                state=state.hex(), anchor=anchors[-1].hex(), issued=100 * len(records), fees=fees,
                funded=len(leaves), spent=len(nfs), spent_set_sha256=sha256(b''.join(sorted(nfs))).hexdigest(),
                raw_B=sum(x['raw_B'] for x in records), core_B=sum(x['core_B'] for x in records),
                all_height_full_tree_roots_checked=len(actual), sids=paid)


def from_capture(capture, roots, rewards):
    old = json.loads((capture / 'CAPTURE.json').read_bytes())
    alternate = json.loads((capture / 'BRANCH.json').read_bytes())
    sets = {'original': (old['original_selected'], old['original']),
            'replacement': (alternate['winner'], alternate['winning_state'])}
    bank = {}
    views = {}
    for name, (ids, observed) in sets.items():
        for identifier in ids:
            if identifier not in bank:
                raw = (capture / 'blocks' / (identifier + '.bin')).read_bytes()
                block = dissect(raw, roots)
                assert block['id'].hex() == identifier
                bank[identifier] = block
        result = evaluate([bank[i] for i in ids], roots, rewards)
        for key in ('tip', 'height', 'work', 'issued', 'fees', 'spent', 'spent_set_sha256'):
            assert result[key] == observed[key]
        assert result['root'] == observed['header'][-64:]
        views[name] = result
    common = len(set(views['original']['sids']) & set(views['replacement']['sids']))
    assert common == 7 and views['replacement']['work'] > views['original']['work']
    assert len(views['original']['sids']) == len(views['replacement']['sids']) == 8
    return dict(network=NET.hex(), genesis=GENESIS.hex(), raw_captured_blocks=len(bank),
                shared_original_sids=common, outside=alternate['outside']['sid'], branches=views)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('capture', 'roots', 'rewards'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    print(json.dumps(from_capture(a.capture, a.roots.resolve(), a.rewards.resolve()), sort_keys=True, indent=2))
