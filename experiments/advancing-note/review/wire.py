"""Independent byte accounting on the selected, publicly replayable N7P2 history."""
import argparse
from collections import Counter
from hashlib import sha3_384
import json
from pathlib import Path
import struct


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(tag, data):
    return sha3_384(tag + b'\0' + data).digest()


def read_core(raw, kind, net):
    require(raw[:5] == b'N7P2' + bytes([kind]) and raw[5:53] == net, 'leg identity')
    count, fee = struct.unpack_from('<QQ', raw, 109)
    nfs = [raw[i:i+56] for i in (125, 181)]
    cms = [raw[i:i+56] for i in (237, 293)]
    size_offset = 349 + 2 * 1744
    if kind:
        size_offset += 85
    proof_size, = struct.unpack_from('<I', raw, size_offset)
    require(proof_size > 0 and size_offset + 4 + proof_size == len(raw), 'proof framing')
    return count, fee, nfs, cms, proof_size


def read_packet(raw, net):
    if not raw:
        return []
    if raw.startswith(b'N7P2'):
        return [read_core(raw, 0, net)]
    require(raw[:4] == b'N7S2', 'operation kind')
    p = 4
    legs = []
    for side in (1, 2):
        length, = struct.unpack_from('<I', raw, p)
        p += 4
        require(17088 < length <= 272 * 1024 and p + length <= len(raw), 'signed frame size')
        legs.append(read_core(raw[p:p+length-17088], side, net))
        p += length
    require(p == len(raw), 'bundle length')
    return legs


def inspect(folder, approved_genesis):
    genesis = json.loads((folder/'genesis.json').read_bytes())
    canonical = json.dumps(genesis, sort_keys=True, separators=(',', ':')).encode()
    parent = digest(b'N7G2/genesis', canonical)
    require(parent.hex() == approved_genesis, 'founding identity')
    net = bytes.fromhex(genesis['network'])
    cms = {struct.pack('<7Q', *c['cm']) for c in genesis['credits']}
    require(len(cms) == len(genesis['credits']), 'duplicate genesis commitment')
    counts = [len(cms)]
    nfs = set()
    miner_fees = Counter()
    totals = Counter()
    rows = []
    blocks = sorted(folder.glob('block-*.bin'), key=lambda p: int(p.stem[6:]))
    for height, path in enumerate(blocks, 1):
        require(path.name == f'block-{height:04}.bin', 'non-contiguous blocks')
        raw = path.read_bytes()
        require(raw[:4] == b'N7B2' and raw[4:52] == net, 'block identity')
        require(int.from_bytes(raw[52:56], 'little') == height and raw[56:104] == parent, 'parent')
        require(raw[104:152] == digest(b'N7B2/body', raw[176:]), 'body binding')
        parent = digest(b'N7B2/work', raw[:176])
        require(int.from_bytes(parent[:2], 'big') < 64, 'PoW')
        payload = raw[180:]
        require(struct.unpack_from('<I', raw, 176)[0] == len(payload), 'operation length')
        legs = read_packet(payload, net)
        fee = sum(leg[1] for leg in legs)
        require(fee == (3 if legs else 0) == struct.unpack_from('<I', raw, 168)[0], 'miner credit')
        if fee:
            miner_fees[raw[152:168].hex()] += fee
        # A count alone supplies a recency lower bound. The native verifier checks the actual root.
        prior = counts[-64:]
        ages = []
        for count, _, spent, created, proof_size in legs:
            require(count in prior, 'anchor count outside selected window')
            ages.append(prior[::-1].index(count))
            require(len(set(spent)) == len(set(created)) == 2, 'duplicate effect')
            require(nfs.isdisjoint(spent) and cms.isdisjoint(created), 'selected history conflict')
            nfs.update(spent)
            cms.update(created)
            totals['proof_B'] += proof_size
        counts.append(len(cms))
        totals['operation_B'] += len(payload)
        totals['archive_block_B'] += len(raw)
        totals['legs'] += len(legs)
        rows.append(dict(height=height, legs=len(legs), packet_B=len(payload), block_B=len(raw),
                         proof_B=[l[4] for l in legs], min_anchor_age=ages))
    require(rows, 'empty history')
    return dict(genesis=approved_genesis, tip=parent.hex(), leaves=len(cms), nullifiers=len(nfs),
                spent_hash=digest(b'N7B2/spent', b''.join(sorted(nfs))).hex(),
                miner_fees=dict(miner_fees), totals=dict(totals), rows=rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('public', type=Path)
    parser.add_argument('founding_id', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.public, args.founding_id.read_text().strip()), indent=2))
