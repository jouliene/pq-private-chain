"""Independent public FTL1 framing, statement context, query, and Merkle readback."""
import argparse
from hashlib import sha256, sha3_512, shake_256
import json
from pathlib import Path
import struct

P = 2**64 - 2**32 + 1
N, K, S, OPEN, D, REP, MASKS, PACKS, HINTS, WIDTH, DEGREE = PARAMS = (2**18, 256, 117, 32, 148, 5, 33, 450, 10, 533, 7)
SHAPE = bytes.fromhex('77533cc1c383bec78358ae8b304a1151aab834c34656d2edcc167dccdaf1c339')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(bundle, network, endpoint, count, aux_root):
    off = 5
    require(bundle[:off] == b'FTB1\x01', 'expected mixed bundle')
    frames = []
    for side in (0, 1):
        size, = struct.unpack_from('<I', bundle, off)
        off += 4
        frame = bundle[off:off+size]
        off += size
        require(len(frame) == size <= 262144 and frame[:6] == b'FTF1\x01'+bytes([side]), 'physical frame')
        require(frame[11:43] == network, 'network')
        frames.append(frame)
    require(off == len(bundle) and frames[0][6:75] == frames[1][6:75], 'pair binding')
    legs = [f[107+17088:] for f in frames]
    for j, frame in enumerate(frames):
        require(frame[75:107] == sha256(legs[1-j]).digest(), 'other leg binding')
    leg = legs[0]
    size, = struct.unpack_from('<I', leg, 5)
    statement, proof, receipts = leg[9:313], leg[313:313+size], leg[313+size:]
    require(leg[:5] == b'FTL1\x01' and legs[1][:5] == b'SLG1\x01' and len(receipts) == 3584, 'leg framing')
    words = struct.unpack('<38Q', statement)
    require(all(w<P for w in words) and statement[-32:] == aux_root, 'auxiliary root or public words')
    ctxt = sha256(b'FTL1/proof-context/v1\x00'+network+endpoint+struct.pack('<Q', count)+receipts).digest()
    prefix = sha3_512(b'FTL1/TCitH-MT/SLG1/Goldilocks/fixed-parent/fft256/v1\x00'+SHAPE+
                      struct.pack('<11Q', *PARAMS)+ctxt+statement).digest()
    def h(tag, b):
        return sha3_512(tag+prefix+b).digest()
    sampled = set()
    counter = 0
    while len(sampled) < OPEN:
        block = shake_256(b'I'+prefix+proof[:192]+struct.pack('<Q',counter)).digest(4096)
        for w, in struct.iter_unpack('<Q',block):
            sampled.add(w % N)
            if len(sampled) == OPEN:
                break
        counter += 1
    active = {}
    pos = 192
    for idx in sorted(sampled):
        stride = 32+8*WIDTH
        row = proof[pos:pos+stride]
        require(len(row) == stride and all(w<P for w, in struct.iter_unpack('<Q',row[32:])), 'opened field rows')
        active[N+idx] = h(b'L',struct.pack('<Q',idx)+row)
        pos += stride
    siblings = 0
    while len(active)>1 or 1 not in active:
        parents = {}
        for node in sorted({i//2 for i in active}):
            children = []
            for i in (2*node,2*node+1):
                if i in active:
                    children.append(active[i])
                else:
                    children.append(proof[pos:pos+64])
                    pos += 64
                    siblings += 1
            parents[node] = h(b'N',struct.pack('<Q',node)+b''.join(children))
        active = parents
    require(h(b'R',active[1]) == proof[:64], 'committed public openings')
    tail_words = MASKS*S + REP*((DEGREE*D+1-S-OPEN)+(S-1)+(2*S+OPEN-2+1-S-OPEN))
    require(len(proof)-pos == 8*tail_words and all(w<P for w, in struct.iter_unpack('<Q',proof[pos:])), 'terminal encoding')
    require(len(proof) == 213352+64*siblings, 'commitment frontier count')
    return dict(physical_frames=list(map(len, frames)), bare_proof=len(proof), merkle_siblings=siblings,
                terminal_words=tail_words, digest_sha256=sha256(bundle).hexdigest(), opened_parties=len(sampled),
                height=words[4], fee=words[21], remaining_frame_bytes=262144-len(frames[0]))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('events', type=Path)
    args = p.parse_args()
    source = json.loads((args.events/'SOURCE.json').read_bytes())
    print(json.dumps(read((args.events/'mixed.swap').read_bytes(), bytes.fromhex(source['network']),
                          bytes.fromhex(source['common']['tip']),source['common']['notes'],
                          bytes.fromhex(source['aux_root'])), indent=2))
