"""Fixed-width diagnostic transcript and canonical ordered SHA3-512 Merkle frontier."""

from hashlib import sha3_512
from secrets import token_bytes

from field import K, P


def u32(n):
    return n.to_bytes(4, 'little')


def hash_parts(label, *parts):
    data = b'CFW-primary-interactive-toy-v1'
    for part in (label.encode(), *parts):
        data += u32(len(part)) + part
    return sha3_512(data).digest()


class Tape:
    def __init__(self, public, encoded=None):
        self.digest = hash_parts('instance', public)
        self.proving = encoded is None
        self.proof = bytearray() if self.proving else encoded
        self.at = 0
        self.sections = {}

    def message(self, label, length, data=None):
        if self.proving:
            if data is None or len(data) != length:
                raise ValueError("prover length: "+label)
            self.proof.extend(data)
        else:
            data = self.proof[self.at:self.at+length]
            if len(data) != length:
                raise ValueError("short proof: "+label)
        self.sections[label] = (self.at, length)
        self.at += length
        self.digest = hash_parts('message/'+label, self.digest, data)
        return data

    def elements(self, label, length, values=None):
        data = self.message(label, 40*length, None if values is None else
                            b''.join(v.pack() for v in values))
        return [K.unpack(data[i:i+40]) for i in range(0, len(data), 40)]

    def sample(self, label, modulus):
        counter, out = 0, None
        while out is None:
            raw = hash_parts('draw/'+label, self.digest, u32(counter))
            n = int.from_bytes(raw, 'little')
            if n < (1 << 512)//modulus * modulus:
                out = n % modulus
            counter += 1
        self.digest = hash_parts('draw-result/'+label, self.digest, raw)
        return out

    def challenge(self, label, excluded=()):
        while True:
            x = K([self.sample(label+'/'+str(i), P) for i in range(5)])
            if x not in excluded:
                return x


def tree(label, columns):
    salts = [token_bytes(64) for _ in columns]
    layer = [hash_parts('leaf/'+label, u32(i), salts[i], b''.join(x.pack() for x in col))
             for i, col in enumerate(columns)]
    layers = [layer]
    while len(layer) > 1:
        layer = [hash_parts('node/'+label, l, r) for l, r in zip(layer[::2], layer[1::2])]
        layers.append(layer)
    return columns, layers, salts


def open_tree(tape, label, length, width, root, indices, oracle=None):
    current = {}
    selected = sorted(set(indices))
    data = tape.elements(label+'/rows', width*len(selected),
                         [v for i in selected for v in oracle[0][i]] if oracle else None)
    rows = dict(zip(selected, (data[i:i+width] for i in range(0, len(data), width)), strict=True))
    salts = tape.message(label+'/salts', 64*len(selected),
                         b''.join(oracle[2][i] for i in selected) if oracle else None)
    for j, (i, row) in enumerate(rows.items()):
        current[i] = hash_parts('leaf/'+label, u32(i), salts[64*j:64*j+64],
                                b''.join(x.pack() for x in row))
    for depth in range(length.bit_length()-1):
        absent = sorted(i^1 for i in current if i^1 not in current)
        raw = tape.message(f'{label}/frontier/{depth}', len(absent)*64,
                           b''.join(oracle[1][depth][j] for j in absent) if oracle else None)
        for k, j in enumerate(absent):
            current[j] = raw[64*k:64*(k+1)]
        current = {j//2:hash_parts('node/'+label, current[j], current[j+1])
                   for j in sorted(current) if j%2 == 0}
    if current != {0:root}:
        raise ValueError('invalid commitment: '+label)
    return [rows[i] for i in indices]
