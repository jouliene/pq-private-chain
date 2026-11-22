"""Verifier-owned sparse binary R1CS over GF(2^16). Keccak rounds use three affine maps."""
from functools import reduce
from operator import xor as bitxor
import hashlib

import numpy as np
from field import U, xor

ROT = (0,1,62,28,27, 36,44,6,55,20, 3,10,43,25,39, 41,45,15,21,8, 18,2,61,56,14)
LENGTH = 512


def bits(data):
    return np.unpackbits(np.frombuffer(data, np.uint8), bitorder="little").tolist()


def parent(level, child, sibling, direction):
    left, right = (sibling, child) if direction else (child, sibling)
    return hashlib.shake_256(bytes([0xf1, 7, level]) + left + right).digest(64)


class Matrix:
    def __init__(self, rows):
        # Index zero is a dedicated zero coordinate checked by the public LCS.
        self.index = np.zeros((len(rows), max(map(len, rows))), dtype=np.int32)
        for i, row in enumerate(rows):
            self.index[i, :len(row)] = row

    def apply(self, witness):
        return xor(witness[self.index], axis=1)

    def transpose(self, values, length):
        result = np.zeros(length, U)
        for column in self.index.T:
            np.bitwise_xor.at(result, column, values)
        return result


class Circuit:
    def __init__(self, level, expected, secret=None, detached=None):
        if len(expected) != 64 or not 0 <= level < 39:
            raise ValueError("invalid public statement")
        self.values = [0, 1]
        self.rows = [[], [], []]
        self.private = secret is not None
        data = secret if self.private else (bytes(64), bytes(64), bytes(64), 0, 0)
        if any(len(d) != 64 for d in data[:3]) or any(x not in (0, 1) for x in data[3:]):
            raise ValueError("unexpected private shape")
        groups = [[self.bit(v) for v in bits(s)] for s in data[:3]]
        directions = [self.bit(d) for d in data[3:]]
        self.input_coordinates = groups
        self.direction_coordinates = directions
        current = groups[0]
        for k in range(2):
            sibling = groups[k+1]
            swap = []
            for u, v in zip(current, sibling):
                t = self.new(self.values[directions[k]] & (self.values[u] ^ self.values[v]))
                self.row([directions[k]], [u,v], [t])
                swap.append(t)
            ordered = []
            for nodes in [current, sibling]:
                for j, (u, t) in enumerate(zip(nodes, swap)):
                    value = self.values[u] ^ self.values[t]
                    # Test-only inconsistent assignment to the exact same public matrices.
                    if detached is not None and k == 1 and nodes is (
                            current if data[4] == 0 else sibling):
                        value = detached[j]
                    w = self.new(value)
                    self.row([1], [u,t], [w])
                    ordered.append(w)
            state = bits(bytes([0xf1, 7, level+k])) + ordered + bits(b"\x1f\0\0\0\x80") + [0]*512
            current = self.permute(state)[:512]
        self.digest_coordinates = current
        self.root_check_rows = range(len(self.rows[0]), len(self.rows[0])+512)
        for w, b in zip(current, bits(expected)):
            self.row([1], [w], [b])
        self.matrices = tuple(Matrix(rows) for rows in self.rows)
        self.w = np.array(self.values, dtype=U) if self.private else None
        self.width = len(self.values)
        self.height = len(self.rows[0])
        self.ell = (max(self.height, self.width)-1).bit_length()
        del self.rows, self.values

    def new(self, v):
        self.values.append(v)
        return len(self.values)-1

    def row(self, a, b, c):
        for plane, term in zip(self.rows, (a,b,c)):
            plane.append(term)

    def bit(self, v):
        i = self.new(v)
        self.row([i], [i], [i])
        return i

    def permute(self, state):
        lfsr = 1
        for _ in range(24):
            b = [None]*1600
            for y in range(5):
                for x in range(5):
                    lane = x + 5*y
                    target = y + 5*((2*x+3*y) % 5)
                    for z in range(64):
                        indices = [64*lane+z]
                        indices += [64*((x+4)%5+5*j)+z for j in range(5)]
                        indices += [64*((x+1)%5+5*j)+(z-1)%64 for j in range(5)]
                        b[64*target+(z+ROT[lane])%64] = [state[i] for i in indices]
            rc = set()
            for j in range(7):
                if lfsr & 1:
                    rc.add((1 << j)-1)
                lfsr = ((lfsr << 1) & 255) ^ (0x71 if lfsr & 128 else 0)
            out = []
            for y in range(5):
                for x in range(5):
                    for z in range(64):
                        i = 64*(x+5*y)+z
                        left = [1] + b[64*((x+1)%5+5*y)+z]
                        right = b[64*((x+2)%5+5*y)+z]
                        offset = b[i] + ([1] if i in rc else [])
                        value = 0
                        if self.private:
                            def val(indices):
                                return reduce(bitxor, map(self.values.__getitem__, indices), 0)
                            value = (val(left) & val(right)) ^ val(offset)
                        w = self.new(value)
                        self.row(left, right, [w]+offset)
                        out.append(w)
            state = out
        return state
