"""Two independent typed note openings, private depth-40 paths and public nullifiers."""
import hashlib
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "smallwood"))
from commitment import Commitment
from engine import PROFILE
from field import U, WIDE, mul, random_fields
from relation import Circuit, Matrix, bits, parent
import sumcheck
from transcript import Transcript


class Opening(Circuit):
    """FS01 account, commitment, occurrence and nullifier in the path proof."""
    def __init__(self, chain, nf, secret):
        self.values, self.rows = [0, 1], [[], [], []]
        self.private = secret is not None
        def private(name, length):
            value = secret[name] if self.private else bytes(length)
            if len(value) != length:
                raise ValueError("private field width")
            return [self.bit(b) for b in bits(value)]
        key, occ = private("ask",64), private("occ",64)
        native, aid, qty, salt = (private(name,length) for name,length in
                                   (("native",8),("asset",64),("qty",8),("salt",64)))

        def hash_wires(tag, *parts):
            message = bits(bytes((0xf1,tag)))
            for part in parts:
                message.extend(part)
            n = len(message)//8
            padding = bytearray(136 - n%136)
            padding[0] = 0x1f
            padding[-1] |= 0x80
            message.extend(bits(padding))
            state = [0]*1600
            for start in range(0,len(message),1088):
                for i, w in enumerate(message[start:start+1088]):
                    if not w:
                        continue
                    if state[i] == 0:
                        state[i] = w
                    else:
                        joint = self.new(self.values[state[i]] ^ self.values[w])
                        self.row([1], [state[i],w], [joint])
                        state[i] = joint
                state = self.permute(state)
            return state[:512]

        owner = hash_wires(3,key)
        cm = hash_wires(4,bits(chain),owner,native,aid,qty,salt)
        self.digest_coordinates = hash_wires(5,occ,cm)
        actual_nf = hash_wires(8,key,occ)
        for coordinate, bit in zip(actual_nf, bits(nf)):
            self.row([1],[coordinate],[bit])
        self.width = len(self.values)
        self.w = np.asarray(self.values, U) if self.private else None
        self.matrices = tuple(Matrix(rows) for rows in self.rows)
        self.height = len(self.rows[0])
        del self.rows,self.values


class Pieces:
    """Block-diagonal sparse maps with a small final matrix of cross-block equalities."""
    def __init__(self, parts, joins, lane, width):
        self.parts, self.joins, self.lane, self.width = parts, joins, lane, width

    def apply(self, w):
        blocks = [c.matrices[self.lane].apply(w[offset:offset+c.width])
                  for c, offset in self.parts]
        return np.concatenate([*blocks,self.joins.apply(w)])

    def transpose(self, rows, length):
        if length != self.width:
            raise ValueError("transpose width")
        offset_rows = 0
        out = np.zeros(length,U)
        for c, offset_cols in self.parts:
            end = offset_rows + c.height
            out[offset_cols:offset_cols+c.width] = c.matrices[self.lane].transpose(
                rows[offset_rows:end],c.width)
            offset_rows = end
        return out ^ self.joins.transpose(rows[offset_rows:],length)


class Funded:
    def __init__(self, chain, root, count, nfs, secrets):
        if (len(chain)!=64 or len(root)!=64 or not 2 <= count <= 1<<40 or
            len(nfs)!=2 or any(len(n)!=64 for n in nfs) or nfs[0]==nfs[1]):
            raise ValueError("invalid funded statement")
        self.width, self.height = 2, 0
        private = secrets is not None
        parts, joins = [], [[],[],[]]
        def row(a,b,c):
            for plane, item in zip(joins,(a,b,c)):
                plane.append(item)
        def equality(a,b):
            row([1],[a],[b])
        def add(part):
            start = self.width
            self.width += part.width
            self.height += part.height
            parts.append((part,start))
            equality(start,0)
            equality(start+1,1)
            return start

        indices = []
        self.path_chunks, self.entry_joins, self.range_chunks = [],[],[]
        for slot,nf in enumerate(nfs):
            secret = secrets[slot] if private else None
            first = Opening(chain,nf,secret)
            offset = add(first)
            previous = np.array(first.digest_coordinates) + offset
            if private:
                digest = hashlib.shake_256(b"\xf1\x05"+secret["occ"]+secret["cm"]).digest(64)
                path = secret["path"]
                if len(path)!=40 or any(len(s)!=64 for s in path):
                    raise ValueError("invalid path")
            index_bits = []
            chunk_ranges = []
            for level in range(0,40,2):
                args = None
                if private:
                    choices = tuple((secret["index"] >> j)&1 for j in (level,level+1))
                    args = (digest,path[level],path[level+1],*choices)
                    digest = parent(level+1,parent(level,digest,path[level],choices[0]),
                                    path[level+1],choices[1])
                c = Circuit(level,root,args)
                # The standalone two-level circuit enforces a final public digest.
                # Internal chunks instead connect those 512 private coordinates.
                if level < 38:
                    for m in c.matrices:
                        m.index = m.index[:c.root_check_rows.start]
                    c.height = c.root_check_rows.start
                offset = add(c)
                chunk_ranges.append(slice(offset,offset+c.width))
                if level == 0:
                    self.entry_joins.append(range(len(joins[0]),len(joins[0])+512))
                for a,b in zip(previous,c.input_coordinates[0]):
                    equality(int(a),offset+b)
                index_bits.extend(offset+d for d in c.direction_coordinates)
                previous = np.array(c.digest_coordinates) + offset
            indices.append(index_bits)
            self.path_chunks.append(chunk_ranges)

        # The following additional witness bits are fully determined by the
        # hidden direction bits. Verifier matrices are identical for every index.
        extra = []
        def aux(value):
            coord = self.width
            self.width += 1
            extra.append(value)
            return coord
        for slot, idx in enumerate(indices):
            self.range_chunks.append(slice(self.width,self.width+(40 if count < 1<<40 else 0)))
            if count == 1<<40:
                continue
            less, value = 0, 0
            for j,x in enumerate(idx):
                v = (secrets[slot]["index"] >> j)&1 if private else 0
                if (count>>j)&1:
                    # less' = 1 + x*(1+less)
                    value = 1 ^ (v & (1 ^ value))
                    z = aux(value)
                    row([x],[1,less],[1,z])
                else:
                    value = (1 ^ v) & value
                    z = aux(value)
                    row([1,x],[less],[z])
                less = z
            equality(less,1)
        same, value = 1, 1
        for j,(x,y) in enumerate(zip(*indices)):
            if private:
                value &= 1 ^ (((secrets[0]["index"]^secrets[1]["index"])>>j)&1)
            z = aux(value)
            row([same],[1,x,y],[z])
            same = z
        equality(same,0)
        self.block_rows = self.height
        self.height += len(joins[0])
        self.ell = (max(self.width,self.height)-1).bit_length()
        self.w = np.concatenate([np.array([0,1],U),*(c.w for c,_ in parts),
                                 np.asarray(extra,U)]) if private else None
        self.matrices = tuple(Pieces(parts,Matrix(rows),lane,self.width)
                              for lane,rows in enumerate(joins))

    def check_detached_paths(self):
        """Swap two intact, valid paths under the same root, keeping authorized openings in place."""
        def failures(w):
            a,b,c = (matrix.apply(w) for matrix in self.matrices)
            return np.flatnonzero(mul(a,b) != c)
        if len(failures(self.w)):
            raise ValueError("honest assignment fails a field equation")
        other = self.w.copy()
        for a,b in [*zip(*self.path_chunks),tuple(self.range_chunks)]:
            other[a],other[b] = self.w[b],self.w[a]
        bad = failures(other)
        # Every detached path and both branch roots still pass locally. Only the
        # two opening-to-first-path equalities should detect the substitution.
        allowed = {self.block_rows+j for block in self.entry_joins for j in block}
        if not len(bad) or not set(map(int,bad)).issubset(allowed):
            raise ValueError("detachment did not isolate the two funded edges")
        if not all(any(self.block_rows+j in bad for j in block) for block in self.entry_joins):
            raise ValueError("one detached opening was not detected")


def execute(chain, root, count, nfs, *, genesis_pin, profile, secrets=None, packet=None):
    mixed = profile == "mixed"
    if profile not in ("gf16","mixed") or mixed != WIDE:
        raise ValueError("unregistered path profile")
    if not mixed and (PROFILE.pack,PROFILE.opens,PROFILE.leaves,PROFILE.decs_rows,
                PROFILE.salt_bytes,PROFILE.hash_bytes) != (32,16,256,16,16,32):
        raise ValueError("unregistered depth-40 calibration profile")
    if (secrets is None)==(packet is None):
        raise ValueError("select exactly one role")
    c = Funded(chain,root,count,nfs,secrets)
    if len(genesis_pin)!=32:
        raise ValueError("bad genesis identifier")
    if mixed:
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"smallwood"/"mixed"))
        from backend import MixedCommitment, PROFILE_ID, packed_length, pack_coeff, pack_secret
        suite = b"FS01/two-funded-paths/" + PROFILE_ID
    else:
        suite = b"FS01/two-funded-paths/gf16-c1-v1"
    statement = suite + genesis_pin + chain + root + count.to_bytes(6,"little") + b"".join(nfs)
    tr = Transcript(statement,packet)
    mask_count = 3*c.ell+5
    masks = random_fields((mask_count,)) if tr.producing else None
    if mixed:
        wt = pack_secret(c.w,masks) if tr.producing else None
        pcs = MixedCommitment(tr,packed_length(c.width,mask_count),wt)
    else:
        wt = np.concatenate((c.w,masks)) if tr.producing else None
        pcs = Commitment(PROFILE,tr,c.width+mask_count,wt)
    coef,target = sumcheck.run(c,tr,masks)
    if mixed:
        coef = pack_coeff(coef,c.width)
    pcs.open(tr,coef,target)
    if not tr.producing and tr.pos != len(packet):
        raise ValueError("trailing bytes")
    return bytes(tr.packet) if tr.producing else (c.width,c.height,c.ell)
