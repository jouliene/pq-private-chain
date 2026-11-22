"""Private reduction of an arbitrary binary K-linear functional to one packed LCS."""
from pathlib import Path
import sys

import numpy as np

SMALLWOOD = Path(__file__).resolve().parents[2] / "hidden-membership" / "smallwood"
sys.path[:0] = [str(SMALLWOOD / "mixed"), str(SMALLWOOD)]
from backend import MixedCommitment, PROFILE as LEGACY_PROFILE, ff_message
from commitment import Profile
from field import mul, xor
from subfield import ALPHA, BETA, EMBED, F, fmul, frandom, join, split
from wide import decode, encode, interpolation_batch

PROFILE = Profile(pack=91, opens=60, leaves=4096, decs_rows=75, salt_bytes=32, hash_bytes=64)
RING_ID = (b"FS01-ring-trace-AS-v1/F1100b/K-X256+X10+X5+X2+1/beta=1..X^15/"
           + int(ALPHA).to_bytes(32, "little"))
RING_SYMBOLS = 2 * (256 + 16)
# Chunking bounds the transient byte arrays for dense terminal coefficients.
BLOCK_WORDS = 2048


def trace_table():
    elems = np.arange(65536, dtype=F)
    total = elems.copy()
    for _ in range(1, 16):
        elems = fmul(elems, elems)
        total ^= elems
    if np.any(total > 1):
        raise RuntimeError("wrong absolute trace")
    return total


TRACE = trace_table()
BASE = (1 << np.arange(16)).astype(F)


def dual_basis():
    # Map each field element to its trace pairing against all polynomial basis vectors.
    elems = np.arange(65536, dtype=F)
    labels = np.zeros(65536, F)
    for i, b in enumerate(BASE):
        labels |= TRACE[fmul(elems, b)] << i
    if np.unique(labels).size != 65536:
        raise RuntimeError("singular absolute trace pairing")
    inverse = np.empty_like(labels)
    inverse[labels] = elems
    return inverse[BASE]


DUAL = dual_basis()
BETA_K = np.asarray(BETA, object)
K_LIMBS = np.dtype("<u8")


def bit_coordinates(x):
    return ((split(x)[:, None] >> np.arange(16)) & 1).ravel().astype(F)


def wire_size(nbits, ntrace, profile=PROFILE, *, early_degree=False):
    """Ring commitment, projection messages and opening only, excluding caller data."""
    n = (nbits + 15) // 16 + 16*ntrace + RING_SYMBOLS
    p = profile
    rows = (n + p.pack - 1) // p.pack
    sizes = dict(symbols=n, rows=rows, columns=2*p.opens*(rows + 32 + p.decs_rows),
                salts=p.opens*p.salt_bytes, siblings=p.opens*(p.leaves.bit_length()-1)*p.hash_bytes,
                R_completion=2*p.pack*p.decs_rows, Q=32*len(p.qpoints),
                roots=2*p.hash_bytes, masked_projections=512, blinded_square=32)
    if early_degree:
        sizes.update(roots=p.hash_bytes, R_completion=0,
                     explicit_degree_table=2*len(p.points)*p.decs_rows)
    return sizes


def wire_bytes(nbits, ntrace, profile=PROFILE, *, early_degree=False):
    sizes = wire_size(nbits, ntrace, profile, early_degree=early_degree)
    return sum(v for k, v in sizes.items() if k not in ("symbols", "rows"))


def _blocks(coefs):
    for start in range(0, len(coefs), BLOCK_WORDS*16):
        c = coefs[start:start + BLOCK_WORDS*16]
        yield start // 16, np.pad(c, (0, (-len(c)) % 16)).reshape(-1, 16)


def projections(coefs, words, trace_total):
    # Accumulate the sixteen binary planes in K, converting coordinate bases once at the end.
    planes = np.zeros(16, object)
    for start, chunk in _blocks(coefs):
        contributions = fmul(words[start:start+len(chunk),None], DUAL)
        for plane in range(16):
            planes[plane] ^= xor(chunk[((contributions >> plane) & 1) != 0])
    v = np.zeros(256, F)
    for plane, value in enumerate(planes):
        v ^= bit_coordinates(value) << plane
    return v ^ fmul(split(trace_total)[:, None], DUAL).ravel()


def _byte_table(images):
    # Input basis images in K, stored as uint64 limbs for batched XOR.
    limbs = np.frombuffer(encode(images), K_LIMBS).reshape(32, 8, 4)
    table = np.zeros((32, 256, 4), K_LIMBS)
    for k in range(8):
        table[:, 1<<k:2<<k] = table[:, :1<<k] ^ limbs[:, k:k+1]
    return table


# Basis change from the canonical raw K bit representation to tower bit coordinates.
_RAW_SUPPORTS = [np.flatnonzero(bit_coordinates(1 << i)) for i in range(256)]


def _word_coefficients(coefs, weights):
    raw_images = [xor(weights[support]) for support in _RAW_SUPPORTS]
    table = _byte_table(raw_images)
    out = np.empty((len(coefs)+15)//16, object)
    for start, chunk in _blocks(coefs):
        raw = np.frombuffer(encode(chunk), np.uint8).reshape(-1, 32)
        mapped = np.zeros((len(raw), 4), K_LIMBS)
        for j in range(32):
            mapped ^= table[j, raw[:, j]]
        # Use the native matrix product on rows of sixteen wide labels.
        out[start:start+len(chunk)] = interpolation_batch(
            decode(mapped.tobytes()).reshape(-1, 16), EMBED[DUAL].reshape(1, 16))[0]
    return out


def _trace_coefficients(trace_coefs, weights):
    # H(z) = sum_l split(z)_l * sum_k g_lk * dual_k is F16-linear.
    h = xor(mul(weights.reshape(16, 16), EMBED[DUAL]), axis=1)
    scaled = mul(trace_coefs[:, None], BETA_K)
    coeffs = np.empty(scaled.size, object)
    flat = scaled.ravel()
    for start in range(0, len(flat), BLOCK_WORDS):
        part = flat[start:start+BLOCK_WORDS]
        coordinates = np.asarray([split(z) for z in part], F)
        coeffs[start:start+len(part)] = interpolation_batch(EMBED[coordinates], h.reshape(1, 16))[0]
    return coeffs


def _pads():
    r = frandom((256,))
    d = frandom((16,))
    return r, fmul(r, r), d, fmul(d, d)


class RingCommitment:
    def __init__(self, tr, nbits, ntrace, bits=None, masks=None, *, profile=PROFILE, early_degree=False):
        if nbits < 0 or ntrace < 0:
            raise ValueError("invalid ring dimensions")
        self.nbits, self.ntrace = nbits, ntrace
        self.producing = tr.producing
        self.opened = False
        dims = nbits.to_bytes(8, "little") + ntrace.to_bytes(8, "little")
        if profile not in (PROFILE, LEGACY_PROFILE):
            raise ValueError("unknown ring commitment profile")
        params = (profile.pack, profile.opens, profile.leaves, profile.decs_rows,
                  profile.salt_bytes, profile.hash_bytes)
        tr.challenge(RING_ID + bytes().join(v.to_bytes(4, "little") for v in params) + dims, 0)
        witness = None
        if tr.producing:
            data = np.asarray(bits)
            if data.shape != (nbits,) or np.any((data != 0) & (data != 1)):
                raise ValueError("ring witness must be binary")
            self.trace = np.asarray(masks, object)
            if self.trace.shape != (ntrace,):
                raise ValueError("wrong trace dimensions")
            packed = np.packbits(np.pad(data.astype(np.uint8), (0, (-nbits)%16)),
                                 bitorder="little")
            self.words = packed.view(F)
            self.r, self.q, self.d, self.e = _pads()
            witness = np.concatenate([self.words, np.asarray([split(v) for v in self.trace], F).ravel(),
                                      self.r, self.q, self.d, self.e])
        elif bits is not None or masks is not None:
            raise ValueError("private values in verifier")
        self.commitment = MixedCommitment(tr, (nbits+15)//16+16*ntrace+RING_SYMBOLS, witness, profile=profile, early_degree=early_degree)

    def open(self, tr, coef, trace_coef, rhs, *, invalid_calibration=False):
        if self.opened or tr.producing != self.producing:
            raise ValueError("ring commitment is single use")
        self.opened = True
        coef, trace_coef = np.asarray(coef, object), np.asarray(trace_coef, object)
        if coef.shape != (self.nbits,) or trace_coef.shape != (self.ntrace,):
            raise ValueError("wrong ring coefficient dimensions")
        v = None
        if tr.producing:
            z = xor(mul(self.trace, trace_coef))
            v = projections(coef, self.words, z) ^ self.r ^ self.q
        sent = ff_message(tr, b"ring masked projections", 256, v)
        if np.any(TRACE[sent] != bit_coordinates(rhs)) and not (tr.producing and invalid_calibration):
            raise ValueError("ring trace projection rejected")
        a = tr.challenge(b"ring square batch", 256)
        clear = None
        if tr.producing:
            clear = [xor(mul(a, EMBED[self.r])) ^ join(self.d)]
        u = int(tr.fields(b"ring blinded square projection", 1, clear)[0])
        scales = tr.challenge(b"ring authenticate projections and squares", 258)
        g, s, t = scales[:256], scales[256], scales[257]
        final = np.concatenate([_word_coefficients(coef, g), _trace_coefficients(trace_coef, g),
                                g ^ mul(s,a), g ^ mul(t,mul(a,a)),
                                mul(s,BETA_K), mul(t,mul(BETA_K,BETA_K))])
        target = xor(mul(g,EMBED[sent])) ^ mul(s,u) ^ mul(t,mul(u,u))
        self.commitment.open(tr, final, target, invalid_calibration=invalid_calibration)
