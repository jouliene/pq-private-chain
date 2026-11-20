"""Versioned comparison packets. The live devnet has no registration for these types."""
from hashlib import sha256
from pathlib import Path
from struct import pack, unpack_from
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "atomic-swap"))
from swap_wire import CT_PAIR, Frame, HEADER, LIMIT, SIG, digest, require

LEG = b"FWL1\x01"
FRAME = b"FWF1\x01"
BUNDLE = b"FWB1\x01"


def fields(leg):
    require(leg.startswith(LEG) and len(leg) > 9 + 34 * 8 + CT_PAIR, "funded leg shape")
    size, = unpack_from("<I", leg, 5)
    require(len(leg) == 9 + size + 34 * 8 + CT_PAIR, "funded leg length")
    return unpack_from("<34Q", leg, 9)


def assemble(network, terms, expiry, payer, legs, signatures):
    digest(network, terms, expiry, payer, legs)
    require(len(signatures) == 2 and all(len(s) == SIG for s in signatures), "signature length")
    frames = []
    for side, leg in enumerate(legs):
        fields(leg)
        header = FRAME + pack("<BBI", side, payer, expiry) + network + terms + sha256(legs[1-side]).digest()
        frames.append(header + signatures[side] + leg)
    require(all(len(f) <= LIMIT for f in frames), "candidate frame exceeds devnet limit")
    return BUNDLE + b"".join(pack("<I", len(f)) + f for f in frames)


def split(raw):
    require(raw.startswith(BUNDLE) and len(raw) <= 13 + 2*LIMIT, "funded bundle encoding")
    off = len(BUNDLE)
    parts = []
    for index in (0, 1):
        require(off + 4 <= len(raw), "missing frame prefix")
        size, = unpack_from("<I", raw, off)
        off += 4
        require(HEADER + SIG < size <= LIMIT and off + size <= len(raw), "frame size")
        f = raw[off:off+size]
        off += size
        require(f.startswith(FRAME), "frame type")
        side, payer, expiry = unpack_from("<BBI", f, 5)
        require(side == index and payer in (0, 1) and expiry > 0 and f[43:75] != bytes(32), "swap fields")
        p = Frame(side, payer, expiry, f[11:43], f[43:75], f[75:107], f[107:107+SIG], f[107+SIG:])
        fields(p.leg)
        parts.append(p)
    a, b = parts
    require(off == len(raw) and (a.network, a.terms, a.expiry, a.payer) ==
            (b.network, b.terms, b.expiry, b.payer), "inconsistent pair")
    require(a.other == sha256(b.leg).digest() and b.other == sha256(a.leg).digest(), "cross commitment")
    return a, b


def validate(raw, network, height, binary, matrix, signature_role):
    """Verify both proofs, both signatures and pair effects using public data.

    The caller still checks branch anchors and current spentness before admitting effects.
    """
    a, b = split(raw)
    require(a.network == network and height <= a.expiry, "network or expiry")
    signed = digest(network, a.terms, a.expiry, a.payer, [a.leg, b.leg])
    keys, nullifiers, commitments = [], [], []
    with tempfile.TemporaryDirectory() as public:
        for p in (a, b):
            path = Path(public)/f"leg-{p.side}.bin"
            path.write_bytes(p.leg)
            subprocess.run([binary, "verify", "SLG1", matrix, path], check=True, stdout=subprocess.DEVNULL)
            words = fields(p.leg)
            require(words[21] == (3 if a.payer == p.side else 0), "fee payer")
            key = pack("<8I", *words[26:34])
            require(signature_role.call(b"V" + key + signed + p.signature) == b"1", "swap authorization")
            keys.append(key)
            nullifiers.extend([words[5:9], words[9:13]])
            commitments.extend([words[13:17], words[17:21]])
    require(len(set(keys)) == 2 and len(set(nullifiers)) == 4 and len(set(commitments)) == 4,
            "duplicate swap authority or effect")
    return a, b
