"""SWB1 submission and its two ordered, length-bounded block frames."""
from dataclasses import dataclass
from hashlib import sha256
from struct import pack, unpack_from

FRAME = b"SWF1\x01"
BUNDLE = b"SWB1\x01"
LEG = b"SLG1\x01"
LIMIT = 262144
SIG = 17088
CT_PAIR = 3584
HEADER = 107
MAX_BUNDLE = len(BUNDLE) + 8 + 2 * LIMIT


def require(condition, msg):
    if not condition:
        raise ValueError(msg)


def leg_shape(leg):
    require(len(leg) > 9 + CT_PAIR and leg[:5] == LEG and
            unpack_from("<I", leg, 5)[0] == len(leg) - 9 - CT_PAIR, "swap leg encoding")


def digest(network, terms, expiry, payer, legs):
    require(len(network) == len(terms) == 32 and terms != bytes(32) and
            1 <= expiry < 2**32 and payer in (0, 1) and len(legs) == 2, "swap statement")
    return sha256(b"SWP1/joint-authorization/v1\0" + network + terms + pack("<IB", expiry, payer)
                  + b"".join(sha256(leg).digest() for leg in legs)).digest()


@dataclass(frozen=True)
class Frame:
    side: int
    payer: int
    expiry: int
    network: bytes
    terms: bytes
    other: bytes
    signature: bytes
    leg: bytes


def read_frame(raw):
    require(HEADER + SIG < len(raw) <= LIMIT and raw.startswith(FRAME), "swap frame length or version")
    side, payer, expiry = unpack_from("<BBI", raw, 5)
    require(side <= 1 and payer <= 1 and expiry and raw[43:75] != bytes(32), "swap frame fields")
    leg = raw[HEADER + SIG:]
    leg_shape(leg)
    return Frame(side, payer, expiry, raw[11:43], raw[43:75], raw[75:107], raw[107:HEADER + SIG], leg)


def pair(frames):
    require(len(frames) == 2, "incomplete atomic swap")
    a, b = map(read_frame, frames)
    require((a.side,b.side) == (0,1) and (a.payer,a.expiry,a.network,a.terms) ==
            (b.payer,b.expiry,b.network,b.terms) and a.other == sha256(b.leg).digest()
            and b.other == sha256(a.leg).digest(), "unmatched atomic swap")
    return a, b


def bundle(frames):
    pair(frames)
    return BUNDLE + b"".join(pack("<I",len(f)) + f for f in frames)


def split(raw):
    require(raw.startswith(BUNDLE) and len(raw) <= MAX_BUNDLE, "swap submission framing")
    frames = []
    off = len(BUNDLE)
    for _ in range(2):
        require(off+4 <= len(raw), "incomplete atomic swap")
        size, = unpack_from("<I",raw,off)
        off += 4
        require(0 < size <= LIMIT and off+size <= len(raw), "incomplete atomic swap")
        frames.append(raw[off:off+size])
        off += size
    require(off == len(raw), "trailing atomic swap bytes")
    pair(frames)
    return tuple(frames)


def assemble(network, terms, expiry, payer, legs, signatures):
    digest(network,terms,expiry,payer,legs)
    require(len(signatures) == 2 and all(len(s) == SIG for s in signatures), "swap authorization width")
    frames = [FRAME + pack("<BBI",i,payer,expiry) + network + terms + sha256(legs[1-i]).digest()
              + signatures[i] + legs[i] for i in range(2)]
    return bundle(frames)


def groups(packets):
    """Yield full groups in physical order. An orphan, reordered or truncated leg is invalid."""
    stream = iter(packets)
    for first in stream:
        if first.startswith(FRAME):
            second = next(stream, None)
            require(second is not None, "incomplete atomic swap")
            pair((first,second))
            yield first,second
        else:
            yield (first,)
