"""K384 off-chain candidate framing. No change to active packet or block limits."""
from hashlib import sha256
import struct

SIG=17088
ZERO=bytes(32)


def require(ok,msg):
    if not ok:
        raise ValueError(msg)


def statement(network,terms,expiry,payer,legs):
    require(len(network)==len(terms)==32 and terms!=ZERO and 1<=expiry<2**32 and payer in (0,1)
            and len(legs)==2, "candidate statement")
    return sha256(b"K384/joint-authorization/v1\0"+network+terms+struct.pack("<IB",expiry,payer)
                  +b"".join(sha256(leg).digest() for leg in legs)).digest()


def bundle(network,terms,expiry,payer,legs,signatures):
    statement(network,terms,expiry,payer,legs)
    require(all(len(s)==SIG for s in signatures) and len(signatures)==2,"signature lengths")
    frames=[b"K3F1\x01"+struct.pack("<BBI",i,payer,expiry)+network+terms
            +sha256(legs[1-i]).digest()+signatures[i]+legs[i] for i in (0,1)]
    return b"K3B1\x01"+b"".join(struct.pack("<I",len(f))+f for f in frames)


def decode(raw):
    require(raw[:5]==b"K3B1\x01", "candidate bundle version")
    frames=[]; off=5
    for i in (0,1):
        require(off+4<=len(raw),"frame bound")
        size=struct.unpack_from("<I",raw,off)[0]; off+=4
        require(107+SIG+3593 < size <= 2**21 and off+size<=len(raw), "isolated frame bound")
        f=raw[off:off+size]; off+=size
        require(f[:6]==b"K3F1\x01"+bytes([i]), "candidate frame order")
        frames.append(f)
    require(off==len(raw) and frames[0][6:75]==frames[1][6:75], "candidate shared fields")
    legs=[f[107+SIG:] for f in frames]
    require(all(l[:5]==b"K3L1\x01" and len(l)==3593+int.from_bytes(l[5:9],"little") for l in legs),
            "candidate leg framing")
    require(all(frames[i][75:107]==sha256(legs[1-i]).digest() for i in (0,1)), "companion")
    f=frames[0]
    digest=statement(f[11:43],f[43:75],int.from_bytes(f[7:11],"little"),f[6],legs)
    return legs,[f[107:107+SIG] for f in frames],digest,f[6]
