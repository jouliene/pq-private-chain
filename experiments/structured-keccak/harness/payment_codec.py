"""Separate SGM1 research registration with the fixed-width FS01 ordinary envelope."""
import hashlib
from pathlib import Path
import sys

EXPERIMENTS = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(EXPERIMENTS/"fresh-spend"/"binding"))
from envelope import Body, RECEIPT
from relation import Statement


class Ordinary(Body):
    def prefix(self):
        if self.role!=0 or self.backend!=1:
            raise ValueError("unregistered ordinary type")
        return b"SGM1" + super().prefix()[4:]


def anchor(pin,chain,root,count):
    return hashlib.shake_256(b"SGM1/signed-prefix/v1" + bytes.fromhex(pin)
                             + chain + root + count.to_bytes(6,"little")).digest(64)


def parse_head(head, pin, chain, root, count):
    if len(head)!=3982 or head[:6]!=b"SGM1\x01\x00":
        raise ValueError("invalid version or ordinary envelope")
    if head[6:70]!=anchor(pin,chain,root,count):
        raise ValueError("ineligible funding anchor")
    fee = int.from_bytes(head[70:78],"little")
    n0,n1,c0,c1,auth = (head[i:i+64] for i in range(78,398,64))
    b = Ordinary(1,0,head[6:70],fee,(n0,n1),(c0,c1),(head[398:398+RECEIPT],head[398+RECEIPT:]))
    if b.prefix()+auth+b.tails()!=head or n0==n1:
        raise ValueError("noncanonical payment")
    return Statement(chain,root,count,fee,b.nfs,b.cms,b.intent(chain,root,count),auth)
