"""Local independently implemented low-strength SmallWood+ Compiler 1 calibration."""
import numpy as np

from commitment import Commitment, Profile
from field import random_fields, WIDE
from relation import Circuit
from transcript import Transcript
import sumcheck

PROFILE = Profile(pack=32,opens=84,leaves=1024,decs_rows=4,salt_bytes=32,hash_bytes=64) if WIDE else Profile()
PROFILE_ID = b"GF256-S32-T84-N1024-ETA4-v1" if WIDE else b"GF16-S32-T16-N256-ETA16-v1"


def execute(level, root, *, secret=None, packet=None, detached=None):
    if (secret is None) == (packet is None):
        raise ValueError("select prover or verifier")
    c = Circuit(level,root,secret,detached)
    tr = Transcript(PROFILE_ID + bytes([level]) + root, packet)
    tlen = 3*c.ell+5
    masks = random_fields((tlen,)) if tr.producing else None
    wt = np.concatenate([c.w,masks]) if tr.producing else None
    lcs = Commitment(PROFILE,tr,c.width+tlen,wt)
    coef,target = sumcheck.run(c,tr,masks)
    lcs.open(tr,coef,target,diagnostic_invalid_prover=secret is not None and detached is not None)
    if not tr.producing and tr.pos != len(packet):
        raise ValueError("trailing bytes")
    return bytes(tr.packet) if tr.producing else True
