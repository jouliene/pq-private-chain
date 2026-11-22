"""Publicly registered circuit composition entry point for GKR plus packed witness commitment."""
import sys
import numpy as np
from cbip import Context
from runtime import EXPERIMENTS, Transcript, random_fields

sys.path.insert(0,str(EXPERIMENTS/"structured-keccak"/"ring"))
from ring_switch import RingCommitment


def execute(statement,nbits,ntrace,build_constraints,*,bits=None,packet=None,
            invalid_calibration=False,profile=None):
    if (bits is None)==(packet is None) or (packet is not None and invalid_calibration):
        raise ValueError("select exactly one proof role")
    tr = Transcript(b"structured Keccak GKR/C1/v1"+statement,packet)
    masks = random_fields((ntrace,)) if tr.producing else None
    if tr.producing:
        bits = np.asarray(bits)
        if bits.shape != (nbits,) or np.any((bits != 0) & (bits != 1)):
            raise ValueError("expected one binary witness vector")
        bits = bits.astype(np.uint8, copy=False)
    ring = RingCommitment(tr,nbits,ntrace,bits,masks,**({} if profile is None else {"profile":profile}))
    ctx = Context(tr,nbits,ntrace,bits,masks)
    build_constraints(ctx)
    coeff,trace_coeff,target = ctx.finalize()
    ring.open(tr,coeff,trace_coeff,target,invalid_calibration=invalid_calibration)
    if not tr.producing and tr.pos != len(packet):
        raise ValueError("trailing proof bytes rejected")
    return bytes(tr.packet) if tr.producing else True
