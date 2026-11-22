"""Component algebra controls and fixed-role independent replay. No private fixture on disk."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

os.environ["SW_FIELD"] = "gf256"
import numpy as np
import ring_switch as rs
from field import random_fields
from transcript import Transcript

NBITS, NTRACE = 514, 4
STATEMENT = b"FS01-ring-paired-projection-test-v1/257+257,2+2"


def run(packet=None, invalid=None):
    tr = Transcript(STATEMENT, packet)
    bits = masks = None
    if tr.producing:
        half = np.unpackbits(np.frombuffer(os.urandom(33), np.uint8), bitorder="little")[:257]
        bits = np.tile(half, 2)
        if invalid == "bit":
            bits[-1] ^= 1
        masks = np.tile(random_fields((2,)), 2)
        if invalid == "trace":
            masks[-1] ^= 1
    if invalid == "square":
        r, q, d, e = rs._pads()
        q[0] ^= 1  # Trace(1)=0 in this even-degree base, so the first gate still passes.
        with patch.object(rs, "_pads", return_value=(r, q, d, e)):
            com = rs.RingCommitment(tr, NBITS, NTRACE, bits, masks)
    else:
        com = rs.RingCommitment(tr, NBITS, NTRACE, bits, masks)
    c = np.tile(tr.challenge(b"paired-bit weights", 257), 2)
    t = np.tile(tr.challenge(b"paired-K weights", 2), 2)
    com.open(tr, c, t, 0, invalid_calibration=invalid is not None)
    if len(tr.packet) != rs.wire_bytes(NBITS, NTRACE) or (not tr.producing and tr.pos != len(packet)):
        raise ValueError("wire size rejected")
    return bytes(tr.packet) if tr.producing else True


def algebra():
    field = np.arange(65536, dtype=rs.F)
    pairing = rs.TRACE[rs.fmul(field[:, None], rs.DUAL)]
    if not np.array_equal(field, (pairing * rs.BASE).sum(axis=1)):
        raise AssertionError("absolute trace-dual extraction on all F16 symbols")
    cardinalities = np.bincount(rs.fmul(field,field) ^ field, minlength=65536)
    if not np.array_equal(cardinalities, np.where(rs.TRACE == 0, 2, 0)):
        raise AssertionError("Artin-Schreier image and fiber distribution")
    g = random_fields((256,))
    for count in (0, 1, 15, 16, 17, 255, 512, 1023):
        c, t = random_fields((count,)), random_fields((3,))
        words, masks = rs.frandom(((count+15)//16,)), random_fields((3,))
        z = rs.xor(rs.mul(t,masks))
        v = rs.projections(c,words,z)
        b = np.unpackbits(words.view(np.uint8), bitorder="little")[:count]
        if not np.array_equal(rs.TRACE[v], rs.bit_coordinates(rs.xor(c[b != 0]) ^ z)):
            raise AssertionError("trace target basis projection")
        left = rs.xor(rs.mul(g, rs.EMBED[v]))
        right = rs.xor(rs.mul(rs._word_coefficients(c,g),rs.EMBED[words]))
        right ^= rs.xor(rs.mul(rs._trace_coefficients(t,g),rs.EMBED[np.array([rs.split(m) for m in masks]).ravel()]))
        if int(left) != int(right):
            raise AssertionError("linear adjoint")
    return {"trace_dual_symbols":65536,"artin_schreier_symbols":65536,
            "adjoint_bit_widths":[0,1,15,16,17,255,512,1023]}


def verify_subprocess(proof):
    # Fixed statement and code. This role reads only the public proof supplied on stdin.
    return subprocess.run([sys.executable, __file__, "verify"],input=proof, capture_output=True,
                          cwd=Path(__file__).resolve().parent)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("verify","record","algebra"))
    parser.add_argument("output",nargs="?",type=Path)
    args = parser.parse_args()
    if args.action == "verify":
        run(sys.stdin.buffer.read(rs.wire_bytes(NBITS,NTRACE)+1))
        return
    if args.action == "algebra":
        print(json.dumps(algebra(),indent=2))
        return
    if args.output is None:
        parser.error("record requires a new output directory")
    args.output.mkdir(parents=True,exist_ok=False)
    data = algebra()
    packet = run()
    passed = verify_subprocess(packet)
    if passed.returncode:
        raise RuntimeError(passed.stderr.decode())
    failure = {}
    for label, body in (("wrong input bit",run(invalid="bit")),
                        ("wrong wide trace coordinate",run(invalid="trace")),
                        ("inconsistent committed square",run(invalid="square")),
                        ("truncated packet",packet[:-1]),("trailing bytes",packet+b"\0")):
        proc = verify_subprocess(body)
        if not proc.returncode:
            raise RuntimeError("unexpected acceptance: "+label)
        failure[label] = proc.stderr.decode().strip()
    for index, label in [(0,"commitment root"),(128,"masked projection"),
                         (640,"blinded square projection"),(672,"LCS Q")]:
        body = bytearray(packet)
        body[index] ^= 1
        proc = verify_subprocess(body)
        if not proc.returncode:
            raise RuntimeError("unexpected acceptance: "+label)
        failure[label] = proc.stderr.decode().strip()
    (args.output/"projection.proof").write_bytes(packet)
    data.update({"proof_bytes":len(packet),"sha256":hashlib.sha256(packet).hexdigest(),
                 "public_only_subprocess":True,"parts":rs.wire_size(NBITS,NTRACE),
                 "rejected":failure})
    (args.output/"receipt.json").write_text(json.dumps(data,indent=2)+"\n")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(str(error))
