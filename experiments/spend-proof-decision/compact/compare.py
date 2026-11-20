"""Run the public compact-proof experiment on a complete funded payment and signed swap."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parent / "candidate"
sys.path.insert(0, str(CANDIDATE))
from packet import SIG, decode

KEYS = {
    "ordinary": ("managed.vk", "3b95354b7e56303c636901e1fbb99d85598eb099445ba7e7203b22777764fefb"),
    "leg": ("swap.vk", "5815e098dec35adf6b75b8d636a5e2b7800b15dff4884ac3d3b5338e02cf761a"),
}
FULL = {"ordinary": b"K3M1", "leg": b"K3L1"}
SMALL = {"ordinary": b"KCM1", "leg": b"KCL1"}
FRAME_MAIN = 107 + SIG


def require(ok, description):
    if not ok:
        raise ValueError(description)


def convert(codec, registry, packet, kind, mode, workspace, meters):
    original, result = (FULL, SMALL) if mode == "encode" else (SMALL, FULL)
    require(packet[:5] == original[kind] + b"\x01", "inner proof version")
    n, = struct.unpack_from("<I", packet, 5)
    require(0 < n <= 2**20 and len(packet) == 9 + n + 3584, "two receipts and sized proof")
    path, pin = KEYS[kind]
    key = registry / path
    require(sha256(key.read_bytes()).hexdigest() == pin, "unregistered verifier key")
    input_path, output_path, meter = [workspace / name for name in ("input", "output", "meter")]
    input_path.write_bytes(packet[9:9+n])
    start = time.perf_counter()
    subprocess.run(["/usr/bin/time", "-f", "%U %S %M", "-o", meter, codec, mode, key,
                    input_path, output_path], check=True)
    seconds = time.perf_counter() - start
    user, system, rss = meter.read_text().split()
    data = output_path.read_bytes()
    meters.append({"mode": mode, "kind": kind, "input_proof_B": n, "output_proof_B": len(data),
                   "cpu_user_s": float(user), "cpu_system_s": float(system),
                   "elapsed_s": seconds, "max_rss_KiB": int(rss)})
    return result[kind] + b"\x01" + struct.pack("<I", len(data)) + data + packet[-3584:]


def transform(codec, registry, ordinary, swap, mode, workspace, meters):
    encoding = mode == "encode"
    src, dst = (b"K3", b"KC") if encoding else (b"KC", b"K3")
    require(ordinary[:6] == src + b"P1\x01\x00", "ordinary transfer wrapper")
    if encoding:
        decode(swap)  # Validate original K384 pairing before re-encoding.
    inner = convert(codec, registry, ordinary[6:], "ordinary", mode, workspace, meters)
    require(swap[:5] == src + b"B1\x01", "two-owner bundle")
    offset = 5
    frames = []
    for side in (0, 1):
        size, = struct.unpack_from("<I", swap, offset)
        offset += 4
        require(FRAME_MAIN < size <= 2**21 and offset + size <= len(swap), "leg frame size")
        frame = swap[offset:offset + size]
        offset += size
        require(frame[:6] == src + b"F1\x01" + bytes([side]), "leg version or side")
        leg = convert(codec, registry, frame[FRAME_MAIN:], "leg", mode, workspace, meters)
        # Preserve the hashes of the expanded legs and both original signatures.
        frames.append(dst + frame[2:FRAME_MAIN] + leg)
    require(offset == len(swap), "end of bundle")
    bundle = dst + b"B1\x01" + b"".join(struct.pack("<I",len(f)) + f for f in frames)
    if not encoding:
        decode(bundle)
    return dst + ordinary[2:6] + inner, bundle, [len(f) for f in frames]


def run(codec, public, out):
    out.mkdir(parents=True, exist_ok=False)
    registry = CANDIDATE / "registry"
    ordinary, swap = [(public / name).read_bytes() for name in ("ordinary.bin", "swap.bin")]
    meters = []
    with tempfile.TemporaryDirectory() as tmp:
        compact, bundle, frames = transform(codec, registry, ordinary, swap, "encode", Path(tmp), meters)
    (out/"ordinary.compact").write_bytes(compact)
    (out/"swap.compact").write_bytes(bundle)
    with tempfile.TemporaryDirectory() as tmp:
        full, signed, _ = transform(codec, registry, (out/"ordinary.compact").read_bytes(),
                                   (out/"swap.compact").read_bytes(), "decode", Path(tmp), meters)
    require((full, signed) == (ordinary, swap), "complete signed transaction did not round trip")
    (out/"ordinary.bin").write_bytes(full)
    (out/"swap.bin").write_bytes(signed)
    result = {"canonical_sha256": [sha256(v).hexdigest() for v in (full, signed)],
              "encoded_sha256": [sha256(v).hexdigest() for v in (compact, bundle)],
              "full_B": [len(full), len(signed)], "compact_B": [len(compact), len(bundle)],
              "compact_swap_frames_B": frames, "max_live_frame_B": 262144,
              "within_size_bound": [size <= 262144 for size in [len(compact), *frames]],
              "codec_meters": meters, "same_expanded_proofs_receipts_and_signatures": True}
    (out/"RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("codec", "public", "new_output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.codec.resolve(), args.public, args.new_output), indent=2))
