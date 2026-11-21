"""Archive only validated public PoW block bodies and the already-public signed swap."""
import argparse
import gzip
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import tarfile


def pack(public, dest, deployment):
    import sys
    sys.path.insert(0, str(deployment.resolve(strict=True) / "devnet"))
    from chain import block_id, decode_block
    from swap_wire import split
    if public.is_symlink() or (public / "blocks").is_symlink():
        raise ValueError("expected a local public capture")
    bundle = public / "SWAP.bin"
    if bundle.is_symlink() or not bundle.is_file():
        raise ValueError("missing public swap")
    signed = bundle.read_bytes()
    frames = tuple(split(signed))
    seen_swap = False
    entries = {"public/SWAP.bin": signed}
    for block in sorted((public / "blocks").iterdir()):
        if not re.fullmatch("[0-9a-f]{64}\\.bin", block.name) or not block.is_file() or block.is_symlink():
            raise ValueError("unexpected block entry")
        raw = block.read_bytes()
        if block.stem != block_id(raw).hex():
            raise ValueError("public block identity mismatch")
        packets = decode_block(raw).packets
        seen_swap |= any(tuple(packets[idx:idx+2]) == frames
                         for idx in range(len(packets)-1))
        entries["public/blocks/" + block.name] = raw
    early = public / "early/BLOCK.bin"
    if early.is_symlink() or early.parent.is_symlink() or not early.is_file():
        raise ValueError("missing early boundary block")
    raw = early.read_bytes()
    parsed = decode_block(raw)
    if parsed.height != 13 or len(parsed.packets) != 1 or not parsed.packets[0].startswith(b"MSP2\x01"):
        raise ValueError("wrong early boundary block")
    entries["public/early/BLOCK.bin"] = raw
    if not seen_swap:
        raise ValueError("swap missing from captured blocks")
    with dest.open("xb") as file, gzip.GzipFile(fileobj=file, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            for name, data in sorted(entries.items()):
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    with tarfile.open(dest) as archive:
        if archive.getnames() != sorted(entries) or any(not m.isfile() or archive.extractfile(m).read() != entries[m.name]
                                                        for m in archive.getmembers()):
            raise ValueError("archive verification failed")
    return {"bytes": dest.stat().st_size, "sha256": sha256(dest.read_bytes()).hexdigest(),
            "main_graph_blocks": len(entries)-2, "extra_boundary_blocks": 1, "swap_bytes": len(signed)}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("public", "new_archive", "deployment"):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    print(json.dumps(pack(a.public, a.new_archive, a.deployment), sort_keys=True, indent=2))
