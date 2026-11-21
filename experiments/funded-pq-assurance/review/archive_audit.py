#!/usr/bin/env python3
"""Audit privacy inputs directly inside the pinned author release archive."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile


AUTHOR_SHA256 = "24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87"
RUN_KEYS = {"tips", "operations", "registries", "balances", "asset_ids", "controls", "recovery", "genesis"}
RECEIPT_WIDTH = 1792


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def receipt(raw: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    need(len(raw) == RECEIPT_WIDTH, "receipt width")
    need(struct.unpack_from("<BHI", raw) == (1, 1, 0), "receipt header")
    offset = 7
    parts = []
    for expected in (1568, 128, 77):
        size = struct.unpack_from("<I", raw, offset)[0]
        need(size == expected, "receipt component width")
        offset += 4
        parts.append(raw[offset : offset + size])
        offset += size
    need(offset == len(raw), "receipt trailing bytes")
    return raw, *parts


def packet_receipts(raw: bytes) -> tuple[tuple[bytes, bytes, bytes, bytes], ...]:
    if raw[:4] == b"SWF3" or raw[:4] in (b"SWF1", b"SWF2"):
        need(raw[4] == 1 and len(raw) > 17195, "swap frame")
        inner = raw[17195:]
    else:
        need(raw[:4] in (b"MSP1", b"MSP2", b"MSP3") and raw[4] == 1, "managed frame")
        need(raw[5] <= 4, "managed operation")
        inner = raw[17166:] if raw[5] in (2, 3) else raw[6:]
    need(inner[:4] in (b"MNG1", b"MNG2", b"MNG3", b"SLG1", b"SLG2", b"SLG3"), "proof suite")
    need(inner[4] == 1 and len(inner) >= 9, "proof version")
    end = 9 + struct.unpack_from("<I", inner, 5)[0]
    need(end + 2 * RECEIPT_WIDTH == len(inner), "proof/receipt frame")
    return receipt(inner[end : end + RECEIPT_WIDTH]), receipt(inner[end + RECEIPT_WIDTH :])


def audit(archive: Path) -> dict[str, object]:
    archive_raw = archive.read_bytes()
    archive_sha = sha256(archive_raw).hexdigest()
    need(archive_sha == AUTHOR_SHA256, "not the pinned author archive")
    entries: dict[str, bytes] = {}
    with tarfile.open(archive) as package:
        for member in package.getmembers():
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and ".." not in path.parts, "unsafe archive path")
            need(member.isfile() and not member.issym() and not member.islnk(), "non-regular archive member")
            need(member.name not in entries, "duplicate archive member")
            handle = package.extractfile(member)
            need(handle is not None, "unreadable archive member")
            entries[member.name] = handle.read()

    fixed = {
        "public/RUN.json",
        "public/SWAP.bin",
        "public/controls/legacy-b.bin",
        "public/controls/legacy-b-block.bin",
        "public/controls/legacy-b-costs.json",
    }
    packet_names = sorted(name for name in entries if name.startswith("public/packets/"))
    block_names = sorted(name for name in entries if name.startswith("public/blocks/"))
    need(len(packet_names) == 20 and len(block_names) == 34, "archive population")
    need(set(entries) == fixed | set(packet_names) | set(block_names), "unexpected archive member")
    for name in packet_names:
        need(re.fullmatch(r"public/packets/[0-9a-f]{64}\.bin", name) is not None, "packet filename")
        need(PurePosixPath(name).stem == sha256(entries[name]).hexdigest(), "packet identity")
    for name in block_names:
        need(re.fullmatch(r"public/blocks/[0-9a-f]{64}\.bin", name) is not None, "block filename")
        need(entries[name].startswith(b"ASTPOW01"), "block encoding")
    need(entries["public/SWAP.bin"].startswith(b"SWB3\x01"), "swap bundle encoding")
    need(entries["public/controls/legacy-b-block.bin"].startswith(b"ASTPOW01"), "legacy block encoding")

    run = json.loads(entries["public/RUN.json"])
    need(set(run) == RUN_KEYS, "RUN schema")
    legacy = entries["public/controls/legacy-b.bin"]
    need(sha256(legacy).hexdigest() == run["controls"]["legacy_B"]["tx"], "legacy identity")
    costs = json.loads(entries["public/controls/legacy-b-costs.json"])
    need(costs["tx"] == run["controls"]["legacy_B"]["tx"], "legacy cost identity")

    graph_receipts = [part for name in packet_names for part in packet_receipts(entries[name])]
    legacy_receipts = list(packet_receipts(legacy))
    all_receipts = graph_receipts + legacy_receipts
    need(len(graph_receipts) == 40 and len(all_receipts) == 42, "receipt population")
    distinct = {
        "complete": len({row[0] for row in all_receipts}),
        "kem": len({row[1] for row in all_receipts}),
        "note": len({row[2] for row in all_receipts}),
        "memo": len({row[3] for row in all_receipts}),
    }
    need(set(distinct.values()) == {42}, "receipt component reuse")
    return {
        "schema": "funded-pq-independent-archive-audit-v1",
        "archive_sha256": archive_sha,
        "regular_members": len(entries),
        "graph_packets": len(packet_names),
        "blocks": len(block_names),
        "graph_receipts": len(graph_receipts),
        "legacy_control_receipts": len(legacy_receipts),
        "distinct_receipt_components": distinct,
        "input_boundary": "all analyzed bytes read directly from the pinned regular-file-only tar archive",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(audit(args.archive.resolve(strict=True)), indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.check.read_text() != encoded:
            raise SystemExit(f"archive audit differs: {args.check}")
        print("Pinned author archive boundary and receipt observations matched.")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
