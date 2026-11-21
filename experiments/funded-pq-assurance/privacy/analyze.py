"""Compare privacy-relevant fields in the public funded-membership release.

The input is the extracted ``public/`` directory produced by
``experiments/funded-membership/package.py``.  This reader neither accepts nor
opens wallet backups, databases, receipt keys, witnesses, or negotiation files.
It deliberately reports byte equality and public framing only; those
observations are not cryptographic anonymity claims.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import tarfile


OPERATIONS = ("transfer", "fixed", "register", "mint", "burn")
SIGNED = {"register", "mint"}
PROFILES = {
    b"MNG1\x01": (31, "MNG1"),
    b"MNG2\x01": (31, "MNG2"),
    b"MNG3\x01": (32, "MNG3"),
    b"SLG1\x01": (34, "SLG1"),
    b"SLG2\x01": (34, "SLG2"),
    b"SLG3\x01": (35, "SLG3"),
}
RUN_KEYS = {"tips", "operations", "registries", "balances", "asset_ids", "controls", "recovery", "genesis"}
AUTHOR_ARCHIVE_SHA256 = "24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87"
PUBLIC_TOP_LEVEL = {"RUN.json", "SWAP.bin", "blocks", "controls", "packets"}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return sha256(data).hexdigest()


def digest_path(path):
    hasher = sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def archive_public_manifest(archive):
    """Return the complete regular-file manifest below public/ in the archive."""
    manifest = {}
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            need(member.isfile(), "non-regular archive entry")
            parts = Path(member.name).parts
            need(parts and parts[0] == "public" and len(parts) > 1,
                 "archive entry outside public")
            need(not Path(member.name).is_absolute() and
                 all(part not in ("", ".", "..") for part in parts),
                 "unsafe archive entry")
            relative = Path(*parts[1:]).as_posix()
            need(relative not in manifest, "duplicate archive entry")
            extracted = source.extractfile(member)
            need(extracted is not None, "unreadable archive entry")
            raw = extracted.read()
            need(len(raw) == member.size, "archive entry size mismatch")
            manifest[relative] = [member.size, digest(raw)]
    need(manifest, "empty public archive")
    return manifest


def extracted_public_manifest(public):
    manifest = {}
    for path in public.rglob("*"):
        need(not path.is_symlink(), "symlink in public release")
        if path.is_dir():
            continue
        need(path.is_file(), "non-regular public release entry")
        relative = path.relative_to(public).as_posix()
        manifest[relative] = [path.stat().st_size, digest_path(path)]
    return manifest


def receipt(raw):
    need(len(raw) == 1792, "receipt width")
    version, suite, diversifier = struct.unpack_from("<BHI", raw)
    offset = 7
    parts = []
    for expected in (1568, 128, 77):
        size, = struct.unpack_from("<I", raw, offset)
        need(size == expected, "receipt component width")
        offset += 4
        parts.append(raw[offset:offset + size])
        offset += size
    need(offset == len(raw), "receipt trailing bytes")
    return {
        "header": [version, suite, diversifier],
        "kem": parts[0],
        "note": parts[1],
        "memo": parts[2],
        "raw": raw,
    }


def parse_packet(raw):
    swap = raw[:5] in (b"SWF1\x01", b"SWF2\x01", b"SWF3\x01")
    if swap:
        need(len(raw) > 17195, "short swap frame")
        side, payer, expiry = struct.unpack_from("<BBI", raw, 5)
        need(side in (0, 1) and payer in (0, 1) and expiry, "swap header")
        frame = {
            "side": side,
            "payer": payer,
            "expiry": expiry,
            "network": raw[11:43].hex(),
            "terms": raw[43:75].hex(),
            "other_leg_digest": raw[75:107].hex(),
            "signature_sha256": digest(raw[107:17195]),
        }
        inner = raw[17195:]
        operation = "swap-leg"
    else:
        need(raw[:5] in (b"MSP1\x01", b"MSP2\x01", b"MSP3\x01"), "unknown packet")
        need(raw[5] < len(OPERATIONS), "unknown operation")
        operation = OPERATIONS[raw[5]]
        offset = 17166 if operation in SIGNED else 6
        need(len(raw) > offset, "short managed envelope")
        inner = raw[offset:]
        frame = None

    need(len(inner) >= 9 and inner[:5] in PROFILES, "unknown proof profile")
    width, profile = PROFILES[inner[:5]]
    proof_size, = struct.unpack_from("<I", inner, 5)
    end = 9 + proof_size
    need(proof_size and end + 3584 == len(inner), "proof/receipt framing")
    count, = struct.unpack_from("<Q", inner, end - 8 * (width + 1))
    need(count == width, "public vector width")
    public = inner[end - 8 * width:end]
    words = struct.unpack(f"<{width}Q", public)
    nfs = (public[40:72].hex(), public[72:104].hex())
    cms = (public[104:136].hex(), public[136:168].hex())
    need(len(set(nfs)) == len(set(cms)) == 2, "duplicate public identity")
    receipts = (receipt(inner[end:end + 1792]), receipt(inner[end + 1792:]))
    return {
        "packet_sha256": digest(raw),
        "packet_B": len(raw),
        "operation": operation,
        "profile": profile,
        "proof_B_including_public_vector": end - 9,
        "public_words": width,
        "anchor": public[:40].hex(),
        "nullifiers": nfs,
        "commitments": cms,
        "fee": words[21],
        "public_tail": list(words[22:]),
        "receipts": receipts,
        "swap": frame,
    }


def equality(left, right):
    def count(field):
        return len(set(left[field]) & set(right[field]))
    return {
        "anchor_equal": left["anchor"] == right["anchor"],
        "shared_nullifiers": count("nullifiers"),
        "shared_commitments": count("commitments"),
        "shared_complete_receipts": len({r["raw"] for r in left["receipts"]} &
                                        {r["raw"] for r in right["receipts"]}),
        "shared_kem_ciphertexts": len({r["kem"] for r in left["receipts"]} &
                                      {r["kem"] for r in right["receipts"]}),
    }


def analyze(public, archive):
    need(public.is_dir() and not public.is_symlink(), "missing public release directory")
    need({path.name for path in public.iterdir()} == PUBLIC_TOP_LEVEL,
         "unexpected public release entry")
    need(archive.is_file() and not archive.is_symlink(), "release archive file")
    archive_sha = digest_path(archive)
    need(archive_sha == AUTHOR_ARCHIVE_SHA256, "unexpected funded-membership archive")
    archived_files = archive_public_manifest(archive)
    need(extracted_public_manifest(public) == archived_files,
         "extracted public tree differs from pinned archive")
    run_path = public / "RUN.json"
    need(run_path.is_file() and not run_path.is_symlink(), "RUN file type")
    run_raw = run_path.read_bytes()
    run = json.loads(run_raw)
    need(set(run) == RUN_KEYS, "unexpected RUN schema")
    packets = {}
    for path in sorted((public / "packets").iterdir()):
        need(path.is_file() and not path.is_symlink() and path.suffix == ".bin", "packet file type")
        raw = path.read_bytes()
        need(path.stem == digest(raw), "packet filename identity")
        packets[path.stem] = parse_packet(raw)

    labels = {}
    for label, row in run["operations"].items():
        frames = row["frames"]
        need(frames and all(frame in packets for frame in frames), "operation packet missing")
        labels[label] = [packets[frame] for frame in frames]
        need(row["nfs"] == [nf for packet in labels[label] for nf in packet["nullifiers"]],
             "RUN nullifier projection mismatch")

    legacy_path = public / "controls" / "legacy-b.bin"
    need(legacy_path.is_file() and not legacy_path.is_symlink(), "legacy control file type")
    legacy_raw = legacy_path.read_bytes()
    legacy = parse_packet(legacy_raw)
    legacy_row = run["controls"]["legacy_B"]
    need(digest(legacy_raw) == legacy_row["tx"] and list(legacy["nullifiers"]) == legacy_row["nfs"],
         "legacy comparison mismatch")

    retry_group = {
        "legacy_B": legacy,
        "alternate_C": labels["alternate"][0],
        "paid_C": labels["paid"][0],
    }
    retry_comparisons = {}
    retry_names = list(retry_group)
    for i, left in enumerate(retry_names):
        for right in retry_names[i + 1:]:
            retry_comparisons[f"{left}__{right}"] = equality(retry_group[left], retry_group[right])

    graph_receipts = [r for packet in packets.values() for r in packet["receipts"]]
    all_receipts = graph_receipts + list(legacy["receipts"])
    headers = sorted({tuple(r["header"]) for r in all_receipts})
    swap = labels["swap"]
    need(len(swap) == 2 and [p["swap"]["side"] for p in swap] == [0, 1], "swap frame order")
    swap_common = ("payer", "expiry", "network", "terms")
    need(all(swap[0]["swap"][key] == swap[1]["swap"][key] for key in swap_common), "swap pair header")

    later = {}
    for source, spend in (("paid", "onward"), ("onward", "final")):
        a, b = labels[source][0], labels[spend][0]
        later[f"{source}__{spend}"] = {
            "source_commitment_equals_later_nullifier": len(set(a["commitments"]) & set(b["nullifiers"])),
            "source_receipt_equals_later_receipt": len({r["raw"] for r in a["receipts"]} &
                                                       {r["raw"] for r in b["receipts"]}),
            "public_fixture_labels_are_not_a_cryptographic_link": True,
        }

    profile_counts = {}
    for packet in packets.values():
        profile_counts[packet["profile"]] = profile_counts.get(packet["profile"], 0) + 1
    return {
        "format": "FUNDED-PQ-PRIVACY-PUBLIC-OBSERVATIONS-v3",
        "inputs": {
            "archive_sha256": archive_sha,
            "archive_public_files": len(archived_files),
            "exact_archive_tree": True,
            "run_sha256": digest(run_raw),
            "packet_files": len(packets),
            "secret_inputs": 0,
        },
        "proof_and_operation_metadata": {
            "profile_packet_counts": dict(sorted(profile_counts.items())),
            "packet_sizes_B": sorted({packet["packet_B"] for packet in packets.values()}),
            "public_word_widths": sorted({packet["public_words"] for packet in packets.values()}),
            "operation_labels": sorted(run["operations"]),
            "fees": sorted({packet["fee"] for packet in packets.values()}),
        },
        "retry_and_fork_equality": {
            "comparison_packets": {name: {key: row[key] for key in
                ("packet_sha256", "profile", "packet_B", "anchor", "nullifiers", "commitments")}
                for name, row in retry_group.items()},
            "pairwise": retry_comparisons,
            "same_height_competing_C_blocks": run["operations"]["alternate"]["height"] ==
                                               run["operations"]["paid"]["height"] == 25,
            "competing_C_block_ids_distinct": run["operations"]["alternate"]["block"] !=
                                              run["operations"]["paid"]["block"],
            "legacy_packet_absent_from_C_graph": legacy_row["tx"] not in packets,
        },
        "encrypted_receipts": {
            "graph_packet_count": len(graph_receipts),
            "including_legacy_control_count": len(all_receipts),
            "headers": [list(row) for row in headers],
            "component_widths_B": [1568, 128, 77],
            "distinct_complete": len({r["raw"] for r in all_receipts}),
            "distinct_kem": len({r["kem"] for r in all_receipts}),
            "distinct_note": len({r["note"] for r in all_receipts}),
            "distinct_memo": len({r["memo"] for r in all_receipts}),
        },
        "swap_metadata": {
            "frame_sides": [packet["swap"]["side"] for packet in swap],
            "payer": swap[0]["swap"]["payer"],
            "expiry": swap[0]["swap"]["expiry"],
            "network": swap[0]["swap"]["network"],
            "shared_terms_commitment": swap[0]["swap"]["terms"] == swap[1]["swap"]["terms"],
            "fees_by_side": [packet["fee"] for packet in swap],
            "fixed_output_roles": ["counterparty payment", "change"],
        },
        "later_spend_public_equality": later,
        "scope": {
            "observes": "released public packets, RUN projection, byte equality and framing",
            "does_not_test": [
                "recipient identification advantage",
                "proof zero knowledge or knowledge soundness",
                "KEM key privacy or cross-key robustness",
                "wallet error/timing or network metadata",
                "post-compromise secrecy",
            ],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public", type=Path, help="extracted funded-membership public/ directory")
    parser.add_argument("--archive", type=Path, required=True,
                        help="pinned author release archive whose SHA-256 is verified")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze(args.public.resolve(strict=True), args.archive.resolve(strict=True))
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
