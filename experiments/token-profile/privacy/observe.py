"""Compare named, previously verified public research transcripts. No wallet or decryption keys."""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import io
from itertools import combinations
import json
from pathlib import Path
import struct
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
D8 = ROOT / "experiments/delayed-eight"
sys.path.insert(0, str(D8 / "review"))
from retained import sections
from certificate import layout, read_certificate
from ledger import sid

DIRECT_DIGEST = "b1b757c8620bed2fc8ff533e918c8282f08f056f0b80375e92708d8d54d0d436"
DIRECT_RELEASE = "https://github.com/jouliene/pq-private-chain/releases/download/payment-proof-architecture-2026-11-19/independent-clean.tar.gz"
CT = 1792


@dataclass(frozen=True)
class Public:
    anchor: bytes
    height: int
    nullifiers: tuple
    commitments: tuple
    receipts: tuple


def effect(body):
    assert len(body) == 172 + 2 * CT and int.from_bytes(body[164:172], "little") == 3
    return Public(body[:32], int.from_bytes(body[32:36], "little"),
                  (body[36:68], body[68:100]), (body[100:132], body[132:164]),
                  (body[172:172+CT], body[172+CT:]))


def packet(body, magic):
    assert body[:5] == magic + b"\x01"
    size = int.from_bytes(body[5:9], "little")
    assert len(body) == size + 9 + 2 * CT and int.from_bytes(body[9+size-216:9+size-208], "little") == 26
    pi = body[9+size-208:9+size]
    assert int.from_bytes(pi[32:40], "little") < 2**32
    return effect(pi[:36] + pi[40:176] + body[9+size:])


def components(receipt):
    version, suite, index = struct.unpack_from("<BHI", receipt)
    assert (version, suite, index) == (1, 1, 0)
    offset = 7
    fields = []
    for expected in (1568, 128, 77):
        size, = struct.unpack_from("<I", receipt, offset)
        assert size == expected
        offset += 4
        fields.append(receipt[offset:offset+size])
        offset += size
    assert offset == CT
    return fields


def intersection(a, b):
    return dict(equal_anchor=a.anchor == b.anchor, shared_nf=len(set(a.nullifiers) & set(b.nullifiers)),
                same_nf_positions=[i for i in range(2) if a.nullifiers[i] == b.nullifiers[i]],
                shared_cm=len(set(a.commitments) & set(b.commitments)),
                shared_receipts=len(set(a.receipts) & set(b.receipts)),
                shared_encapsulations=len({components(c)[0] for c in a.receipts} &
                                          {components(c)[0] for c in b.receipts}))


def retry_chain(bodies):
    rows = [packet(b, b"APV2") for b in bodies]
    observed = [intersection(a, b) for a, b in combinations(rows, 2)]
    assert all(r == dict(equal_anchor=False, shared_nf=1, same_nf_positions=[0], shared_cm=0,
                         shared_receipts=0, shared_encapsulations=0) for r in observed)
    return dict(packet_sha256=[sha256(b).hexdigest() for b in bodies],
                public_anchor_heights=[p.height for p in rows], distinct_packets=len(set(bodies)),
                all_pairwise_comparisons=observed)


def direct(blob):
    assert sha256(blob).hexdigest() == DIRECT_DIGEST
    payments = {}
    with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
        info = json.load(archive.extractfile("core/RUN.json"))
        for bid in sorted(set(info["orphan"]) | set(info["selected"])):
            raw = archive.extractfile(f"core/blocks/{bid}.bin").read()
            assert raw[:8] == b"PQDEVBL1"
            prefix = sha256(b"PQDEV1/template\0" + raw[:-8]).digest()
            assert sha256(b"PQDEV1/work\0" + prefix + raw[-8:]).hexdigest() == bid
            off = 214
            for _ in range(raw[213]):
                n, = struct.unpack_from("<I", raw, off)
                off += 4
                body = raw[off:off+n]
                payments[sha256(body).hexdigest()] = packet(body, b"DLF1")
                off += n
            assert off + 8 == len(raw)
    alt = info["orphan_payment"]
    left, right = info["concurrent"]
    collision = intersection(payments[alt["tx"]], payments[left["tx"]])
    independent = intersection(payments[right["tx"]], payments[left["tx"]])
    assert collision["same_nf_positions"] == [0, 1] and collision["shared_nf"] == 2
    assert independent["shared_nf"] == 0 and independent["equal_anchor"]
    assert all(r["shared_cm"] == r["shared_receipts"] == r["shared_encapsulations"] == 0
               for r in (collision, independent))
    return dict(capture_sha256=DIRECT_DIGEST, distinct_packets=len(payments),
                txids=[p["tx"] for p in (alt, left, right)], competing_public_authorizations=collision,
                independently_funded_same_anchor=independent)


def delayed():
    archive = (D8 / "evidence/retained.d8").read_bytes()
    _, sources = sections(archive)
    cert, = (x for x in sources if x[:4] == b"D8C1")
    outsider, = (x for x in sources if x[:4] == b"DLF1")
    key = (D8 / "crypto/keys/eight.vk").read_bytes()
    rows = read_certificate(cert, layout(key))
    record = json.loads((D8 / "evidence/CAPTURE.json").read_bytes())
    assert [sid(row).hex() for row in rows] == [p["sid"] for p in record["payments"]]
    slots = [effect(row) for row in rows] + [packet(outsider, b"DLF1")]
    observations = [intersection(a, b) for a, b in combinations(slots, 2)]
    assert all(r["shared_nf"] == r["shared_cm"] == r["shared_receipts"] == r["shared_encapsulations"] == 0
               for r in observations)
    components_seen = list(zip(*(components(c) for p in slots for c in p.receipts)))
    return dict(archive_sha256=sha256(archive).hexdigest(), ordered_SIDs_agree_with_original_send_log=True,
                public_payments=len(slots), cross_payment_pairs=len(observations),
                equal_nullifier_pairs=sum(bool(r["shared_nf"]) for r in observations),
                distinct_ciphertexts=len({c for p in slots for c in p.receipts}),
                distinct_components_by_KEM_payload_memo=[len(set(group)) for group in components_seen],
                public_header_version_suite_diversifier=[1, 1, 0], receipt_B=CT)


def run(archive):
    simple = ROOT / "devnet/evidence/live"
    ids = [x["packet"] for x in json.loads((simple / "LIVE.json").read_bytes())["attempts"]]
    first = [(simple / "packets" / (i + ".bin")).read_bytes() for i in ids]
    assert [sha256(b).hexdigest() for b in first] == ids
    clean = ROOT / "devnet/wallet-review/evidence/clean"
    ids = json.loads((clean / "WALLET.json").read_bytes())["live_intent"]["attempts"]
    with tarfile.open(clean / "public-capture.tar.gz") as tar:
        second = [tar.extractfile("attempts/" + name + ".bin").read() for name in ids]
    assert [sha256(b).hexdigest() for b in second] == ids
    return dict(revision_of_captures="9c21c2b4297657b8c4cca219c4c480910557d00e",
                APV2_stale=retry_chain(first), APV2_pinned_intent=retry_chain(second),
                DLF1_fork=direct(archive), D8C1_public=delayed())


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Use without -O so transcript invariants are checked.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direct-archive", type=Path)
    args = parser.parse_args()
    if args.direct_archive:
        blob = args.direct_archive.read_bytes()
    else:
        with urllib.request.urlopen(DIRECT_RELEASE, timeout=30) as response:
            blob = response.read(1_533_078)
    print(json.dumps(run(blob), sort_keys=True, indent=2))
