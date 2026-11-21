"""Count public funded fixture bytes at both sides of each statement boundary."""
import argparse
import json
import runpy
import struct
from pathlib import Path

EX = Path(__file__).resolve().parents[2]
OLD = EX / "funded-tcith"
LIMIT = 262_144
RECEIPTS = 2 * 1_792
SIGNED = 107 + 17_088
SHELL = 5 + 4 + RECEIPTS
P = 2**64 - 2**32 + 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def frontier(height, indices):
    nodes = {(1 << height) + i for i in indices}
    result = 0
    while nodes != {1}:
        result += sum((i ^ 1) not in nodes for i in nodes)
        nodes = {i // 2 for i in nodes}
    return result


def parts(s, opened, degree, rows, rho, eta, siblings, repetitions=1):
    # The broadcasts are interpolated from degree+1 points. Known secret and
    # opened values save wire space; one linear secret is determined by its sum.
    d = s + opened - 1
    extra_poly = degree*d + 1 - s - opened
    extra_linear = (2*s + opened - 2) + 1 - s - opened
    return dict(stages=3*64, salts=repetitions*32*opened,
                opened_fields=repetitions*8*rows*opened,
                merkle=repetitions*64*siblings,
                degree_tail=repetitions*8*eta*s,
                nonlinear_tail=repetitions*8*rho*extra_poly,
                linear_secrets=repetitions*8*rho*(s-1),
                linear_other=repetitions*8*rho*extra_linear)


def frames(bundle):
    pos = 5
    result = []
    for _ in range(2):
        length, = struct.unpack_from("<I", bundle, pos)
        pos += 4
        result.append(bundle[pos:pos+length])
        require(len(result[-1]) == length <= LIMIT, "frame extent")
        pos += length
    require(pos == len(bundle), "bundle extent")
    return result


def released(leg, words, tag):
    require(leg[:5] == tag, "released leg ID")
    size, = struct.unpack_from("<I", leg, 5)
    payload = leg[9:9+size]
    require(len(leg) == size+SHELL, "released leg extent")
    count_offset = size - 8*(words+1)
    require(count_offset > 0 and struct.unpack_from("<Q", payload, count_offset) == (words,),
            "embedded public-input vector prefix")
    statement = payload[count_offset+8:]
    require(all(w < P for w, in struct.iter_unpack("<Q", statement)), "noncanonical statement")
    return count_offset, statement


def ordinary_frames(directory):
    result = set()
    for path in (directory / "blocks").glob("*"):
        block = path.read_bytes()
        require(block[:8] == b"ASTPOW01", "funding block ID")
        pos = 214
        for _ in range(block[213]):
            size, = struct.unpack_from("<I", block, pos)
            packet = block[pos+4:pos+4+size]
            pos += 4+size
            if packet[:6] == b"MSP1\x01\x00":
                proof, statement = released(packet[6:], 31, b"MNG1\x01")
                require(len(packet) == 6+SHELL+8+len(statement)+proof, "ordinary extent")
                result.add((len(packet), proof))
        require(pos+8 == len(block), "funding block extent")
    require(len(result) == 1, "ordinary funded transfer geometry")
    return result.pop()


def fixture(directory, expected_wire):
    mixed = (directory / "mixed.swap").read_bytes()
    reference = (directory / "released.swap").read_bytes()
    require(mixed[:5] == b"FTB1\x01" and reference[:5] == b"SWB1\x01", "bundle IDs")
    candidate, peer = frames(mixed)
    old, other = frames(reference)
    # Both bundle signatures change; the peer's complete prepared leg does not.
    require(peer[SIGNED:] == other[SIGNED:], "matched peer")
    proof_size, statement = released(old[SIGNED:], 34, b"SLG1\x01")
    ftl = candidate[SIGNED:]
    size, = struct.unpack_from("<I", ftl, 5)
    require(ftl[:5] == b"FTL1\x01" and ftl[9:9+len(statement)] == statement, "matched 34 public words")
    require(ftl[-RECEIPTS:] == old[-RECEIPTS:], "matched receipts")
    require(len(ftl) == SHELL + 38*8 + size, "candidate extent")
    fixed = sum(parts(117, 32, 7, 533, 5, 33, 0).values())
    siblings, remainder = divmod(size-fixed, 64)
    require(remainder == 0 and 13 <= siblings <= 416, "candidate sibling bytes")
    # The published checker separately derives the query set from the entire
    # context, verifies the Merkle opening and checks every terminal word.
    read = runpy.run_path(str(OLD / "review/readback.py"))["read"]
    src = json.loads((directory / "SOURCE.json").read_bytes())
    checked = read(mixed, bytes.fromhex(src["network"]), bytes.fromhex(src["common"]["tip"]),
                   src["common"]["notes"], bytes.fromhex(src["aux_root"]))
    require(checked == json.loads((OLD / "review" / expected_wire).read_bytes())
            and siblings == checked["merkle_siblings"], "published authenticated frontier")
    ordinary_size, ordinary_body = ordinary_frames(directory)
    return dict(candidate_proof=size, candidate_signed=len(candidate), candidate_siblings=siblings,
                released_proof_body=proof_size, released_with_inputs=proof_size+8+len(statement),
                released_signed=len(old), extra_proof_bytes=size-proof_size,
                extra_signed_bytes=len(candidate)-len(old), mixed_pair=len(mixed),
                released_pair=len(reference), ordinary_frame=ordinary_size,
                ordinary_proof_body=ordinary_body)


def projections():
    wider = json.loads((OLD / "security/WIDER.json").read_bytes())
    result = {}
    for label, prices in wider["pricing"].items():
        for suite, wrapper in (("SLG1", SIGNED+SHELL+42*8), ("MNG1", 6+SHELL+39*8)):
            row = prices[suite]
            p = row["profile"]
            height = p["N"].bit_length()-1
            opened = p["ell"]
            # Evenly spread leaves maximize active nodes at every distance.
            maximum = frontier(height, [i*p["N"]//opened for i in range(opened)])
            require(maximum == p["max_frontier_hashes_per_tree"], "wider frontier")
            size = sum(parts(p["s"], opened, p["degree"], p["leaf_words"], p["rho"],
                             p["eta"], maximum, p["tau"]).values())
            require(size == row["proof_bytes"] and size+wrapper == row["framed_bytes"],
                    "wider projected bytes")
            result[f"{label}_{suite}"] = size+wrapper
        require(prices["signed_pair_bytes"] == 2*result[f"{label}_SLG1"]+13, "wider pair")
    for suite, row in json.loads((OLD / "security/PRICE.json").read_bytes())["single_challenge"]["suites"].items():
        view = 64+8*(row["private_words"]+2*row["multiplications_per_repetition"])
        proof = 480*(2*row["residuals"]*8+3*64+2*view)
        wrapper = SIGNED+SHELL+38*8 if suite == "SLG1" else 6+SHELL+35*8
        require(proof == row["proof_bytes"] and proof+wrapper == row["total_bytes"], "single-challenge price")
        result[f"single_challenge_{suite}"] = proof+wrapper
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("author_public", type=Path)
    parser.add_argument("independent_public", type=Path)
    args = parser.parse_args()
    limits = [frontier(18, indices) for indices in (range(32), [i << 13 for i in range(32)])]
    require(limits == [13, 416], "extremal frontiers")
    costs = [sum(parts(117, 32, 7, 533, 5, 33, n).values()) for n in limits]
    print(json.dumps(dict(min_max_siblings=limits, max_components=parts(117, 32, 7, 533, 5, 33, 416),
                          min_max_proof=costs, min_max_frame=[n+SIGNED+SHELL+304 for n in costs],
                          author=fixture(args.author_public, "WIRE.json"),
                          independent=fixture(args.independent_public, "FRESH_WIRE.json"),
                          projected_frames=projections()), indent=2))
