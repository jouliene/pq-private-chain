"""Read pinned public inputs and independently check two hiding-WHIR parameter examples."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess

PROJECT = Path(__file__).resolve().parents[3]
SPARTAN = "14d6da4211eda59e65cfd0af5e2dcd89d523edc3"
PROVEKIT = "893f6d5866d52124e12c4a90a71c0f4d625f083b"
SPARTAN_PINS = {
    "src/security.rs": "fe187cb193debfe7c3893c044cda3c7c92b1aef3faedc12828d6074671e4d32d",
    "src/sumcheck.rs": "6ceee388b2a5762d9724f8a4d7c8b7a99c1091fb6f1e5f66abb3261b812ef929",
    "src/protocol.rs": "34abed4f457dfd64b714a8b2500ab1313929b4e73bacb5eba06e46e81521d7ba",
    "testdata/leanvm-full-zk-direct-poseidon2/full_zk_direct_manifest.json":
        "a6442c7015572bea99b08ecdfa85ef277d60adec6eb5adaf9f4ac9ada086132a",
}
PROVEKIT_PINS = {
    "provekit/prover/src/whir_r1cs.rs": "54089166a32283a8bccb63ce7f7f4cb550e092cb2ff72f00000339216173e699",
    "provekit/verifier/src/whir_r1cs.rs": "ca4300ae5abdd5ff30a41810d6440cab1878fd8f32821ea35049627ba603bc33",
    "provekit/common/src/whir_r1cs.rs": "26b3644705e45d47c483c46ac57bc57720269ef8db2ab0e868b32449d187f8f6",
}
P = 2**31 - 2**24 + 1  # KoalaBear


def pinned(root, rev, paths):
    contents = {}
    for path, expected in paths.items():
        data = subprocess.check_output(["git", "-C", root, "show", f"{rev}:{path}"])
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Upstream blob hash mismatch for {path}")
        contents[path] = data
    return contents


def mask_at(x, linear, quadratic):
    return (linear*x + quadratic*x*x - (linear + quadratic)*x**3) % P


def mask_probe():
    # Published upstream application_relation unit vector, whose entries all lie
    # in the prime subfield. All operations here embed identically into EF5.
    points = (2, 3)
    masks = ((1, 2), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13))
    values = (19, 23, 29)
    published = []
    for column, unmasked in enumerate(values):
        coeffs = masks[2*column:2*column + 2]
        assert all(mask_at(x, a, b) == 0 for x in (0, 1) for a, b in coeffs)
        published.append((unmasked + sum(mask_at(x, a, b)
                                         for x, (a, b) in zip(points, coeffs))) % P)
    # Vary each matrix's second linear-independent coefficient at the first
    # round. The three output columns are disjoint, giving a diagonal minor.
    diagonal = mask_at(points[0], 0, 1)
    determinant = pow(diagonal, 3, P)
    assert determinant and all(a != b for a, b in zip(values, published))
    return {"fixture_unmasked": values, "fixture_masked": published,
            "linear_minor_determinant_mod_p": determinant, "rank_of_three_masked_claims": 3,
            "scope": "three terminal matrix claims in isolation; fixed public unit vector"}


def wrapped_main_tree():
    # Only the main-trace Merkle tree; counters are lower bounds even if two
    # different queried positions happened to carry identical salted rows.
    data = (PROJECT / "fixtures/cp03-reference/payer2x2.body").read_bytes()
    assert hashlib.sha256(data).hexdigest() == "8907fff56f7b6418c0752c8160cdbae13e10a0ddb19de884d89e99f924a5abe9"
    start = data.index(b"CPFRI003")
    assert start == 4876 and len(data) - start - 206 == int.from_bytes(data[start+202:start+206], "little")
    # Four-byte degree, three one-digest caps, OOD values and helpers, one
    # batch PoW word, and ten FRI commitment/PoW pairs precede input rows.
    ood = 2*579 + 2*114 + 8*5 + 5
    helpers = (1 + 2 + 8)*5
    head = 4 + 3*64 + (ood+helpers)*40 + 8 + 10*(64+8)
    assert head == 60364
    offset = start + 206 + head
    def batch(at, width):
        rows = [data[at+i*width:at+(i+1)*width] for i in range(160)]
        at += 160*width
        salts = [data[at+i*64:at+(i+1)*64] for i in range(160)]
        at += 160*64
        siblings = int.from_bytes(data[at:at+4], "little")
        assert siblings <= 160*14
        return at + 4 + 64*siblings, len(set(zip(rows, salts))), siblings
    offset, _, _ = batch(offset, 10*8)
    _, leaves, siblings = batch(offset, 584*8)
    # L distinct queried leaves and S frontier hashes require L+S-1 merges
    # to form a single binary root. SHA3-512 absorbs 72 bytes per permutation.
    nodes = leaves + siblings - 1
    leaf_calls = (len(b"PQPC/CP-FRI/01/LEAF\x00") + (584+8)*8 + 8)//72 + 1
    node_calls = (len(b"PQPC/CP-FRI/01/NODE\x00") + 128 + 8)//72 + 1
    return {"distinct_main_salted_rows": leaves, "main_frontier_digests": siblings,
            "minimum_main_binary_merges": nodes, "permutations_per_main_leaf": leaf_calls,
            "permutations_per_binary_node": node_calls,
            "minimum_keccak_f1600_permutations_main_tree": leaves*leaf_calls + nodes*node_calls}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spartan", type=Path)
    parser.add_argument("provekit", type=Path)
    args = parser.parse_args()
    blobs = pinned(args.spartan, SPARTAN, SPARTAN_PINS)
    pinned(args.provekit, PROVEKIT, PROVEKIT_PINS)
    fixture = json.loads(next(v for k, v in blobs.items() if k.endswith(".json")))
    assert fixture["matrix_closing"] == "direct_sparse" and fixture["extension_degree"] == 5
    source_security = blobs["src/security.rs"]
    assert b"pub const MAX_SECURITY_BITS: u32 = 123;" in source_security
    # Published five-fold full-ZK budget. Its setup counts 2r+3 fresh-mask
    # groups and 3r+6+groups commitment events before three-way error splitting.
    n = 5
    events = 3*n + 6 + (2*n + 3)
    slack = (3*events - 1).bit_length()
    assert (events, slack) == (34, 7)
    retained = PROJECT / "source/experiments/compact-challenge-v1/view01/whir/src/pcs/zk/security.rs"
    assert hashlib.sha256(retained.read_bytes()).hexdigest() == "74478ebe997ae7835110fe29bde8fdecbf476b10bdf95753d3d6c528d30d6d7d"
    # Independent geometry in the retained upstream p3-whir security regression.
    # Source oracle dimension grows when privacy randomness is included.
    dimension = 512 + 237
    radius = (1 - dimension / 1024) / 2
    approximation = -237 * math.log2(1 - radius)
    assert abs(approximation - 49.3014934470108) < 1e-10
    print(json.dumps({
        "kind": "pinned-source arithmetic and published-fixture readback",
        "cp03_wrapper_input": wrapped_main_tree(),
        "spartan_commit": SPARTAN, "provekit_commit": PROVEKIT,
        "spartan": {"mask": mask_probe(), "fixture_constraints": fixture["fixture"]["num_constraints"],
                    "fixture_security_target": fixture["setup"]["security"]["security_level_bits"],
                    "fixture_guest_input_bytes": fixture["artifacts"]["guest_input"]["bytes"],
                    "raw_ideal_classical_birthday_exponent_eight_symbols": math.log2(P)*4,
                    "five_fold_commitment_count": events,
                    "five_fold_max_composed_target_after_merkle_slack": 123 - slack},
        "retained_p3_hiding_intermediate": {"message_symbols": 512, "uniform_symbols": 237,
                    "codeword_symbols": 1024, "queries": 237, "pow_bits": 30,
                    "unique_decoding_radius": radius, "query_approx_before_pow_bits": approximation,
                    "query_approx_with_classical_pow_bits": approximation + 30},
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
