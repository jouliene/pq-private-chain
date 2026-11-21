"""Price the fixed N3R1 relation and N3B1 Boolean commit-and-open codec."""
import json
from math import ceil, log2
from relation import DEPTH, example

REPS = 560
SEED = 64
PACKED_OUTPUT = 1
RECEIPT = 1568 + 144 + 16
FRAME = 262144
SIGNATURE = 17088
PROOF_HEADER = 0  # suite selected by enclosing registration


def main():
    circuit = example()
    permutations = sum(circuit.perms.values())
    nonlinear = permutations * 24 * 1600 + sum(circuit.groups.values())
    gate_bytes = ceil(nonlinear / 8)
    private_input = 48 + 32 + 2 * (48 + 8 + 8 + 48 + 5 + DEPTH * 48) + 2 * (48 + 48 + 8 + 8)
    view = SEED + private_input + gate_bytes
    first_message = REPS * (3 * 64 + PACKED_OUTPUT)
    proof = PROOF_HEADER + first_message + REPS * 2 * view
    ordinary = 4 + 1 + 48 + 48 + 8 + 8 + 4 * 48 + 2 * RECEIPT + 4 + proof
    leg = ordinary + 4 + 1 + 48 + 32 + SIGNATURE
    swap = 4 + 2 * 4 + 2 * leg
    # Two passes use the same seed/input shares, first for first messages, then responses.
    wallet_tapes = REPS * 6 * gate_bytes
    node_tapes = REPS * 2 * gate_bytes
    wallet_view_bytes = REPS * 3 * view
    node_view_bytes = REPS * 2 * view
    # One 64-byte seed per party/repetition. 2 witness-share buffers/repetition
    # can be regenerated using separate initial opening randomness (64-byte seed).
    wallet_workspace = (REPS * (4 * SEED) + first_message + 3 * view + 3 * gate_bytes +
                        2 * private_input + 65536)
    node_workspace = first_message + 2 * view + 2 * gate_bytes + 65536
    rates = [10_000_000, 30_000_000, 100_000_000]
    report = {
        "permutations_by_role": dict(circuit.perms), "permutations": permutations,
        "other_AND_by_role": dict(circuit.groups), "other_AND": sum(circuit.groups.values()),
        "all_AND": nonlinear, "per_party_gate_bytes": gate_bytes, "witness_bytes": private_input,
        "view_bytes": view, "first_message_bytes": first_message, "proof_bytes": proof,
        "ordinary_bytes": ordinary, "signed_leg_bytes": leg, "swap_bundle_bytes": swap,
        "signed_leg_excess_over_frame": leg - FRAME, "receipt_bytes": RECEIPT, "repetitions": REPS,
        "challenge_bits": (3**REPS).bit_length()-1,
        "wallet_Keccak_f": 2*REPS*permutations, "node_Keccak_f": REPS*permutations,
        "wallet_tape_bytes": wallet_tapes, "node_tape_bytes": node_tapes,
        "wallet_view_hash_payload_bytes": wallet_view_bytes,
        "node_view_hash_payload_bytes": node_view_bytes,
        "workspace_wallet_algorithmic_B": wallet_workspace, "workspace_node_algorithmic_B": node_workspace,
        "rounding": "decimal bytes and seconds. ceil(bits/8) independently per vector",
        "hypothetical_archive_payload_B_per_year": {str(r): {"ordinary_only": r*ordinary,
                                                              "swap_only": r*swap} for r in rates},
    }
    # DFMS Thm 4.2. Counting one extra query per rehashed view, plus transcript.
    q = 2 * 2**128 + REPS*2 + 4
    bits = report["challenge_bits"]
    fail = (22*3*REPS+60)*q**3/2**512 + 20*q*q*2**(REPS-bits)
    report["ideal_per_statement_extraction_failure_log2_bound"] = round(log2(fail), 3)
    report["ideal_2^40_union_failure_log2_bound"] = round(log2(fail) + 40, 3)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
