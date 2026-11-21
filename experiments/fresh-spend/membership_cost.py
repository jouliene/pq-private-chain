"""Membership-only sensitivity of two wallet encodings at 2**40 capacity."""
import json
from math import ceil, log2


def cost():
    # Same full-width child digests and SHAKE256 rate as the shared relation.
    # Try uniform or mixed power-of-two arities up to 256. Price a final padded
    # absorption block even if the input exactly occupies an integer of blocks.
    per_level = {bits: (3 + 64 * (1 << bits)) // 136 + 1 for bits in range(1, 9)}
    best = [0]
    for capacity_bits in range(1, 41):
        best.append(min(best[capacity_bits - width] + permutations
                        for width, permutations in per_level.items()
                        if width <= capacity_bits))
    permutations = 2 * best[40]
    hashed_and_bits = permutations * 24 * 1600
    # Positive terms only. VOLE 256s: tau-1 correction strings plus d.
    vole_floor = 22 * ceil(hashed_and_bits / 8)
    # ZKB++-UR stock L5 repetition count: open one communicated-bit stream
    # and send one length-preserving response hash per execution.
    picnic_floor = 438 * 2 * ceil(hashed_and_bits / 8)
    # Sensitivity only. Upstream fixed single-block Groestl-512 consumes
    # 14 rounds x 128 substitution bytes x (P,Q,P) witness bytes per node.
    groestl_floor = 2 * 40 * 14 * 128 * 3 * 22
    return {
        "shake_absorptions_by_arity": {1 << k: v for k, v in per_level.items()},
        "best_two_paths_permutations": permutations,
        "keccak_chi_ands_two_paths": hashed_and_bits,
        "vole_bit_path_only_bytes_floor": vole_floor,
        "picnic_ur_path_only_bytes_floor": picnic_floor,
        "vole_gf8_fixed_groestl512_two_paths_witness_only_bytes_floor": groestl_floor,
        # Lemma 5.9 in the Picnic v2.2 design. One component of the bound.
        "ur_bad_challenge_log2_upper_at_2pow128_queries_438_rounds":
            round(1 + log2(2**128 + 1) + (438 / 2) * log2(2 / 3), 4),
    }


if __name__ == "__main__":
    print(json.dumps(cost(), indent=2))
