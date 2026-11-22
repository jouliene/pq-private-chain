"""Reprice a specified SmallWood+ Compiler 1 component, using public dimensions only."""
from fractions import Fraction
from math import comb, log2


def ceildiv(a, b):
    return (a + b - 1) // b


def expected_siblings(leaves, opened):
    """Exact mean sibling digests sent by a binary multiproof on a uniform subset."""
    assert leaves > 0 and leaves & (leaves - 1) == 0
    subsets = comb(leaves, opened)
    total = Fraction()
    size = 1
    while size < leaves:
        empty = comb(leaves - size, opened)
        both_empty = comb(leaves - 2 * size, opened)
        total += Fraction((leaves // size) * (empty - both_empty), subsets)
        size *= 2
    return total


def local_test_geometry(leaves, pack, error_bits):
    intermediate_bits = 16
    for opened in range(1, leaves - 2 * pack):
        degree_p = pack + opened - 1
        degree_q = 2 * pack + opened - 1
        if (comb(degree_q, opened) << error_bits) <= comb(leaves, opened):
            break
    else:
        raise ValueError("No opening count meets this target")

    # Theorem 1 uses binomial(N,dP+2)/|I|^dimension. In the paper's
    # default sizing the target exponent is lambda. Here we select it explicitly.
    numerator = comb(leaves, degree_p + 2) << error_bits
    dimension = ceildiv((numerator - 1).bit_length(), intermediate_bits)
    assert (1 << (dimension * intermediate_bits)) >= numerator
    assert (1 << ((dimension - 1) * intermediate_bits)) < numerator
    return opened, dimension


def polynomial_bits(witness_elements, field_bits, salt_bits, pack, opened,
                    dimension, paths, full_q, intermediate_bits=16):
    rows = ceildiv(witness_elements, pack)
    degree_p = pack + opened - 1
    degree_q = 2 * pack + opened - 1
    extension = field_bits // intermediate_bits
    assert extension * intermediate_bits == field_bits
    mask_rows = extension * ceildiv(degree_q + 1, degree_p + 1)
    q_elements = degree_q + 1 if full_q else degree_q + 1 - opened
    return ((4 + opened) * salt_bits
            + dimension * (degree_p + 1) * intermediate_bits
            + 2 * salt_bits * paths
            + q_elements * field_bits
            + opened * (rows + mask_rows) * intermediate_bits)


def cico_cost(field_bits, salt_bits, error_bits):
    # Table 1 flattening factor 2 commits the free input and one 1600-bit state.
    # Omit witness/trace masks, trace, and outer messages.
    leaves, pack = 2048, 64
    witness_elements = ceildiv(100 * (1344 + 1600), 16)
    opened, dimension = local_test_geometry(leaves, pack, error_bits)
    paths = expected_siblings(leaves, opened)
    bits = polynomial_bits(witness_elements, field_bits, salt_bits, pack, opened,
                           dimension, paths, False)
    return opened, dimension, float(bits / 8)


def linked_bytes(field_bits, salt_bits, leaves, pack, opened, dimension):
    # Concrete local generic R1CS. Over a larger K decompose every trace
    # coordinate into [K:F] base-field coordinates inside the same LCS.
    trace = 3 * 17 + 5
    elements = 81412 + trace * (field_bits // 16)
    # Current format sends Q in full and one unshared Merkle path per leaf.
    paths = opened * (leaves.bit_length() - 1)
    bits = polynomial_bits(elements, field_bits, salt_bits, pack, opened,
                           dimension, paths, True)
    return (trace * field_bits + bits) // 8


def compare_layouts(field_bits, salt_bits, error_bits):
    best_full = None
    best_shared = None
    for leaves in (512, 1024, 2048, 4096):
        for pack in (16, 32, 64, 128, 256):
            # The ratio p(t+1)/p(t) = (2s+t)/(N-t) gives a minimizing t.
            optimum = (leaves - 2 * pack) // 2
            if optimum < 1:
                continue
            numerator = comb(2 * pack + optimum - 1, optimum) << error_bits
            if numerator > comb(leaves, optimum):
                continue
            opened, dimension = local_test_geometry(leaves, pack, error_bits)
            full = linked_bytes(field_bits, salt_bits, leaves, pack, opened, dimension)
            unshared = opened * (leaves.bit_length() - 1)
            saving = (unshared - expected_siblings(leaves, opened)) * Fraction(salt_bits, 4)
            shared = full - saving
            params = (leaves, pack, opened, dimension)
            if best_full is None or full < best_full[0]:
                best_full = full, params
            if best_shared is None or shared < best_shared[0]:
                best_shared = shared, params
    return best_full, best_shared


def literal_payment_floor(field_bits, error_bits):
    """Necessary communication for a specified binary-circuit-to-R1CS encoding."""
    # One cell for each AND output or private input, omitting constants and trace.
    cells = 3_854_992 + 49_233
    base_bits = 16
    domain_limit = 1 << base_bits
    min_dimension = ceildiv(error_bits, base_bits)
    best = None
    for pack in range(1, domain_limit // 2):
        q_bits = 2 * pack * field_bits
        # All subsequent pack sizes have an even larger cost for Q alone.
        if best is not None and q_bits >= best[0]:
            break
        # Minimum t with (2s/Nmax)^t <= 2^-e. The float seeds a search,
        # then both neighboring inequalities are checked with integers.
        base = 2 * pack
        opened = max(1, int(error_bits / log2(domain_limit / base)))
        while (base ** opened << error_bits) > 1 << (base_bits * opened):
            opened += 1
        while opened > 1 and (base ** (opened-1) << error_bits) <= 1 << (base_bits * (opened-1)):
            opened -= 1
        data = base_bits * opened * ceildiv(cells, pack)
        decs = base_bits * min_dimension * (pack + opened)
        candidate = q_bits + data + decs, pack, opened
        if best is None or candidate < best:
            best = candidate
    return best


def main():
    assert expected_siblings(4, 1) == 2
    assert expected_siblings(4, 2) == Fraction(5, 3)
    assert expected_siblings(4, 4) == 0
    assert linked_bytes(16, 128, 256, 32, 16, 16) == 87760
    print(f"linked_local_bytes={linked_bytes(16, 128, 256, 32, 16, 16)}")
    print("linked_local_negative_log2_errors "
          f"decs={256-log2(comb(256, 49)):.6f} "
          f"opening={log2(comb(256,16))-log2(comb(79,16)):.6f} "
          f"row={16-log2(17):.6f}")
    wide_bits = polynomial_bits(81412 + 56, 256, 256, 32, 84, 4, 84 * 10,
                                True, intermediate_bits=256)
    assert (wide_bits + 56 * 256) // 8 == 6926976
    print(f"linked_wide_bytes={(wide_bits + 56*256)//8}")
    print("linked_wide_negative_log2_errors "
          f"decs={4*256-log2(comb(1024,117)):.6f} "
          f"opening={log2(comb(1024,84))-log2(comb(147,84)):.6f} "
          f"row={256-log2(17):.6f}")
    # Larger hashes, fields, and local-error targets are separate switches.
    for field_bits, salt_bits, error_bits in ((128, 128, 128), (256, 256, 256),
                                               (512, 256, 288), (512, 288, 416)):
        opened, dimension, mean = cico_cost(field_bits, salt_bits, error_bits)
        print(f"CICO K_bits={field_bits} salt_bits={salt_bits} local_bits={error_bits} "
              f"opened={opened} decs_dimension={dimension} partial_mean_bytes={mean:.2f}")
        # Fixed comparison geometry avoids relying on an unavailable optimizer.
        leaves, pack = 2048, 64
        full = linked_bytes(field_bits, salt_bits, leaves, pack, opened, dimension)
        print(f"linked K_bits={field_bits} salt_bits={salt_bits} local_bits={error_bits} "
              f"payload_bytes={full}")
        floor_bits, witness_pack, minimum_t = literal_payment_floor(field_bits, error_bits)
        print(f"literal_payment_floor_bytes={ceildiv(floor_bits, 8)} "
              f"relaxed_minimizer=(s={witness_pack},t={minimum_t})")
        best, shared = compare_layouts(field_bits, salt_bits, error_bits)
        print(f"linked menu_best_bytes={best[0]} at {best[1]} "
              f"menu_best_shared_mean_bytes={float(shared[0]):.2f} at {shared[1]}")
    offers, years, swap_share = 100_000_000, 20, Fraction(1, 10)
    operations = offers * years
    legs = operations * (1 + swap_share)
    for events in (1, legs, 2 * legs):
        loss = log2(events)
        print(f"events={events} log2={loss:.6f} "
              f"unit_q2_loss_bits={256 + loss:.6f} unit_q3_loss_bits={384 + loss:.6f}")
    observed_acceptance = 1 - Fraction(71196, 100000)
    print(f"binary_last_rank_step_expected_draws_at_observed_rate={float(1 / observed_acceptance):.5f}")


if __name__ == "__main__":
    main()
