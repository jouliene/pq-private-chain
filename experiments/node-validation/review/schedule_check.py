"""Independently price named nonuniform guarded 2x2 Construction 10.2 schedules."""

from decimal import Decimal as D, ROUND_CEILING, localcontext
import json

P = 2**64 - 2**32 + 1
K = P**5
DIGEST = 64
ELEMENT = 40
FOLDS = (4, 4, 4, 0)
SCENARIOS = {
    "salted-burst": (4, 6, 7, 8),
    "salted-burst-worst-case": (4, 6, 8, 8),
    "paired-burst": (3, 5, 8, 8),
    "threshold-sensitivity": (7, 10, 11, 12),
    "high-memory": (9, 11, 15, 16),
    "high-memory-salted-pair": (10, 13, 14, 16),
    "extreme-salted-separate": (15, 19, 21, 17),
}


def ceil(value):
    return int(D(value).to_integral_value(rounding=ROUND_CEILING))


def next_power_of_two(x):
    return 1 << (x - 1).bit_length()


def rs(main, aux, fold, exponent):
    spare = 2 if fold else 0
    for q in range(1, 2049):
        d = main + aux + spare + q + 1
        n = next_power_of_two(d) << exponent
        if n > 2**32:
            raise ValueError("unsupported base-field domain")
        rate = D(d - 1) / n
        agreement = (D(d + 1) / n).sqrt() + D(1) / 4096
        missed = agreement**q
        if missed <= D(2)**-131:  # Four stages each at <= 2^-129 / 4.
            break
    else:
        raise ValueError("unavailable query schedule")
    list_size = ceil((1 - rate) / (agreement**2 - rate))
    # Retained Johnson MCA bound. Round m upwards before evaluating the numerator.
    m = D(max(3, ceil(rate.sqrt() / (agreement - rate.sqrt())))) + D("0.5")
    mca = (2 * m**5 + 3 * m * (1 - agreement) * rate) * n / (3 * rate**D("1.5")) + m / rate.sqrt()
    return dict(d=d, n=n, q=q, missed=missed, list_size=list_size, mca=mca, fold=fold)


def expected_path(n, q):
    # At every non-root level a sibling digest is needed iff its own subtree
    # receives no draw and its sibling's subtree receives at least one draw.
    def empty_prob(count):
        return (1 - D(1) / count)**q
    rows = n * (1 - empty_prob(n))
    frontier = D(0)
    pending = n
    while pending > 1:
        frontier += pending * (empty_prob(pending) - empty_prob(pending // 2))
        pending //= 2
    return rows, frontier


def price(exponents):
    main, aux = 2**16, ceil(D(3 + 5 * 22 + 4) / 16)
    stages = []
    for i, (fold, exponent) in enumerate(zip(FOLDS, exponents, strict=True)):
        s = rs(main, aux, fold, exponent)
        stages.append(s)
        if fold:
            next_width = 2**FOLDS[i + 1]
            aux = ceil(D(aux + 2 + s["q"] + 1 + 1) / next_width)
            main //= next_width

    fields = 6 * 21 + 4
    # Body frame, exact expected statement, both encrypted receipts,
    # outer CFW fields and four canonical masked subfield responses.
    separate = paired = unsalted_pair = D(20 + 528 + 2 * 2164 + fields * ELEMENT + 4 * 8)
    worst_separate = worst_paired = int(separate)
    raw_rows = separate_trees = separate_salts = 0
    L0 = stages[0]["list_size"]
    error = L0 * ((D(296448) / P)**4 + D(22 + 5 * 20 + 7) / K + D(5) / (K - 2))
    for i, s in enumerate(stages):
        k, d, n, q, size = (s[key] for key in ("fold", "d", "n", "q", "list_size"))
        trees = 1 if k else 2
        width = 1 << k
        rows, siblings = expected_path(n, q)
        direct = (3 * k + 2) if k else (1 + d)
        separate += trees * (DIGEST + rows * (ELEMENT * width + DIGEST) + siblings * DIGEST) + direct * ELEMENT
        # Final codeword and fresh mask share one two-entry leaf. CF&W 11.1
        # also recovers one coefficient of every inner round polynomial.
        pair_values = rows * trees * width * ELEMENT
        paired_chunk = DIGEST + pair_values + siblings * DIGEST + (direct - k) * ELEMENT
        paired += paired_chunk + rows * DIGEST
        unsalted_pair += paired_chunk
        # The maximum over all query tapes can be attained by spreading leaves
        # across as many parents as possible. These domains have n >> q.
        assert n >= 4 * q
        maximum_frontier = 2 - q + sum(min(2**level, q) for level in range(1, n.bit_length() - 1))
        worst_separate += trees * (DIGEST + q * (width * ELEMENT + DIGEST) + maximum_frontier * DIGEST) + direct * ELEMENT
        worst_paired += DIGEST + q * (trees * width * ELEMENT + DIGEST) + maximum_frontier * DIGEST + (direct - k) * ELEMENT
        raw_rows += n * width * trees * ELEMENT
        separate_trees += (2 * n - 1) * DIGEST * trees
        separate_salts += n * DIGEST * trees
        error += s["missed"]
        if k:
            next_size = stages[i + 1]["list_size"]
            error += (size + (2**k - 1) * s["mca"] + 2 * k * size
                      + D(next_size**2) / 2 * max(d - 1, D(K) / (K - 1))
                      + next_size * (1 + q)) / K
        else:
            error += (s["mca"] + size) / K
    assert error < D(2)**-128
    return {
        "stages": [[s[k] for k in ("n", "d", "q", "list_size")] for s in stages],
        "interactive_error_bits": round(float(-error.ln() / D(2).ln()), 6),
        "expected_salted_separate_B": round(float(separate), 3),
        "expected_salted_paired_B": round(float(paired), 3),
        "expected_unsalted_paired_B": round(float(unsalted_pair), 3),
        "maximum_salted_separate_B": worst_separate,
        "maximum_salted_paired_B": worst_paired,
        "all_rs_value_B": raw_rows,
        "all_separate_merkle_node_B": separate_trees,
        "all_separate_salt_B": separate_salts,
    }


if __name__ == "__main__":
    with localcontext() as ctx:
        ctx.prec = 75
        print(json.dumps({name: price(profile) for name, profile in SCENARIOS.items()}, indent=2))
