"""Independent prefix occupancy and signed-frame tail, conditional on IID indices."""
import json
import math
import random

HEIGHT = 19
FOLDS = (17, 15, 13, 11, 9, 7)
NONPROOF_SIGNED = 21_014
FRAME = 262_144
SEED = 20261121
TRIALS = 100_000


def body(active):
    # An authenticated tree transmits the unvisited siblings below its public cap.
    def siblings(height):
        return 2 * active[4] + sum(active[5:height]) - active[height]

    initial_leaves = (243 * 8 + 4) * active[HEIGHT]
    fixed = 9 * 16 * 48 + 233 * 32 + 32 * 4 + 4 * 32 + 8
    total = fixed + initial_leaves + 4 * 48 * siblings(HEIGHT)
    for height in FOLDS:
        total += (3 * 32 + 1) * active[height] + 48 * siblings(height)
    return total


def occupancy(indices):
    # A neighbor gap contributes a new prefix starting at the first differing bit.
    ordered = sorted(set(indices))
    starts = [0] * (HEIGHT + 1)
    for a, b in zip(ordered, ordered[1:]):
        first_different = HEIGHT + 1 - (a ^ b).bit_length()
        starts[first_different] += 1
    active = [1]
    for d in range(1, HEIGHT + 1):
        active.append(active[-1] + starts[d])
    return active


def main():
    spaced = [i << (HEIGHT - 5) for i in range(32)]
    largest = body(occupancy(spaced))
    expected_counts = [1.0] + [
        -(2**d) * math.expm1(32 * math.log1p(-2.0**-d)) for d in range(1, HEIGHT + 1)
    ]
    rng = random.Random(SEED)
    above = 0
    for _ in range(TRIALS):
        indices = [rng.getrandbits(HEIGHT) for _ in range(32)]
        if body(occupancy(indices)) + NONPROOF_SIGNED > FRAME:
            above += 1
    prop = above / TRIALS
    z = 1.96
    center = prop + z**2 / (2 * TRIALS)
    radius = z * math.sqrt(prop * (1 - prop) / TRIALS + z**2 / (4 * TRIALS**2))
    scale = 1 + z**2 / TRIALS
    print(json.dumps({
        "max_body_B": largest,
        "max_signed_B": largest + NONPROOF_SIGNED,
        "iid_expected_body_B": round(body(expected_counts), 2),
        "iid_trials": TRIALS,
        "iid_sampler_seed": SEED,
        "iid_above_signed_frame": above,
        "iid_fraction_wilson95": [round((center - radius) / scale, 7),
                                  round((center + radius) / scale, 7)],
    }, indent=2))


if __name__ == "__main__":
    main()
