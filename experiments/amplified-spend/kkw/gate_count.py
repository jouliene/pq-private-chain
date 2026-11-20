"""Evaluate a fixed Boolean Goldilocks x^7 network and price its Picnic3-L5 broadcasts."""
import argparse
import json
from pathlib import Path
import sys
import random

P = 2**64 - 2**32 + 1
PARTIES, EXECUTIONS, OPENED = 16, 601, 68


def bits(value, width):
    return [(value >> i) & 1 for i in range(width)]


def integer(wires):
    return sum(bit << i for i, bit in enumerate(wires))


class Gates:
    def __init__(self):
        self.ands = 0
        self.partial_products = 0

    def binary_and(self, left, right):
        self.ands += 1
        return left & right

    def add(self, left, right, carry=0):
        out = []
        for a, b in zip(left, right, strict=True):
            out.append(a ^ b ^ carry)
            carry = a ^ self.binary_and(a ^ b, a ^ carry)
        return out, carry

    def mul(self, a, b):
        # Rows of the unreduced integer product. Before row j its top bit is below 64+j.
        out = [0] * 128
        for j, bit in enumerate(b):
            row = [self.binary_and(x, bit) for x in a]
            self.partial_products += len(row)
            out[j:j+64], out[j+64] = self.add(out[j:j+64], row)

        # MSB-first restoring division. Each new prefix v=2*r+bit is below 2p.
        remainder = [0] * 64
        complement = bits(~P, 65)
        for bit in reversed(out):
            value = [bit] + remainder
            diff, at_least_p = self.add(value, complement, 1)
            remainder = [a ^ self.binary_and(at_least_p, a ^ b)
                         for a, b in zip(value[:64], diff[:64], strict=True)]
        return remainder

    def sbox(self, x):
        x2 = self.mul(x, x)
        x4 = self.mul(x2, x2)
        start = self.partial_products
        result = self.mul(self.mul(x4, x2), x)
        return result, self.partial_products - start


def check():
    rng = random.Random(20261121)
    cases = [0, 1, 2, 2**32-1, 2**32, 2**63, P-2, P-1] + [rng.randrange(P) for _ in range(32)]
    for x, y in zip(cases, [*reversed(cases[:8]), *cases[9:], cases[8]], strict=True):
        g = Gates()
        assert integer(g.mul(bits(x, 64), bits(y, 64))) == x*y % P
        assert g.ands == 24704 and g.partial_products == 4096
        g = Gates()
        s, lower = g.sbox(bits(x, 64))
        assert integer(s) == pow(x, 7, P)
        assert g.ands == 98816 and lower == 8192
    # The full-adder expression uses just one AND and preserves the integer carry.
    for a in (0, 1):
        for b in (0, 1):
            for c in (0, 1):
                out, carry = Gates().add([a], [b], c)
                assert out[0] + 2*carry == a+b+c
    suites = {}
    for name, perms in (("MNG1", 160), ("SLG1", 164)):
        sboxes = perms * (8*12 + 22)
        gates_floor = sboxes * lower
        suites[name] = dict(permutations=perms, sboxes=sboxes, floor_partial_ANDs=gates_floor,
                            online_B_floor=OPENED*((gates_floor+7)//8),
                            online_B_full_sbox_network=OPENED*((sboxes*g.ands+7)//8))
    path_B = 2*20*3*4*8
    return dict(profile="Picnic3_L5", executions=EXECUTIONS, parties=PARTIES, online_openings=OPENED,
                tested_field_pairs=len(cases), tested_seventh_powers=len(cases), generic_mod_mul_ANDs=24704,
                x7_ANDs=g.ands, non_square_partial_ANDs_per_x7=lower, four_x7_online_B_floor=4*lower*OPENED//8,
                explicit_two_path_masked_input_B_per_opening=path_B,
                explicit_two_path_masked_input_B=OPENED*path_B, suites=suites)


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("enable assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--constants", type=Path, help="also replay the pinned funded frontend shape")
    args = parser.parse_args()
    result = check()
    if args.constants:
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"funded-whir/relation"))
        import frontend
        params = frontend.constants(args.constants)
        for suite, expected in result["suites"].items():
            circuit = frontend.compile_relation(suite, params, frontend.blank(suite))
            assert circuit.permutations == expected["permutations"]
            assert circuit.rows == {"MNG1":136975, "SLG1":140619}[suite]
    print(json.dumps(result, indent=2))
