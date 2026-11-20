"""Lower the legacy four-child commitment hash to Goldilocks R1CS and compare with the funded reference."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "atomic-swap"))
from swap_wire import pair, split

P = (1 << 64) - (1 << 32) + 1
ONE = {0: 1}
SOURCE_SHA = "54604af022354364c45fbdde106be3f223775992d6fa5685e77c75e66fd970f6"


def add(*terms):
    result = {}
    for term, scalar in terms:
        for column, value in term.items():
            result[column] = (result.get(column, 0) + scalar * value) % P
    return {column: value for column, value in result.items() if value}


class R1CS:
    def __init__(self, public, private):
        self.assignment = [1, *public, *private]
        self.rows = []
        self.multiplications = 0

    def evaluate(self, term, assignment):
        return sum(assignment[c] * v for c, v in term.items()) % P

    def assign(self, a, b):
        value = self.evaluate(a, self.assignment) * self.evaluate(b, self.assignment) % P
        result = {len(self.assignment): 1}
        self.assignment.append(value)
        self.rows.append((a, b, result))
        return result

    def sbox(self, x):
        self.multiplications += 4
        x2 = self.assign(x, x)
        x4 = self.assign(x2, x2)
        x6 = self.assign(x4, x2)
        return self.assign(x6, x)

    def satisfied(self, assignment):
        return all((self.evaluate(a, assignment) * self.evaluate(b, assignment)
                    - self.evaluate(c, assignment)) % P == 0 for a, b, c in self.rows)


def constants(path):
    data = path.read_bytes()
    if sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError("expected qp-poseidon-core 3.1.0 permutation source")
    source = data.decode()

    def array(name, size):
        text = source.split("pub const " + name + ":", 1)[1].split("= [", 1)[1].split("\n];", 1)[0]
        words = [int(v, 16) for v in re.findall(r"0x[0-9a-fA-F]+", text)]
        if len(words) != size:
            raise ValueError("round-constant dimensions")
        return words

    return (array("INITIAL_EXTERNAL_CONSTANTS", 48), array("INTERNAL_CONSTANTS", 22),
            array("MATRIX_DIAG", 12), array("TERMINAL_EXTERNAL_CONSTANTS", 48))


def permute(system, state, parameters):
    initial, internal, diagonal, final = parameters
    matrix = ((2,3,1,1), (1,2,3,1), (1,1,2,3), (3,1,1,2))

    def external(s):
        grouped = [add(*zip(s[off:off+4], row)) for off in (0,4,8) for row in matrix]
        sums = [add(*[(term, 1) for term in grouped[j::4]]) for j in range(4)]
        return [system.assign(add((term, 1), (sums[i%4], 1)), ONE) for i, term in enumerate(grouped)]

    def full_rounds(s, words):
        for start in range(0, 48, 12):
            s = external([system.sbox(add((v, 1), (ONE, rc))) for v, rc in zip(s, words[start:start+12])])
        return s

    state = full_rounds(external(state), initial)
    for rc in internal:
        state[0] = system.sbox(add((state[0], 1), (ONE, rc)))
        total = add(*[(v, 1) for v in state])
        state = [system.assign(add((total, 1), (v, coeff)), ONE) for v, coeff in zip(state, diagonal)]
    return full_rounds(state, final)


def run(source, reference, swap):
    frames = pair(split(swap.read_bytes()))
    # Four already-public, chain-funded output commitments, used in a new four-leaf test tree.
    cms = []
    for frame in frames:
        end = len(frame.leg) - 3584
        pi = frame.leg[end-34*8:end]
        cms.extend([pi[104:136], pi[136:168]])
    record = subprocess.check_output([reference, "4"], input=b"".join(cms)).decode().split()
    if record[:2] != ["4", "1"] or len(record) != 3:
        raise ValueError("native tree reference")
    public = struct.unpack("<4Q", bytes.fromhex(record[2]))
    private = struct.unpack("<16Q", b"".join(sorted(cms)))
    system = R1CS(public, private)
    state = [{} for _ in range(12)]
    message = [{i:1} for i in range(5, 21)] + [ONE] + [{} for _ in range(7)]
    params = constants(source)
    for start in (0, 8, 16):
        state[:8] = [add((a,1), (b,1)) for a,b in zip(state, message[start:start+8])]
        state = permute(system, state, params)
    for j in range(4):
        system.rows.append((state[j], ONE, {1+j:1}))
    if not system.satisfied(system.assignment):
        raise ValueError("R1CS disagrees with upstream commitment tree")
    changed = list(system.assignment)
    changed[1] = (changed[1] + 1) % P
    if system.satisfied(changed):
        raise ValueError("changed public root")
    return {"parameter_source_sha256": SOURCE_SHA, "public_swap_sha256": sha256(swap.read_bytes()).hexdigest(),
            "native_reference_root": record[2], "checked_public_parents": 1,
            "permutations": 3, "sboxes_per_permutation": 118, "sbox_multiplication_rows": system.multiplications,
            "matrix_or_public_equality_rows": len(system.rows)-system.multiplications,
            "total_rows": len(system.rows), "witness_columns_including_private_children": len(system.assignment)-5,
            "matrix_nonzero_coefficients": [sum(len(row[i]) for row in system.rows) for i in range(3)],
            "two_max_depth20_paths_hash_rows_with_intermediate_parent_wires": 40*(len(system.rows)-4),
            "altered_public_root_rejected": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "reference", "swap"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    print(json.dumps(run(a.source, a.reference.resolve(), a.swap), indent=2, sort_keys=True))
