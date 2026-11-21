"""Read the registered N7P2 profile independently of its proof library."""
from hashlib import sha3_384
from io import BytesIO
import json
from pathlib import Path


def inspect(path):
    raw = path.read_bytes()
    stream = BytesIO(raw)

    def take(width):
        data = stream.read(width)
        if len(data) != width:
            raise ValueError('truncated registration')
        return data

    def word(width=8):
        return int.from_bytes(take(width), 'little')

    def vector():
        return [word() for _ in range(word())]

    def fri():
        rate, cap, queries, work = word(), word(), word(), word(4)
        assert word(1) == 1  # ConstantArityBits
        return [rate, cap, queries, work, word(), word()]

    cap_height = word()
    cap = take(48 * 2**cap_height)
    fixed = take(48)
    wires, routed, arithmetic_constants, configured_security, alpha_count, limit = [word() for _ in range(6)]
    assert (word(1), word(1)) == (1, 1)  # base arithmetic, ZK
    fri_profile = fri()
    trace_bits = word()
    assert fri() == fri_profile
    folds = vector()
    degree_bits, hidden, initial_bits = word(), word(1), word()
    selectors = vector()
    groups = [(word(), word()) for _ in range(word())]
    factor, gate_constraints, constants, stock_pis = [word() for _ in range(4)]
    ks = vector()
    products, lookup_polys, lookup_selectors, lookups, gate_count = [word() for _ in range(5)]
    assert len(ks) == routed and (lookup_polys, lookup_selectors, lookups) == (0, 0, 0)
    # The registered deployment uses six of the upstream default serializer tags plus its own.
    names = {0: ('Arithmetic', True), 2: ('BaseSum', True), 3: ('Constant', True),
             9: ('Noop', False), 14: ('Poseidon2', False), 15: ('PublicInput', False)}
    gates = []
    for _ in range(gate_count):
        tag = word(1)
        if tag == 1:
            name = 'Statement49'
        else:
            assert tag == 0
            name, has_count = names[word(4)]
            if has_count:
                name += '(' + str(word()) + ')'
        gates.append(name)
    assert stream.read() == b'' and gates.count('Statement49') == 1
    ix = gates.index('Statement49')
    low, high = groups[selectors[ix]]
    assert low <= ix < high and routed >= 49 and stock_pis == 0
    degree = high - low - 1 + int(len(groups) > 1) + 1
    rows = 2**trace_bits
    assert trace_bits == degree_bits == initial_bits and hidden and degree <= factor
    fold_product = 2**sum(folds)
    fri_openings = fri_profile[2] * (1 + 4 * sum(2**b-1 for b in folds) + 4 * (rows//fold_product))
    regular, paired = fri_openings + 4, fri_openings + 8
    return dict(bytes=len(raw), sha3_384=sha3_384(raw).hexdigest(), cap_height=cap_height,
                cap_sha3_384=sha3_384(cap).hexdigest(), fixed_digest=fixed.hex(),
                wires=wires, routed_wires=routed, arithmetic_constants=arithmetic_constants,
                configured_security=configured_security, alpha_count=alpha_count, fri=fri_profile,
                fri_fold_bits=folds, trace_rows=rows, leaf_hiding=bool(hidden), gates=gates,
                gate_group_indices=selectors, selector_groups=groups, stock_public_inputs=stock_pis,
                quotient_factor=factor, max_quotient_factor=limit, gate_constraints=gate_constraints,
                constants=constants, partial_products=products, statement_filtered_degree=degree,
                numerator_bound=degree*(rows-1), individual_quotient_bound=degree*(rows-1)-rows,
                regular_blinding_rows=regular, paired_blinding_rows=2*paired)


if __name__ == '__main__':
    location = Path(__file__).resolve().parents[1] / 'proof/registered.vk'
    print(json.dumps(inspect(location), indent=2))
