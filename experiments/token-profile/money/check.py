"""Check monetary interval bounds and existing native verification-key registration."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
GOLDILOCKS = (1 << 64) - (1 << 32) + 1
VALUE_BITS = 62
NATIVE_FEE = 3


def interval(inputs, outputs, *, value_bits=VALUE_BITS, max_fee=0):
    """Independent upper bounds for unsigned inputs and outputs plus fee."""
    largest = (1 << value_bits) - 1
    left = inputs * largest
    right = outputs * largest + max_fee
    return {"inputs": inputs, "outputs": outputs, "value_bits": value_bits,
            "max_fee": max_fee, "max_input_sum": left, "max_output_plus_fee": right,
            "both_sides_below_modulus": max(left, right) < GOLDILOCKS}


def registered_native_keys():
    base = ROOT / 'experiments' / 'delayed-eight' / 'crypto'
    registry = json.loads((base / 'registry.json').read_bytes())
    observed = {name: sha256((base / 'keys' / name).read_bytes()).hexdigest()
                for name in ('direct.vk', 'eight.vk')}
    if observed != registry['key_sha256'] or registry['dimensions']['public_inputs'] != 2 + 8 * 26:
        raise ValueError('native D8 registry mismatch')
    return observed



def registered_token():
    base = ROOT / 'experiments/token-profile/candidate'
    digest = lambda path: sha256(path.read_bytes()).hexdigest()
    key = base / 'registry/token.vk'
    approved = 'f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b'
    receipt = json.loads((base / 'evidence/BUILD.json').read_bytes())
    generated = receipt['generated_sources']
    for name, reference in [('profile.rs', 'registry.rs'), ('wallet.rs', 'wallet.rs')]:
        if digest(base / name) != generated['crates/qnero-prover/examples/token_pair/' + reference]:
            raise ValueError('registered built source mismatch: ' + name)
    if digest(key) != approved or digest(base / 'PROFILE.md') != receipt['registration_design_sha256']:
        raise ValueError('typed key/design registration mismatch')
    registration = json.loads((base / 'evidence/REGISTER.json').read_bytes())
    expected = {'suite': 'TKN1', 'gates_before_blinding': 468, 'degree_bits': 12,
                'folds': [2] * 5, 'public_inputs': 26}
    if registration != expected:
        raise ValueError('typed circuit registration mismatch')
    return {'key_sha256': approved, 'key_bytes': key.stat().st_size, **registration}

def source_parameters(upstream):
    sources = ['qnero-note-core/src/note.rs', 'qnero-circuit/src/circuit.rs',
               'qnero-circuit/src/note_gadget.rs', 'qnero-circuit/src/header.rs',
               'qnero-circuit/src/merkle.rs', 'qnero-circuit/src/chain.rs',
               'qnero-notes/src/encrypt.rs', 'qnero-pqcrypto/src/note_encryption.rs',
               'qnero-aggregator/src/recursive.rs']
    crates = upstream / 'crates'
    note = (crates / sources[0]).read_text()
    if int(re.search(r'pub const VALUE_BITS: u32 = (\d+);', note).group(1)) != VALUE_BITS:
        raise ValueError('unexpected value range')
    return {p: sha256((crates / p).read_bytes()).hexdigest() for p in sources}



def public_vector_example():
    """Benign integer accounting only. Each tuple is (native, token)."""
    inventory = {"payer-a": (40, 70), "payer-b": (9, 0), "receiver-fee": (4, 0)}
    initial = tuple(map(sum, zip(*inventory.values())))
    total_fees = 0
    payments = [("external", ("payer-a", "payer-b"), (0, 17)),
                ("respend", ("external-recipient", "receiver-fee"), (0, 12))]
    for name, input_ids, paid in payments:
        inputs = [inventory.pop(ident) for ident in input_ids]
        native, token = map(sum, zip(*inputs))
        change = (native - paid[0] - NATIVE_FEE, token - paid[1])
        for value in (*paid, *change):
            if not 0 <= value < (1 << VALUE_BITS):
                raise ValueError('synthetic output range')
        inventory[name + '-recipient'] = paid
        inventory[name + '-change'] = change
        total_fees += NATIVE_FEE
    final = tuple(map(sum, zip(*inventory.values())))
    if (final[0] + total_fees, final[1]) != initial or total_fees != 2 * NATIVE_FEE:
        raise ValueError('synthetic accounting induction')
    return {'initial_total_native_token': initial, 'final_total_native_token': final,
            'unspendable_native_fee_sink': total_fees, 'ordinary_transfers': len(payments),
            'mint_burn_subsidy_in_example': 0, 'prover_or_consensus_execution': False}

def report():
    max_value = (1 << VALUE_BITS) - 1
    cases = {
        'DLF1_circuit': interval(2, 2, max_fee=max_value),
        'DLF1_consensus_fee': interval(2, 2, max_fee=NATIVE_FEE),
        'two_scalar_roles_token': interval(1, 2),
        'two_scalar_roles_native': interval(1, 1, max_fee=NATIVE_FEE),
        'two_vector_notes_token': interval(2, 2),
        'two_vector_notes_native': interval(2, 2, max_fee=NATIVE_FEE),
        'three_fungible_inputs_and_outputs': interval(3, 3, max_fee=NATIVE_FEE),
        'four_fungible_inputs_and_outputs': interval(4, 4, max_fee=NATIVE_FEE),
        'four_fungible_inputs_and_outputs_at_61_bits': interval(4, 4, value_bits=61, max_fee=NATIVE_FEE),
    }
    excess = 4 * max_value - GOLDILOCKS
    if excess != (1 << 32) - 5:
        raise ValueError('four-term threshold mismatch')
    if {name for name, data in cases.items() if not data['both_sides_below_modulus']} != {'four_fungible_inputs_and_outputs'}:
        raise ValueError('unexpected monetary interval result')
    return {'modulus': GOLDILOCKS, 'max_62_bit_value': max_value,
            'four_max_values_excess_above_modulus': excess,
            'native_verified_key_sha256': registered_native_keys(), 'per_lane_integer_bounds': cases,
            'registered_token': registered_token(), 'public_two_lane_example': public_vector_example()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, help='public upstream Qnero source checkout to fingerprint')
    args = parser.parse_args()
    result = report()
    if args.upstream:
        result['upstream_source_sha256'] = source_parameters(args.upstream)
    print(json.dumps(result, indent=2, sort_keys=True))
