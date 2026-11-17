"""PUBLIC symbolic schedule only: no CP03 hashes, real proofs or private mapping."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from dataclasses import dataclass
import argparse
import hashlib
import json
import re

REPOSITORY = Path(__file__).resolve().parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(text, marker):
    start = text.index(marker)
    at = text.index('{', start)
    level = 1
    end = at + 1
    while level:
        level += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def source_checks():
    paths = ['source/experiments/compact-arities-v3/src/statement.rs',
             'source/experiments/compact-all-payments-v3/src/frame.rs',
             'source/crates/ledger-cp03/src/tree.rs', 'source/crates/ledger-cp03/src/admission.rs',
             'source/crates/ledger-cp03/src/store.rs', 'source/experiments/compact-history-v3/src/body.rs',
             'source/runtime/cp03/source-signature.mjs']
    statement, frame, tree, admission, store, body, signature = [
        (REPOSITORY / path).read_text() for path in paths]
    core = function(statement, 'pub fn core(')
    origins = function(statement, 'pub fn output_origins(')
    fields = set(re.findall(r'self\.([A-Za-z_][A-Za-z0-9_]*)', core))
    assert fields == {'canonical_shape', 'arity', 'nullifiers', 'commitments', 'fee', 'nonce', 'source_id', 'credit', 'chain'}
    assert 'let c = self.core()?' in origins and 'hash::ORIGIN' in origins
    assert not any(word in core + origins for word in ['block_id', 'height', 'parent_id'])
    assert 'v.extend(self.root)' in statement and 'v.extend([self.count, self.credit, self.debit])' in statement
    assert 'bytes.extend(statement)' in frame and 'parsed.projection()' in frame
    append = function(tree, 'pub fn append(')
    node = function(tree, 'pub fn node(')
    assert 'let mut v = origin.to_vec()' in append and 'v.extend(cm)' in append
    assert 'hash::hash(chain, hash::LEAF, &v)' in append
    assert 'height' not in node and 'node(chain, level, &left, &right)' in append
    assert 'if s.count > parent_count' in admission and 'FROM anchors WHERE root=?1 AND leaf_count=?2' in admission
    assert 'admission::verify(tx, installed, parent.leaf_count, body)' in store
    assert store.index('INSERT INTO anchors(height,root,leaf_count)', store.index('for body in &parsed')) > store.index('for body in &parsed')
    assert 'height.saturating_sub(255)' in store
    assert 'hash_blob(b"PROOF",proof' in body and 'hash_blob(b"BODY",prefix.raw' in body
    claim = function(signature, 'export function claimMessage(')
    assert 'statement' in claim and not any(word in claim for word in ['blockId', 'height', 'parentId'])
    return {path: sha(REPOSITORY / path) for path in paths}


@dataclass(frozen=True)
class ToyBody:
    name: str
    anchor_prefix: int
    inputs: tuple
    outputs: tuple
    source: str | None = None


class ScheduleFailure(ValueError):
    def __init__(self, kind, body):
        self.kind, self.body = kind, body
        super().__init__(kind)


def public_model():
    funding = [ToyBody('credit-' + str(i), 0, (), (f'c{i}.0', f'c{i}.1'), 'source-' + str(i)) for i in range(97)]
    groups = [funding]
    prior = [body.outputs for body in funding[1:]]  # Public toy reserve c0, not a real owned mapping.
    prefix = 97
    for batch in range(1, 4):
        rows = [ToyBody(f'b{batch}-{i}', prefix, prior[i], (f'b{batch}.{i}.0', f'b{batch}.{i}.1')) for i in range(96)]
        groups.append(rows)
        prior = [body.outputs for body in rows]
        prefix += 96
    return groups


def simulate(schedule, original):
    # Root identity is a complete PUBLIC toy leaf-prefix tuple, not a CP03 digest.
    # Equality here establishes only ordered-prefix preservation in this model.
    original_leaves = [leaf for body in original for leaf in body.outputs]
    leaves, unspent, cores, sources = [], set(), set(), set()
    anchors = {((), 0): 0}
    funding_anchor = (tuple(original_leaves[:194]), 194)
    bounds = {}
    for height, block in enumerate(schedule, 1):
        assert 1 <= len(block) <= 128
        assert 228 + 68 * len(block) + 2106575 * len(block) <= 256 * 1024**2
        parent_count = len(leaves)
        for transaction in block:
            count = 2 * transaction.anchor_prefix
            if count > parent_count:
                raise ScheduleFailure('AnchorCountExceedsBlockParent', transaction.name)
            anchor = (tuple(original_leaves[:count]), count)
            if anchor not in anchors:
                raise ScheduleFailure('RequiredOrderedPrefixAnchorAbsent', transaction.name)
            if transaction.name in cores or any(leaf not in unspent for leaf in transaction.inputs):
                raise ScheduleFailure('ReplayOrUnavailableInput', transaction.name)
            if transaction.source is not None:
                if transaction.source in sources:
                    raise ScheduleFailure('SourceAlreadyConsumed', transaction.name)
                sources.add(transaction.source)
            cores.add(transaction.name)
            unspent.difference_update(transaction.inputs)
            leaves.extend(transaction.outputs)
            unspent.update(transaction.outputs)
        anchors[tuple(leaves), len(leaves)] = height
        anchors = {key: at for key, at in anchors.items() if at >= max(0, height - 255)}
        if height in (256, 257):
            bounds[str(height)] = funding_anchor in anchors
    assert set(('c0.0', 'c0.1')) <= unspent
    return {'tip_height': height, 'funded_occurrences': len(leaves), 'body_count': len(cores),
            'reserve_outputs_unspent': 2, 'funding_anchor_publication_height': 1,
            'funding_anchor_eligible_at_tips': bounds, 'funding_anchor_eligible_at_final_tip': funding_anchor in anchors,
            'ordinary_anchors_latest_inclusion_age': 96,
            'ordered_leaf_prefix_equal_to_original': leaves == original_leaves}


def rejected(schedule, original):
    try:
        simulate(schedule, original)
    except ScheduleFailure as error:
        return {'kind': error.kind, 'public_toy_body': error.body}
    raise AssertionError('invalid public toy schedule unexpectedly accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    pins = source_checks()
    groups = public_model()
    original = [body for group in groups for body in group]
    schedule = [tuple(groups[0])] + [(body,) for group in groups[1:] for body in group]
    valid = simulate(schedule, original)
    assert valid['tip_height'] == 289 and valid['funded_occurrences'] == 770
    assert valid['funding_anchor_eligible_at_tips'] == {'256': True, '257': False}
    assert not valid['funding_anchor_eligible_at_final_tip']
    reordered = list(schedule)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    premature = list(schedule)
    premature[96], premature[97] = premature[97], premature[96]
    merged = schedule[:96] + [schedule[96] + schedule[97]] + schedule[98:]
    duplicated = schedule[:2] + [schedule[1]] + schedule[2:]
    negatives = {'swap_within_batch_changes_later_anchor': rejected(reordered, original),
        'move_next_batch_before_boundary': rejected(premature, original),
        'merge_away_required_anchor_boundary': rejected(merged, original),
        'duplicate_body_is_not_distinct_traffic': rejected(duplicated, original)}
    assert all(sha(REPOSITORY / name) == digest for name, digest in pins.items())
    result = {'format': 'WALLET-WITNESS-REBLOCK-SCHEDULE01', 'passed': True,
        'source_pins': pins, 'planned_three_batch_schedule': valid, 'counterexamples': negatives,
        'original_block_groups': 4, 'reblocked_groups': 289, 'changing_root_steps_after_reserve_funding': 288,
        'reserve_requires_successor_workload_design_before_proof_generation': True,
        'real_private_backup_custody_not_demonstrated': True,
        'genuine_bodies_or_private_material_consumed': 0, 'native_hashes_or_proofs_executed': False,
        'real_reblocking_or_expiry_admission_executed': False, 'gate3_acceptance': False,
        'scope': 'Source-correspondence and PUBLIC symbolic schedule only; actual unchanged-body replay and private reserve recovery remain mandatory'}
    with args.output.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'passed': True, 'symbolic_reblocked_height': 289, 'counterexamples': len(negatives), 'gate3_acceptance': False}))


if __name__ == '__main__':
    main()
