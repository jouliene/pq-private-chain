"""Independent cheap PUBLIC diagnostic-hash controls; never CP03/Gate3 evidence."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import hashlib
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'experiments/network-feasibility/wallet-witness/stream.py'
raw = SOURCE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '1d8bd4c1b04ff3b73150df717b9961f9bf776ba11b3d401040c7db037d04b0d8'
spec = importlib.util.spec_from_file_location('reviewed_witness01', SOURCE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
D, ZERO = 8, (0,)

def node(level, left, right):
    data = level.to_bytes(2, 'little') + left[0].to_bytes(32, 'little') + right[0].to_bytes(32, 'little')
    return (int.from_bytes(hashlib.sha256(b'PUBLIC-DIAGNOSTIC-NODE' + data).digest(), 'little'),)

def leaf(index):
    return (index + 1,)

def oracle(leaves, targets):
    # Deliberately independent full-width PUBLIC oracle, never passed to algorithm.
    level = leaves + [ZERO] * ((1 << D) - len(leaves))
    paths = {index: [] for index in targets}
    for depth in range(D):
        for index in targets:
            paths[index].append(level[(index >> depth) ^ 1])
        level = [node(depth, level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], {index: tuple(path) for index, path in paths.items()}

frontier = m.SelectiveFrontier(D, node, ZERO, 8)
targets = {0, 1, 2, 5, 13, 63, 127, 255}
leaves = []
for index in range(1 << D):
    frontier.append(leaf(index), f'public-{index}' if index in targets else None)
    leaves.append(leaf(index))
    if index == 20:
        frontier.forget('public-2')
    before = (frontier.count, list(frontier.stack), {k: list(v) for k, v in frontier.paths.items()},
              {k: set(v) for k, v in frontier.wanted.items()})
    root, paths = frontier.view()
    assert before == (frontier.count, frontier.stack, frontier.paths, frontier.wanted)
    expected_root, expected = oracle(leaves, list(frontier.indices.values()))
    assert root == expected_root
    assert all(paths[token] == expected[at] for token, at in frontier.indices.items())
    assert frontier.payload_counts()['wanted_references'] <= 8 * D
    assert frontier.payload_counts()['path_slots'] <= 8 * D
assert 'public-2' not in frontier.paths

g = m.Head(0, b'public-g', 0, oracle([], [])[0])
w = m.WalletWitnesses(g, node, ZERO, depth=D, max_owned=4, rewind_blocks=2, anchor_window=3)
all_leaves = []

def accept(selected=(), spent=()):
    global all_leaves
    prior = w.state.head
    new = tuple(leaf(len(all_leaves) + i) for i in range(2))
    all_leaves += list(new)
    root = oracle(all_leaves, [])[0]
    head = m.Head(prior.height + 1, b'public-h' + bytes([prior.height + 1]), len(all_leaves), root)
    block = m.Block(head.height, prior.identity, head.identity, head.count, head.root, new)
    e = w.epoch(head)
    mapping = dict(selected)
    e.apply(block, lambda index, _: mapping.get(index), spent)
    e.finish()
    return head

first = accept([(0, 'public-A'), (1, 'public-B')])
before = w.witness('public-A')
second = accept([(2, 'public-C')], ['public-A'])
third = accept(spent=['public-B'])
stale = w.epoch(third)
w.rewind(first)
all_leaves = all_leaves[:2]
assert w.witness('public-A') == before and 'public-B' in w.state.frontier.indices
assert 'public-C' not in w.state.frontier.indices
try:
    stale.finish()
except m.WitnessError:
    pass
else:
    raise AssertionError('stale epoch overwrote rewind')
assert w.state.head == first

for _ in range(4):
    accept()
saved = w.state.head
try:
    w.rewind(first)
except m.ReplayRequired:
    pass
else:
    raise AssertionError('deep rewind silently reconstructed missing state')
assert w.state.head == saved
assert not w.anchor_eligible(first.root, first.count)

empty_head = m.Head(saved.height + 1, b'public-empty', saved.count, saved.root)
empty_epoch = w.epoch(empty_head)
try:
    empty_epoch.apply(m.Block(empty_head.height, saved.identity, empty_head.identity,
                             saved.count, saved.root, ()), lambda *_: None)
except m.WitnessError as error:
    assert str(error) == 'bounded nonempty block'
else:
    raise AssertionError('baseline empty-block limitation changed')
assert w.state.head == saved and empty_epoch.phase == 'poisoned'

result = {'format': 'NETWORK-WITNESS-INDEPENDENT-DIAGNOSTIC01', 'passed': True,
          'source_sha256': hashlib.sha256(raw).hexdigest(),
          'diagnostic_depth': D, 'append_prefixes_checked': 256, 'max_selected': 8,
          'checks': ['shared-right-subtree-targets', 'dynamic-late-discovery',
                     'clone-view-does-not-consume-live-frontier', 'forget-removes-waiting-references',
                     'full-tree-terminal-boundary', 'forget-then-rewind-restores-targets',
                     'stale-epoch-after-rewind-rejected', 'deep-rewind-explicit-replay-required',
                     'anchor-window-policy', 'empty-block-current-rejection-atomic'],
          'empty_block_support': False, 'empty_block_is_integration_repair': True,
          'actual_cp03_hash_or_proof_execution': False, 'private_material': False,
          'scope': 'Independent small diagnostic-hash source discriminator only; no Gate3, native or scalar-Poseidon run'}
assert SOURCE.read_bytes() == raw
with (Path(__file__).parent / 'WITNESS_DIAGNOSTIC_ACTUAL01.json').open('x') as f:
    json.dump(result, f, indent=2)
    f.write('\n')
print(json.dumps(result))
