"""Fast PUBLIC structural controls. Diagnostic hashes are not CP03/Gate3 evidence."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse
import hashlib
import json
sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream import Block, Head, ReplayRequired, SelectiveFrontier, WalletWitnesses, WitnessError

DEPTH = 40
ZERO = (0,) * 8


def pack(value):
    return b''.join(word.to_bytes(8, 'little') for word in value)


def diagnostic(role, payload):
    raw = hashlib.sha3_512(role + payload).digest()
    return tuple(int.from_bytes(raw[i:i + 8], 'little') for i in range(0, 64, 8))


def node(level, left, right):
    return diagnostic(b'DIAGNOSTIC-ONLY-NODE', level.to_bytes(2, 'little') + pack(left) + pack(right))


def leaf(number):
    return diagnostic(b'DIAGNOSTIC-ONLY-LEAF', number.to_bytes(8, 'little'))


def oracle(leaves, wanted):
    """Full sparse tree kept ONLY by this public test generator/oracle."""
    empties = [ZERO]
    levels = [dict(enumerate(leaves))]
    for level in range(DEPTH):
        empties.append(node(level, empties[-1], empties[-1]))
        previous = levels[-1]
        parents = {}
        for index in {child // 2 for child in previous}:
            parents[index] = node(level, previous.get(2 * index, empties[level]),
                                  previous.get(2 * index + 1, empties[level]))
        levels.append(parents)
    root = levels[-1].get(0, empties[-1])
    return root, {index: tuple(levels[level].get((index >> level) ^ 1, empties[level])
                               for level in range(DEPTH)) for index in wanted}


def genesis():
    return Head(0, b'public diagnostic genesis', 0, oracle([], [])[0])


def generated(parent, prior_leaves, additions, tag):
    leaves = prior_leaves + list(additions)
    root, _ = oracle(leaves, [])
    height = parent.height + 1
    identity = hashlib.sha3_512(parent.identity + tag + height.to_bytes(8, 'little') + pack(root)).digest()
    block = Block(height, parent.identity, identity, len(leaves), root, tuple(additions))
    return block, Head(height, identity, len(leaves), root), leaves


def accept(wallet, block, head, selected=(), spent=()):
    epoch = wallet.epoch(head)
    selected = dict(selected)
    epoch.apply(block, lambda index, _value: selected.get(index), spent)
    epoch.finish()


def rejection(operation, expected=WitnessError):
    try:
        operation()
    except expected:
        return
    raise AssertionError('negative control unexpectedly accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    checks = []
    g = genesis()
    wallet = WalletWitnesses(g, node, ZERO, max_owned=4, rewind_blocks=8)
    all_leaves, head = [], g
    old_anchor = None
    peak = {'frontier_digests': 0, 'path_slots': 0, 'wanted_references': 0, 'empty_digests': 0}
    for height in range(1, 261):
        block, head, all_leaves = generated(head, all_leaves, (leaf(2 * height), leaf(2 * height + 1)), b'main')
        selected = [(index, token) for index, token in [(0, 'old-unspent'), (1, 'later-spent'), (257, 'late-discovery')]
                    if block.count - 2 <= index < block.count]
        accept(wallet, block, head, selected, ['later-spent'] if height == 150 else [])
        if height == 1:
            old_anchor = head
        wanted = wallet.state.frontier.indices
        oracle_root, oracle_paths = oracle(all_leaves, wanted.values())
        assert oracle_root == head.root
        for token, index in wanted.items():
            witness = wallet.witness(token)
            assert witness.index == index and witness.siblings == oracle_paths[index] and witness.anchor == head
        values = wallet.state.frontier.payload_counts()
        peak = {key: max(peak[key], value) for key, value in values.items()}
        assert len(wallet.history) <= 9 and len(wallet.state.anchors) <= 256
        if height == 256:
            assert wallet.anchor_eligible(old_anchor.root, old_anchor.count)
        if height == 257:
            assert not wallet.anchor_eligible(old_anchor.root, old_anchor.count)
    assert wallet.draft_eligible('old-unspent', head.root, head.count)
    assert not wallet.draft_eligible('old-unspent', old_anchor.root, old_anchor.count)
    rejection(lambda: wallet.witness('later-spent'))
    assert peak['frontier_digests'] <= DEPTH + 1 and peak['path_slots'] <= 4 * DEPTH
    assert peak['wanted_references'] <= 4 * DEPTH
    checks += ['260-changing-root-refreshes', 'late-dynamic-discovery-without-history-vector',
               'public-full-oracle-path-equivalence', 'spent-note-removed',
               'height256-old-anchor-eligible-height257-expired-policy', 'current-anchor-old-note-refreshed',
               'bounded-frontier-owned-and-rewind-state']

    # Branch A spends common-prefix A and discovers orphan-only B. Rewind must
    # restore A and remove B before accepting replacement branch C.
    fork = WalletWitnesses(g, node, ZERO, max_owned=4, rewind_blocks=8)
    prefix_block, prefix, prefix_leaves = generated(g, [], (leaf(1000), leaf(1001)), b'prefix')
    accept(fork, prefix_block, prefix, [(0, 'common-A')])
    before = fork.witness('common-A')
    a_block, a_head, _ = generated(prefix, prefix_leaves, (leaf(1002), leaf(1003)), b'old-branch')
    accept(fork, a_block, a_head, [(2, 'orphan-B')], ['common-A'])
    rejection(lambda: fork.witness('common-A'))
    assert fork.witness('orphan-B').index == 2
    stale = fork.epoch(a_head)
    fork.rewind(prefix)
    assert fork.witness('common-A') == before
    rejection(lambda: fork.witness('orphan-B'))
    c_block, c_head, c_leaves = generated(prefix, prefix_leaves, (leaf(2002), leaf(2003)), b'replacement')
    accept(fork, c_block, c_head, [(2, 'replacement-C')])
    assert fork.draft_eligible('common-A', prefix.root, prefix.count)
    assert not fork.draft_eligible('common-A', a_head.root, a_head.count)
    assert not fork.draft_eligible('orphan-B', prefix.root, prefix.count)
    rejection(stale.finish)
    assert fork.witness('common-A').siblings == oracle(c_leaves, [0])[1][0]
    checks += ['rewind-restores-common-prefix-unspentness', 'orphan-discovery-and-witness-removed',
               'replacement-branch-refresh', 'orphan-only-anchor-rejected',
               'old-branch-draft-with-eligible-common-prefix-retained', 'stale-epoch-cannot-overwrite-branch']

    # Each malformed epoch leaves the committed object exactly unchanged.
    current = fork.witness('common-A')
    good, good_head, _ = generated(c_head, c_leaves, (leaf(3000), leaf(3001)), b'next')
    for malformed in [Block(good.height + 1, good.parent, good.identity, good.count, good.root, good.leaves),
                      Block(good.height, b'wrong parent', good.identity, good.count, good.root, good.leaves),
                      Block(good.height, good.parent, good.identity, good.count + 1, good.root, good.leaves),
                      Block(good.height, good.parent, good.identity, good.count, ZERO, good.leaves)]:
        epoch = fork.epoch(good_head)
        rejection(lambda: epoch.apply(malformed, lambda *_: None))
        rejection(epoch.finish)
        assert fork.witness('common-A') == current
    wrong_endpoint = Head(good_head.height, b'wrong endpoint', good_head.count, good_head.root)
    epoch = fork.epoch(wrong_endpoint)
    epoch.apply(good, lambda *_: None)
    rejection(epoch.finish)
    assert fork.witness('common-A') == current
    rejection(lambda: fork.rewind(Head(0, b'not common genesis', 0, g.root)), ReplayRequired)
    # The long chain dropped its ancient private snapshot: no silent full-tree
    # lookup is available as a fallback, even though the test oracle still has it.
    rejection(lambda: wallet.rewind(old_anchor), ReplayRequired)
    limited = WalletWitnesses(g, node, ZERO, max_owned=1)
    epoch = limited.epoch(prefix)
    rejection(lambda: epoch.apply(prefix_block, lambda index, _: str(index)))
    assert limited.state.head == g
    checks += ['ordering-parent-count-root-failures-atomic', 'wrong-endpoint-no-published-view',
               'unknown-common-prefix-rejected', 'deep-rewind-explicit-replay-required',
               'owned-capacity-overflow-aborts-without-dropping-note']
    result = {'format': 'WALLET-WITNESS-STRUCTURAL-CONTROLS01', 'passed': True, 'checks': checks,
        'changing_roots': 260, 'maximum_algorithm_payload_counts': peak,
        'rewind_checkpoint_cap': 9, 'recent_anchor_cap': 256,
        'full_oracle_retained_only_in_test': True, 'algorithm_has_file_or_network_api': False,
        'diagnostic_hash_not_cp03': True, 'actual_wallet_discovery': False,
        'genuine_new_proof_or_admission': False, 'actual_gate3_expiry_or_reorg_acceptance': False,
        'private_material_read_or_recorded': False,
        'scope': 'Public structural controls only; no resource profile, real wallet integration or Gate3 PASS'}
    with args.output.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'passed': True, 'checks': len(checks), 'diagnostic_hash_not_cp03': True}))


if __name__ == '__main__':
    main()
