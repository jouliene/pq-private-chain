"""PUBLIC regression for revoked wallet capabilities after a deep branch change.

Diagnostic hashes only: this does not generate a payment or establish Gate3.
The previous implementation's actual failure is preserved in
evidence/deep-rewind-counterexample01.json and structural02.sources/stream.py.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import controls as c
from stream import Epoch, ReplayRequired, WalletWitnesses, WitnessError


def rejected(operation, error):
    try:
        operation()
    except error:
        return True
    return False


def run():
    g = c.genesis()
    wallet = WalletWitnesses(g, c.node, c.ZERO, max_owned=4, rewind_blocks=0)
    b1, h1, leaves = c.generated(g, [], (c.leaf(11), c.leaf(12)), b'prefix')
    c.accept(wallet, b1, h1, [(0, 'PUBLIC-OLD-NOTE')])
    saved = wallet.witness('PUBLIC-OLD-NOTE')
    b2, h2, _ = c.generated(h1, leaves, (c.leaf(13), c.leaf(14)), b'old-branch')
    stale = wallet.epoch(h2)
    stale.apply(b2, lambda *_: None)
    before = wallet.revision
    checks = {}
    checks['deep_prefix_requires_replay'] = rejected(lambda: wallet.rewind(g), ReplayRequired)
    checks['branch_revision_revoked_before_replay'] = wallet.revision == before + 1
    checks['active_epoch_aborted_and_released'] = (
        wallet.active_epoch is None and stale.state is None and not stale.history)
    checks['old_committed_state_and_journal_released'] = wallet.state is None and not wallet.history
    checks['old_epoch_cannot_finish'] = rejected(stale.finish, WitnessError)
    checks['old_epoch_cannot_append'] = rejected(lambda: stale.apply(b2, lambda *_: None), WitnessError)
    checks['old_witness_api_revoked'] = rejected(lambda: wallet.witness('PUBLIC-OLD-NOTE'), ReplayRequired)
    checks['old_anchor_api_revoked'] = rejected(lambda: wallet.anchor_eligible(saved.anchor.root, saved.anchor.count), ReplayRequired)
    checks['saved_draft_cannot_be_authorized'] = rejected(
        lambda: wallet.draft_eligible('PUBLIC-OLD-NOTE', saved.anchor.root, saved.anchor.count), ReplayRequired)
    checks['epoch_method_revoked'] = rejected(lambda: wallet.epoch(h2), ReplayRequired)
    checks['direct_epoch_constructor_revoked'] = rejected(lambda: Epoch(wallet, h2), ReplayRequired)
    checks['old_journal_cannot_reactivate'] = rejected(lambda: wallet.rewind(h1), ReplayRequired)
    # A new object must actually replay selected common history. No old path or
    # selection map is supplied to it; the callback models fresh LOCAL discovery.
    fresh = WalletWitnesses(g, c.node, c.ZERO, max_owned=4, rewind_blocks=0)
    replacement, target, selected = c.generated(g, [], (c.leaf(21), c.leaf(22)), b'replacement')
    c.accept(fresh, replacement, target, [(1, 'PUBLIC-REPLAYED-NOTE')])
    found = fresh.witness('PUBLIC-REPLAYED-NOTE')
    checks['fresh_selected_history_replay_works'] = (
        found.anchor == target and found.siblings == c.oracle(selected, [1])[1][1])
    checks['old_owned_token_not_resurrected'] = rejected(lambda: fresh.witness('PUBLIC-OLD-NOTE'), WitnessError)
    return {
        'format': 'WALLET-DEEP-REWIND-REGRESSION01', 'passed': all(checks.values()),
        'checks': checks, 'source_sha256': hashlib.sha256((HERE / 'stream.py').read_bytes()).hexdigest(),
        'diagnostic_hash_not_cp03': True, 'private_material_read_or_recorded': False,
        'genuine_payment_or_gate3_claim': False,
        'scope': 'Prototype lifecycle only; real receipt/opening-map composition is not implemented',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = run()
    with args.output.open('x') as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'passed': result['passed'], 'checks': len(result['checks']), 'diagnostic_hash_not_cp03': True}))
    raise SystemExit(0 if result['passed'] else 1)
