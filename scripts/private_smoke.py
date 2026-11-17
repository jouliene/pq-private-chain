#!/usr/bin/env python3
"""Fresh-key private credit/payment/receipt/backup-only new-process/new-spend."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse
import importlib.util
import json
import re

RESULT = dict(format='CP03-FRESH-PRIVATE-REPRO01', private_credit_payment_receipt=True,
    fresh_backup_only_restore_and_admitted_spend=True, genuine_proofs_created=3,
    resource_profile_pass=False, whole_protocol_pq_privacy_theorem=False, production_ready=False)
STAGES = {'startup', 'restore-worker', 'wallet-creation', 'genesis', 'credit-proof',
          'credit-admission', 'payer-proof', 'offline-receipt', 'backup-only-new-process',
          'final-history', 'public-artifact-manifest', 'cleanup'}


def exact(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(b, dict):
        return a.keys() == b.keys() and all(exact(a[k], v) for k, v in b.items())
    return a == b


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--approve-installation', required=True)
    parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('private_common', Path(__file__).parent / 'common.py')
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    common.need(re.fullmatch('[a-z][a-z0-9_-]{0,31}', args.attempt) is not None, 'immutable private attempt')
    installation = common.load_installation(args.installation, args.approve_installation)
    source = Path(installation['source_root'])
    workspace = Path(installation['workspace'])
    receipt = workspace / ('private-' + args.attempt + '.json')
    common.need(not receipt.exists(), 'immutable private result')
    claim = workspace / ('private-' + args.attempt + '.claim.json')
    common.save(claim, {'private_stream_logging_or_hashing': False, 'fresh_keys': True})
    operator = installation['operator']
    result, output, errors = common.run_private([installation['node'], '--disable-sigusr1',
        str(source / 'wallet/cp03/cycle.mjs'), operator['path'], operator['sha256'], args.attempt],
        cwd=source, env=installation['proof_environment'], seconds=240, cap=65536)
    passed, stage = False, None
    try:
        # Exact duplicate/nonfinite rejection without routing raw private output
        # through a file or digest. JSON values are fixed public constants only.
        def pairs(items):
            value = {}
            for key, item in items:
                common.need(key not in value, 'duplicate private result key')
                value[key] = item
            return value
        def invalid(_):
            raise ValueError('nonfinite private result')
        passed = (result.get('process_exit') == result.get('wrapper_exit') == 0 and
                  not result.get('timeout') and not errors and
                  exact(json.loads(output, object_pairs_hook=pairs, parse_constant=invalid), RESULT))
        for candidate in STAGES:
            if errors == ('CP03_CYCLE_FAILED ' + candidate + '\n').encode():
                stage = candidate
    except BaseException:
        passed = False
    finally:
        output = errors = None
    stable = False
    try:
        common.hashes(installation['pins'])
        stable = True
    except BaseException:
        passed = False
    common.save(receipt, {'format': 'CP03-PUBLIC-PRIVATE-SMOKE01', 'actual_process': result,
        'passed': passed, 'source_runtime_unchanged': stable, 'fixed_source_failure_stage': stage,
        'private_input_or_raw_output_persisted_or_hashed': False, 'result': RESULT if passed else None,
        'public_workload': str(source / 'experiments/cp03-private-cycle/evidence' /
                               (args.attempt + '.public/workload.json')) if passed else None,
        'membership_dependency': 'local public Ledger; owned-note indices are queried locally',
        'endpoint_dependency': 'independently supplied local validating endpoint; no consensus implementation'})
    common.need(passed, 'private smoke failed; fixed receipt retained')
    print(json.dumps(RESULT, sort_keys=True))


if __name__ == '__main__':
    main()
