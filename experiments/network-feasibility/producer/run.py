#!/usr/bin/env python3
"""Bounded Gate2 rolling workload; private worker streams have no log/hash sink."""
import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
PROFILE = REPOSITORY / 'experiments/network-feasibility/GATE2_PROFILE.json'
STAGES = {'preflight', 'key-generation', 'genesis', 'credit-proofs', 'credit-block',
          'ordinary-receipts', 'ordinary-proofs', 'ordinary-block', 'final-history',
          'workload-manifest', 'cleanup'}
SOURCE_FILES = {'run.py', 'driver.mjs', 'retain-init.mjs', 'README.md'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def exact(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
    return actual == expected


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON')
            result[key] = value
        return result

    def bad(_):
        raise ValueError('nonfinite JSON')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True)
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--approve-installation', required=True)
    parser.add_argument('--approve-source', required=True)
    parser.add_argument('--payments', type=int, choices=[2, 96], default=96,
                        help='rolling lanes: diagnostic2x3 or full96x8')
    args = parser.parse_args()
    need(re.fullmatch('[a-z][a-z0-9_-]{0,31}', args.label) is not None, 'exclusive label')
    batches = 3 if args.payments == 2 else 8
    seconds = 360 if args.payments == 2 else 10800
    result = dict(format='CP04-NETWORK-PIPELINE-PRODUCER01', credit_proofs=args.payments,
                  ordinary_proofs=args.payments * batches, accepted_blocks=batches + 1,
                  private_material_or_mapping_persisted=False, resource_profile_pass=False)
    source_path = HERE / 'SOURCE.json'
    need(sha(source_path) == args.approve_source, 'explicit reviewed source approval')
    source = decode(source_path.read_bytes())
    need(source['format'] == 'CP04-NETWORK-PRODUCER-SOURCE03', 'source format')
    need(set(source['files']) == SOURCE_FILES, 'fixed source closure')
    need(source['profile'] == {'path': str(PROFILE.relative_to(REPOSITORY)), 'sha256': sha(PROFILE)},
         'declared Gate2 profile pin')
    pins = {HERE / name: digest for name, digest in source['files'].items()}
    pins[source_path] = args.approve_source
    pins[PROFILE] = source['profile']['sha256']
    need(all(path.is_file() and not path.is_symlink() and sha(path) == digest
             for path, digest in pins.items()), 'source pins')
    profile = decode(PROFILE.read_bytes())
    allocation = profile['generator_allocation']
    need(profile['format'] == 'CP04-GATE2-PROFILE01' and
         profile['workload']['fresh_credit_proofs'] == 96 and
         profile['workload']['fresh_ordinary_proofs'] == 768 and
         profile['workload']['ordinary_blocks'] == 8 and
         profile['workload']['gate3_secret_custody'] is False and
         profile['research_resources']['fresh_validator_retain_raw_body_quota_bytes'] == 2147483648 and
         allocation['diagnostic_lanes'] == 2 and allocation['diagnostic_ordinary_batches'] == 3 and
         allocation['diagnostic_total_proofs'] == 8 and allocation['total_proof_ceiling'] == 864 and
         allocation['diagnostic_watchdog_seconds'] == 360 and allocation['watchdog_seconds'] == 10800 and
         allocation['address_space_limit_bytes'] == 4294967296, 'fixed reviewed profiles')
    helper = REPOSITORY / 'scripts/common.py'
    spec = importlib.util.spec_from_file_location('public_common', helper)
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    installation_path = args.installation.resolve(strict=True)
    installed = common.load_installation(installation_path, args.approve_installation)
    need(Path(installed['repository']) == REPOSITORY, 'this repository installation')
    need(installed['pins'].get(str(helper)) == sha(helper), 'approved lifecycle helper')
    need(str(Path(sys.executable).resolve()) in installed['pins'], 'approved Python')
    parent = HERE / '.work'
    parent.mkdir(exist_ok=True)
    work = parent / args.label
    work.mkdir()
    save(work / 'claim.json', dict(format='CP04-NETWORK-PRODUCER-CLAIM03',
         source_sha256=args.approve_source, profile_sha256=pins[PROFILE],
         installation_sha256=args.approve_installation, proof_job_ceiling=args.payments * (batches + 1),
         rolling_lanes=args.payments, ordinary_batch_count=batches, ordinary_count=args.payments * batches,
         diagnostic=args.payments != 96, private_streams_persisted=False, backup_custody=False))
    receipt, stdout, stderr = common.run_private(
        [installed['node'], '--disable-sigusr1', str(HERE / 'driver.mjs'), args.label,
         str(installation_path), args.approve_installation, str(args.payments)],
        cwd=HERE, env=installed['proof_environment'], seconds=seconds, cap=65536)
    passed, failed_stage = False, None
    try:
        passed = (receipt.get('process_exit') == receipt.get('wrapper_exit') == 0 and
                  not receipt.get('timeout') and not stderr and exact(decode(stdout), result))
        for stage in STAGES:
            if stderr == ('CP04_WORKLOAD_FAILED ' + stage + '\n').encode():
                failed_stage = stage
    except BaseException:
        passed = False
    finally:
        stdout = stderr = None
    stable = False
    try:
        common.load_installation(installation_path, args.approve_installation)
        need(all(sha(path) == digest for path, digest in pins.items()), 'source postcheck')
        stable = True
    except BaseException:
        passed = False
    save(work / 'receipt.json', dict(format='CP04-NETWORK-PRODUCER-RECEIPT03', actual_process=receipt,
         installation_sha256=args.approve_installation, source_sha256=args.approve_source,
         profile_sha256=pins[PROFILE], passed=passed, fixed_source_failure_stage=failed_stage,
         source_runtime_unchanged=stable, raw_private_streams_persisted_or_hashed=False,
         result=result if passed else None,
         scope=('Gate2 fresh96x8 generator' if args.payments == 96 else 'diagnostic2x3 only') +
               '; fixture-local receiving/membership, not Gate3 discovery or node throughput/privacy/PQ assurance'))
    print(json.dumps(result if passed else {'format': 'CP04-NETWORK-PRODUCER-FAILED03'}, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
