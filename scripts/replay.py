#!/usr/bin/env python3
"""Run the meaningful retained public scenario against the newly built ledger."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse
import importlib.util
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--approve-installation', required=True)
    parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('public_common', Path(__file__).parent / 'common.py')
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    common.need(re.fullmatch('[a-z][a-z0-9_-]{0,31}', args.attempt) is not None, 'immutable public attempt')
    installation = common.load_installation(args.installation, args.approve_installation)
    workspace = Path(installation['workspace'])
    result, output, errors = common.run([sys.executable, '-I', str(workspace / 'replay.py'),
        '--label', args.attempt], cwd=workspace, seconds=650, cap=65536,
        record=workspace / 'results' / ('outer-' + args.attempt))
    common.hashes(installation['pins'])
    common.need(result['process_exit'] == result['wrapper_exit'] == 0 and not errors, 'actual public replay')
    sys.stdout.buffer.write(output)


if __name__ == '__main__':
    main()
