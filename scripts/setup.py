#!/usr/bin/env python3
"""Prepare an immutable local installation from this public checkout only."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse
import importlib.util
import json
import re
import shutil

REPOSITORY = Path(__file__).resolve().parents[1]


def load(name, p):
    spec = importlib.util.spec_from_file_location(name, p)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['prepare', 'discover', 'install', 'build'])
    parser.add_argument('--label', required=True)
    parser.add_argument('--node', type=Path)
    parser.add_argument('--libcrypto', type=Path)
    parser.add_argument('--approve-runtime')
    parser.add_argument('--cargo', type=Path)
    parser.add_argument('--seconds', type=int, default=900)
    args = parser.parse_args()
    common = load('common', REPOSITORY / 'scripts/common.py')
    common.need(re.fullmatch('[a-z][a-z0-9_-]{0,31}', args.label) is not None, 'immutable installation label')
    common.verify_repository(REPOSITORY)
    workspace = REPOSITORY / '.work' / args.label
    if args.mode == 'prepare':
        common.need(not workspace.exists(), 'new immutable installation required')
        workspace.mkdir(parents=True)
        (workspace / '.tmp').mkdir()
        shutil.copytree(REPOSITORY / 'source', workspace / 'source')
        shutil.copytree(REPOSITORY / 'fixtures/cp03-reference', workspace / 'public')
        for origin, target in [('common.py', 'common.py'), ('prepare_runtime.py', 'prepare_runtime.py'),
                               ('replay_checks.py', 'replay.py')]:
            shutil.copyfile(REPOSITORY / 'scripts' / origin, workspace / target)
        (workspace / 'fresh').mkdir()
        cargo = (REPOSITORY / 'Cargo.toml').read_text()
        common.need('path = "source/' in cargo, 'reviewed root Cargo paths')
        (workspace / 'fresh/Cargo.toml').write_text(cargo.replace('path = "source/', 'path = "../source/'))
        shutil.copyfile(REPOSITORY / 'Cargo.lock', workspace / 'fresh/Cargo.lock')
        files = {str(p.relative_to(workspace)): {'sha256': common.sha(p), 'bytes': p.stat().st_size}
                 for p in sorted(workspace.rglob('*')) if p.is_file()}
        common.save(workspace / 'MANIFEST.json', {'format': 'CP03-PUBLIC-WORKSPACE01', 'files': files,
            'repository_core_manifest_sha256': common.sha(REPOSITORY / 'CORE_MANIFEST.json'),
            'private_inputs': False})
        print(json.dumps({'workspace': str(workspace), 'source_files': len(files), 'private_inputs': False}))
        return
    common.need(workspace.is_dir(), 'prepare first')
    common.bind_workspace(workspace)
    common.need(common.read_json(workspace / 'MANIFEST.json')['repository_core_manifest_sha256'] ==
                common.sha(REPOSITORY / 'CORE_MANIFEST.json'), 'public source boundary changed')
    if args.mode in ('discover', 'install'):
        command = [sys.executable, '-I', str(workspace / 'prepare_runtime.py'), args.mode]
        if args.mode == 'discover':
            common.need(args.node is not None and args.libcrypto is not None, 'explicit Node/libcrypto paths')
            command += ['--node', str(args.node), '--libcrypto', str(args.libcrypto),
                        '--output', str(workspace / 'runtime-candidate.json')]
        else:
            common.need(args.approve_runtime is not None, 'explicit reviewed runtime digest')
            command += ['--manifest', str(workspace / 'runtime-candidate.json'),
                        '--approve-runtime', args.approve_runtime]
        result, output, errors = common.run(command, cwd=workspace, seconds=120,
            record=workspace / 'results' / args.mode)
        common.need(result['process_exit'] == result['wrapper_exit'] == 0 and not errors, 'actual runtime ' + args.mode)
        sys.stdout.buffer.write(output)
        return
    common.need(args.cargo is not None and 1 <= args.seconds <= 1800, 'explicit Cargo path and build watchdog')
    build = load('public_build', REPOSITORY / 'scripts/build.py')
    build.build(args, workspace)


if __name__ == '__main__':
    main()
