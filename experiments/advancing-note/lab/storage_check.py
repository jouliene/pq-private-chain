"""Crash just after publishing a genuine block; recover and reverse it from public data."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
CRASH_STATUS = 19


def worker(phase):
    sys.path.insert(0, str(HERE))
    from common import Arithmetic, PublicVerifier, need, pack, parse
    from state import BlockStore, BranchIndex, MINER, replay

    folder = Path('/public')
    raw = Path('/item').read_bytes()
    with (BlockStore(folder) as store, BranchIndex(folder / '.n7-index.sqlite') as index,
          Arithmetic() as arith, PublicVerifier() as verifier):
        db = replay(arith, folder, verifier, index)
        if phase == 'reverse':
            need(db.height == 10, 'expected ten released blocks')
            deep = 0
            for _ in range(9):
                deep += int(not db.undo)
                db.revert(store)
            need(deep == 1 and db.height == 1, 'deep disconnect path')
            print(json.dumps(dict(deep_rebuilds=deep, state=db.summary())))
            return
        if phase == 'restart':
            need(db.height == 1, 'expected disconnected branch after restart')
            print(json.dumps(db.summary()))
            return
        packet = raw[180:]
        leg = parse(packet, db.genesis)
        need(leg['kind'] == 0, 'expected an ordinary first payment')
        if phase == 'crash':
            need(db.height == db.spent_count == 0, 'crash fixture must start at genesis')

            def terminate_after_fsync(block, height):
                store.publish(block, height)
                os._exit(CRASH_STATUS)

            db.accept(raw, terminate_after_fsync)
            raise RuntimeError('crash point not reached')

        statement = leg['statement']
        nfs = list(map(pack, statement['nullifiers']))
        cms = list(map(pack, statement['outputs']))
        before = db.summary()
        need(before['height'] == 1 and before['spent'] == 2, 'durable payment missing')
        need(sum(before['miner_fees'].values()) == statement['fee'] == 3, 'wrong recovered fee')
        need(all(index.contains('spent', [key]) for key in nfs), 'missing recovered nullifier')
        need(all(index.contains('commitments', [key]) for key in cms), 'missing recovered output')
        try:
            db.accept(db.mine(packet, MINER), store.publish)
        except ValueError as error:
            need('spent' in str(error), 'unexpected duplicate rejection')
        else:
            raise ValueError('accepted recovered payment twice')
        need(db.summary() == before, 'duplicate changed recovered state')

        db.revert(store)
        need(db.height == db.spent_count == 0 and not index.fees(), 'incomplete disconnect')
        need(not index.contains('spent', nfs), 'remaining disconnected input')
        need(not index.contains('commitments', cms), 'remaining disconnected output')
        db.accept(raw, store.publish)
        need(before == db.summary(), 'reinclusion did not reconstruct payment state')
        print(json.dumps(dict(crash_exit=CRASH_STATUS, recovered_height=before['height'],
                              recovered_spent=before['spent'], recovered_fee=statement['fee'],
                              duplicate_rejected=True, disconnect_reinclusion=True,
                              index_stat=index.stat(), state=before), sort_keys=True))


def check(binary, node, public, founding_id):
    bindings = [(name, name) for name in ('/usr', '/lib', '/lib64', '/bin', '/etc/ld.so.cache')]
    bindings.extend([(binary.resolve(strict=True), '/circuit'), (HERE, '/lab'), (node.resolve(strict=True), '/node'),
                     (founding_id.resolve(strict=True), '/founding-id'),
                     ((public / 'block-0001.bin').resolve(strict=True), '/item')])
    command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
               '--cap-drop', 'ALL', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
               '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'RAYON_NUM_THREADS', '2']
    for source, destination in bindings:
        command.extend(['--ro-bind', str(source), destination])
    with tempfile.TemporaryDirectory(prefix='n7p2-crash-') as temporary:
        target = Path(temporary)
        shutil.copyfile(public / 'genesis.json', target / 'genesis.json')
        command.extend(['--bind', str(target), '/public', '--remount-ro', '/', '--chdir', '/',
                        '--', '/usr/bin/python3', '-IB', '/lab/storage_check.py', '--worker'])
        result = subprocess.run(command + ['crash'])
        if result.returncode != CRASH_STATUS or not (target / 'block-0001.bin').is_file():
            raise RuntimeError('durable commit crash was not observed')
        recovered = json.loads(subprocess.check_output(command + ['recover']))
        for height in range(2, 11):
            name = f'block-{height:04}.bin'
            shutil.copyfile(public / name, target / name)
        disconnected = json.loads(subprocess.check_output(command + ['reverse']))
        restarted = json.loads(subprocess.check_output(command + ['restart']))
        if not recovered.pop('state') == disconnected['state'] == restarted:
            raise RuntimeError('deep disconnect and restart disagree with isolated first payment')
        recovered.update(reversed_released_blocks=9, deep_prefix_rebuilds=disconnected['deep_rebuilds'],
                         restarted_height=restarted['height'])
        print(json.dumps(recovered, sort_keys=True))
        if any(target.glob('.n7-index.sqlite*')):
            raise RuntimeError('clean exit left derived index files')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker' and sys.argv[2] in ('crash', 'recover', 'reverse', 'restart'):
        worker(sys.argv[2])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('binary', type=Path)
        parser.add_argument('node', type=Path)
        parser.add_argument('public', type=Path)
        parser.add_argument('founding_id', type=Path)
        args = parser.parse_args()
        check(args.binary, args.node, args.public, args.founding_id)
