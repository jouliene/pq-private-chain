#!/usr/bin/env python3
"""One bounded public test of the wallet namespace, before new cryptography.

This controls the exact fixed policy and real descendant denial. It is not an
integrated wallet, proof, recovery or resource-profile acceptance result.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import selectors
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('wallet_isolation', HERE / 'isolation.py')
isolation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolation)
need = isolation.need


def children(pid):
    yield pid
    try:
        values = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except FileNotFoundError:
        return
    for value in values:
        yield from children(int(value))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    need(args.label.isascii() and args.label.replace('-', '').isalnum(), 'exclusive label')
    work = HERE / '.work' / args.label
    work.mkdir(parents=True)
    denied = [ROOT / 'experiments/network-feasibility/producer/.work/gate2-96x8-01.public/producer.sqlite',
              ROOT / 'experiments/network-feasibility/transport/.work/gate2-96x8-01/validator/ledger.sqlite']
    need(all(p.is_file() for p in denied), 'actual existing public ledger prerequisites')
    handles = [os.open(p, os.O_RDONLY) for p in denied]
    for fd in handles:
        os.set_inheritable(fd, True)
    identities = [[os.fstat(fd).st_dev, os.fstat(fd).st_ino] for fd in handles]
    config = work / 'public-config.json'
    config.write_text(json.dumps({'denied_files': [str(p) for p in denied],
                                 'denied_inodes': identities, 'host_pid': os.getpid()}))
    result = {'format': 'CP04-WALLET-ISOLATION-CONTROL01', 'passed': False,
              'scope': 'Public policy/descendant probe only; no private wallet or proof executed',
              'source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (HERE / 'isolation.py', HERE / 'isolation_probe.py', Path(__file__))}}
    child = None
    waited = False
    buffers = {}
    selector = selectors.DefaultSelector()
    start = time.monotonic()
    try:
        with isolation.network_filter() as filter_fd:
            cmd = isolation.command(readonly_trees=[],
                readonly_files=[config, HERE / 'isolation_probe.py', Path('/etc/ld.so.cache')],
                writable_public_trees=[], cwd=Path('/tmp'), filter_fd=filter_fd,
                argv=['/usr/bin/python3', '-I', '-B', str(HERE / 'isolation_probe.py'), str(config)])
            child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, pass_fds=(filter_fd,), start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        for stream in (child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
            buffers[stream] = bytearray()
        received = None
        while received is None:
            need(time.monotonic() - start < 10, 'bounded namespace startup')
            for key, _ in selector.select(.02):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    buffers[key.fileobj].extend(data)
                    need(len(buffers[key.fileobj]) <= 8192, 'fixed public probe output cap')
            need(not buffers[child.stderr], 'no probe failure')
            raw = buffers[child.stdout]
            if b'\n' in raw:
                need(raw.count(b'\n') == 1 and raw[-1:] == b'\n', 'one probe record')
                received = json.loads(raw)['ready']
            else:
                need(os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None,
                     'probe stays alive for outside namespace readback')
        host_pid = None
        for pid in children(child.pid):
            try:
                if os.readlink(f'/proc/{pid}/ns/pid') == received['namespaces']['pid']:
                    nspid = next(x for x in Path(f'/proc/{pid}/status').read_text().splitlines()
                                 if x.startswith('NSpid:')).split()[-1]
                    if int(nspid) == received['pid']:
                        host_pid = pid
            except FileNotFoundError:
                continue
        need(host_pid is not None, 'actual probe host PID')
        readback = {}
        for kind in ('pid', 'mnt', 'net'):
            actual = os.readlink(f'/proc/{host_pid}/ns/{kind}')
            need(actual == received['namespaces'][kind] and actual != os.readlink('/proc/self/ns/' + kind),
                 'actual distinct namespace')
            need(received['descendant']['namespaces'][kind] == actual, 'descendant inherits namespace')
            readback[kind] = True
        need(all(not Path(f'/proc/{host_pid}/root{p}').exists() for p in denied),
             'outside actual mount denial readback')
        need(received['seccomp'] == received['descendant']['seccomp'] == '2', 'filter active for both')
        result.update(probe=received, actual_host_pid=host_pid, external_namespace_readback=readback,
                      inherited_public_database_fds_open_in_parent=len(handles),
                      inherited_public_database_fds_passed_to_child=0,
                      external_actual_mount_denials=len(denied))
        child.stdin.write(b'finish\n')
        child.stdin.flush()
        child.stdin.close()
        while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            need(time.monotonic() - start < 12, 'bounded probe termination')
            time.sleep(.01)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _, status, usage = os.wait4(child.pid, 0)
        waited = True
        child.returncode = os.waitstatus_to_exitcode(status)
        need(child.returncode == 0, 'probe terminal success')
        result.update(passed=True, exit=child.returncode, wall_seconds=time.monotonic()-start,
                      first_wait4_wrapper_user_seconds=usage.ru_utime,
                      first_wait4_wrapper_system_seconds=usage.ru_stime,
                      wrapper_usage_is_not_wallet_tree_resource_accounting=True)
    except BaseException as exc:
        result['failure_type'] = type(exc).__name__
        result['fixed_failure_reason'] = str(exc) if isinstance(exc, ValueError) else None
    finally:
        if child is not None and not waited:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, _ = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            result['cleanup_exit'] = child.returncode
        if child is not None:
            for stream in (child.stdin, child.stdout, child.stderr):
                if not stream.closed:
                    stream.close()
        selector.close()
        for fd in handles:
            os.close(fd)
        (work / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'passed': result['passed'], 'receipt': str(work / 'RESULT.json')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
