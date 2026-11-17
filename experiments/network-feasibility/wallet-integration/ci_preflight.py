#!/usr/bin/env python3
"""Two fixed public sandbox probes, before compilation or any private actor."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NODE_SHA256 = 'e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC',
       'RUST_BACKTRACE': '0', 'RAYON_NUM_THREADS': '1'}
CAP, SECONDS = 8192, 10


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def public_probe(isolation, argv, files):
    result = {'argv': None, 'passed': False, 'timeout': False, 'output_overflow': False,
              'readonly_files': [str(p) for p in files], 'readonly_trees': [],
              'writable_trees': [], 'public_fixed_command': argv}
    child = None
    waited = False
    selector = selectors.DefaultSelector()
    buffers = {}
    started = time.monotonic()
    parent = os.getpid()

    def limits():
        if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(125)
        os.sched_setaffinity(0, {0})
        for kind, bound in ((resource.RLIMIT_AS, 4 * 1024**3), (resource.RLIMIT_CPU, SECONDS),
                            (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64)):
            resource.setrlimit(kind, (bound, bound))

    def capture(stream, raw):
        sink = buffers[stream]
        remaining = CAP - len(sink)
        sink.extend(raw[:remaining])
        if len(raw) > remaining:
            result['output_overflow'] = True
            raise BufferError()

    try:
        with isolation.network_filter() as fd:
            command = isolation.command(readonly_trees=[], readonly_files=files,
                writable_public_trees=[], cwd=Path('/usr'), filter_fd=fd, argv=argv)
            result['argv'] = command
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, pass_fds=(fd,), start_new_session=True,
                env=ENV, preexec_fn=limits)
        for stream in (child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
            buffers[stream] = bytearray()
            selector.register(stream, selectors.EVENT_READ)
        while True:
            for key, _ in selector.select(.01):
                raw = os.read(key.fileobj.fileno(), 4096)
                if raw:
                    capture(key.fileobj, raw)
                else:
                    selector.unregister(key.fileobj)
            if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                break
            if time.monotonic() - started >= SECONDS:
                result['timeout'] = True
                raise TimeoutError()
    except BaseException as error:
        result.update(exception_type=type(error).__name__, errno=getattr(error, 'errno', None))
    finally:
        if child is not None:
            # Keep the leader waitable until cleanup; never signal a reused PID.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, usage = os.wait4(child.pid, 0)
            waited = True
            child.returncode = os.waitstatus_to_exitcode(status)
            result.update(returncode=child.returncode, first_wait4=True,
                          user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
                          maxrss_kib=usage.ru_maxrss,
                          resource_scope='bubblewrap leader first-wait4, not whole descendant tree CPU')
            for stream in (child.stdout, child.stderr):
                try:
                    while True:
                        raw = os.read(stream.fileno(), 4096)
                        if not raw:
                            break
                        capture(stream, raw)
                except BlockingIOError:
                    pass
                except BufferError:
                    result['exception_type'] = 'BufferError'
            result.update(stdout=bytes(buffers[child.stdout]).decode('utf-8', 'replace'),
                          stderr=bytes(buffers[child.stderr]).decode('utf-8', 'replace'))
            child.stdout.close()
            child.stderr.close()
        selector.close()
        result['wall_seconds'] = time.monotonic() - started
    expected = '' if argv == ['/usr/bin/true'] else 'v24.22.1\n'
    if result['wall_seconds'] >= SECONDS:
        result['timeout'] = True
    result['passed'] = (waited and result['returncode'] == 0 and not result['timeout']
                        and not result['output_overflow'] and 'exception_type' not in result
                        and result['stdout'] == expected and not result['stderr'])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Reserve the public receipt before attempting any subprocess; never overwrite.
    with args.output.open('x') as output:
        result = {'format': 'CP04-CI-PUBLIC-SANDBOX-PREFLIGHT01', 'passed': False, 'probes': [],
                  'scope': 'Fixed /usr/bin/true then pinned Node --version only; no wallet, '
                           'private data, installation, native verifier or proof. Public stderr retained. '
                           'Tests sandbox/runtime startup, not the complete wallet mount closure.',
                  'per_probe_seconds': SECONDS, 'per_stream_cap_bytes': CAP, 'environment': ENV}
        stage = 'source_identity'
        pins = {}
        try:
            pins = {str(p): sha(p) for p in (Path(__file__).resolve(), HERE / 'isolation.py')}
            result['source_before'] = pins
            result['host'] = {'kernel': platform.release(), 'machine': platform.machine(),
                              'uid': os.getuid(), 'gid': os.getgid(),
                              'affinity': sorted(os.sched_getaffinity(0)),
                              'namespaces': {k: os.readlink('/proc/self/ns/' + k)
                                             for k in ('user', 'pid', 'mnt', 'net')}}
            result['readonly_sysctls'] = {}
            for name in ('/proc/sys/kernel/unprivileged_userns_clone',
                         '/proc/sys/kernel/apparmor_restrict_unprivileged_userns',
                         '/proc/sys/user/max_user_namespaces'):
                try:
                    with open(name, 'rb') as stream:
                        value = stream.read(1025)
                    if len(value) > 1024:
                        raise ValueError('bounded public sysctl')
                    result['readonly_sysctls'][name] = {'value': value.decode('ascii').strip()}
                except OSError as error:
                    result['readonly_sysctls'][name] = {'errno': error.errno}
            result['runtime'] = {str(p): {'sha256': sha(p), 'mode': oct(p.stat().st_mode)}
                                 for p in (Path('/usr/bin/bwrap'), Path('/usr/bin/true'))}
            if 0 not in os.sched_getaffinity(0):
                raise ValueError('CPU0 unavailable')
            spec = importlib.util.spec_from_file_location('fixed_public_isolation', HERE / 'isolation.py')
            isolation = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(isolation)
            stage = 'sandbox_true'
            result['probes'].append(public_probe(isolation, ['/usr/bin/true'], []))
            if result['probes'][-1]['passed']:
                stage = 'pinned_node_identity'
                node = args.node.resolve(strict=True)
                node_before = sha(node)
                result['node'] = {'path': str(node), 'sha256': node_before,
                                  'expected_sha256': NODE_SHA256}
                if node_before != NODE_SHA256:
                    raise ValueError('official Node identity')
                stage = 'sandbox_node_version'
                result['probes'].append(public_probe(isolation, [str(node), '--version'], [node]))
                result['node']['sha256_after'] = sha(node)
                if result['node']['sha256_after'] != node_before:
                    raise ValueError('Node changed')
                result['passed'] = all(p['passed'] for p in result['probes'])
        except BaseException as error:
            result.update(exception_type=type(error).__name__, errno=getattr(error, 'errno', None))
        finally:
            result['last_stage'] = stage
            result['source_after'] = {p: sha(p) for p in pins}
            if result['source_after'] != pins:
                result['passed'] = False
            json.dump(result, output, indent=2, sort_keys=True)
            output.write('\n')
    print(json.dumps({'passed': result['passed'], 'receipt': str(args.output)}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
