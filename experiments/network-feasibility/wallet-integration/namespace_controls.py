#!/usr/bin/env python3
"""Bounded public namespace-contract controls; no wallet, native or child jobs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('namespace_probe_controls', HERE / 'isolation_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
            ('namespace_controls.py', 'isolation_probe.py', 'run.py', 'isolation_control.py')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    before, start = pins(), time.monotonic()
    rows = []
    namespaces = {'pid': 'pid:[222]', 'mnt': 'mnt:[333]', 'net': 'net:[444]'}
    config = {'controller_pid': 3, 'controller_pid_namespace': 'pid:[111]'}

    def exercise(name, operation, error=None):
        try:
            operation()
        except BaseException as exc:
            rows.append({'name': name, 'passed': error is not None and type(exc) is error,
                         'error_type': type(exc).__name__})
        else:
            rows.append({'name': name, 'passed': error is None})

    def simulated(config=config, own=namespaces, procfs='pid:[222]', numeric='pid:[222]',
                  numeric_error=None, directory_error=FileNotFoundError):
        def readlink(path):
            if path == '/proc/1/ns/pid':
                return procfs
            if path != f"/proc/{config['controller_pid']}/ns/pid":
                raise AssertionError('fixed numeric namespace path')
            if numeric_error:
                raise numeric_error()
            return numeric

        def lstat(path):
            if path != f"/proc/{config['controller_pid']}":
                raise AssertionError('fixed numeric directory path')
            if directory_error:
                raise directory_error()
            return object()

        return probe.namespace_boundary(config, own, readlink=readlink, lstat=lstat)

    def accept(**kwargs):
        value = simulated(**kwargs)
        probe.validate_namespace_result({'namespaces': namespaces, **value}, namespaces, 3, 'pid:[111]')
        return value

    exercise('verified-local-process-or-thread-collision', accept)
    exercise('confirmed-numeric-absence', lambda: accept(numeric_error=FileNotFoundError))
    exercise('same-controller-namespace-even-with-absence', lambda: simulated(
        config={**config, 'controller_pid_namespace': namespaces['pid']},
        numeric_error=FileNotFoundError), ValueError)
    exercise('procfs-pid1-is-not-own-namespace', lambda: simulated(procfs='pid:[999]'), ValueError)
    exercise('present-numeric-controller-namespace', lambda: simulated(numeric='pid:[111]'), ValueError)
    exercise('present-unrelated-numeric-namespace', lambda: simulated(numeric='pid:[999]'), ValueError)
    exercise('numeric-namespace-permission-denied', lambda: simulated(numeric_error=PermissionError), PermissionError)
    exercise('missing-link-live-numeric-directory', lambda: simulated(
        numeric_error=FileNotFoundError, directory_error=None), ValueError)
    exercise('missing-link-directory-permission-denied', lambda: simulated(
        numeric_error=FileNotFoundError, directory_error=PermissionError), PermissionError)
    for name, bad in (('bool', True), ('zero', 0), ('negative', -1), ('string', '3')):
        exercise('invalid-controller-pid-' + name,
                 lambda bad=bad: simulated(config={**config, 'controller_pid': bad}), ValueError)
    exercise('missing-controller-identity', lambda: simulated(config={}), KeyError)
    exercise('malformed-controller-namespace', lambda: simulated(
        config={**config, 'controller_pid_namespace': 'not-a-namespace'}), ValueError)
    valid = {'namespaces': namespaces, **simulated()}
    changes = (
        ('controller-pid', {'controller_pid': 4}),
        ('controller-pid-bool', {'controller_pid': True}),
        ('controller-namespace', {'controller_pid_namespace': 'pid:[999]'}),
        ('procfs-namespace', {'procfs_pid_namespace': 'pid:[999]'}),
        ('exclusion-false', {'controller_proc_namespace_excluded': False}),
        ('numeric-classification', {'controller_number_classification': 'unreadable'}),
        ('numeric-namespace', {'controller_number_pid_namespace': 'pid:[999]'}),
        ('absence-with-present-namespace', {'controller_number_classification': 'absent'}),
        ('child-namespace-null', {'controller_number_pid_namespace': None}),
        ('reported-child-namespace', {'namespaces': {**namespaces, 'pid': 'pid:[999]'}}),
    )
    for name, change in changes:
        exercise('consumer-rejects-' + name, lambda change=change: probe.validate_namespace_result(
            {**valid, **change}, namespaces, 3, 'pid:[111]'), ValueError)
    exercise('consumer-rejects-missing-field', lambda: probe.validate_namespace_result(
        {k: v for k, v in valid.items() if k != 'procfs_pid_namespace'}, namespaces, 3, 'pid:[111]'), KeyError)
    # One real public read: a probe must reject its controller's own namespace.
    actual = {name: os.readlink('/proc/self/ns/' + name) for name in ('pid', 'mnt', 'net')}
    exercise('actual-same-namespace-rejected', lambda: probe.namespace_boundary(
        {'controller_pid': os.getpid(), 'controller_pid_namespace': actual['pid']}, actual), ValueError)
    after = pins()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result = {'format': 'CP04-NAMESPACE-PROBE-CONTROLS01',
              'passed': all(row['passed'] for row in rows) and before == after,
              'scope': 'Public typed namespace metadata controls and one real same-namespace rejection; '
                       'no isolated wallet, cryptography or additional subprocess. Actual collision evidence is '
                       'pid-namespace-probe/RESULT01.json, not these simulated observations.',
              'controls': rows, 'control_count': len(rows), 'direct_child_launches': 0,
              'source_before': before, 'source_after': after,
              'wall_seconds': time.monotonic() - start,
              'process_self': {'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                               'maxrss_kib': usage.ru_maxrss}}
    with args.output.open('x') as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'passed': result['passed'], 'controls': len(rows), 'receipt': str(args.output)}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
