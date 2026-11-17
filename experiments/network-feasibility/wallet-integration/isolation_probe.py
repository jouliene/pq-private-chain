#!/usr/bin/env python3
"""Fixed public capability controls, executed before wallet secrets are created."""
from pathlib import Path
import errno
import json
import os
import re
import socket
import subprocess
import sys


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def namespace_boundary(config, namespaces, *, readlink=os.readlink, lstat=os.lstat):
    controller = config['controller_pid']
    controller_ns = config['controller_pid_namespace']
    need(type(controller) is int and controller > 0 and type(controller_ns) is str
         and re.fullmatch(r'pid:\[[0-9]+\]', controller_ns) is not None,
         'typed controller namespace identity')
    own_ns = namespaces['pid']
    need(own_ns != controller_ns, 'child namespace distinct from controller')
    procfs_ns = readlink('/proc/1/ns/pid')
    need(procfs_ns == own_ns, 'child scoped procfs')
    numeric_path = f'/proc/{controller}'
    try:
        numeric_ns = readlink(numeric_path + '/ns/pid')
    except FileNotFoundError:
        # A missing namespace link alone does not establish a missing process.
        # Inaccessible or ambiguous live entries must still fail closed.
        try:
            lstat(numeric_path)
        except FileNotFoundError:
            classification, numeric_ns = 'absent', None
        else:
            raise ValueError('numeric controller entry remains ambiguous')
    else:
        need(numeric_ns == own_ns, 'numeric controller entry is child local')
        classification = 'child_namespace'
    return {'controller_pid': controller, 'controller_pid_namespace': controller_ns,
            'procfs_pid_namespace': procfs_ns, 'controller_proc_namespace_excluded': True,
            'controller_number_classification': classification,
            'controller_number_pid_namespace': numeric_ns}


def validate_namespace_result(result, namespaces, controller, controller_ns):
    """External callers bind the public report to their actual namespace links."""
    need(result['namespaces'] == namespaces and type(result['controller_pid']) is int
         and result['controller_pid'] == controller
         and result['controller_pid_namespace'] == controller_ns
         and namespaces['pid'] != controller_ns
         and result['procfs_pid_namespace'] == namespaces['pid']
         and result['controller_proc_namespace_excluded'] is True,
         'actual controller and child namespace binding')
    classification = result['controller_number_classification']
    need((classification == 'absent' and result['controller_number_pid_namespace'] is None)
         or (classification == 'child_namespace'
             and result['controller_number_pid_namespace'] == namespaces['pid']),
         'typed child-local numeric collision')


def inspect(config):
    denied = 0
    for name in config['denied_files']:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            need(exc.errno in (errno.ENOENT, errno.EACCES, errno.EPERM), 'typed path denial')
            denied += 1
        else:
            os.close(fd)
            raise ValueError('forbidden database readable')
    identities = {tuple(v) for v in config['denied_inodes']}
    checked = 0
    for name in os.listdir('/proc/self/fd'):
        try:
            info = os.fstat(int(name))
        except OSError as exc:
            need(exc.errno == errno.EBADF, 'fd probe')
            continue
        need((info.st_dev, info.st_ino) not in identities, 'forbidden inherited handle')
        checked += 1
    families = []
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            need(exc.errno == errno.EPERM, 'fixed socket API denial')
            families.append(int(family))
        else:
            sock.close()
            raise ValueError('external socket API available')
    # PID numbers are relative: the controller's number may name a local thread.
    namespaces = {k: os.readlink('/proc/self/ns/' + k) for k in ('pid', 'mnt', 'net')}
    boundary = namespace_boundary(config, namespaces)
    return {'pid': os.getpid(), 'denied_paths': denied,
            'inherited_fd_identity_checks': checked, 'denied_socket_families': families,
            **boundary, 'namespaces': namespaces,
            'seccomp': next(line.split(':', 1)[1].strip() for line in
                            Path('/proc/self/status').read_text().splitlines()
                            if line.startswith('Seccomp:'))}


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    result = inspect(config)
    if len(sys.argv) == 2:
        child = subprocess.run([sys.executable, '-I', '-B', __file__, sys.argv[1], '--descendant'],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                               close_fds=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        need(child.returncode == 0 and not child.stderr and len(child.stdout) < 8192,
             'actual descendant probe')
        result['descendant'] = json.loads(child.stdout)
        print(json.dumps({'ready': result}, sort_keys=True), flush=True)
        need(sys.stdin.buffer.readline(16) == b'finish\n', 'outside readback handshake')
    else:
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('WALLET_ISOLATION_PROBE_FAILED', file=sys.stderr)
        raise SystemExit(1)
