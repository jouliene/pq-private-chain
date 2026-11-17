#!/usr/bin/env python3
"""Fixed public capability controls, executed before wallet secrets are created."""
from pathlib import Path
import errno
import json
import os
import socket
import subprocess
import sys


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


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
    # Self /proc is useful to pinned runtime capture, host /proc must not exist.
    host = config['host_pid']
    need(not Path(f'/proc/{host}/root').exists(), 'host process root inaccessible')
    return {'pid': os.getpid(), 'denied_paths': denied,
            'inherited_fd_identity_checks': checked, 'denied_socket_families': families,
            'host_proc_root_denied': True,
            'namespaces': {k: os.readlink('/proc/self/ns/' + k) for k in ('pid', 'mnt', 'net')},
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
