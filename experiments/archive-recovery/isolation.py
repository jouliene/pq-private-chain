"""Run each role with its own data mounts. Only peer roles share loopback networking."""
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def command(deployment, argv, mounts, peer=False):
    args = ['bwrap', '--unshare-all']
    if peer:
        args.append('--share-net')
    args += ['--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv',
             '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C',
             '--setenv', 'RAYON_NUM_THREADS', '2', '--dev', '/dev', '--proc', '/proc',
             '--tmpfs', '/tmp', '--ro-bind', '/usr', '/usr']
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        path = Path('/') / name
        if path.is_symlink():
            args += ['--symlink', os.readlink(path), str(path)]
        elif path.is_dir():
            args += ['--ro-bind', str(path), str(path)]
    # Only the source files actually invoked inside the role are visible.
    for name in ('archive.py', 'node.py', 'store.py', 'wallet.py'):
        args += ['--ro-bind', str(HERE / name), '/code/' + name]
    args += ['--ro-bind', str(deployment.resolve(strict=True)), '/deployment']
    for source, destination, writable in mounts:
        args += ['--bind' if writable else '--ro-bind', str(source.resolve(strict=True)), destination]
    return args + ['--remount-ro', '/', '--chdir', '/tmp', '--', '/usr/bin/python3', '-IB', *argv]


def start(deployment, argv, mounts, log, peer):
    with log.open('ab') as stream:
        return subprocess.Popen(command(deployment, argv, mounts, peer), stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, close_fds=True)
