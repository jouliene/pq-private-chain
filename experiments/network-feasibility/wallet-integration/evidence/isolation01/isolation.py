"""Allowlisted Linux research wallet namespace; no host-root or ledger bind.

The caller owns process lifetime and private IPC. Only approved source/runtime,
common public input and explicit public output directories are mounted. This is
an experiment capability boundary, not protection from a privileged host.
"""
from pathlib import Path
import contextlib
import errno
import os
import platform
import stat
import struct


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def regular(path):
    p = Path(path).absolute()
    need(not p.is_symlink() and p.is_file(), 'regular allowlisted file')
    return p


def directory(path):
    p = Path(path).absolute()
    need(not p.is_symlink() and p.is_dir() and p.resolve() == p,
         'canonical allowlisted directory')
    return p


def inspect_tree(root):
    """No database, socket, device or symlink escape in a mounted project tree."""
    root = directory(root)
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(base) / name
            mode = p.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'no project mount symlinks')
            need(stat.S_ISREG(mode) or stat.S_ISDIR(mode), 'regular project tree')
            need(not name.endswith(('.sqlite', '.sqlite3', '.db', '-wal', '-shm', '-journal')),
                 'no database in wallet mount')
    return root


@contextlib.contextmanager
def network_filter():
    """Fixed x86-64 seccomp: deny external socket APIs and namespace escape APIs.

    socketpair remains available for inherited local process pipes. Popen must
    close all unrelated inherited descriptors; only this filter FD is passed to
    bubblewrap, which consumes it. The actual probe tests inherited DB exclusion.
    """
    need(platform.machine() == 'x86_64', 'supported isolation architecture')
    # linux/filter.h classic BPF and installed asm/unistd_64.h syscall numbers.
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
            (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0),
            (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for number in (41, 42, 43, 49, 50, 101, 155, 165, 272, 288, 304, 308):
        rows.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x00050000 | errno.EPERM)])
    rows.append((0x06, 0, 0, 0x7FFF0000))
    fd = os.memfd_create('wallet-fixed-network-filter', os.MFD_CLOEXEC)
    try:
        data = b''.join(struct.pack('HBBI', *row) for row in rows)
        need(os.write(fd, data) == len(data), 'complete public filter')
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd
    finally:
        os.close(fd)


def command(*, readonly_trees, readonly_files, writable_public_trees, cwd, argv,
            filter_fd):
    """Create a new empty root, never a masked copy of the entire host root."""
    need(argv and all(isinstance(v, str) for v in argv), 'fixed local command')
    trees = [inspect_tree(p) for p in readonly_trees]
    writable = [inspect_tree(p) for p in writable_public_trees]
    files = [regular(p) for p in readonly_files]
    need(all(not str(p).startswith(('/proc/', '/dev/')) for p in trees + writable + files),
         'no host process/device mount')
    roots = trees + writable
    need(all(p != Path('/') and not p.is_relative_to('/usr') for p in roots),
         'system runtime bound separately')
    cmd = ['/usr/bin/bwrap', '--die-with-parent', '--new-session',
           '--unshare-user', '--unshare-pid', '--unshare-net', '--unshare-ipc',
           '--unshare-uts', '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr',
           '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
           '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
           '--tmpfs', '/tmp']
    for p in trees:
        cmd += ['--ro-bind', str(p), str(p)]
    for p in files:
        # The runtime /usr mount already supplies these paths. No broad /etc/home.
        if not p.is_relative_to('/usr') and not any(p.is_relative_to(d) for d in trees):
            cmd += ['--ro-bind', str(p), str(p)]
    for p in writable:
        cmd += ['--bind', str(p), str(p)]
    cmd += ['--chdir', str(cwd), '--seccomp', str(filter_fd), '--'] + argv
    return cmd
