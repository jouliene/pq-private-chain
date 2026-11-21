"""Isolate each wallet and its private store; measure an independent durable public node."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'funded-tcith/wallet'))
from subtree import sample


def physical_cpus():
    """Select exactly two different physical cores in the permitted affinity mask."""
    selected = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        topo = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        key = tuple((topo / name).read_text().strip() for name in ('physical_package_id', 'core_id'))
        selected.setdefault(key, cpu)
    if len(selected) < 2:
        raise RuntimeError('the two-core scenario requires two available physical cores')
    return list(selected.values())[:2]


def tree_cpu(pid):
    # Kernel ticks of live descendants plus exited children already waited for by each.
    # Call only at quiescent request boundaries, when ephemeral signature workers have exited.
    total = 0
    queue = [pid]
    seen = set()
    while queue:
        pid = queue.pop()
        if pid in seen:
            continue
        seen.add(pid)
        proc = Path('/proc') / str(pid)
        row = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        total += sum(map(int, row[11:15]))
        for tid in (proc / 'task').iterdir():
            try:
                queue.extend(map(int, (tid / 'children').read_text().split()))
            except FileNotFoundError:
                pass
    return total / os.sysconf('SC_CLK_TCK')


class Peak:
    def __init__(self, pid):
        self.stop = threading.Event()
        self.rss = self.pss = 0
        self.error = None

        def poll():
            try:
                while not self.stop.is_set():
                    rss, pss = sample(pid)
                    self.rss = max(self.rss, rss)
                    self.pss = max(self.pss, pss or 0)
                    self.stop.wait(.025)
            except Exception as exc:
                self.error = exc
        self.thread = threading.Thread(target=poll, daemon=True)
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join()
        if self.error:
            raise self.error
        return dict(sampled_tree_RSS_KiB=self.rss, sampled_tree_PSS_KiB=self.pss)


class Roles:
    def __init__(self, binary, node, folder, private):
        self.binary = binary.resolve(strict=True)
        self.node = node.resolve(strict=True)
        self.folder = folder.resolve()
        self.public = self.folder / 'public'
        self.private = private
        # Every child in this campaign executes the same four source files, even across restarts.
        self.role_source = self.private / 'runtime'
        self.role_source.mkdir(mode=0o700)
        for name in ('common.py','state.py','wallet.py','crypto.mjs'):
            shutil.copyfile(HERE/name, self.role_source/name)
        self.wallet_cost = {}
        self.cpus = physical_cpus()

    def command(self, script, mode, public, *, writable=False, owner=None, exchange=None):
        args = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                '--cap-drop', 'ALL', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C',
                '--setenv', 'RAYON_NUM_THREADS', '4' if owner else '2',
                '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp']
        for src, dst in [(p, p) for p in ('/usr', '/lib', '/lib64', '/bin', '/etc/ld.so.cache')] + [
                (self.binary, '/circuit'), (self.node, '/node'), (self.role_source, '/lab')]:
            args += ['--ro-bind', str(src), dst]
        args += ['--bind' if writable else '--ro-bind', str(public), '/public']
        if (self.folder / 'founding-id').exists():
            args += ['--ro-bind', str(self.folder / 'founding-id'), '/founding-id']
        if owner:
            args += ['--ro-bind', str(self.private / 'seeds' / owner), '/seed',
                     '--bind', str(self.private / owner), '/own']
        if exchange:
            args += ['--ro-bind', str(exchange), '/exchange']
        args += ['--remount-ro', '/', '--chdir', '/', '--', '/usr/bin/time', '-f', 'ROLE %U %S %M',
                 '/usr/bin/python3', '-IBu', f'/lab/{script}.py', mode]
        if not owner:
            args = ['taskset', '--cpu-list', ','.join(map(str, self.cpus))] + args
        return args

    def wallet(self, who, mode, cfg, *, label, exchange=None, public=None):
        cmd = self.command('wallet', mode, public or self.public, owner=who, exchange=exchange)
        start = time.monotonic_ns()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        peak = Peak(proc.pid)
        try:
            out, err = proc.communicate(json.dumps(cfg).encode())
        finally:
            meter = peak.finish()
        if proc.returncode:
            # Wallet output and witness never cross the diagnostic boundary.
            raise RuntimeError(f'{label}: wallet role failed: ' + err.decode()[-850:])
        tag, user, system, rss = err.decode().splitlines()[-1].split()
        if tag != 'ROLE':
            raise RuntimeError('missing wallet CPU accounting')
        self.wallet_cost[label] = dict(wall_s=(time.monotonic_ns()-start)/1e9,
            user_s=float(user), system_s=float(system), max_individual_RSS_KiB=int(rss), **meter)
        return json.loads(out)

    @contextmanager
    def service(self, public, *, forks=False):
        args = self.command('state', 'serve-test-forks' if forks else 'serve', public, writable=True)
        start = time.monotonic()
        proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        peak = Peak(proc.pid)
        server = Server(proc)
        try:
            server.ready = server.read()
            if not server.ready.get('ready'):
                raise RuntimeError('failed to initialize public verifier')
            server.cold = dict(wall_s=time.monotonic()-start, cpu_s=tree_cpu(proc.pid), **peak.finish())
            yield server
            server.call('quit')
        finally:
            if peak.thread.is_alive():
                peak.finish()
            proc.stdin.close()
            proc.wait(timeout=25)
            proc.stdout.close()
            err = proc.stderr.read()
            proc.stderr.close()
            if proc.returncode:
                raise RuntimeError('public service failed: '+err.decode()[-1200:])


class Server:
    def __init__(self, proc):
        self.proc = proc

    def read(self):
        raw = self.proc.stdout.readline(4*1024*1024)
        if not raw:
            raise RuntimeError('public service closed its response stream')
        return json.loads(raw)

    def call(self, op, *, reject=None, **kw):
        self.proc.stdin.write((json.dumps(dict(op=op, **kw), separators=(',', ':'))+'\n').encode())
        self.proc.stdin.flush()
        r = self.read()
        if reject is None:
            if not r.get('ok'):
                raise ValueError(f'{op} rejected: {r.get("error")}')
        elif r.get('ok') or reject not in str(r.get('error')):
            raise ValueError(f'{op}: unexpected control verdict {r.get("error")}, expected {reject}')
        return r

    def mined(self, packet):
        return bytes.fromhex(self.call('mine', packet=packet.hex())['block'])

    def include(self, packet):
        block = self.mined(packet)
        self.call('accept', block=block.hex())
        return block

    def summary(self):
        return self.call('summary')['state']

    def rejected(self, packet, reason):
        before = self.summary()
        block = self.mined(packet)
        error = self.call('accept', block=block.hex(), reject=reason)['error']
        if self.summary() != before:
            raise ValueError('rejection changed public ledger')
        return error
