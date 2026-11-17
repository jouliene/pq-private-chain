#!/usr/bin/env python3
"""Fixed isolated wallet acceptance controller. Private frames never have a log sink."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
SOURCE_KEYS = {'run.py', 'wallet.mjs', 'isolation.py', 'isolation_probe.py', 'GATE3_PROFILE.json',
               '../wallet-witness/joint_controls.mjs', '../transport/oracle.py'}
HEAD_KEYS = {'schema', 'chain', 'genesis_id', 'height', 'block_id', 'leaf_count', 'root_le',
             'fee_escrow', 'unconsumed_liabilities', 'block_version'}
OPS = {'boundary': {'op', 'pid', 'namespaces', 'descendant'}, 'init': {'op', 'chain', 'genesis'},
       'proof': {'op', 'label', 'body', 'receipt'}, 'admit': {'op', 'files'},
       'rollback': {'op', 'expected_tip'}, 'scan': {'op'}, 'context': {'op'},
       'reject': {'op', 'file', 'expected'}, 'mark': {'op', 'name'}}
PRIVATE_CAP = 16 * 1024**2
PUBLIC_CAP = 65536
MAX_BODY = 2106575


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json')
            result[key] = value
        return result
    def bad(_):
        raise ValueError('nonfinite_json')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def hex_bytes(value, size):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(2 * size) + '}', value) is not None, 'public_hex')
    return value


def head(value):
    need(isinstance(value, dict) and set(value) == HEAD_KEYS and value['schema'] == 'CP03-LEDGER-CLI-01'
         and value['block_version'] == '4', 'native_head_schema')
    for name in ('height', 'leaf_count', 'fee_escrow', 'unconsumed_liabilities'):
        need(isinstance(value[name], str) and re.fullmatch('0|[1-9][0-9]{0,19}', value[name]) is not None, 'native_head_decimal')
    for name, size in [('chain', 32), ('genesis_id', 64), ('block_id', 64), ('root_le', 64)]:
        hex_bytes(value[name], size)
    need(int(value['leaf_count']) <= 2**40 and int(value['height']) < 2**64, 'native_head_bounds')
    return value


def descendants(pid):
    yield pid
    try:
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except (FileNotFoundError, ProcessLookupError):
        return
    for child in children:
        yield from descendants(int(child))


def proc_info(pid):
    fields = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            fields[key] = value.strip()
    raw = Path(f'/proc/{pid}/stat').read_text()
    tail = raw[raw.rindex(')') + 2:].split()
    fields['_cpu_ticks'] = {'self_user': int(tail[11]), 'self_system': int(tail[12]),
                           'reaped_child_user': int(tail[13]), 'reaped_child_system': int(tail[14])}
    return fields, int(tail[19])  # Linux stat field22 starttime.


def limits(cpu, seconds):
    parent = os.getpid()
    def apply():
        if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(125)
        os.sched_setaffinity(0, {cpu})
        for kind, bound in [(resource.RLIMIT_AS, 4 * 1024**3), (resource.RLIMIT_CPU, seconds),
                            (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64)]:
            resource.setrlimit(kind, (bound, bound))
    return apply


def inspect_binary(fd, path, expected):
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 * 1024**2, 'native_binary_shape')
    h = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        raw = os.pread(fd, min(65536, before.st_size - offset), offset)
        need(raw and (offset != 0 or raw[:4] == b'\x7fELF'), 'native_binary_read')
        h.update(raw)
        offset += len(raw)
    after, named = os.fstat(fd), os.lstat(path)
    names = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(before, n) == getattr(after, n) == getattr(named, n) for n in names)
         and h.hexdigest() == expected, 'native_binary_pin')


class Actor:
    def __init__(self, controller, restore):
        self.owner, self.restore = controller, restore
        self.child = None
        self.waited = False
        self.selector = selectors.DefaultSelector()
        self.stdout, self.stderr = bytearray(), bytearray()
        self.outgoing = []
        self.done = None
        self.node_pid = None
        self.namespaces = None
        self.boundary_seen = False
        self.backup_seen = False
        self.samples = {}
        self.sample_count = self.sample_races = 0
        self.sampled_tree_peak = 0
        self.last_sample = 0
        self.start = time.monotonic()
        self.proof_start = len(controller.proofs)
        self.scan_bytes = self.scans = 0
        self.public_result = {'restore': restore, 'passed': False}

    def launch(self):
        c = self.owner
        probe_config = c.common / ('restore-probe.json' if self.restore else 'original-probe.json')
        save(probe_config, {'denied_files': [str(p) for p in c.denied_files],
                            'denied_inodes': [list(x) for x in c.denied_inodes], 'host_pid': os.getpid()})
        config = c.common / ('restore-config.json' if self.restore else 'original-config.json')
        controls = HERE.parent / 'wallet-witness/joint_controls.mjs'
        save(config, {'format': 'CP04-ISOLATED-WALLET-CONFIG01', 'profile': c.args.profile,
            'restore': self.restore, 'label': c.args.label, 'installation': str(c.installation_path),
            'installation_sha256': c.args.approve_installation, 'public_output': str(c.output),
            'probe_script': str(HERE / 'isolation_probe.py'), 'probe_config': str(probe_config),
            'controls_script': str(controls), 'controls_sha256': c.source['files']['../wallet-witness/joint_controls.mjs']})
        files = c.runtime_files + [c.installation_path, config, probe_config, HERE / 'wallet.mjs',
                                   HERE / 'isolation_probe.py', controls]
        with c.isolation.network_filter() as filter_fd:
            command = c.isolation.command(readonly_trees=[c.source_root, c.common],
                readonly_files=list(dict.fromkeys(files)), writable_public_trees=[c.output],
                writable_public_overlays=[(c.parent_public, c.sandbox_public), (c.parent_evidence, c.sandbox_evidence)],
                cwd=c.source_root, filter_fd=filter_fd,
                argv=[c.inst['node'], '--disable-sigusr1', str(HERE / 'wallet.mjs'), str(config), sha(config)])
            self.child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, pass_fds=(filter_fd,), start_new_session=True,
                env=c.inst['proof_environment'], preexec_fn=limits(c.wallet_cpu, c.seconds))
        for stream in (self.child.stdout, self.child.stderr):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ)
        os.set_blocking(self.child.stdin.fileno(), False)

    def enqueue(self, kind, payload, private=False):
        need(isinstance(payload, bytearray), 'owned_frame_buffer')
        cap = PRIVATE_CAP if private else PUBLIC_CAP
        need(len(payload) <= cap, 'outbound_frame_cap')
        self.outgoing.append([bytearray(struct.pack('<BI', kind, len(payload))), 0])
        self.outgoing.append([payload, 0])
        try:
            self.selector.register(self.child.stdin, selectors.EVENT_WRITE)
        except KeyError:
            self.selector.modify(self.child.stdin, selectors.EVENT_WRITE)

    def reply(self, value):
        self.enqueue(2, bytearray(json.dumps(value, separators=(',', ':')).encode()))

    def find_node(self, message):
        ns = message['namespaces']
        need(set(ns) == {'pid', 'mnt', 'net'} and type(message['pid']) is int, 'boundary_message')
        for pid in descendants(self.child.pid):
            try:
                fields, _ = proc_info(pid)
                if int(fields.get('NSpid', '0').split()[-1]) == message['pid'] and os.readlink(f'/proc/{pid}/ns/pid') == ns['pid']:
                    self.node_pid = pid
                    break
            except (FileNotFoundError, ProcessLookupError):
                continue
        need(self.node_pid is not None, 'actual_node_pid')
        observed_exe = Path(f'/proc/{self.node_pid}/exe').stat()
        approved_exe = Path(self.owner.inst['node']).stat()
        need((observed_exe.st_dev, observed_exe.st_ino) == (approved_exe.st_dev, approved_exe.st_ino),
             'actual_approved_node_executable')
        for name in ('pid', 'mnt', 'net'):
            need(os.readlink(f'/proc/{self.node_pid}/ns/{name}') == ns[name]
                 and ns[name] != os.readlink('/proc/self/ns/' + name), 'actual_distinct_namespace')
        descendant = message['descendant']
        need(descendant['namespaces'] == ns and descendant['seccomp'] == '2'
             and descendant['denied_paths'] == len(self.owner.denied_files)
             and set(descendant['denied_socket_families']) == {1, 2, 10}
             and descendant['host_proc_root_denied'] is True, 'actual_descendant_probe')
        self.namespaces = ns
        self.boundary_seen = True
        need(self.node_pid in self.sample(force=True), 'live_node_boundary_sample')
        self.public_result['boundary'] = {'actual_node_host_pid': self.node_pid,
            'reported_namespace_pid': message['pid'], 'namespaces': ns, 'descendant': {
                key: descendant[key] for key in ('pid', 'denied_paths', 'inherited_fd_identity_checks',
                    'denied_socket_families', 'host_proc_root_denied', 'seccomp')},
            'inheritable_denied_fds_in_controller': len(self.owner.denied_handles),
            'approved_node_executable_inode_matched': True,
            'denied_database_fds_passed_to_wallet': 0}

    def sample(self, force=False):
        now = time.monotonic()
        if not self.node_pid or (not force and now - self.last_sample < .05):
            return []
        self.last_sample = now
        tree_rss = 0
        observed = []
        for pid in descendants(self.node_pid):
            try:
                fields, start = proc_info(pid)
                if fields.get('State', '').startswith('Z'):
                    continue
                actual_ns = {name: os.readlink(f'/proc/{pid}/ns/{name}') for name in ('pid', 'mnt', 'net')}
                need(actual_ns == self.namespaces and fields.get('Seccomp') == '2', 'descendant_boundary_changed')
                for denied in self.owner.denied_files:
                    need(not Path(f'/proc/{pid}/root{denied}').exists(), 'descendant_database_mount_visible')
                checked = 0
                for fd in Path(f'/proc/{pid}/fd').iterdir():
                    try:
                        info = fd.stat()
                    except FileNotFoundError:
                        continue
                    need((info.st_dev, info.st_ino) not in self.owner.denied_inodes, 'descendant_database_fd_visible')
                    checked += 1
                # Only mount destinations/options are read, never FD symlink targets
                # or private stdin/stdout contents.
                mounts = {}
                for line in Path(f'/proc/{pid}/mountinfo').read_text().splitlines():
                    pieces = line.split()
                    if len(pieces) >= 6:
                        mounts[pieces[4]] = pieces[5].split(',')
                need('ro' in mounts.get('/usr', []) and 'ro' in mounts.get(str(self.owner.source_root), [])
                     and 'ro' in mounts.get(str(self.owner.common), []), 'readonly_mount_policy')
                for destination in (self.owner.output, self.owner.sandbox_public, self.owner.sandbox_evidence):
                    need('rw' in mounts.get(str(destination), []), 'public_output_mount_policy')
                rss = int(fields.get('VmRSS', '0 kB').split()[0])
                tree_rss += rss
                key = (pid, start)
                item = self.samples.setdefault(key, {'host_pid': pid, 'starttime_ticks': start,
                    'namespace_pid': int(fields.get('NSpid', '0').split()[-1]), 'name': fields.get('Name', ''),
                    'samples': 0, 'peak_sampled_rss_kib': 0, 'fd_identity_checks': 0,
                    'first_seconds': now - self.start, 'namespace_fd_mount_seccomp_pass': True})
                item['samples'] += 1
                item['last_seconds'] = now - self.start
                item['peak_sampled_rss_kib'] = max(item['peak_sampled_rss_kib'], rss)
                item['fd_identity_checks'] += checked
                item['last_observed_cpu_ticks'] = fields['_cpu_ticks']
                observed.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                self.sample_races += 1
        self.sample_count += 1
        self.sampled_tree_peak = max(self.sampled_tree_peak, tree_rss)
        return observed

    def parse_frames(self):
        while len(self.stdout) >= 5:
            kind, length = struct.unpack('<BI', self.stdout[:5])
            need(kind in (1, 4, 5), 'wallet_frame_kind')
            need(length <= (PRIVATE_CAP if kind == 4 else PUBLIC_CAP), 'wallet_frame_cap')
            if len(self.stdout) < length + 5:
                return
            payload = bytearray(self.stdout[5:5 + length])
            self.stdout[:5 + length] = b'\0' * (5 + length)
            del self.stdout[:5 + length]
            try:
                need(self.done is None, 'no_frames_after_terminal_metrics')
                if kind == 4:
                    need(not self.restore and not self.backup_seen and self.owner.backup is None and length > 0, 'single_private_backup')
                    self.owner.backup = payload
                    self.backup_seen = True
                    payload = None
                elif kind == 5:
                    value = decode(payload)
                    need(set(value) == {'format', 'restore', 'counts', 'process_self', 'private_material_persisted_or_hashed'}
                         and value['format'] == 'CP04-ISOLATED-WALLET-DONE01'
                         and value['restore'] is self.restore and value['private_material_persisted_or_hashed'] is False,
                         'fixed_terminal_metrics')
                    need(set(value['counts']) == {'proofs', 'history_reads', 'history_bytes', 'history_wall_seconds'}, 'terminal_count_keys')
                    for key, number in value['counts'].items():
                        need(type(number) in (int, float) and math.isfinite(number) and number >= 0, 'finite_terminal_count')
                    need(value['counts']['proofs'] == len(self.owner.proofs) - self.proof_start
                         and value['counts']['history_reads'] == self.scans and value['counts']['history_bytes'] == self.scan_bytes,
                         'actual_terminal_count_match')
                    usage = value['process_self']
                    names = ('userCPUTime', 'systemCPUTime', 'maxRSS', 'fsRead', 'fsWrite',
                             'voluntaryContextSwitches', 'involuntaryContextSwitches')
                    need(all(type(usage.get(key)) is int and usage[key] >= 0 for key in names), 'node_process_self_fields')
                    self.done = {'format': value['format'], 'restore': self.restore, 'counts': value['counts'],
                        'process_self': {key: usage[key] for key in names}, 'private_material_persisted_or_hashed': False,
                        'resource_scope': 'Node process_self only; CPU microseconds, RSS KiB; not descendant tree CPU'}
                else:
                    need(not self.backup_seen, 'no_rpc_after_backup_handoff')
                    message = decode(payload)
                    need(isinstance(message, dict) and message.get('op') in OPS
                         and set(message) == OPS[message['op']], 'fixed_rpc_grammar')
                    response = self.owner.rpc(self, message)
                    self.reply(response)
                    if message['op'] == 'boundary' and self.restore:
                        need(self.owner.backup is not None, 'backup_available_after_original_exit')
                        owned = self.owner.backup; self.owner.backup = None
                        self.enqueue(3, owned, private=True)
            finally:
                if payload is not None:
                    payload[:] = b'\0' * len(payload)

    def run(self):
        try:
            self.launch()
            while True:
                self.owner.guard()
                self.sample()
                for key, _ in self.selector.select(.02):
                    stream = key.fileobj
                    if stream is self.child.stdin:
                        while self.outgoing:
                            data, offset = self.outgoing[0]
                            view = memoryview(data)[offset:offset + 65536]
                            try:
                                count = os.write(stream.fileno(), view)
                            except BlockingIOError:
                                break
                            finally:
                                view.release()
                            data[offset:offset + count] = b'\0' * count
                            offset += count
                            self.outgoing[0][1] = offset
                            if offset < len(data):
                                break
                            data.clear(); self.outgoing.pop(0)
                        if not self.outgoing:
                            self.selector.unregister(stream)
                    else:
                        raw = os.read(stream.fileno(), 65536)
                        if not raw:
                            self.selector.unregister(stream)
                        elif stream is self.child.stderr:
                            need(len(self.stderr) + len(raw) <= PUBLIC_CAP, 'private_stderr_bound')
                            self.stderr.extend(raw)
                        else:
                            need(len(self.stdout) + len(raw) <= PRIVATE_CAP + PUBLIC_CAP + 10, 'private_stdout_bound')
                            self.stdout.extend(raw); self.parse_frames()
                terminal = os.waitid(os.P_PID, self.child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if terminal is not None:
                    break
            self.finish_wait()
            # Drain only already-written final bytes after actual process termination.
            for stream, sink in [(self.child.stdout, self.stdout), (self.child.stderr, self.stderr)]:
                while True:
                    try:
                        raw = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        break
                    if not raw:
                        break
                    need(len(sink) + len(raw) <= PRIVATE_CAP + PUBLIC_CAP + 10, 'terminal_private_capture_bound')
                    sink.extend(raw)
            self.parse_frames()
            stage = None
            for allowed in self.owner.failure_stages:
                if self.stderr == ('CP04_WALLET_FAILED ' + allowed + '\n').encode():
                    stage = allowed
            self.public_result['fixed_failure_stage'] = stage
            need(self.child.returncode == 0 and not self.stderr and not self.stdout and self.done is not None
                 and self.boundary_seen and (self.restore or self.backup_seen)
                 and 'terminal_cpu' in self.public_result, 'wallet_terminal_success')
            need(not self.outgoing, 'wallet_consumed_all_replies')
            self.public_result.update(passed=True, terminal_metrics=self.done)
            return self.public_result
        finally:
            if self.child is not None and not self.waited:
                self.finish_wait(kill=True)
            self.public_result['sampling'] = {'interval_seconds': .05, 'epochs': self.sample_count,
                'observed_processes': list(self.samples.values()), 'raced_exits': self.sample_races,
                'maximum_sampled_tree_rss_kib': self.sampled_tree_peak,
                'scope': 'Finite external live PID/namespace/mount/FD metadata samples; short-lived processes can be missed. No private pipe bytes or FD link targets read; RSS sum is sampled concurrent tree RSS, not CPU.'}
            for data, _ in self.outgoing:
                data[:] = b'\0' * len(data)
            self.outgoing.clear()
            self.stdout[:] = b'\0' * len(self.stdout); self.stderr[:] = b'\0' * len(self.stderr)
            self.selector.close()
            if self.child is not None:
                for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            save(self.owner.work / ('restore-process.json' if self.restore else 'original-process.json'), self.public_result)

    def finish_wait(self, kill=False):
        if kill:
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _, status, usage = os.wait4(self.child.pid, 0)
        self.waited = True
        self.child.returncode = os.waitstatus_to_exitcode(status)
        self.public_result['actual_wrapper'] = {'exit': self.child.returncode,
            'wall_seconds': time.monotonic() - self.start, 'first_wait4': True,
            'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime, 'maxrss_kib': usage.ru_maxrss,
            'scope': 'bubblewrap leader first-wait4; not whole native wallet/prover tree CPU or RSS'}


class Controller:
    def __init__(self, args, common, isolation, oracle, source, work):
        self.args, self.common_module, self.isolation, self.oracle, self.source = args, common, isolation, oracle, source
        self.installation_path = args.installation.resolve(strict=True)
        self.inst = common.load_installation(self.installation_path, args.approve_installation)
        need(Path(self.inst['repository']) == REPOSITORY, 'this_repository_installation')
        need(self.inst['pins'].get(str(REPOSITORY / 'scripts/common.py')) == sha(REPOSITORY / 'scripts/common.py'), 'approved_common_helper')
        need(str(Path(sys.executable).resolve()) in self.inst['pins'], 'approved_python_interpreter')
        self.source_root = Path(self.inst['source_root'])
        self.operator = decode(Path(self.inst['operator_path']).read_bytes())
        approval_path = self.source_root / self.operator['private_approval']['path']
        need(sha(approval_path) == self.operator['private_approval']['sha256'], 'private_approval_pin')
        approval = decode(approval_path.read_bytes())
        self.private_approval = approval
        runtime_path = self.source_root / approval['runtime_receipt']
        need(sha(runtime_path) == approval['runtime_receipt_sha256'], 'private_runtime_receipt_pin')
        runtime = decode(runtime_path.read_bytes())
        need(runtime['runtime_pins_unchanged'] and runtime['source_pins_unchanged'], 'private_runtime_receipt_status')
        source_manifest = decode((self.source_root/approval['source_manifest']).read_bytes())
        frozen = {str((self.source_root/name).resolve()): digest for name,digest in source_manifest['sources'].items()}
        for name in ('source_manifest','build_receipt','binary','runtime_receipt'):
            frozen[str((self.source_root/approval[name]).resolve())] = approval[name+'_sha256']
        frozen[str(approval_path.resolve())] = self.operator['private_approval']['sha256']
        expected_runtime = {}
        for name,digest in runtime['runtime_before'].items():
            pinned = frozen.get(str(Path(name).resolve()))
            if pinned is not None:
                need(pinned == digest, 'runtime_frozen_source_association')
            else:
                expected_runtime[name] = digest
        self.expected_runtime_digest = sha_bytes(json.dumps(expected_runtime,sort_keys=True,separators=(',',':')).encode())
        # /usr is the explicit system runtime; every other allowed runtime file is
        # selected by the approved captured map, not an inherited host root.
        self.runtime_files = [Path(p) for p in runtime['runtime_before']]
        self.work = work
        self.common, self.output = self.work / 'common', self.work / 'public-output'
        self.parent_public, self.parent_evidence = self.work / 'parent-public', self.work / 'parent-evidence'
        self.control = self.work / 'controller'
        for path in (self.common, self.output, self.parent_public, self.parent_evidence, self.control):
            path.mkdir(mode=0o700)
        self.database = self.control / 'ledger.sqlite'
        self.sandbox_public = self.source_root / 'experiments/compact-all-payments-v3/public'
        self.sandbox_evidence = self.source_root / 'experiments/compact-all-payments-v3/evidence'
        need(self.sandbox_public.is_dir() and self.sandbox_evidence.is_dir(), 'approved_source_output_mountpoints')
        self.seconds = 900 if args.profile == 'small' else 5400
        self.proof_limit = 5 if args.profile == 'small' else 264
        self.start = time.monotonic()
        self.deadline = self.start + self.seconds
        affinity = os.sched_getaffinity(0)
        need(0 in affinity, 'wallet_cpu0_available')
        self.wallet_cpu, self.ledger_cpu = 0, (1 if 1 in affinity else 0)
        self.head = self.genesis_head = self.genesis_file = None
        self.chain = None
        self.backup = None
        self.events, self.proofs, self.cli_receipts = [], [], []
        self.generated = {}; self.scan_count = self.reject_count = 0
        self.actor = None
        self.last_disk_check = 0
        text = (HERE / 'wallet.mjs').read_text()
        self.marks = set(re.findall(r"mark\('([a-z][a-z0-9-]{0,79})'\)", text))
        self.failure_stages = set(re.findall(r"stage = '([a-z][a-z0-9-]{0,63})'", text))
        need(1 <= len(self.marks) <= 32 and 1 <= len(self.failure_stages) <= 32, 'fixed_actor_public_labels')
        sentinel = self.control / 'denied-control-sentinel.db'
        need(not sentinel.exists(), 'create_only_public_sentinel')
        sentinel_db = sqlite3.connect(sentinel)
        sentinel_db.execute('CREATE TABLE public_sentinel(value TEXT NOT NULL)')
        sentinel_db.execute("INSERT INTO public_sentinel VALUES('PUBLIC_WALLET_DENIAL_SENTINEL')")
        sentinel_db.commit(); sentinel_db.close()
        candidates = [REPOSITORY / 'experiments/network-feasibility/producer/.work/gate2-96x8-01.public/producer.sqlite',
                      REPOSITORY / 'experiments/network-feasibility/transport/.work/gate2-96x8-01/validator/ledger.sqlite']
        self.denied_files = [self.database, sentinel] + [p for p in candidates if p.is_file()]
        # Old Gate2 DBs are optional extra controls, never a clean-clone prerequisite.
        need(len(self.denied_files) >= 2, 'current_ledger_and_public_sentinel')
        self.denied_handles, self.denied_inodes = [], set()
        for path in self.denied_files:
            if path.exists():
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                os.set_inheritable(fd, True)
                self.denied_handles.append(fd)
                info = os.fstat(fd); self.denied_inodes.add((info.st_dev, info.st_ino))

    def guard(self):
        need(time.monotonic() < self.deadline, 'outer_watchdog')
        need(len(self.proofs) <= self.proof_limit, 'proof_ceiling')
        if time.monotonic() - self.last_disk_check > 2:
            self.last_disk_check = time.monotonic()
            need(self.oracle.disk(self.work)['logical_bytes'] <= 8 * 1024**3, 'public_disk_watchdog')

    def native(self, arguments, expected_error=None):
        self.guard()
        binary = self.source_root / self.operator['ledger_binary']['path']
        expected = self.operator['ledger_binary']['sha256']
        fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        process = None; waited = False; selector = selectors.DefaultSelector(); buffers = {}
        started = time.monotonic(); actual = {'operation': arguments[0], 'cpu': self.ledger_cpu, 'first_wait4': False,
            'binary_before_checked': False, 'binary_after_checked': False, 'public_result_validated': False}
        try:
            inspect_binary(fd, binary, expected)
            actual['binary_before_checked'] = True
            process = subprocess.Popen([f'/proc/self/fd/{fd}', *map(str, arguments)], pass_fds=(fd,),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, start_new_session=True, env=self.inst['proof_environment'],
                preexec_fn=limits(self.ledger_cpu, min(120, self.seconds)))
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ); buffers[stream] = bytearray()
            while True:
                self.guard()
                if self.actor:
                    self.actor.sample()
                need(time.monotonic() - started < 120, 'native_cli_watchdog')
                for key, _ in selector.select(.02):
                    raw = os.read(key.fileobj.fileno(), 8192)
                    if not raw:
                        selector.unregister(key.fileobj)
                    else:
                        need(len(buffers[key.fileobj]) + len(raw) <= PUBLIC_CAP, 'native_public_output_cap')
                        buffers[key.fileobj].extend(raw)
                if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                    break
            _, status, usage = os.wait4(process.pid, 0); waited = True; process.returncode = os.waitstatus_to_exitcode(status)
            actual.update(exit=process.returncode, first_wait4=True, wall_seconds=time.monotonic()-started,
                          user_seconds=usage.ru_utime, system_seconds=usage.ru_stime, maxrss_kib=usage.ru_maxrss)
            for stream in (process.stdout, process.stderr):
                while True:
                    try:
                        raw = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        break
                    if not raw:
                        break
                    need(len(buffers[stream]) + len(raw) <= PUBLIC_CAP, 'native_terminal_output_cap')
                    buffers[stream].extend(raw)
            inspect_binary(fd, binary, expected)
            actual['binary_after_checked'] = True
            stdout, stderr = buffers[process.stdout], buffers[process.stderr]
            if expected_error:
                need(process.returncode == 1 and not stdout and stderr == ('CP03_LEDGER_ERROR ' + expected_error + '\n').encode(), 'exact_native_rejection')
                actual['rejected'] = expected_error
                actual['public_result_validated'] = True
                return None
            need(process.returncode == 0 and not stderr, 'native_success')
            value = decode(stdout)
            need(json.dumps(value, separators=(',', ':')).encode() + b'\n' == stdout, 'canonical_native_json')
            value = head(value); actual['public_result_validated'] = True
            return value
        finally:
            if process is not None and not waited:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(process.pid, 0); process.returncode = os.waitstatus_to_exitcode(status)
                actual.update(exit=process.returncode, first_wait4=True, failed=True,
                    wall_seconds=time.monotonic()-started, user_seconds=usage.ru_utime,
                    system_seconds=usage.ru_stime, maxrss_kib=usage.ru_maxrss)
            for value in buffers.values():
                value[:] = b'\0' * len(value)
            selector.close(); os.close(fd)
            if process is not None:
                process.stdout.close(); process.stderr.close()
            self.cli_receipts.append(actual)

    def public_path(self, name):
        need(isinstance(name, str) and '\0' not in name, 'public_path_text')
        path = Path(name)
        need(path.is_absolute() and path.parent == self.output and path.resolve() == path
             and path.is_file() and not path.is_symlink(), 'fixed_public_output_file')
        return path

    def proof(self, actor, message):
        label = message['label']
        need(isinstance(label, str) and re.fullmatch('[a-z][a-z0-9-]{0,63}', label) is not None, 'proof_label')
        body = self.public_path(message['body'])
        need(body.name == label + '.body' and str(body) not in self.generated, 'new_body_identity')
        need(len(self.proofs) < self.proof_limit, 'fresh_proof_ceiling')
        receipt = Path(message['receipt'])
        need(receipt.parent == self.sandbox_evidence and receipt.name == self.args.label + '-' + label + '.json', 'fixed_parent_receipt_path')
        actual_receipt = self.parent_evidence / receipt.name
        raw = actual_receipt.read_bytes(); need(len(raw) <= 8 * 1024**2, 'parent_public_receipt_cap')
        parent = decode(raw)
        need(parent['label'] == self.args.label + '-' + label and parent['mode'] == 'prove-private'
             and parent['process_exit'] == parent['wrapper_exit'] == 0 and not parent['timeout']
             and parent['source_pins_unchanged'] and parent['runtime_pins_unchanged']
             and not parent['private_input_written_or_hashed'] and not parent['unchecked_child_output_persisted'], 'actual_parent_status')
        for field, approval_field in [('binary_sha256','binary_sha256'), ('manifest_sha256','source_manifest_sha256'),
            ('build_receipt_sha256','build_receipt_sha256'), ('approved_runtime_receipt_sha256','runtime_receipt_sha256')]:
            need(parent[field] == self.private_approval[approval_field], 'parent_approved_identity')
        need(parent['approved_runtime_digest'] == parent['observed_runtime_digest'] ==
             parent['runtime_after_digest'] == self.expected_runtime_digest, 'parent_approved_runtime_digest')
        need(parent['first_wait4']['pid'] > 0, 'actual_parent_worker_pid')
        actor.sample(force=True)
        observed = any(row['namespace_pid'] == parent['first_wait4']['pid'] for row in actor.samples.values())
        need(observed, 'actual_live_prover_descendant_sample')
        info = body.stat(); need(info.st_size <= MAX_BODY, 'body_cap')
        data = body.read_bytes(); need(data[:8] == b'CPBODY03', 'body_magic')
        version, n, p, auth, reserved = struct.unpack('<HHIHH', data[8:20])
        need(version == 3 and reserved == 0 and n in (448,464,528) and 0 < p <= 2097152,
             'body_prefix_bounds')
        offset = 20 + n + 4328 + auth
        need(offset + p == len(data), 'body_exact_length')
        directory = self.parent_public / parent['label']
        need((directory/'statement.bin').read_bytes() == data[20:20+n]
             and sha(directory/'proof.bin') == sha_bytes(data[offset:]), 'parent_body_correspondence')
        manifest = decode((directory/'manifest.json').read_bytes())
        need(manifest['genuine_proof_created'] and manifest['private_input_boundary']
             and not manifest['private_packet_persisted'] and not manifest['private_input_debug_digest_created'], 'genuine_parent_manifest')
        row = {'label': label, 'restore': actor.restore, 'body': str(body.relative_to(self.work)),
            'body_sha256': sha_bytes(data), 'body_bytes': len(data), 'proof_bytes': p,
            'arity': parent['arity'], 'parent_receipt': str(actual_receipt.relative_to(self.work)),
            'parent_receipt_sha256': sha_bytes(raw), 'positive_admissions': 0,
            'actual_worker': {key: parent[key] for key in ('child_wall_seconds','wait4_user_seconds','wait4_system_seconds','wait4_maxrss_kib')},
            'actual_worker_namespace_pid': parent['first_wait4']['pid'], 'live_descendant_sampled': True,
            'source_runtime_pins_unchanged': True, 'private_input_or_unchecked_output_persisted': False}
        row['approved_identities'] = {key:parent[key] for key in ('binary_sha256','manifest_sha256',
            'approved_runtime_receipt_sha256','approved_runtime_digest')}
        self.proofs.append(row); self.generated[str(body)] = row
        return {}

    def rpc(self, actor, message):
        op = message['op']
        self.events.append({'seconds': time.monotonic()-self.start, 'restore': actor.restore, 'op': op})
        if op == 'boundary':
            need(not actor.boundary_seen, 'one_boundary_record')
            actor.find_node(message)
            return {}
        need(actor.boundary_seen, 'boundary_before_operations')
        if op == 'init':
            need(not actor.restore and self.head is None, 'single_genesis_init')
            self.chain = hex_bytes(message['chain'], 32)
            self.genesis_file = self.public_path(message['genesis'])
            self.head = self.native(['init-retain', self.database, self.chain, self.genesis_file, '2147483648'])
            self.genesis_head = self.head.copy()
            fd = os.open(self.database, os.O_RDONLY | os.O_NOFOLLOW); os.set_inheritable(fd, True)
            self.denied_handles.append(fd); info = os.fstat(fd); self.denied_inodes.add((info.st_dev,info.st_ino))
            need(actor.node_pid in actor.sample(force=True), 'live_wallet_new_ledger_denial')
            self.events[-1]['actual_new_ledger_exists_and_wallet_denied'] = True
            return {'head': self.head}
        if op == 'proof':
            return self.proof(actor, message)
        need(self.head is not None, 'initialized_controller')
        if op == 'admit':
            files = message['files']
            need(isinstance(files,list) and 1 <= len(files) <= 128 and len(set(files)) == len(files), 'admission_files')
            for name in files:
                need(name in self.generated and sha(self.public_path(name)) == self.generated[name]['body_sha256'], 'registered_immutable_body')
            self.head = self.native(['admit', self.database, self.chain, *files])
            for name in files:
                self.generated[name]['positive_admissions'] += 1
            self.events[-1].update(height=self.head['height'], proof_bodies=len(files))
            return {'head': self.head}
        if op == 'rollback':
            need(message['expected_tip'] == self.head['block_id'], 'exact_rollback_tip')
            self.head = self.native(['rollback', self.database, self.chain, message['expected_tip']])
            self.events[-1]['height'] = self.head['height']
            return {'head': self.head}
        if op == 'scan':
            self.scan_count += 1
            file = self.common / ('history-' + str(self.scan_count).zfill(4) + '.scan')
            actual = self.native(['scan', self.database, self.chain, file])
            need(actual == self.head, 'actual_scan_selected_head')
            actor.scans += 1; actor.scan_bytes += file.stat().st_size
            self.events[-1].update(bytes=file.stat().st_size,height=self.head['height'])
            return {'file': str(file), 'head': self.head}
        if op == 'context':
            need(actor.restore, 'restore_public_context_only')
            return {'genesis': str(self.genesis_file), 'genesis_head': self.genesis_head}
        if op == 'reject':
            file = self.public_path(message['file'])
            need(str(file) in self.generated and message['expected'] == 'Anchor', 'fixed_anchor_rejection')
            registered = self.generated[str(file)]
            need(sha(file) == registered['body_sha256'] and registered['positive_admissions'] >= 1,
                 'same_positively_verified_rejection_body')
            before = self.oracle.snapshot(self.database)
            self.native(['admit', self.database, self.chain, file], expected_error='Anchor')
            after = self.oracle.snapshot(self.database)
            need(before == after, 'all14_rejection_atomicity')
            self.reject_count += 1
            save(self.work / ('anchor-reject-' + str(self.reject_count).zfill(2) + '.json'),
                 {'before':before,'after':after,'all14_unchanged':True,'expected':'Anchor',
                  'label':registered['label'],'body_sha256':registered['body_sha256'],
                  'positive_admissions_before_rejection':registered['positive_admissions']})
            return {'rejected':'Anchor','all14_unchanged':True}
        if op == 'mark':
            need(message['name'] in self.marks, 'fixed_public_mark')
            self.events[-1]['name'] = message['name']
            if message['name'] == 'native-work-complete':
                need('terminal_cpu' not in actor.public_result, 'one_native_terminal_handshake')
                # Actor is blocked on this reply AFTER awaited private cleanup.
                # No descendant can still own an unfinished private operation.
                need(list(descendants(actor.node_pid)) == [actor.node_pid], 'all_wallet_children_reaped_at_handshake')
                need(actor.node_pid in actor.sample(force=True), 'live_node_terminal_sample')
                fields, start = proc_info(actor.node_pid)
                ticks = fields['_cpu_ticks']; hz = os.sysconf('SC_CLK_TCK')
                actor.public_result['terminal_cpu'] = {'actual_node_host_pid':actor.node_pid,
                    'starttime_ticks':start, 'clock_ticks_per_second':hz, 'ticks':ticks,
                    'node_self_seconds':(ticks['self_user']+ticks['self_system'])/hz,
                    'node_waited_descendant_seconds':(ticks['reaped_child_user']+ticks['reaped_child_system'])/hz,
                    'scope':'External live Node procfs SELF and reaped-child-chain CPU at public terminal handshake. Tick granularity; excludes unawaited/orphan processes. Waited child CPU contains Parent/helper descendants and must not be added to their nested metrics; excludes controller/native admission CLI.'}
            return {}
        raise ValueError('no_membership_or_other_rpc')

    def run(self):
        outcomes = []
        for restore in (False, True):
            if restore:
                need(outcomes[0]['passed'] and outcomes[0]['actual_wrapper']['exit'] == 0 and self.backup is not None,
                     'original_exited_before_fresh_restore')
            self.actor = Actor(self, restore)
            outcomes.append(self.actor.run())
        self.actor = None
        need(len(self.proofs) == self.proof_limit and all(p['positive_admissions'] >= 1 for p in self.proofs),
             'every_generated_proof_has_positive_genuine_native_admission')
        expected_height = 4 if self.args.profile == 'small' else 260
        need(self.head['height'] == str(expected_height), 'declared_final_height')
        need(self.reject_count == (0 if self.args.profile == 'small' else 2), 'declared_anchor_rejections')
        required = {'joint-lease-and-packet-controls', 'genuine-private-receipt-and-local-witnesses',
                    'recipient-fresh-local-witness-spend', 'backup-only-new-process-spend', 'native-work-complete'}
        if self.args.profile == 'full':
            required |= {'old-draft-genuine-positive-before-expiry', 'old-origin-draft-valid-on-common-prefix',
                         'changing-root-anchor-expiry-atomic-rejection', 'old-note-refreshed-and-spent',
                         'orphan-child-genuine-positive-before-reorg', 'joint-rewind-orphan-discovery-and-spentness-repaired',
                         'joint-deep-replay-revocation-and-recovery'}
        actual_marks = {event['name'] for event in self.events if event['op'] == 'mark'}
        need(actual_marks == required, 'exact_profile_public_marks')
        final_head = self.native(['head', self.database, self.chain])
        need(final_head == self.head, 'final_actual_head')
        retained = self.oracle.retained(self.database)
        need(retained['missing_full'] == retained['pending'] == retained['unexported_bytes'] == 0
             and retained['retention'] == 1, 'final_full_retention')
        final_snapshot = self.oracle.snapshot(self.database)
        expected_bodies, expected_nullifiers, expected_fees = ((5,4,10570146) if self.args.profile == 'small'
            else (261,516,551305634))
        need(final_snapshot['blocks']['rows'] == expected_height and
             final_snapshot['bodies']['rows'] == final_snapshot['cores']['rows'] == expected_bodies and
             final_snapshot['leaves']['rows'] == 2*expected_bodies and
             final_snapshot['nullifiers']['rows'] == expected_nullifiers and
             final_snapshot['sources']['rows'] == 2 and self.head['fee_escrow'] == str(expected_fees) and
             self.head['unconsumed_liabilities'] == '0', 'final_public_accounting')
        connection = sqlite3.connect(self.database.as_uri()+'?mode=ro', uri=True)
        total, consumed = connection.execute('SELECT total,(SELECT count(*) FROM sources WHERE consumed_height=1) FROM meta').fetchone()
        connection.close()
        need(total == 1100000000 and consumed == 2, 'laboratory_source_total')
        self.common_module.load_installation(self.installation_path, self.args.approve_installation)
        need(all(sha(HERE/name) == digest for name,digest in self.source['files'].items()), 'runner_source_postcheck')
        return {'actors':outcomes,'head':self.head,'retained':retained,'public_disk':self.oracle.disk(self.work),
            'final_all14_snapshot':final_snapshot, 'proofs':self.proofs,'events':self.events,
            'accounting': {'total':total,'fees':expected_fees,'liabilities':0,
                           'remaining_note_supply_by_conservation':total-expected_fees},
            'controller_process_self': {'user_seconds':resource.getrusage(resource.RUSAGE_SELF).ru_utime,
                'system_seconds':resource.getrusage(resource.RUSAGE_SELF).ru_stime,
                'maxrss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                'scope':'Controller Python SELF only; excludes native CLI and isolated wallet descendants'},
            'native_cli':self.cli_receipts,'no_private_backup_or_stream_written_or_hashed':True,
            'all_generated_proofs_positive_native_admission':True,
            'scope':'Finite actual wallet/controller experiment; source/runtime/delegated history and namespace assumptions remain explicit. No production or joint PQ/privacy theorem.'}

    def cleanup(self):
        if self.backup is not None:
            self.backup[:] = b'\0' * len(self.backup); self.backup = None
        for fd in self.denied_handles:
            os.close(fd)
        self.denied_handles.clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True)
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--approve-installation', required=True)
    parser.add_argument('--approve-source', required=True)
    parser.add_argument('--profile', choices=['small','full'], required=True)
    args = parser.parse_args()
    need(re.fullmatch('[a-z][a-z0-9-]{0,31}', args.label) is not None, 'exclusive_label')
    source_path = HERE/'SOURCE.json'
    need(sha(source_path) == args.approve_source, 'explicit_source_approval')
    source = decode(source_path.read_bytes())
    need(source['format'] == 'CP04-WALLET-INTEGRATION-SOURCE01' and set(source['files']) == SOURCE_KEYS, 'exact_source_closure')
    need(all(sha(HERE/name) == digest for name,digest in source['files'].items()), 'source_pins')
    profile = decode((HERE/'GATE3_PROFILE.json').read_bytes())
    need(profile['format'] == 'CP04-GATE3-RESEARCH-PROFILE01' and
         profile['bounds']['full_proof_ceiling'] == 264 and profile['bounds']['small_proof_ceiling'] == 5 and
         profile['bounds']['full_outer_watchdog_seconds'] == 5400 and profile['bounds']['small_outer_watchdog_seconds'] == 900 and
         profile['bounds']['wallet_address_space_bytes'] == 4*1024**3 and
         profile['bounds']['experiment_public_disk_bytes'] == 8*1024**3, 'fixed_declared_profile')
    common = module('wallet_public_common', REPOSITORY/'scripts/common.py')
    isolation = module('wallet_isolation', HERE/'isolation.py')
    oracle = module('wallet_public_oracle', HERE.parent/'transport/oracle.py')
    controller = None
    work = HERE/'.work'/args.label
    work.parent.mkdir(exist_ok=True); work.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (4*1024**3, 4*1024**3))
    result = {'format':'CP04-WALLET-INTEGRATION-RESULT01','passed':False,
              'source_sha256':args.approve_source,'installation_sha256':args.approve_installation,
              'profile':args.profile,'private_raw_streams_or_backup_persisted_or_hashed':False}
    try:
        controller = Controller(args,common,isolation,oracle,source,work)
        save(controller.work/'claim.json',{'format':'CP04-WALLET-INTEGRATION-CLAIM01',
            'profile':args.profile,'proof_ceiling':controller.proof_limit,'watchdog_seconds':controller.seconds,
            'source_sha256':args.approve_source,'installation_sha256':args.approve_installation,
            'wallet_cpu':controller.wallet_cpu,'ledger_cpu':controller.ledger_cpu,'oracle_db_never_mounted':True})
        result.update(controller.run()); result['passed'] = True
    except BaseException as error:
        result['failure_type'] = type(error).__name__
        result['fixed_failure_reason'] = str(error) if isinstance(error,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(error)) else None
        if controller:
            result.update(events=controller.events,proofs=controller.proofs,native_cli=controller.cli_receipts)
    finally:
        if controller:
            try:
                common.load_installation(controller.installation_path,args.approve_installation)
                need(all(sha(HERE/name)==digest for name,digest in source['files'].items()),'source_postcheck')
                result['source_runtime_unchanged'] = True
            except BaseException:
                result['source_runtime_unchanged'] = False; result['passed'] = False
            try:
                controller.cleanup()
            except BaseException:
                result['cleanup_failed'] = True; result['passed'] = False
        save(work/'RESULT.json',result)
    print(json.dumps({'passed':result['passed'],'receipt':str(controller.work/'RESULT.json') if controller else None}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
