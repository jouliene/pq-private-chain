#!/usr/bin/env python3
"""Fixed public-history measurement with an isolated zero-owned wallet."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import sqlite3
import stat
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SOURCE_KEYS = {'trace.py', 'trace.mjs', 'PROFILE.json', 'CONTRACT.md', '../../scripts/common.py',
               '../network-feasibility/wallet-integration/run.py',
               '../network-feasibility/wallet-integration/isolation.py',
               '../network-feasibility/wallet-integration/isolation_probe.py',
               '../network-feasibility/transport/oracle.py'}
PREFIXES = (32, 128, 260)


def need(ok, reason):
    if not ok: raise ValueError(reason)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def bounded_json(path, cap, approved, common, native):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd); need(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'public_json_bound')
        raw = bytearray()
        while True:
            block = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not block: break
            raw.extend(block); need(len(raw) <= cap, 'public_json_bound')
        after, named = os.fstat(fd), os.lstat(path)
        need(all(getattr(info,k) == getattr(after,k) == getattr(named,k)
                 for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'stable_public_json')
        need(hashlib.sha256(raw).hexdigest() == approved, 'explicit_public_json_approval')
        return native.decode(raw)
    finally: os.close(fd)


def dec(value):
    return isinstance(value, str) and re.fullmatch('0|[1-9][0-9]{0,19}', value) is not None


def cursor_bytes(head):
    return (struct.pack('<Q', int(head['height'])) + bytes.fromhex(head['block_id']) +
            struct.pack('<Q', int(head['leaf_count'])) + bytes.fromhex(head['root_le']) +
            struct.pack('<QQ', int(head['fee_escrow']), int(head['unconsumed_liabilities'])))


class Trace:
    def __init__(self, args, common, native, isolation, oracle, source, work):
        self.args, self.common_module, self.native_module, self.isolation, self.oracle = args, common, native, isolation, oracle
        self.work, self.source = work, source
        self.installation_path = args.installation.resolve(strict=True)
        self.inst = common.load_installation(self.installation_path, args.approve_installation)
        need(Path(self.inst['repository']) == REPO and self.inst['pins'].get(str(REPO/'scripts/common.py')) == common.sha(REPO/'scripts/common.py'), 'approved_common_repository')
        need(str(Path(sys.executable).resolve()) in self.inst['pins'], 'approved_python')
        self.source_root = Path(self.inst['source_root']); self.operator = common.read_json(self.inst['operator_path'])
        approval = common.read_json(self.source_root/self.operator['private_approval']['path'])
        need(common.sha(self.source_root/self.operator['private_approval']['path']) == self.operator['private_approval']['sha256'], 'runtime_approval')
        runtime = common.read_json(self.source_root/approval['runtime_receipt'])
        need(common.sha(self.source_root/approval['runtime_receipt']) == approval['runtime_receipt_sha256'], 'runtime_receipt')
        self.runtime_files = [Path(p) for p in runtime['runtime_before']]
        self.seconds = 1800; self.deadline = time.monotonic()+self.seconds; self.last_disk_check = 0
        self.ledger_cpu = 1 if 1 in os.sched_getaffinity(0) else 0; self.wallet_cpu = 0
        need(0 in os.sched_getaffinity(0), 'CPU0_required')
        self.actor = None; self.proofs = []; self.cli_receipts = []; self.rows = []; self.cases = []
        self.measuring = False; self.current_prefix = None; self.height = 0; self.noop_seen = False
        self.common = work/'common'; self.output = work/'public-output'
        self.parent_public, self.parent_evidence = work/'parent-public', work/'parent-evidence'
        for p in (self.common, self.output, self.parent_public, self.parent_evidence): p.mkdir()
        self.sandbox_public = self.source_root/'experiments/compact-all-payments-v3/public'
        self.sandbox_evidence = self.source_root/'experiments/compact-all-payments-v3/evidence'
        need(self.sandbox_public.is_dir() and self.sandbox_evidence.is_dir(), 'existing_empty_output_mountpoints')
        replay_path = args.replay_result.resolve(strict=True)
        self.replay = bounded_json(replay_path, 8*1024**2, args.approve_replay, common, native)
        need(self.replay['passed'] and self.replay['source_runtime_unchanged'] and self.replay['new_proofs_generated'] == 0
             and self.replay['positive_proof_admissions'] == 265 and self.replay['successful_block_admissions'] == 264,
             'fresh_public_replay_input')
        # Root explicitly approves prior genuine public replay provenance. Data
        # need not have been generated under this new installation; no old ELF
        # or verdict is loaded by the wallet. All14/head/genesis must match now.
        self.database = replay_path.parent/'fresh-ledger.sqlite'
        need(not self.database.is_symlink() and self.database.resolve(strict=True) == self.database and
             not self.database.is_relative_to(self.source_root), 'public_database_outside_wallet_mount')
        self.db_identity = self.database.stat()
        genesis = args.genesis.resolve(strict=True)
        need(not args.genesis.is_symlink() and common.sha(genesis) == args.approve_genesis and genesis.stat().st_size <= 339320, 'public_genesis')
        raw = genesis.read_bytes(); (self.common/'genesis.bin').write_bytes(raw)
        connection = sqlite3.connect(self.database.as_uri()+'?mode=ro', uri=True)
        try:
            stored, gid, chain, total = connection.execute('SELECT genesis,genesis_id,chain,total FROM meta').fetchone()
            need(stored == raw, 'genesis_database_correspondence')
            values = connection.execute('SELECT height,id,leaf_count,root,fees,liabilities FROM blocks ORDER BY height').fetchall()
            old_count, old_root, old_fees, old_liabilities = connection.execute('SELECT old_count,old_root,old_fees,old_liabilities FROM blocks WHERE height=1').fetchone()
        finally: connection.close()
        self.chain = chain.hex()
        def head(height, identity, count, root, fees, liabilities):
            value = {'schema':'CP03-LEDGER-CLI-01', 'block_version':'4', 'chain':self.chain, 'genesis_id':gid.hex(),
                     'height':str(height), 'block_id':identity.hex(), 'leaf_count':str(count), 'root_le':root.hex(),
                     'fee_escrow':str(fees), 'unconsumed_liabilities':str(liabilities)}
            return native.head(value)
        need(old_count == old_fees == 0 and old_liabilities == total and len(values) == 260, 'fixed260_history')
        self.heads = [head(0, gid, 0, old_root, 0, total)] + [head(*row) for row in values]
        need([int(row['height']) for row in self.heads] == list(range(261)), 'ordered_public_endpoints')
        need(self.heads[-1] == self.replay['final_head'] == self.native(['head', self.database, self.chain]), 'actual_final_endpoint')
        need(oracle.snapshot(self.database, canonical=True) == self.replay['final_canonical_snapshot'], 'input_all14')
        full = self.common/'full260.scan'
        need(self.native(['scan', self.database, self.chain, full]) == self.heads[-1], 'oracle_full_scan')
        data = full.read_bytes(); need(len(data) < 4*1024**2, 'fixed_public_scan_bound')
        self.frames = []; at = 0; reduced_rows = 0
        while at < len(data):
            size = struct.unpack_from('<I', data, at)[0]; end = at+4+size
            need(0 < size <= 1224804 and end <= len(data), 'oracle_frame_bound')
            frame = data[at:end]; header_len = struct.unpack_from('<I', frame, 12)[0]
            header = frame[16:16+header_len]
            need(frame[4:12] == b'CPSBLK04' and header[:8] == b'CPBLOCK4', 'oracle_frame_version')
            height, count = struct.unpack_from('<Q', header, 108)[0], struct.unpack_from('<H', header, 116)[0]
            need(height == len(self.frames)+1 and header_len == 216+64*count, 'oracle_frame_order')
            pos, reduced_bytes = 16+header_len, 0
            for _ in range(count):
                length = struct.unpack_from('<I', frame, pos)[0]; pos += 4
                need(0 < length <= 9499 and pos+length <= len(frame), 'oracle_reduced_bound')
                reduced_bytes += length; pos += length
            need(pos == len(frame), 'oracle_frame_eof')
            self.frames.append({'bytes':len(frame), 'records':count, 'header_bytes':header_len, 'reduced_bytes':reduced_bytes})
            at = end; reduced_rows += count
            if height in PREFIXES: (self.common/f'prefix-{height}.scan').write_bytes(data[:end])
        need(len(self.frames) == 260 and reduced_rows == 261, 'genuine_selected_frame_count')
        (self.common/'empty.scan').write_bytes(b'')
        common.save(self.common/'inputs.json', {'heads':self.heads, 'prefixes':list(PREFIXES),
            'genesis':str(self.common/'genesis.bin'), 'genesis_sha256':args.approve_genesis,
            'empty_scan':str(self.common/'empty.scan'), 'references':{str(n):str(self.common/f'prefix-{n}.scan') for n in PREFIXES}})
        self.input_context = {'preloaded_public_endpoints':261, 'context_json_bytes':(self.common/'inputs.json').stat().st_size,
            'genesis_bytes':len(raw), 'full260_scan_bytes':len(data),
            'reference_prefix_file_bytes':sum((self.common/f'prefix-{n}.scan').stat().st_size for n in PREFIXES),
            'scope':'Fixed externally selected endpoint schedule and oracle files prepared outside measured roles. '
                    'Endpoint acquisition/freshness is not measured or zero-cost production traffic; all14 oracle physical IO is not instrumented.'}
        sentinel = work/'denied-sentinel.db'
        with sqlite3.connect(sentinel) as c: c.execute('CREATE TABLE public_sentinel(value INTEGER)')
        self.denied_files = [self.database, sentinel]; self.denied_handles = []; self.denied_inodes = set()
        for p in self.denied_files:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW); os.set_inheritable(fd, True); self.denied_handles.append(fd)
            info = os.fstat(fd); self.denied_inodes.add((info.st_dev, info.st_ino))
        self.preparation_cli_count = len(self.cli_receipts)

    def guard(self):
        need(time.monotonic() < self.deadline, 'trace_deadline')
        if time.monotonic()-self.last_disk_check > 2:
            self.last_disk_check = time.monotonic(); need(self.oracle.disk(self.work)['logical_bytes'] <= 8*1024**3, 'trace_disk')

    def native(self, arguments):
        need(arguments[0] in ('head', 'scan', 'scan-range'), 'public_history_operations_only')
        return self.native_module.Controller.native(self, arguments)

    def rpc(self, worker, message):
        op = message.get('op')
        if op == 'boundary':
            need(set(message) == {'op','pid','namespaces','descendant'}, 'boundary_fields'); worker.find_node(message); return {'ok':True}
        need(worker.boundary_seen, 'boundary_before_trace')
        if op == 'case-start':
            need(set(message) == {'op','prefix'} and self.current_prefix is None and
                 type(message['prefix']) is int and message['prefix'] == PREFIXES[len(self.cases)], 'fixed_case_order')
            self.current_prefix = message['prefix']; self.height = 0; self.noop_seen = False; return {'ok':True}
        if op == 'range':
            need(set(message) == {'op','prefix','height','request'} and not self.measuring and
                 type(message['prefix']) is type(message['height']) is int and
                 message['prefix'] == self.current_prefix and message['height'] == self.height+1 <= self.current_prefix, 'one_block_range_order')
            height = message['height']; raw = message['request']
            need(isinstance(raw,str) and re.fullmatch('[0-9a-f]{872}',raw) is not None, 'fixed_common_request')
            expected = (b'CPHREQ01'+struct.pack('<HH',1,4)+bytes.fromhex(self.chain)+bytes.fromhex(self.heads[0]['genesis_id'])+
                        cursor_bytes(self.heads[height-1])+cursor_bytes(self.heads[height])+struct.pack('<Q',1))
            need(bytes.fromhex(raw) == expected, 'wallet_own_range_matches_common_public_endpoints')
            stem = f'{self.current_prefix}-{height:03d}'; request, response = self.common/(stem+'.request'), self.common/(stem+'.range')
            request.write_bytes(expected)
            report = self.native(['scan-range', self.database, self.chain, request, response])
            frame = self.frames[height-1]
            need(report['endpoint'] == self.heads[height] and report['frame_count'] == '1' and
                 report['serving']['history_frame_bytes'] == frame['bytes'] and report['serving']['reduced_record_rows'] == frame['records'] and
                 report['serving']['reduced_record_bytes'] == frame['reduced_bytes'] and report['serving']['history_header_bytes'] == frame['header_bytes'] and
                 response.stat().st_size == 436+frame['bytes'], 'actual_indexed_server_work')
            self.rows.append({'prefix':self.current_prefix, 'height':height, 'request_bytes':436,
                              'server':report, 'server_cli':self.cli_receipts[-1]})
            self.height = height; return {'file':str(response)}
        if op == 'sync-start':
            need(set(message) == {'op','prefix','height'} and message['prefix'] == self.current_prefix and
                 message['height'] == self.height and not self.measuring and 'wallet' not in self.rows[-1], 'sync_start_order')
            worker.whole_peak = max(worker.whole_peak,worker.sampled_tree_peak); worker.sampled_tree_peak = 0
            self.measuring = True; worker.sample(force=True); return {'ok':True}
        if op == 'sync-row':
            need(set(message) == {'op','prefix','height','metrics','cost'} and self.measuring and
                 message['prefix'] == self.current_prefix and message['height'] == self.height, 'sync_row_order')
            self.validate_metrics(message['metrics']); self.validate_cost(message['cost']); worker.sample(force=True)
            frame = self.frames[self.height-1]; metrics = message['metrics']
            need(metrics['mode'] == 'append' and metrics['read_bytes'] == str(436+frame['bytes']) and
                 metrics['blocks'] == '1' and metrics['records'] == str(frame['records']), 'actual_wallet_suffix_work')
            self.rows[-1].update(wallet=metrics, cost=message['cost'], sampled_sync_bracket_tree_rss_kib=worker.sampled_tree_peak)
            self.measuring = False; return {'ok':True}
        if op == 'noop':
            need(set(message) == {'op','prefix','same_view','request_null','metrics'} and self.height == self.current_prefix and
                 message['prefix'] == self.current_prefix and message['same_view'] is True and message['request_null'] is True and not self.noop_seen, 'noop_control')
            self.validate_metrics(message['metrics']); need(message['metrics']['mode'] == 'unchanged' and
                all(message['metrics'][k] == '0' for k in ('read_bytes','blocks','records')), 'noop_zero_work')
            self.noop_seen = True; return {'ok':True}
        if op == 'case-complete':
            need(set(message) == {'op','prefix','equivalent','zero_owned_notes','reference_metrics','reference_cost'} and
                 message['prefix'] == self.current_prefix == self.height and self.noop_seen and
                 message['equivalent'] is True and message['zero_owned_notes'] is True, 'case_complete')
            self.validate_metrics(message['reference_metrics']); self.validate_cost(message['reference_cost'])
            n = self.current_prefix; frames = self.frames[:n]; ref = message['reference_metrics']
            need(ref['read_bytes'] == str(sum(f['bytes'] for f in frames)) and ref['blocks'] == str(n) and
                 ref['records'] == str(sum(f['records'] for f in frames)), 'full_private_reference_count')
            self.cases.append({k:v for k,v in message.items() if k != 'op'}); self.current_prefix = None; return {'ok':True}
        if op == 'native-work-complete':
            need(set(message) == {'op'} and len(self.cases) == 3 and not self.measuring, 'terminal_native_work')
            need(list(self.native_module.descendants(worker.node_pid)) == [worker.node_pid], 'terminal_no_native_descendants')
            worker.sample(force=True); fields,_ = self.native_module.proc_info(worker.node_pid)
            worker.public_result['terminal_cpu_ticks'] = fields['_cpu_ticks']; return {'ok':True}
        raise ValueError('fixed_trace_rpc')

    @staticmethod
    def validate_metrics(value):
        need(isinstance(value,dict) and set(value) == {'mode','read_bytes','blocks','records','peak_window_blocks','peak_window_records','retained'}, 'metric_fields')
        need(value['mode'] in ('append','unchanged','full-prefix-reference') and all(dec(value[k]) for k in ('read_bytes','blocks','records')), 'metric_counts')
        need(all(type(value[k]) is int and 0 <= value[k] <= 256 for k in ('peak_window_blocks','peak_window_records')), 'window_bounds')
        retained = value['retained']; need(set(retained) == {'currentBufferBytes','journalBufferBytes','journalCheckpoints','scope'} and
            all(type(retained[k]) is int and 0 <= retained[k] < 64*1024**2 for k in ('currentBufferBytes','journalBufferBytes','journalCheckpoints')) and
            retained['scope'] == 'Committed state/journal Buffer payload bytes only; excludes JS objects, allocator, staging, packet, recipients and process RSS.', 'retained_metric_scope')

    @staticmethod
    def validate_cost(value):
        need(isinstance(value,dict) and set(value) == {'wall_nanoseconds','node_self_user_microseconds','node_self_system_microseconds','waited_user_ticks','waited_system_ticks'} and
             all(dec(value[k]) for k in ('wall_nanoseconds','waited_user_ticks','waited_system_ticks')) and
             all(type(value[k]) is int and 0 <= value[k] < 2**53 for k in ('node_self_user_microseconds','node_self_system_microseconds')), 'fixed_cost_fields')

    def result(self, actor):
        summaries = []
        for n in PREFIXES:
            rows = [r for r in self.rows if r['prefix'] == n]; frames = self.frames[:n]
            need(len(rows) == n and all('wallet' in r for r in rows), 'complete_measured_case')
            summaries.append({'prefix':n, 'actual_requests':n, 'actual_request_bytes':436*n,
                'actual_response_bytes':sum(r['server']['serving']['response_bytes_written'] for r in rows),
                'actual_wallet_blocks':sum(int(r['wallet']['blocks']) for r in rows),
                'actual_wallet_records':sum(int(r['wallet']['records']) for r in rows),
                'old_repeated_prefix_bytes_counterfactual':sum((n-i)*f['bytes'] for i,f in enumerate(frames)),
                'old_repeated_prefix_blocks_counterfactual':n*(n+1)//2,
                'old_repeated_prefix_records_counterfactual':sum((n-i)*f['records'] for i,f in enumerate(frames)),
                'baseline_scope':'Exact arithmetic from actual genuine frame sizes; repeated legacy CPU/service was not executed.',
                'server_startup':{k:sum(int(r['server']['startup'][k]) for r in rows) for k in rows[0]['server']['startup'] if k != 'scope'},
                'server_serving':{k:sum(int(r['server']['serving'][k]) for r in rows) for k in rows[0]['server']['serving'] if k != 'scope'},
                'server_cli_cost':{'wall_seconds':sum(r['server_cli']['wall_seconds'] for r in rows),
                    'user_seconds':sum(r['server_cli']['user_seconds'] for r in rows),
                    'system_seconds':sum(r['server_cli']['system_seconds'] for r in rows),
                    'maximum_individual_cli_rss_kib':max(r['server_cli']['maxrss_kib'] for r in rows),
                    'scope':'Fresh CLI leader first-wait4 CPU includes registry preparation. Wrapper wall also includes held ELF checks; startup/serving spans are nested, not additive.'},
                'sync_cost':{k:sum(int(r['cost'][k]) for r in rows) for k in rows[0]['cost']},
                'maximum_sampled_sync_bracket_tree_rss_kib':max(r['sampled_sync_bracket_tree_rss_kib'] for r in rows)})
        need(not any(self.parent_public.iterdir()) and not any(self.parent_evidence.iterdir()), 'no_prover_public_outputs')
        need(self.oracle.snapshot(self.database,canonical=True) == self.replay['final_canonical_snapshot'], 'source_all14_unchanged')
        after = self.database.stat()
        need(all(getattr(after,k) == getattr(self.db_identity,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'source_database_identity_unchanged')
        return {'actor':actor, 'summaries':summaries, 'reference_cases':self.cases, 'rows':self.rows,
            'oracle_preparation_cli':self.cli_receipts[:self.preparation_cli_count],
            'source_database_bytes':after.st_size, 'public_work_disk':self.oracle.disk(self.work),
            'input_all14_checked':True, 'source_all14_unchanged':True,
            'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),
            'input_context_outside_roles':self.input_context,
            'input_trust':'Explicitly approved prior genuine public replay dataset, with current all14/head/genesis correspondence. '
                          'No current264-proof reverification. A receipt PASS alone is not verification authority; '
                          'the independently reviewed primary evidence and selected validating source remain required. '
                          'A clean reproduction constructs its one new DB from the public release closure.',
            'scope':'Zero-owned fresh wallets only. Real indexed serving and own-cursor synchronization; no receiving/spend claim. '
                    'Preparation and end-of-case full private reference excluded from sync spans. Node SELF and waited ticks are separate; '
                    'sampled sync-bracket RSS includes baseline heap, not a guaranteed peak or memory attribution. '
                    'Server startup/serving timings are nested in CLI wall/CPU and must not be added twice.'}


def worker_class(native):
    class Worker(native.Actor):
        def __init__(self, owner):
            super().__init__(owner,False); self.whole_peak = 0
            self.pipe_rx_bytes = self.pipe_tx_bytes = 0; self.frame_bytes = {}

        def sample(self, force=False):
            value = super().sample(force); self.whole_peak = max(self.whole_peak,self.sampled_tree_peak); return value

        def launch(self):
            c = self.owner; probe = c.common/'probe.json'; config = c.common/'config.json'
            c.common_module.save(probe, {'denied_files':[str(p) for p in c.denied_files], 'denied_inodes':list(c.denied_inodes),
                'controller_pid':os.getpid(),'controller_pid_namespace':os.readlink('/proc/self/ns/pid')})
            c.common_module.save(config, {'format':'CP04-INCREMENTAL-TRACE-CONFIG01','installation':str(c.installation_path),
                'installation_sha256':c.args.approve_installation,'probe_script':str(native.HERE/'isolation_probe.py'),
                'probe_config':str(probe),'inputs':str(c.common/'inputs.json'),'inputs_sha256':c.common_module.sha(c.common/'inputs.json')})
            with c.isolation.network_filter() as fd:
                command = c.isolation.command(readonly_trees=[c.source_root,c.common],
                    readonly_files=list(dict.fromkeys(c.runtime_files+[c.installation_path,HERE/'trace.mjs',native.HERE/'isolation_probe.py'])),
                    writable_public_trees=[c.output], writable_public_overlays=[(c.parent_public,c.sandbox_public),(c.parent_evidence,c.sandbox_evidence)],
                    cwd=c.source_root, filter_fd=fd, argv=[c.inst['node'],'--disable-sigusr1',str(HERE/'trace.mjs'),str(config),c.common_module.sha(config)])
                import subprocess
                self.child = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    close_fds=True,pass_fds=(fd,),start_new_session=True,env=c.inst['proof_environment'],preexec_fn=native.limits(0,c.seconds))
            for stream in (self.child.stdout,self.child.stderr):
                os.set_blocking(stream.fileno(),False); self.selector.register(stream,selectors.EVENT_READ)
            os.set_blocking(self.child.stdin.fileno(),False)

        def parse(self):
            while len(self.stdout) >= 5:
                kind,size = struct.unpack_from('<BI',self.stdout); need(kind in (1,5) and size <= 65536,'fixed_public_frame')
                if len(self.stdout) < size+5: return
                raw = self.stdout[5:5+size]; del self.stdout[:5+size]
                try:
                    value = native.decode(raw)
                    if kind == 1:
                        need(self.done is None,'no_postterminal_rpc')
                        response = self.owner.rpc(self,value)
                        encoded = bytearray(json.dumps(response,separators=(',',':')).encode())
                        counts = self.frame_bytes.setdefault(value['op'],{'frames':0,'wallet_frame_bytes':0,'controller_frame_bytes':0})
                        counts['frames'] += 1; counts['wallet_frame_bytes'] += size+5; counts['controller_frame_bytes'] += len(encoded)+5
                        self.enqueue(2,encoded)
                    else:
                        need(isinstance(value,dict) and set(value) == {'format','passed','cases','node_process_self',
                             'node_process_maxrss_kib','resource_scope','new_proofs','owned_note_claim'} and
                             self.done is None and value['format'] == 'CP04-INCREMENTAL-TRACE-DONE01' and value['passed'] is True
                             and value['cases'] == 3 and value['new_proofs'] == 0 and value['owned_note_claim'] is False,'fixed_terminal')
                        need(set(value['node_process_self']) == {'user','system'} and all(type(x) is int and 0 <= x < 2**53
                             for x in value['node_process_self'].values()) and type(value['node_process_maxrss_kib']) is int and
                             0 <= value['node_process_maxrss_kib'] <= 4*1024**2 and
                             value['resource_scope'] == 'Whole Node process includes key setup, reference replay and cleanup; not sync-only cost.',
                             'fixed_terminal_resources')
                        self.done = value
                        self.frame_bytes['terminal'] = {'frames':1,'wallet_frame_bytes':size+5,'controller_frame_bytes':0}
                finally: raw[:] = b'\0'*len(raw)

        def run(self):
            try:
                self.launch()
                while True:
                    self.owner.guard(); self.sample()
                    for key,_ in self.selector.select(.01):
                        stream = key.fileobj
                        if stream is self.child.stdin:
                            while self.outgoing:
                                data,at = self.outgoing[0]
                                try:
                                    with memoryview(data) as view: count = os.write(stream.fileno(),view[at:at+65536])
                                except BlockingIOError: break
                                self.pipe_tx_bytes += count
                                data[at:at+count] = b'\0'*count; at += count; self.outgoing[0][1] = at
                                if at < len(data): break
                                data.clear(); self.outgoing.pop(0)
                            if not self.outgoing: self.selector.unregister(stream)
                        else:
                            raw = os.read(stream.fileno(),65536)
                            if not raw: self.selector.unregister(stream); continue
                            sink = self.stdout if stream is self.child.stdout else self.stderr
                            need(len(sink)+len(raw) <= 131072,'private_capture_cap'); sink.extend(raw)
                            if stream is self.child.stdout: self.pipe_rx_bytes += len(raw); self.parse()
                    if os.waitid(os.P_PID,self.child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None: break
                self.finish_wait()
                for stream,sink in ((self.child.stdout,self.stdout),(self.child.stderr,self.stderr)):
                    while True:
                        try: raw = os.read(stream.fileno(),65536)
                        except BlockingIOError: break
                        if not raw: break
                        need(len(sink)+len(raw) <= 131072,'terminal_capture_cap'); sink.extend(raw)
                        if stream is self.child.stdout: self.pipe_rx_bytes += len(raw)
                self.parse()
                need(self.child.returncode == 0 and not self.stderr and not self.stdout and self.done is not None and
                     self.boundary_seen and not self.outgoing and 'terminal_cpu_ticks' in self.public_result,'trace_actor_terminal')
                need(sum(row['wallet_frame_bytes'] for row in self.frame_bytes.values()) == self.pipe_rx_bytes and
                     sum(row['controller_frame_bytes'] for row in self.frame_bytes.values()) == self.pipe_tx_bytes,'exact_pipe_frame_counts')
                self.public_result.update(passed=True,terminal_metrics=self.done)
                return self.public_result
            finally:
                if self.child is not None and not self.waited: self.finish_wait(kill=True)
                self.public_result['sampling'] = {'epochs':self.sample_count,'observed_processes':list(self.samples.values()),
                    'maximum_sampled_whole_tree_rss_kib':self.whole_peak,'confirmed_permission_exit_races':self.permission_exit_count,
                    'complete_same_pid_policy_after_permission':self.permission_full_count,'permission_retry_wall_seconds':self.permission_retry_wall,
                    'permission_exit_evidence_first64':self.permission_exit_races,'scope':'Existing finite Actor policy sampler; no private pipe or FD link target reads.'}
                self.public_result['experiment_pipe_bytes'] = {'wallet_to_controller':self.pipe_rx_bytes,
                    'controller_to_wallet':self.pipe_tx_bytes,'validated_frames_by_operation':self.frame_bytes,
                    'scope':'Actual local binary-framed JSON control pipes, including hex requests/paths/telemetry. '
                            'History payload travels via readonly files, counted separately by server/wallet. '
                            'Binary436B protocol request sizes are a different layer; do not double-count.'}
                self.public_result['fixed_failure_stage'] = next((name for name in
                    ('configuration','capability-boundary','trace','cleanup')
                    if self.stderr == ('CP04_TRACE_FAILED '+name+'\n').encode()), None)
                self.stdout[:] = b'\0'*len(self.stdout); self.stderr[:] = b'\0'*len(self.stderr)
                for data,_ in self.outgoing: data[:] = b'\0'*len(data)
                self.outgoing.clear(); self.selector.close()
                if self.child:
                    for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
                        if stream and not stream.closed: stream.close()
                self.owner.common_module.save(self.owner.work/'wallet-process.json',self.public_result)
    return Worker


def main():
    parser = argparse.ArgumentParser()
    for key in ('label','approve-installation','approve-source','approve-replay','approve-genesis'): parser.add_argument('--'+key,required=True)
    for key in ('installation','replay-result','genesis'): parser.add_argument('--'+key,type=Path,required=True)
    args = parser.parse_args(); need(re.fullmatch('[a-z][a-z0-9-]{0,31}',args.label) is not None,'exclusive_label')
    common = load('trace_common',REPO/'scripts/common.py')
    native = load('trace_native',HERE.parent/'network-feasibility/wallet-integration/run.py')
    source = bounded_json(HERE/'TRACE_SOURCE.json',65536,args.approve_source,common,native)
    need(source['format'] == 'CP04-INCREMENTAL-TRACE-SOURCE01' and set(source['files']) == SOURCE_KEYS and
         all(common.sha(HERE/name) == digest for name,digest in source['files'].items()),'closed_trace_source')
    isolation = load('trace_isolation',native.HERE/'isolation.py'); oracle = load('trace_oracle',native.HERE.parent/'transport/oracle.py')
    work = HERE/'.work'/args.label; work.parent.mkdir(exist_ok=True); work.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0)); resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3))
    result = {'format':'CP04-INCREMENTAL-TRACE-RESULT01','passed':False,'source_sha256':args.approve_source,
              'installation_sha256':args.approve_installation,'replay_sha256':args.approve_replay,
              'genesis_sha256':args.approve_genesis,'new_proofs':0,'owned_note_claim':False,
              'private_keys_or_backup_logged_or_hashed':False}
    controller = None
    try:
        controller = Trace(args,common,native,isolation,oracle,source,work)
        controller.actor = worker_class(native)(controller)
        result.update(controller.result(controller.actor.run())); result['passed'] = True
    except BaseException as error:
        result.update(failure_type=type(error).__name__,fixed_failure_reason=str(error) if isinstance(error,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(error)) else None)
        if controller: result.update(rows=controller.rows,reference_cases=controller.cases,native_cli=controller.cli_receipts)
    finally:
        if controller:
            for fd in controller.denied_handles: os.close(fd)
        try:
            common.load_installation(args.installation,args.approve_installation)
            need(all(common.sha(HERE/name) == digest for name,digest in source['files'].items()),'source_postcheck')
            result['source_runtime_unchanged'] = True
        except BaseException: result['source_runtime_unchanged'] = False; result['passed'] = False
        result['controller_process_self'] = {'user_seconds':resource.getrusage(resource.RUSAGE_SELF).ru_utime,
            'system_seconds':resource.getrusage(resource.RUSAGE_SELF).ru_stime,'maxrss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'scope':'Whole controller including input oracles and pin pre/postchecks; excludes subprocess CPU.'}
        common.save(work/'RESULT.json',result)
    print(json.dumps({'passed':result['passed'],'receipt':str(work/'RESULT.json')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
