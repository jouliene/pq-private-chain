#!/usr/bin/env python3
"""Dedicated CPPRV004 RAM-pipe parent. Operator arguments are not wallet input.

No secret bytes/digests or unchecked child output are written or returned. This
does NOT perform cryptographic verification; a fresh public verifier is mandatory.
Lifecycle policy is the reviewed first-wait4/owned-group implementation, imported
with its exact source hash. All helpers are loaded before any private read.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import argparse, ctypes, datetime, hashlib, importlib.util, json, math, os, resource
import selectors, signal, stat, subprocess, time

ROOT = Path(__file__).resolve().parents[4]
AREA = ROOT / 'experiments/compact-all-payments-v3'
MAX_PACKET = 128 * 1024
MAX_STREAM = 65536
SECONDS = 120
AS_BYTES = 4 * 1024**3
LIFE = ROOT / 'experiments/compact-challenge-v1/run02.py'
LIFE_SHA = '14d70e7c81c3c98168d0c52fc8775dfa4f926361f40cd6b4dae4c092d15693a6'
RUNTIME = ROOT / 'experiments/compact-payment-v1/runtime_capture03.py'
RUNTIME_SHA = '1f8f3be83e35ba9eb2e5a43fe6339fd81a46d9b838c5fb355388c8a22a608630'
ERRORS = ('Manifest','Identity','Shape','Entropy','Preparation','Statement','Input',
          'Prove','Encode','Decode','Crypto','Io','Resource','ProofTooLarge',
          'BoundedOodAbort','BoundedPcsAbort','ChallengeAlgebra')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def decode_json(data):
    """No duplicate-key overwrite or NaN/Infinity extension at any boundary."""
    def pairs(items):
        value={}
        for k,v in items:
            if k in value:raise ValueError('DUPLICATE_JSON_KEY')
            value[k]=v
        return value
    def constant(_value):raise ValueError('NONFINITE_JSON_TOKEN')
    return json.loads(data,object_pairs_hook=pairs,parse_constant=constant)

def typed_equal(left,right):
    if type(left)is not type(right):return False
    if type(right)is dict:
        return left.keys()==right.keys() and all(typed_equal(left[k],v) for k,v in right.items())
    if type(right)is list:
        return len(left)==len(right) and all(typed_equal(a,b) for a,b in zip(left,right))
    return left==right

def map_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def label(value):
    if not value or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in value):
        raise ValueError('LABEL')
    return value

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def regular(path, cap):
    """Bounded no-follow single-inode read; no producer pathname substitution."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise ValueError('PUBLIC_FILE')
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if len(data) > cap or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or (named.st_dev,named.st_ino) != (before.st_dev,before.st_ino):
            raise ValueError('PUBLIC_FILE_CHANGED')
        return bytes(data)
    finally:
        os.close(fd)

def success(r):
    return type(r.get('process_exit')) is int and r['process_exit']==0 and type(r.get('wrapper_exit')) is int and r['wrapper_exit']==0 and r.get('timeout') is False and r.get('source_pins_unchanged') is True and r.get('runtime_pins_unchanged') is True

def numeric(value, integer=False, positive=False):
    if type(value) not in ((int,) if integer else (int,float)) or not math.isfinite(value) or value < 0 or (positive and value==0) or value > 2**53:
        raise ValueError('PUBLIC_METRIC')

def validate_manifest(value, n, prepared, statement, envelope):
    """Exact producer schema. Variable exports are bounded PUBLIC counts only."""
    timers = ['preparation_seconds','trace_check_seconds','proving_including_entropy_seconds',
              'encoding_roundtrip_seconds','local_verification_seconds','operation_wall_until_sample_seconds']
    flags = dict(private_input_boundary=True,private_input_debug_digest_created=False,
                 private_packet_persisted=False,genuine_proof_created=True,private_fixture=False,
                 source_authorization_verified=False,encrypted_receiving_verified=False,
                 canonical_admission=False,whole_protocol_security_claim=False)
    keys = set(timers) | set(flags) | {'mode','arity','prepared','statement_bytes','envelope_bytes',
        'payload_bytes','statement_sha256','proof_sha256','observations','process_self'}
    if type(value) is not dict or set(value) != keys or value['mode'] != 'prove-private' or not typed_equal(value['arity'],n):
        raise ValueError('PUBLIC_MANIFEST')
    if any(value[k] is not v for k,v in flags.items()) or not typed_equal(value['prepared'],prepared):
        raise ValueError('PUBLIC_MANIFEST_IDENTITY')
    for k in timers:
        numeric(value[k])
    expected = dict(statement_bytes=len(statement),envelope_bytes=len(envelope),payload_bytes=len(envelope)-206,
                    statement_sha256=hashlib.sha256(statement).hexdigest(),proof_sha256=hashlib.sha256(envelope).hexdigest())
    if any(not typed_equal(value[k],v) for k,v in expected.items()):
        raise ValueError('PUBLIC_MANIFEST_BYTES')
    ps = value['process_self']
    if type(ps) is not dict or set(ps) != {'cpu_system_seconds_total_until_sample','cpu_user_seconds_total_until_sample','peak_rss_kib_until_sample','scope','units'} or ps['scope'] != 'Linux RUSAGE_SELF entire process/all threads until post-operation sample; final JSON output excluded' or ps['units'] != 'seconds and KiB':
        raise ValueError('PUBLIC_SELF_SCHEMA')
    for k in ('cpu_system_seconds_total_until_sample','cpu_user_seconds_total_until_sample'):
        numeric(ps[k])
    numeric(ps['peak_rss_kib_until_sample'],True,positive=True)
    o = value['observations']
    fixed = dict(base_bytes=8,digest_bytes=64,extension_bytes=40,helper_ood_extension_fields=55,
        ordinary_ood_extension_fields=1431,main_mask_budget=512,requested_queries=160,
        required_main_mask_budget=340,terminal_extension_fields=1,
        distinct_query_positions='not instrumented; requested count used without dedup credit')
    if type(o) is not dict or set(o) != set(fixed)|{'folds','input_batches'} or any(not typed_equal(o[k],v) for k,v in fixed.items()):
        raise ValueError('PUBLIC_OBSERVATIONS')
    if type(o['folds']) is not list or len(o['folds']) != 10 or type(o['input_batches']) is not list or len(o['input_batches']) != 4:
        raise ValueError('PUBLIC_OBSERVATIONS_LENGTH')
    for i,f in enumerate(o['folds']):
        if type(f) is not dict or set(f) != {'extension_fields','path_digests','queries','round','salt_base_fields'} or not typed_equal({k:f[k] for k in f if k!='path_digests'},dict(round=i,queries=160,extension_fields=160,salt_base_fields=1280)):
            raise ValueError('PUBLIC_FOLD')
        numeric(f['path_digests'],True)
    for i,b in enumerate(o['input_batches']):
        widths = [[10],[584],[10]*8,[114]][i]
        if type(b) is not dict or set(b) != {'base_fields','batch','matrix_widths','path_digests','queries','salt_base_fields'} or not typed_equal({k:b[k] for k in b if k!='path_digests'},dict(batch=i,matrix_widths=widths,queries=160,base_fields=160*sum(widths),salt_base_fields=1280*len(widths))):
            raise ValueError('PUBLIC_BATCH')
        numeric(b['path_digests'],True)

class Parent:
    """Construct before secrets. Approval is an operator file, never packet data."""
    def __init__(self, approval):
        # Installation-only successor: actual fresh build/inspect receipts replace
        # historical developer archive/runtime paths. Packet/proof code is exact.
        if any(k.startswith(('LD_', 'PYTHON')) for k in os.environ):
            raise ValueError('PARENT_ENVIRONMENT')
        self.approval_path = Path(approval).resolve(strict=True)
        a = decode_json(regular(self.approval_path, 65536))
        required = {'format', 'source_manifest', 'source_manifest_sha256',
                    'build_receipt', 'build_receipt_sha256', 'binary',
                    'binary_sha256', 'prepared', 'runtime_receipt',
                    'runtime_receipt_sha256'}
        if set(a) != required or a['format'] != 'CP-PRIVATE-OPERATOR07':
            raise ValueError('OPERATOR_APPROVAL')
        self.a = a
        for name in ('source_manifest', 'build_receipt', 'binary', 'runtime_receipt'):
            rel = Path(a[name])
            if rel.is_absolute() or '..' in rel.parts:
                raise ValueError('REPOSITORY_OPERATOR_PATHS')
            p = ROOT / rel
            if p.is_symlink() or sha(p) != a[name + '_sha256']:
                raise ValueError('OPERATOR_APPROVAL_BYTES')
        self.binary = ROOT / a['binary']
        self.m = decode_json(regular(ROOT / a['source_manifest'], 4 * 1024**2))
        b = decode_json(regular(ROOT / a['build_receipt'], 8 * 1024**2))
        observed = decode_json(regular(ROOT / a['runtime_receipt'], 8 * 1024**2))
        if (not success(b) or b['mode'] != 'build' or
                b['manifest_sha256'] != a['source_manifest_sha256'] or
                b['binary_sha256'] != a['binary_sha256'] or
                not success(observed) or observed['mode'] != 'inspect' or
                observed['manifest_sha256'] != a['source_manifest_sha256'] or
                observed['binary_sha256'] != a['binary_sha256'] or
                observed['runtime_before'] != observed['runtime_after'] or
                observed['prepared'] != a['prepared']):
            raise ValueError('ACTUAL_FRESH_BUILD_INSPECT_REQUIRED')
        self.checked = {ROOT / p: h for p, h in self.m['sources'].items()}
        self.checked.update({ROOT / a[k]: a[k + '_sha256'] for k in
                             ('source_manifest', 'build_receipt', 'binary', 'runtime_receipt')})
        self.checked[self.approval_path] = sha(self.approval_path)
        self.separately_frozen = {str(p.resolve()): h for p, h in self.checked.items()}
        self.approved_full_runtime = observed['runtime_before']
        self.approved_runtime = self.normalized_runtime(self.approved_full_runtime)
        self.runtime = dict(self.approved_full_runtime)
        self.env = dict(observed['controlled_environment'])
        if any(k.startswith(('LD_', 'PYTHON')) for k in self.env):
            raise ValueError('CONTROLLED_ENVIRONMENT')
        # The running interpreter and every current mapped file must be covered
        # by the installation. Full stdlib source/native files are pinned too.
        if str(Path(sys.executable).resolve()) not in self.runtime:
            raise ValueError('PYTHON_INSTALLATION')
        for line in Path('/proc/self/maps').read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and fields[5].startswith('/'):
                p = Path(fields[5]).resolve(strict=True)
                if str(p) not in self.runtime or sha(p) != self.runtime[str(p)]:
                    raise ValueError('UNAPPROVED_PYTHON_MAPPING')
        for p, h in ((LIFE, LIFE_SHA), (RUNTIME, RUNTIME_SHA)):
            if sha(p) != h:
                raise ValueError('REVIEWED_HELPER')
        self.life = load('private06_lifecycle', LIFE)
        self.reference = load('private06_public_reference', AREA / 'reference.py')
        if len(a['prepared']) != 3 or not self.pins_match():
            raise ValueError('SOURCE_RUNTIME_DRIFT')
        for n, prepared in enumerate(a['prepared']):
            if (prepared['profile'] != hashlib.sha3_512((AREA / 'data/profile.json').read_bytes()).hexdigest() or
                    prepared['program'] != hashlib.sha3_512((AREA / f'data/program{n}.json').read_bytes()).hexdigest()):
                raise ValueError('PROGRAM_INSTALLATION')

    def pins_match(self):
        return all(p.is_file() and not p.is_symlink() and sha(p) == h for p,h in self.checked.items()) and all(sha(p) == h for p,h in self.runtime.items())

    def normalized_runtime(self, value):
        # The exact source/registry maps are already independently checked. Only
        # those entries may differ by Python caller-module loading; no system,
        # interpreter, stdlib, loader, tool or binary identity is dropped.
        if type(value)is not dict or any(type(k)is not str or type(v)is not str or len(v)!=64 or any(c not in '0123456789abcdef' for c in v) for k,v in value.items()):
            raise ValueError('RUNTIME_MAP_SCHEMA')
        result={}
        for k,v in value.items():
            fixed=self.separately_frozen.get(str(Path(k).resolve()))
            if fixed is not None:
                if fixed!=v:raise ValueError('FROZEN_RUNTIME_SOURCE_DIGEST')
            else:result[k]=v
        return result

    def frozen_runtime_entries(self, value):
        self.normalized_runtime(value)  # verifies every removed digest first
        return {k:v for k,v in value.items() if str(Path(k).resolve()) in self.separately_frozen}

    def public_artifacts(self, directory, expected_statement):
        if directory.is_symlink() or {p.name for p in directory.iterdir()} != {'statement.bin','proof.bin','manifest.json'}:
            raise ValueError('PUBLIC_DIRECTORY')
        statement = regular(directory/'statement.bin',528)
        if statement != expected_statement:
            raise ValueError('PUBLIC_STATEMENT_MISMATCH')
        parsed = self.reference.r.parse(statement)
        n = len(parsed['nullifiers']); prepared = self.a['prepared'][n]
        envelope = regular(directory/'proof.bin',2097152)
        ids = {k:prepared[k] for k in ('profile','program','preprocessing','preprocessing_commitment')}
        self.reference.decode_envelope(envelope,ids,statement)
        manifest = regular(directory/'manifest.json',MAX_STREAM)
        value = decode_json(manifest)
        validate_manifest(value,n,prepared,statement,envelope)
        # Only after structural/schema checks: these three files are PUBLIC.
        return n,{k:hashlib.sha256(v).hexdigest() for k,v in
                  [('statement.bin',statement),('proof.bin',envelope),('manifest.json',manifest)]}

    def prove(self, packet, attempt, public_label):
        """Consumes/clears mutable packet. No packet length/hash enters receipt."""
        if type(packet) is not bytearray:
            raise ValueError('MUTABLE_PACKET_REQUIRED')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        r = dict(format='CP-ALL-PRIVATE-PARENT07',mode='prove-private',label=attempt,
            public_label=public_label,started_utc=utc(),process_exit=None,wrapper_exit=1,timeout=False,
            source_manifest=self.a['source_manifest'],manifest_sha256=self.a['source_manifest_sha256'],
            installation_source_manifest=self.a['source_manifest'],installation_source_manifest_sha256=self.a['source_manifest_sha256'],
            binary_sha256=self.a['binary_sha256'],build_receipt_sha256=self.a['build_receipt_sha256'],
            private_input_written_or_hashed=False,unchecked_child_output_persisted=False,
            fresh_public_verification_still_required=True,source_pins_unchanged=False,runtime_pins_unchanged=False)
        r.update(approved_runtime_receipt=self.a['runtime_receipt'],
            approved_runtime_receipt_sha256=self.a['runtime_receipt_sha256'],
            approved_runtime_pins=self.approved_runtime,
            approved_runtime_digest=map_digest(self.approved_runtime),runtime_before=dict(self.runtime),
            observed_runtime_digest=map_digest(self.normalized_runtime(self.runtime)),
            approved_full_runtime=self.approved_full_runtime,
            approved_separately_frozen_runtime_entries=self.frozen_runtime_entries(self.approved_full_runtime),
            observed_separately_frozen_runtime_entries=self.frozen_runtime_entries(self.runtime),
            runtime_comparison_scope='exact captured runtime minus separately frozen source/registry paths; both maps checked')
        child=None; reaped=False; start=None; sel=None; bufs={}; written=0; ok=False; cleanup_done=False
        directory=AREA/'public'/public_label
        expected_statement=None
        try:
            label(attempt); label(public_label)
            if not self.pins_match() or directory.exists() or directory.is_symlink():
                raise ValueError('PRELAUNCH')
            if len(packet) > MAX_PACKET:
                raise ValueError('PACKET_LIMIT')
            # This is extraction, not a substitute parser. Rust remains canonical.
            if len(packet) >= 16 and packet[:8] == b'CPPRV004':
                count=int.from_bytes(packet[12:16],'little')
                if count in (448,464,528) and len(packet) >= 16+count:
                    expected_statement=bytes(packet[16:16+count])
            cpu=min(os.sched_getaffinity(0)); r['cpu_affinity']=[cpu]
            r['limits']=dict(cpu_count=1,address_space_bytes=AS_BYTES,cpu_and_wall_seconds=SECONDS,core_bytes=0,nofile=64)
            r['resource_scope']='wait4 worker CPU and peak KiB; excludes parent preflight/stdin; AS watchdog is not RSS acceptance'
            parent_pid=os.getpid()
            def limits():
                # Linux research worker: fail closed if the owning helper dies.
                if ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0) != 0 or os.getppid() != parent_pid:
                    os._exit(125)
                os.sched_setaffinity(0,{cpu})
                resource.setrlimit(resource.RLIMIT_AS,(AS_BYTES,AS_BYTES))
                resource.setrlimit(resource.RLIMIT_CPU,(SECONDS,SECONDS))
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
            directory.parent.mkdir(exist_ok=True)
            start=time.monotonic();r['child_started_utc']=utc()
            child=subprocess.Popen([str(self.binary),'prove-private',str(directory)],cwd=ROOT,
                env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                start_new_session=True,preexec_fn=limits)
            sel=selectors.DefaultSelector()
            for stream in (child.stdout,child.stderr):
                os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ)
                bufs[stream]=bytearray()
            os.set_blocking(child.stdin.fileno(),False)
            if packet:sel.register(child.stdin,selectors.EVENT_WRITE)
            else:child.stdin.close()
            while not reaped or sel.get_map():
                for event,_ in sel.select(.02):
                    stream=event.fileobj
                    if stream is child.stdin:
                        try: count=os.write(stream.fileno(),memoryview(packet)[written:written+4096])
                        except BrokenPipeError:
                            sel.unregister(stream);stream.close();continue
                        written+=count
                        if written == len(packet):
                            sel.unregister(stream);stream.close()
                    else:
                        chunk=os.read(stream.fileno(),4096)
                        if not chunk:sel.unregister(stream);continue
                        if len(bufs[stream])+len(chunk)>MAX_STREAM:
                            raise ValueError('OUTPUT_LIMIT')
                        bufs[stream].extend(chunk)
                if not reaped:
                    pid,status,usage=os.wait4(child.pid,os.WNOHANG)
                    if pid:
                        reaped=self.life.first_wait4(r,child,pid,status,usage,'main',start)
                        reaped=self.life.cleanup_owned(r,child,reaped,start);cleanup_done=True
                        if child.stdin in [x.fileobj for x in sel.get_map().values()]:
                            sel.unregister(child.stdin);child.stdin.close()
                if time.monotonic()-start>SECONDS:
                    r['timeout']=True;raise TimeoutError()
            stderr=bufs[child.stderr]
            if r['process_exit']==0:
                if stderr or written != len(packet) or expected_statement is None:
                    raise ValueError('CHILD_SUCCESS_PROTOCOL')
                n,hashes=self.public_artifacts(directory,expected_statement)
                r.update(arity=n,public_artifacts=hashes)
                ok=True
            else:
                # Compare only complete fixed strings. Never return arbitrary bytes.
                for error in ERRORS:
                    fixed=('PRIVATE_CALLER_ERROR:'+error+'\n').encode()
                    if stderr==fixed:r['private_error_class']=error
                    if error=='Prove' and stderr==b'PRIVATE_PROVER_PANIC\n'+fixed:
                        r.update(private_error_class=error,fixed_panic_marker=True)
                r['public_output_present_on_failure']=directory.exists()
        except BaseException as exc:
            r.update(exception_type=type(exc).__name__,failure_stage='PRIVATE_PARENT_FAILED')
        finally:
            if not cleanup_done:
                reaped=self.life.cleanup_owned(r,child,reaped,start)
            # Imported lifecycle exception repr is not a private-output channel.
            for key in ('kill_exception','reap_exception'):
                if key in r.get('group_cleanup',{}):r['group_cleanup'][key]='OS_OPERATION_FAILED'
            errors=[]
            for stream,b in bufs.items():
                b[:]=b'\0'*len(b)
            for item in ([sel] if sel else [])+([child.stdin,child.stdout,child.stderr] if child else []):
                try:item.close()
                except BaseException as exc:errors.append(type(exc).__name__)
            packet[:]=b'\0'*len(packet)
            expected_statement=None
            r['local_cleanup_errors']=errors
            try:
                r['source_pins_unchanged']=all(p.is_file() and not p.is_symlink() and sha(p)==h for p,h in self.checked.items())
                r['runtime_after']={p:sha(p) for p in self.runtime}
                r['runtime_pins_unchanged']=r['runtime_after']==self.runtime and self.normalized_runtime(r['runtime_after'])==self.approved_runtime
                r['runtime_after_digest']=map_digest(self.normalized_runtime(r['runtime_after']))
            except BaseException as exc:r['postcheck_exception_type']=type(exc).__name__
            clean=not errors and not any(k in r.get('group_cleanup',{}) for k in ('kill_exception','reap_exception')) and (child is None or reaped)
            r['wrapper_exit']=0 if ok and clean and r['source_pins_unchanged'] and r['runtime_pins_unchanged'] else 1
            r['ended_utc']=utc()
        return r

def stdin_packet(fd=0):
    """Physical bounded EOF read, no buffered unbounded read or packet logging."""
    packet=bytearray();sel=selectors.DefaultSelector();start=time.monotonic()
    try:
        os.set_blocking(fd,False);sel.register(fd,selectors.EVENT_READ)
        while True:
            if time.monotonic()-start>SECONDS:raise TimeoutError()
            if not sel.select(.02):continue
            chunk=os.read(fd,min(4096,MAX_PACKET+1-len(packet)))
            if not chunk:return packet
            packet.extend(chunk)
            if len(packet)>MAX_PACKET:raise ValueError('PACKET_LIMIT')
    except BaseException:
        packet[:]=b'\0'*len(packet)
        raise
    finally:sel.close()

def main():
    packet=None;prefix=None;r=None
    # The helper itself must not emit Python traceback/local payloads.
    try:
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        def interrupted(_sig,_frame):raise InterruptedError()
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGINT,interrupted)
        p=argparse.ArgumentParser();p.add_argument('--approval',required=True,type=Path)
        p.add_argument('--label',required=True);p.add_argument('--public-label',required=True)
        a=p.parse_args();label(a.label);label(a.public_label)
        parent=Parent(a.approval)
        directory=AREA/'evidence';directory.mkdir(exist_ok=True);candidate=directory/a.label
        if list(directory.glob(a.label+'.*')):raise ValueError('IMMUTABLE_ATTEMPT')
        with candidate.with_suffix('.claim').open('x') as f:json.dump({'mode':'prove-private'},f)
        prefix=candidate
        packet=stdin_packet()
        r=parent.prove(packet,a.label,a.public_label)
        print(json.dumps({k:r[k] for k in ('format','label','process_exit','wrapper_exit','fresh_public_verification_still_required')}))
        return r['wrapper_exit']
    except BaseException as exc:
        # No arbitrary exception, argv, stdin or stream diagnostic.
        if prefix is not None:
            r=dict(format='CP-ALL-PRIVATE-PARENT07',mode='prove-private',
                label=a.label,public_label=a.public_label,process_exit=None,wrapper_exit=1,
                failure_stage='PRIVATE_PARENT_INPUT_OR_SETUP_FAILED',
                exception_type=type(exc).__name__,timeout=isinstance(exc,TimeoutError),
                private_input_written_or_hashed=False,unchecked_child_output_persisted=False)
        sys.stderr.write('PRIVATE_PARENT_FAILED\n');return 1
    finally:
        if packet is not None:packet[:]=b'\0'*len(packet)
        if prefix is not None and r is not None:
            try:
                with prefix.with_suffix('.json').open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n')
            except BaseException:
                # No exception payload; a receipt publication failure is failure.
                sys.stderr.write('PRIVATE_PARENT_RECEIPT_FAILED\n')
                raise SystemExit(1)
if __name__=='__main__':raise SystemExit(main())
