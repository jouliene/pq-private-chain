#!/usr/bin/env python3
"""Fixed public chronology replay. No wallet, keys, source DB or membership input."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import sqlite3
import stat
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
SOURCE_FILES = {'public_replay.py','run.py','../transport/oracle.py'}
TABLES = {'meta','sources','nullifiers','cores','leaves','nodes','anchors','blocks','body_cache',
          'archive_segments','archive_objects','bodies','archive_pending','node_undo'}
LABELS = ('credit-0','credit-1','ordinary-receipt','old-anchor-draft','recipient-spend',
          *(f'rolling-{i:03d}' for i in range(255)), 'refreshed-old-spend','orphan-child-draft','replacement','restored-spend')
HEAD_KEYS = {'schema','chain','genesis_id','height','block_id','leaf_count','root_le','fee_escrow','unconsumed_liabilities','block_version'}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(65536),b''):
            value.update(data)
    return value.hexdigest()


def read_json(path, cap, expected=None):
    path = Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size<=cap,'bounded_public_json')
        chunks=[];total=0
        while True:
            data=os.read(fd,min(65536,cap+1-total))
            if not data:break
            total+=len(data);need(total<=cap,'public_json_cap');chunks.append(data)
        after,named=os.fstat(fd),os.lstat(path)
        need(all(getattr(before,k)==getattr(after,k)==getattr(named,k)
                 for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'stable_public_json')
        raw=b''.join(chunks)
        if expected is not None:need(hashlib.sha256(raw).hexdigest()==expected,'actual_public_json_approval')
    finally:os.close(fd)
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result,'duplicate_public_json')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_public_json')))


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def digest_text(value):
    need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None,'public_digest')


def label_arity(label):
    if label in ('credit-0','credit-1'):
        return 0
    return 2 if label in ('ordinary-receipt','replacement') or label.startswith('rolling-') else 1


def artifact(root, entry, maximum):
    need(isinstance(entry,dict) and set(entry)=={'path','sha256','bytes'},'public_artifact_fields')
    name = entry['path'];digest_text(entry['sha256'])
    need(isinstance(name,str) and '\\' not in name and '\0' not in name and name and
         not PurePosixPath(name).is_absolute() and PurePosixPath(name).as_posix()==name and
         all(part not in ('.','..') for part in PurePosixPath(name).parts),'normalized_relative_artifact')
    need(type(entry['bytes']) is int and 0<entry['bytes']<=maximum,'artifact_size_bound')
    current = root
    for part in PurePosixPath(name).parts:
        current = current/part
        need(not current.is_symlink(),'no_artifact_symlink')
    need(current.resolve(strict=True)==current and current.is_file() and current.stat().st_size==entry['bytes'],
         'artifact_identity_size')
    return current


def copy_public(source, destination, entry):
    fd = os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd);need(stat.S_ISREG(before.st_mode),'regular_public_artifact')
        value = hashlib.sha256();total=0
        with destination.open('xb') as out:
            while True:
                data = os.read(fd,65536)
                if not data:break
                total+=len(data);need(total<=entry['bytes'],'copy_bound')
                value.update(data);out.write(data)
        after = os.fstat(fd)
        need(total==entry['bytes'] and value.hexdigest()==entry['sha256'],'copied_public_digest')
        need(all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),
             'stable_public_source_copy')
    finally:os.close(fd)


def validate_reference(value):
    need(isinstance(value,dict) and set(value)==TABLES,'exact14_reference_map')
    for entry in value.values():
        need(isinstance(entry,dict) and set(entry)=={'rows','sha256'} and type(entry['rows']) is int
             and entry['rows']>=0,'canonical_reference_entry')
        digest_text(entry['sha256'])


class Replay:
    """Only the reviewed held-FD native method is reused; no Actor/Controller init."""
    def __init__(self,args,common,native_module,oracle,closure,work):
        self.args,self.common,self.native_module,self.oracle,self.work = args,common,native_module,oracle,work
        self.installation_path = args.installation.resolve(strict=True)
        self.inst = common.load_installation(self.installation_path,args.approve_installation)
        need(Path(self.inst['repository'])==REPOSITORY,'clean_checkout_installation')
        need(self.inst['pins'].get(str(REPOSITORY/'scripts/common.py'))==sha(REPOSITORY/'scripts/common.py')
             and str(Path(sys.executable).resolve()) in self.inst['pins'],'approved_python_common')
        self.source_root = Path(self.inst['source_root'])
        self.operator = common.read_json(self.inst['operator_path'])
        self.actor = None
        self.seconds = 900
        self.deadline = time.monotonic()+self.seconds
        self.last_disk_check = 0
        self.ledger_cpu = min(os.sched_getaffinity(0))
        self.cli_receipts,self.steps = [],[]
        self.database = work/'fresh-ledger.sqlite'
        self.chain = closure['chain']
        self.reference = closure['final_canonical_snapshot']
        self.reference_head = closure['final_head']
        self.inputs = work/'public-inputs';self.inputs.mkdir()
        root = args.public.resolve(strict=True).parent
        self.genesis = self.inputs/'genesis.bin'
        copy_public(artifact(root,closure['genesis'],339320),self.genesis,closure['genesis'])
        with self.genesis.open('rb') as stream:genesis_prefix=stream.read(44)
        need(genesis_prefix[:12]==b'CPGEN004\x04\0\0\0' and genesis_prefix[12:44].hex()==self.chain,
             'exact_public_genesis_chain_version')
        self.bodies = {}
        self.coverage = {label:0 for label in LABELS}
        for label in LABELS:
            item = closure['bodies'][label];destination=self.inputs/(label+'.body')
            copy_public(artifact(root,item,2106575),destination,item)
            with destination.open('rb') as stream:
                prefix=stream.read(20);statement=stream.read((448,464,528)[label_arity(label)])
            need(prefix[:8]==b'CPBODY03','body_magic')
            version,n,p,auth,reserved = struct.unpack('<HHIHH',prefix[8:])
            arity=label_arity(label)
            need(version==3 and reserved==0 and n==(448,464,528)[arity] and 0<p<=2097152
                 and auth==(4627 if arity==0 else 0) and statement[:8]==b'CP-P2-03'
                 and statement[10]==arity and statement[16:48].hex()==self.chain
                 and 20+n+4328+auth+p==item['bytes'],'exact_body_label_arity_chain')
            self.bodies[label] = {'path':destination,'sha256':item['sha256']}
        self.head = None;self.stack=[];self.admissions=self.rollbacks=self.rejections=0

    def guard(self):
        need(time.monotonic()<self.deadline,'public_replay_watchdog')
        if time.monotonic()-self.last_disk_check>2:
            self.last_disk_check=time.monotonic()
            need(self.oracle.disk(self.work)['logical_bytes']<=8*1024**3,'public_replay_disk_bound')

    def native(self,arguments,expected_error=None):
        return self.native_module.Controller.native(self,arguments,expected_error)

    def files(self,labels):
        result=[]
        for label in labels:
            item=self.bodies[label]
            need(sha(item['path'])==item['sha256'],'immutable_copied_body')
            result.append(item['path'])
        return result

    def admit(self,*labels):
        prior=self.head
        self.head=self.native(['admit',self.database,self.chain,*self.files(labels)])
        need(self.head['chain']==self.chain and self.head['genesis_id']==self.reference_head['genesis_id']
             and int(self.head['height'])==int(prior['height'])+1
             and int(self.head['leaf_count'])==int(prior['leaf_count'])+2*len(labels)
             and self.head['root_le']!=prior['root_le'],'actual_admission_transition')
        self.stack.append(self.head.copy());self.admissions+=1
        for label in labels:self.coverage[label]+=1
        self.steps.append({'op':'admit','labels':list(labels),'head':self.head.copy()})

    def rollback(self):
        need(len(self.stack)>=2,'rollback_known_actual_head')
        expected=self.stack[-2]
        self.head=self.native(['rollback',self.database,self.chain,self.head['block_id']])
        need(self.head==expected,'exact_actual_common_prefix')
        self.stack.pop();self.rollbacks+=1
        self.steps.append({'op':'rollback','head':self.head.copy()})

    def reject(self,label):
        need(self.coverage[label]>=1,'positive_genuine_verification_before_rejection')
        file=self.files([label])[0]
        before=self.oracle.snapshot(self.database)
        self.native(['admit',self.database,self.chain,file],expected_error='Anchor')
        after=self.oracle.snapshot(self.database)
        need(before==after,'all14_anchor_atomicity')
        self.rejections+=1
        receipt={'op':'reject','label':label,'body_sha256':self.bodies[label]['sha256'],
                 'error':'Anchor','before':before,'after':after,'all14_unchanged':True}
        save(self.work/(label+'-rejection.json'),receipt)
        self.steps.append({key:receipt[key] for key in ('op','label','body_sha256','error','all14_unchanged')})

    def check_scan(self,scan,checked):
        # common.run closes child FDs. Execute the *held parent FD* path instead,
        # whose owner remains alive and keeps that descriptor open through wait4.
        # This public-only special case uses strict checked-scan decoding because
        # Controller.native's existing decoder intentionally accepts heads only.
        binary=self.source_root/self.operator['ledger_binary']['path']
        expected=self.operator['ledger_binary']['sha256']
        self.guard();remaining=int(self.deadline-time.monotonic())
        need(remaining>=1,'public_replay_watchdog')
        fd=os.open(binary,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            self.native_module.inspect_binary(fd,binary,expected)
            executable=f'/proc/{os.getpid()}/fd/{fd}'
            actual,stdout,stderr=self.common.run([executable,'check-scan',self.chain,str(self.genesis),str(scan),
                self.head['height'],self.head['block_id'],str(checked)],cwd=self.work,
                env=self.inst['proof_environment'],seconds=min(120,remaining),cap=65536,record=self.work/'check-scan-invoke')
            self.native_module.inspect_binary(fd,binary,expected)
            need(actual['process_exit']==actual['wrapper_exit']==0 and not actual['timeout'] and not stderr,
                 'check_scan_actual_success')
            value=self.native_module.decode(stdout)
            need(set(value)=={'schema','validity','chain','genesis_id','height','block_id','leaf_count'}
                 and value['schema']=='CP03-CHECKED-SCAN-01' and value['validity']=='delegated-endpoint-relative'
                 and all(value[key]==self.head[key] for key in ('chain','genesis_id','height','block_id','leaf_count')),
                 'check_scan_actual_selected_endpoint')
            need(checked.is_file() and not checked.is_symlink() and checked.stat().st_size==scan.stat().st_size,
                 'bounded_checked_scan_output')
            scan_sha,checked_sha=sha(scan),sha(checked)
            need(scan_sha==checked_sha,'checked_common_history_bytes')
            self.steps.append({'op':'check-scan','result':value,'actual_process':actual,
                               'scan_bytes':scan.stat().st_size,'scan_sha256':scan_sha,'checked_sha256':checked_sha})
            self.guard()
        finally:os.close(fd)

    def run(self):
        self.head=self.native(['init-retain',self.database,self.chain,self.genesis,'2147483648'])
        need(self.head['height']=='0' and self.head['leaf_count']=='0' and self.head['fee_escrow']=='0'
             and self.head['unconsumed_liabilities']=='1100000000'
             and self.head['genesis_id']==self.reference_head['genesis_id'],'fresh_genesis_state')
        self.stack=[self.head.copy()]
        self.admit('credit-0','credit-1');self.admit('ordinary-receipt')
        h2=self.head.copy()
        self.admit('old-anchor-draft');self.rollback()
        self.admit('recipient-spend');self.admit('old-anchor-draft');self.rollback()
        for i in range(255):self.admit(f'rolling-{i:03d}')
        need(self.head['height']=='258','actual_expiry_tip')
        connection=sqlite3.connect(self.database.as_uri()+'?mode=ro',uri=True)
        old_anchor=connection.execute('SELECT count(*) FROM anchors WHERE root=? AND leaf_count=?',
            (bytes.fromhex(h2['root_le']),int(h2['leaf_count']))).fetchone()[0]
        connection.close();need(old_anchor==0,'old_h2_root_count_actually_absent')
        self.reject('old-anchor-draft')
        self.admit('refreshed-old-spend');self.admit('orphan-child-draft');self.rollback();self.rollback()
        self.admit('replacement');self.reject('orphan-child-draft');self.admit('restored-spend')
        need((self.admissions,self.rollbacks,self.rejections)==(264,4,2)
             and sum(self.coverage.values())==265 and all(self.coverage.values()),'exact_public_chronology_counts')
        observed=self.native(['head',self.database,self.chain]);need(observed==self.head,'fresh_final_head')
        need(self.head==self.reference_head and self.head['height']=='260' and self.head['leaf_count']=='522'
             and self.head['fee_escrow']=='551305634' and self.head['unconsumed_liabilities']=='0','exact_final_head_reference')
        scan,checked=self.work/'selected.scan',self.work/'selected.checked.scan'
        need(self.native(['scan',self.database,self.chain,scan])==self.head,'fresh_common_scan_endpoint')
        self.check_scan(scan,checked)
        canonical=self.oracle.snapshot(self.database,canonical=True)
        need(canonical==self.reference,'fresh_final_all14_canonical_correspondence')
        for table,rows in [('blocks',260),('bodies',261),('cores',261),('leaves',522),('nullifiers',516),('sources',2)]:
            need(canonical[table]['rows']==rows,'final_public_table_counts')
        retained=self.oracle.retained(self.database)
        need(retained['bodies']==261 and retained['missing_full']==retained['pending']==retained['unexported_bytes']==0
             and retained['retention']==1,'complete_final_retain')
        self.guard()
        return {'final_head':self.head,'final_canonical_snapshot':canonical,'retention':retained,
            'coverage':self.coverage,'steps':self.steps,'native_cli':self.cli_receipts,
            'copied_public_input_bytes':sum(item['path'].stat().st_size for item in self.bodies.values())+self.genesis.stat().st_size,
            'old_h2_anchor_absent_at_tip258':True,'new_proofs_generated':0,
            'positive_proof_admissions':265,'successful_block_admissions':264,'rollbacks':4,'atomic_anchor_rejections':2,
            'scope':'Fresh public-only proof/state/branch replay. No wallet secret, backup, source DB, membership or cached verdict input; private discovery/rewind/recovery remain separately reviewed original full01 plus fresh small5 obligations.'}


def main():
    parser=argparse.ArgumentParser()
    for name in ('label','approve-installation','approve-source','approve-public'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--installation',type=Path,required=True)
    parser.add_argument('--public',type=Path,required=True)
    args=parser.parse_args()
    need(re.fullmatch('[a-z][a-z0-9-]{0,31}',args.label) is not None,'exclusive_replay_label')
    source_path=HERE/'PUBLIC_REPLAY_SOURCE.json';digest_text(args.approve_source)
    source=read_json(source_path,65536,args.approve_source)
    need(source['format']=='CP04-WALLET-PUBLIC-REPLAY-SOURCE01' and set(source['files'])==SOURCE_FILES,'fixed_public_driver_closure')
    need(all(sha(HERE/name)==digest for name,digest in source['files'].items()),'public_driver_source_pins')
    public=args.public.absolute()
    need(public.resolve(strict=True)==public and not public.is_symlink(),'approved_finite_public_closure')
    digest_text(args.approve_public)
    closure=read_json(public,1024**2,args.approve_public)
    need(set(closure)=={'format','chain','genesis','bodies','final_head','final_canonical_snapshot'}
         and closure['format']=='CP04-WALLET-FULL-PUBLIC-CLOSURE01'
         and set(closure['bodies'])==set(LABELS) and len(closure['bodies'])==264,'exact264_public_closure')
    need(len({item['path'] for item in closure['bodies'].values()})==264
         and len({item['sha256'] for item in closure['bodies'].values()})==264,'distinct264_public_artifacts')
    need(isinstance(closure['chain'],str) and re.fullmatch('[0-9a-f]{64}',closure['chain']) is not None,'closure_chain')
    validate_reference(closure['final_canonical_snapshot'])
    common=load_module('public_replay_common',REPOSITORY/'scripts/common.py')
    native_module=load_module('public_replay_native',HERE/'run.py')
    oracle=load_module('public_replay_oracle',HERE.parent/'transport/oracle.py')
    native_module.head(closure['final_head']);need(closure['final_head']['chain']==closure['chain'],'reference_head_chain')
    work=HERE/'.work'/args.label;work.parent.mkdir(exist_ok=True);work.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3))
    result={'format':'CP04-WALLET-PUBLIC-REPLAY-RESULT01','passed':False,'source_sha256':args.approve_source,
            'installation_sha256':args.approve_installation,'public_closure_sha256':args.approve_public}
    replay=None
    try:
        replay=Replay(args,common,native_module,oracle,closure,work)
        save(work/'claim.json',{'source_sha256':args.approve_source,'installation_sha256':args.approve_installation,
            'public_closure_sha256':args.approve_public,'seconds':900,'address_space_bytes':4*1024**3,
            'disk_bytes':8*1024**3,'cpu':replay.ledger_cpu,'source_DB_seeded':False,'private_material_input':False})
        result.update(replay.run());result['passed']=True
    except BaseException as error:
        result['failure_type']=type(error).__name__
        result['fixed_failure_reason']=str(error) if isinstance(error,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(error)) else None
        if replay:result.update(steps=replay.steps,native_cli=replay.cli_receipts,coverage=replay.coverage)
    finally:
        try:
            common.load_installation(args.installation,args.approve_installation)
            need(all(sha(HERE/name)==digest for name,digest in source['files'].items()),'public_driver_source_postcheck')
            result['source_runtime_unchanged']=True
        except BaseException:result['source_runtime_unchanged']=False;result['passed']=False
        save(work/'RESULT.json',result)
    print(json.dumps({'passed':result['passed'],'receipt':str(work/'RESULT.json')}))
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
