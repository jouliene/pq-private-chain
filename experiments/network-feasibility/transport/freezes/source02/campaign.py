#!/usr/bin/env python3
"""Finite Gate1-specific lifecycle, role isolation, external oracles and first wait4."""
import argparse,ctypes,hashlib,importlib.util,json,os,re,resource,selectors,signal,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import prepare,oracle
ROOT=HERE.parents[2]

def need(ok,s):
 if not ok:raise ValueError(s)
def load(p):return json.loads(Path(p).read_text())
def save(p,v):
 with Path(p).open('x')as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')
class Role:
 def __init__(self,name,command,cpu,env,work,deadline,watch):
  self.name=name;self.command=list(map(str,command));self.start=time.monotonic();self.deadline=deadline;self.watch=watch;self.rows=[];self.buffers={};self.done=False;self.receipt=None;parent=os.getpid()
  def limit():
   need(ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent,'PDEATHSIG');os.sched_setaffinity(0,{cpu})
   for kind,value in [(resource.RLIMIT_CORE,0),(resource.RLIMIT_AS,4*1024**3),(resource.RLIMIT_NOFILE,64),(resource.RLIMIT_CPU,180)]:resource.setrlimit(kind,(value,value))
  self.p=subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT,env=env,start_new_session=True,preexec_fn=limit)
  self.selector=selectors.DefaultSelector()
  for f in(self.p.stdout,self.p.stderr):os.set_blocking(f.fileno(),False);self.selector.register(f,selectors.EVENT_READ);self.buffers[f]=bytearray()
  self.cpu=cpu;self.disk_peak=oracle.disk(work);self.work=work;self.process_peak_rss_kib=0;self.process_tree_peak_rss_kib=0
 def observe(self):
  d=oracle.disk(self.work);need(max(d['logical_bytes'],d['allocated_bytes'])<=8*1024**3,'role disk ceiling')
  for k,v in d.items():self.disk_peak[k]=max(self.disk_peak[k],v)
  # Actual sampled resident tree sum is separate from wait4 cumulative peaks.
  def rss(pid):
   try:
    status=Path(f'/proc/{pid}/status').read_text();r=int(re.search(r'^VmRSS:\s+(\d+)',status,re.M).group(1));kids=Path(f'/proc/{pid}/task/{pid}/children').read_text().split();return r+sum(rss(int(k))for k in kids)
   except(FileNotFoundError,ProcessLookupError,AttributeError):return 0
  self.process_tree_peak_rss_kib=max(self.process_tree_peak_rss_kib,rss(self.p.pid));need(self.process_tree_peak_rss_kib<=4*1024**2,'sampled role-tree RSS ceiling')
 def sample(self):
  need(time.monotonic()<self.deadline,'campaign watchdog');self.watch();self.observe()
 def drain(self,until=None):
  while True:
   self.sample()
   for key,_ in self.selector.select(.02):
    f=key.fileobj;b=os.read(f.fileno(),65536)
    if not b:self.selector.unregister(f);continue
    self.buffers[f].extend(b);need(len(self.buffers[f])<=8*1024**2,'role public output cap')
   out=self.buffers[self.p.stdout]
   while b'\n'in out:
    line,_,rest=out.partition(b'\n');out[:]=rest;row=json.loads(line);self.rows.append(row)
    if until is not None and until(row):return row
   terminal=os.waitid(os.P_PID,self.p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
   if terminal is not None:
    if until is not None:raise RuntimeError('role exited before expected response: '+self.name)
    return
   if until is None:return
 def request(self,c):
  self.p.stdin.write(json.dumps(c,separators=(',',':')).encode()+b'\n');self.p.stdin.flush();return self.drain(lambda row:row.get('op')==c['op'])
 def finish(self,expected=0,terminate=False):
  if terminate:os.kill(self.p.pid,signal.SIGTERM)
  while os.waitid(os.P_PID,self.p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:self.drain();time.sleep(.01)
  self.drain()
  try:os.killpg(self.p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  pid,status,u=os.wait4(self.p.pid,0);self.done=True;self.p.returncode=os.waitstatus_to_exitcode(status)
  self.selector.close()
  self.receipt={'name':self.name,'pid':self.p.pid,'command':self.command,'raw_wait_status':status,'exit':self.p.returncode,'first_wait4':True,'wall_seconds':time.monotonic()-self.start,'user_seconds':u.ru_utime,'system_seconds':u.ru_stime,'wait4_peak_rss_kib':u.ru_maxrss,'sampled_role_tree_peak_rss_kib':self.process_tree_peak_rss_kib,'cpu_affinity':[self.cpu],'disk_peak_sampled':self.disk_peak,'final_disk':oracle.disk(self.work),'rows':self.rows,'wait4_scope':('bwrap wrapper only; native lifetime receipt is authoritative for native CPU/RSS/IO'if self.name.startswith('validator')else'direct Python role process; archive threads share process counters'),'scope':'Never substitute bwrap wrapper CPU/RSS for the native validator. Sampled simultaneous tree RSS may miss short peaks; archive thread cumulative resources overlap and are not summed','public_stderr':self.buffers[self.p.stderr].decode('utf8','replace')}
  need(self.p.returncode==expected,'role terminal exit '+self.name)
  need(not self.buffers[self.p.stderr],'role unexpected stderr '+self.name)
  return self.receipt
 def cleanup(self):
  if self.done:return self.receipt
  try:os.killpg(self.p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  try:
   pid,status,u=os.wait4(self.p.pid,0);self.p.returncode=os.waitstatus_to_exitcode(status)
   terminal={'raw_wait_status':status,'exit':self.p.returncode,'first_wait4':True,'user_seconds':u.ru_utime,'system_seconds':u.ru_stime,'wait4_peak_rss_kib':u.ru_maxrss}
  except ChildProcessError:terminal={'first_wait4':False,'error':'unexpected previously reaped role'}
  self.done=True
  for f in(self.p.stdout,self.p.stderr):
   while True:
    try:b=os.read(f.fileno(),65536)
    except BlockingIOError:break
    if not b:break
    room=8*1024**2-len(self.buffers[f]);self.buffers[f].extend(b[:max(0,room)])
  public_out=self.buffers[self.p.stdout].decode('utf8','replace');public_err=self.buffers[self.p.stderr].decode('utf8','replace')
  self.selector.close();self.receipt={'name':self.name,'pid':self.p.pid,'command':self.command,'cleanup':'group SIGKILL before first reap','wall_seconds':time.monotonic()-self.start,'cpu_affinity':[self.cpu],'disk_peak_sampled':self.disk_peak,'final_disk':oracle.disk(self.work),'sampled_role_tree_peak_rss_kib':self.process_tree_peak_rss_kib,'rows':self.rows,'remaining_public_stdout':public_out,'public_stderr':public_err,**terminal}
  return self.receipt

def native_lifetime(receipt):
 terminals=[row for row in receipt['rows']if row.get('native_terminal')is True]
 need(len(terminals)==1 and terminals[0]['completed']is True,'actual successful native terminal')
 life=terminals[0]['native_lifetime'];need(life['actual_cpu_allowed_list']=='2','actual native affinity')
 inclusive=[span for row in receipt['rows']for span in row.get('stages',[])if span['name']=='inclusive-command-receive-parse-verify-commit-head']
 sums={k:sum(span[k]for span in inclusive)for k in ['self_user_seconds','self_system_seconds','waited_child_user_seconds','waited_child_system_seconds']}
 need(all(life[k]+0.000002>=v for k,v in sums.items()),'absolute native CPU below nonoverlapping command sum')
 return {**life,'checked_nonoverlapping_inclusive_command_cpu_sums':sums,'nested_stage_cpu_not_added':True}

def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--installation',type=Path,required=True);p.add_argument('--approve-installation',required=True);p.add_argument('--approve-source',required=True);p.add_argument('--build-label',required=True);p.add_argument('--approve-build',required=True);p.add_argument('--workload',type=Path,required=True);p.add_argument('--approve-workload',required=True);p.add_argument('--seconds',type=int,default=180);a=p.parse_args()
 need(re.fullmatch('[a-z0-9-]+',a.label)and 0<a.seconds<=180,'finite label/budget');need({0,1,2}<=os.sched_getaffinity(0),'declared CPUs available')
 source=HERE/'SOURCE.json';need(prepare.sha(source)==a.approve_source,'explicit transport source approval');s=load(source)
 need(s['format']=='CP04-TRANSPORT-SOURCE01','transport source schema')
 def pins():
  for n,h in s['files'].items():need(prepare.sha(HERE/n)==h,'transport source changed: '+n)
 pins();spec=importlib.util.spec_from_file_location('public_common',ROOT/'scripts/common.py');common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
 inst=common.load_installation(a.installation.resolve(),a.approve_installation);need(Path(inst['repository'])==ROOT,'same installation repository')
 bpath=HERE/'.work'/a.build_label/'BUILD.json';need(prepare.sha(bpath)==a.approve_build,'explicit actual build approval');b=load(bpath)
 need(b['installation_sha256']==a.approve_installation and b['source_sha256']==a.approve_source,'same source/installation')
 def buildpins():
  for p,h in {**b['compiled_inputs'],**b['runtime'],b['binary']:b['binary_sha256'],b['own_manifest']:b['own_manifest_sha256'],b['lock_path']:b['lock_sha256']}.items():need(prepare.sha(p)==h,'actual build/runtime drift')
 buildpins();work=HERE/'.work'/a.label;work.mkdir();producer=work/'producer';archive=work/'archive';validator=work/'validator';validator.mkdir();archive.mkdir();prepared=prepare.prepare(a.workload,a.approve_workload,producer);save(work/'PREPARED.json',prepared)
 for durable_dir in [archive,validator,producer,work,work.parent,HERE]:
  fd=os.open(durable_dir,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 roles=[];receipts=[];results={};deadline=time.monotonic()+a.seconds;env=common.controlled_env();env.update(inst['proof_environment']);env.update(RAYON_NUM_THREADS='1',RUST_BACKTRACE='0');python=Path(sys.executable).resolve();need(str(python)in inst['pins'],'approved Python')
 # Monitor all role disks/RSS while one is synchronously awaited, without recursion.
 def watch():
  for r in roles:
   if not r.done:
    r.observe()
 def start_archive():
  r=Role('archive',[python,'-I',HERE/'archive.py','--root',archive,'--allow-publication-crash'],1,env,archive,deadline,watch);roles.append(r);ready=r.drain(lambda row:row.get('ready')is True);return r,ready['port']
 def send(name,mode='put'):
  obj=prepared['objects'][name];r=Role('producer-transport-'+name+'-'+mode,[python,HERE/'sender.py','--object',obj['path'],'--sha256',obj['sha256'],'--bytes',obj['bytes'],'--kind',obj['kind'],'--port',port,'--mode',mode],0,env,producer,deadline,watch);roles.append(r);receipts.append(r.finish());return receipts[-1]
 def command(name,op='apply'):
  o=prepared['objects'][name];r=v.request({'op':op,'sha256':o['sha256'],'bytes':o['bytes'],'tag':name});need(r['error']is None,'validator operation failure');return r['result']
 try:
  ar,port=start_archive();results['interrupted_sender']=send('ordinary','interrupt');ar.drain(lambda row:row.get('complete')is False)
  need(not list(archive.glob('*.blob'))and not list(archive.glob('*.part')),'interrupted object not published')
  results['publication_crash_sender']=send('funding','crash');receipts.append(ar.finish(expected=79));need((archive/(prepared['objects']['funding']['sha256']+'.blob')).is_file(),'durable before lost ACK')
  ar,port=start_archive();send('genesis');send('funding');send('invalid_last');send('ordinary')
  proof_public=Path(inst['source_root'])/'experiments/compact-all-payments-v3/public';need(proof_public.is_dir(),'actual generated public proof directory')
  known_proofs=sorted(proof_public.glob('net-*/proof.bin'));need(known_proofs,'actual generated public proof file')
  denied=[a.workload.resolve().parent,producer.resolve(),archive.resolve(),proof_public]
  for optional in [Path(inst['source_root'])/'experiments/cp03-private-cycle/evidence',ROOT/'experiments/architecture-feasibility']:
   if optional.is_dir():denied.append(optional)
  argv=['/usr/bin/bwrap','--die-with-parent','--unshare-pid','--ro-bind','/','/','--proc','/proc','--dev','/dev','--bind',str(validator),str(validator)]
  for d in denied:argv+=['--tmpfs',str(d)]
  argv+=['--',b['binary'],str(validator/'ledger.sqlite'),prepared['chain'],f'127.0.0.1:{port}']
  v=Role('validator',argv,2,env,validator,deadline,watch);roles.append(v);vready=v.drain(lambda row:row.get('ready')is True)
  # Probe the actual child mount namespace while it is alive, from the external oracle.
  def descendants(pid):
   yield pid
   try:kids=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
   except FileNotFoundError:return
   for child in kids:yield from descendants(int(child))
  candidates=[]
  for pid in descendants(v.p.pid):
   try:
    if Path(f'/proc/{pid}/exe').resolve()==Path(b['binary']).resolve():candidates.append(pid)
   except FileNotFoundError:pass
  need(len(candidates)==1,'actual validator host PID');actual_pid=candidates[0]
  need(os.readlink(f'/proc/{actual_pid}/ns/pid')!=os.readlink('/proc/self/ns/pid'),'validator PID namespace')
  hidden=[a.workload.resolve(),a.workload.resolve().parent/'producer.sqlite',Path(prepared['objects']['ordinary']['path']),archive/(prepared['objects']['genesis']['sha256']+'.blob'),known_proofs[0]]
  need(all(not Path('/proc/'+str(actual_pid)+'/root'+str(p)).exists()for p in hidden),'receiver can read forbidden source')
  results['filesystem_boundary']={'actual_namespace_hidden_file_checks':len(hidden),'actual_validator_host_pid':actual_pid,'validator_namespace_pid':vready['pid'],'private_pid_namespace':True,'producer_fixtures_database_and_archive_subtrees_masked':True,'destination_argv_has_no_fixture_paths':True}
  results['init']=command('genesis','init');results['funding']=command('funding')
  n=prepared['ordinary_count'];need(results['funding']['state']['proof_attempts']==n and results['funding']['state']['source_signature_attempts']==n,'actual funding work counts')
  db=validator/'ledger.sqlite';before=oracle.snapshot(db);results['invalid_last']=command('invalid_last');after=oracle.snapshot(db)
  need(results['invalid_last']['accepted']is False and results['invalid_last']['ledger_error']=='Proof'and before==after,'actual late Proof/no partial state')
  n=prepared['ordinary_count'];need(results['invalid_last']['state']['proof_attempts']-results['funding']['state']['proof_attempts']==n,'every invalid candidate proof attempted')
  results['ordinary']=command('ordinary');need(results['ordinary']['accepted']is True,'valid followup');need(results['ordinary']['state']['proof_attempts']==3*n and results['ordinary']['state']['source_signature_attempts']==n,'physical proof/signature attempts include invalid candidate')
  canonical=oracle.snapshot(db,True);producer_db=a.workload.resolve().parent/'producer.sqlite';need(producer_db.is_file(),'public producer DB oracle');producer_canonical=oracle.snapshot(producer_db,True);need(canonical==producer_canonical,'all14-table producer/destination canonical state');results['producer_destination_canonical_equal_except_local_catalog_id']=True;save(work/'CANONICAL.json',canonical);results['retry']=command('ordinary');need(results['retry']['retry_current_canonical']is True and oracle.snapshot(db,True)==canonical,'current canonical exact retry')
  need(results['retry']['state']['proof_attempts']==results['ordinary']['state']['proof_attempts'],'retry performed extra proof work')
  state=results['ordinary']['state'];endpoint=prepared['endpoint']
  need(all(str(state[k])==str(endpoint[k])for k in endpoint),'equal producer/destination endpoint')
  retained=oracle.retained(db);need(retained['bodies']==2*n and retained['missing_full']==retained['pending']==retained['unexported_bytes']==retained['archive_committed_bytes']==0 and retained['retention']==1 and retained['cached_bytes']==retained['full_bytes'],'complete charged retain obligation')
  results['retained']=retained;results['invalid_all_table_snapshot_unchanged']=True
  v.request({'op':'stop'});vr=v.finish();receipts.append(vr);results['native_lifetime']=native_lifetime(vr);receipts.append(ar.finish(terminate=True))
  # Reopen in a fresh isolated process; no producer fixtures or cached verdicts supplied.
  v=Role('validator-reopen',argv,2,env,validator,deadline,watch);roles.append(v);v.drain(lambda row:row.get('ready')is True);results['reopen']=v.request({'op':'open'});need(results['reopen']['error']is None and results['reopen']['result']['block_id']==state['block_id'],'fresh durable reopen');v.request({'op':'stop'});rr=v.finish();receipts.append(rr);results['native_reopen_lifetime']=native_lifetime(rr)
  pins();buildpins();common.load_installation(a.installation.resolve(),a.approve_installation);need(all(prepare.sha(p)==h for p,h in prepared['source_pins'].items()),'public source postcheck')
  results['passed']=True
 except BaseException as exc:
  results['passed']=False;results['failure']={'type':type(exc).__name__,'message':str(exc)};raise
 finally:
  for r in roles:
   receipt=r.cleanup()
   if receipt is not None and not any(x['pid']==receipt['pid']for x in receipts):receipts.append(receipt)
  save(work/'RESULT.json',{'format':'CP04-TRANSPORT-GATE1-RESULT01','results':results,'role_receipts':receipts,'source_producer_public_disk_outside_role':oracle.disk(a.workload.resolve().parent),'launcher_oracles_outside_measured_role_spans':True,'ordinary_count':prepared['ordinary_count'],'source_sha256':a.approve_source,'installation_sha256':a.approve_installation,'build_sha256':a.approve_build,'workload_sha256':a.approve_workload,'scope':'finite loopback actual paced application-byte transport; no WAN/yearscale/PQ theorem; diagnostic2 does not satisfy96 gate'})
 print(json.dumps({'result':str(work/'RESULT.json'),'sha256':prepare.sha(work/'RESULT.json'),'ordinary_count':prepared['ordinary_count'],'passed':results.get('passed',False)}))
if __name__=='__main__':main()
