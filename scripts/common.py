"""Bounded public/private capture and explicit local installation integrity."""
from pathlib import Path
import ctypes,hashlib,json,os,resource,selectors,signal,subprocess,time
ROOT=Path(__file__).resolve().parent
if ROOT.name=='scripts':ROOT=ROOT.parent

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def need(ok,message):
 if not ok:raise ValueError(message)
def read_json(p):
 def pairs(xs):
  d={}
  for k,v in xs:
   need(k not in d,'duplicate JSON');d[k]=v
  return d
 def bad(v):raise ValueError('nonfinite JSON')
 return json.loads(Path(p).read_bytes(),object_pairs_hook=pairs,parse_constant=bad)
def save(p,v):
 with Path(p).open('x')as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')
def hashes(mapping):
 for p,h in mapping.items():need(sha(p)==h,'changed approved file: '+str(p))
def controlled_env():return {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC'}
def _run(command,*,cwd,env=None,data=b'',seconds=120,cap=65536,record=None,private=False):
 """Keep child unreaped until group cleanup; private mode has no file sink."""
 need(not private or record is None,'private streams cannot have a log sink')
 parent=os.getpid();cpu=min(os.sched_getaffinity(0));child=None;waited=False;buffers={};s=selectors.DefaultSelector();start=time.monotonic();r={'command':list(map(str,command)),'timeout':False,'wrapper_exit':1}
 previous_term=signal.getsignal(signal.SIGTERM)
 def terminate(_sig,_frame):raise InterruptedError('public job interrupted')
 signal.signal(signal.SIGTERM,terminate)
 def limits():
  if ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:os._exit(125)
  os.sched_setaffinity(0,{cpu})
  for kind,limit in [(resource.RLIMIT_CORE,0),(resource.RLIMIT_AS,4*1024**3),(resource.RLIMIT_NOFILE,64),(resource.RLIMIT_CPU,seconds)]:resource.setrlimit(kind,(limit,limit))
 try:
  child=subprocess.Popen(r['command'],cwd=cwd,env=env or controlled_env(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits)
  for f in (child.stdout,child.stderr):os.set_blocking(f.fileno(),False);s.register(f,selectors.EVENT_READ);buffers[f]=bytearray()
  os.set_blocking(child.stdin.fileno(),False);s.register(child.stdin,selectors.EVENT_WRITE);pos=0
  while True:
   for k,_ in s.select(.02):
    f=k.fileobj
    if f is child.stdin:
     if pos<len(data):pos+=os.write(f.fileno(),data[pos:pos+4096])
     else:s.unregister(f);f.close()
    else:
     b=os.read(f.fileno(),8192)
     if not b:s.unregister(f)
     else:need(len(buffers[f])+len(b)<=cap,'public output cap');buffers[f].extend(b)
   terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
   if terminal is not None:break
   if time.monotonic()-start>seconds:r['timeout']=True;raise TimeoutError('public job timeout')
  # Leader is still waitable: kill remaining owned children before PID reuse.
  try:os.killpg(child.pid,signal.SIGKILL);r['group_cleanup']='SIGKILL sent before reap'
  except ProcessLookupError:r['group_cleanup']='already absent'
  pid,status,usage=os.wait4(child.pid,0);waited=True;child.returncode=os.waitstatus_to_exitcode(status)
  r.update(process_exit=child.returncode,wall_seconds=time.monotonic()-start,user_seconds=usage.ru_utime,system_seconds=usage.ru_stime,maxrss_kib=usage.ru_maxrss,affinity_cpu=cpu,first_wait4=True)
  for f in (child.stdout,child.stderr):
   while True:
    try:b=os.read(f.fileno(),8192)
    except BlockingIOError:break
    if not b:break
    need(len(buffers[f])+len(b)<=cap,'public output cap');buffers[f].extend(b)
  r['wrapper_exit']=0
  return r,bytes(buffers[child.stdout]),bytes(buffers[child.stderr])
 except BaseException as exc:
  r['exception_type']=type(exc).__name__
  if private:return r,b'',b''
  raise
 finally:
  try:
   if child is not None and not waited:
    try:os.killpg(child.pid,signal.SIGKILL);r['failure_group_cleanup']='SIGKILL'
    except ProcessLookupError:r['failure_group_cleanup']='already absent'
    except BaseException as exc:r['cleanup_exception']=type(exc).__name__
    if 'cleanup_exception'not in r:
     pid,status,u=os.wait4(child.pid,0);waited=True;child.returncode=os.waitstatus_to_exitcode(status);r.update(process_exit=child.returncode,user_seconds=u.ru_utime,system_seconds=u.ru_stime,maxrss_kib=u.ru_maxrss,first_wait4=True,wall_seconds=time.monotonic()-start)
   s.close()
   if child is not None:
    for f in (child.stdin,child.stdout,child.stderr):
     if f is not None and not f.closed:f.close()
   if record is not None:
    record=Path(record);record.parent.mkdir(parents=True,exist_ok=True)
    save(record.with_suffix('.json'),r)
    if child is not None:
     record.with_suffix('.stdout').write_bytes(buffers.get(child.stdout,b''));record.with_suffix('.stderr').write_bytes(buffers.get(child.stderr,b''))
  finally:
   signal.signal(signal.SIGTERM,previous_term)
   if private:
    for value in buffers.values():value[:]=b'\0'*len(value)

def package_sources():
 m=read_json(ROOT/'MANIFEST.json');install=read_json(ROOT/'installation.json')if(ROOT/'installation.json').exists()else None
 overrides=install['source_postimages']if install else {}
 if(ROOT/'source-overrides.json').exists():overrides={**overrides,**read_json(ROOT/'source-overrides.json')}
 for name,item in m['files'].items():
  expected=overrides.get(name,item['sha256']);need(sha(ROOT/name)==expected,'package file drift: '+name)
 return m

def installation():
 v=read_json(ROOT/'installation.json');need(v['format']=='CP03-AUDIT-INSTALLATION01','installation schema');hashes(v['runtime']);return v

def bind_workspace(path):
 global ROOT
 ROOT=Path(path).resolve(strict=True)
 return ROOT

def verify_repository(repository):
 repository=Path(repository).resolve(strict=True)
 manifest=read_json(repository/'CORE_MANIFEST.json')
 need(manifest['format']=='CP03-PUBLIC-CORE01','public source manifest')
 for name,item in manifest['files'].items():
  rel=Path(name);need(not rel.is_absolute()and '..'not in rel.parts,'source path')
  p=repository/rel;need(not p.is_symlink()and p.is_file()and sha(p)==item['sha256'],'public source drift: '+name)
 return manifest

def run(command,*,cwd,env=None,data=b'',seconds=120,cap=65536,record=None):
 return _run(command,cwd=cwd,env=env,data=data,seconds=seconds,cap=cap,record=record,private=False)

def run_private(command,*,cwd,env=None,data=b'',seconds=120,cap=65536):
 """RAM-only private capture. Caller must classify exact fixed output; no raw log/hash."""
 return _run(command,cwd=cwd,env=env,data=data,seconds=seconds,cap=cap,record=None,private=True)

def load_installation(path,approved_sha):
 path=Path(path).resolve(strict=True)
 need(isinstance(approved_sha,str)and len(approved_sha)==64 and sha(path)==approved_sha,'explicit installation approval')
 value=read_json(path)
 need(value['format']=='CP03-PUBLIC-INSTALLATION01'and value['new_source_build']is True,'actual public installation')
 repository=Path(value['repository']).resolve(strict=True)
 workspace=Path(value['workspace']).resolve(strict=True)
 source=Path(value['source_root']).resolve(strict=True)
 need(workspace.is_relative_to(repository/'.work')and source==workspace/'source','installation workspace')
 need(Path(value['vendor']).resolve(strict=True)==repository/'vendor','installation vendor')
 hashes(value['pins'])
 operator=source/value['operator']['path']
 need(operator==Path(value['operator_path'])and sha(operator)==value['operator_sha256']==value['operator']['sha256'],'operator association')
 need(read_json(operator)['helper_sha256']==value['helper_sha256'],'helper association')
 need(value['node']in value['pins'],'approved Node identity')
 need(sha(Path(value['toolchain_path']))==value['toolchain_sha256'],'toolchain record')
 return value
