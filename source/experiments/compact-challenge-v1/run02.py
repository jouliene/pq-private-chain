#!/usr/bin/env python3
"""Root-allocated PUBLIC component jobs; no mode allocates itself.

Runtime/wait4/lifecycle patterns follow executed compact-prepared-v1/run.py.
This harness has no secret-input CLI, private fixture, application verifier or codec copy.
"""
import argparse,datetime,hashlib,importlib.util,json,os,resource,signal,subprocess,tarfile,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];E=HERE/'evidence';BINARY=HERE/'target/release/compact-challenge-v1'
LIMITS={'lock':(512*1024**2,60),'build':(4*1024**3,180),'transcripts':(512*1024**2,60),'pcs':(4*1024**3,120),'stark':(4*1024**3,120)}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def label(v):
 if not v or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in v):raise argparse.ArgumentTypeError('immutable label grammar')
 return v
def success(r):return r.get('wrapper_exit')==0 and r.get('process_exit')==0 and not r.get('timeout') and r.get('source_pins_unchanged') is True and r.get('runtime_pins_unchanged') is True

def first_wait4(record,child,pid,status,usage,origin,start):
 """Retain exactly the first actual status/usage, whether main or cleanup reaps."""
 if 'first_wait4' not in record:
  child.returncode=os.waitstatus_to_exitcode(status)
  record.update(first_wait4=dict(pid=pid,status=status,origin=origin),process_exit=child.returncode,
   child_ended_utc=utc(),child_wall_seconds=time.monotonic()-start if start is not None else None,
   wait4_user_seconds=usage.ru_utime,wait4_system_seconds=usage.ru_stime,wait4_maxrss_kib=usage.ru_maxrss)
 return True

def cleanup_owned(record,child,reaped,start,*,killpg=None,wait4=None):
 """Actual finally path. Injection is used only by noncryptographic source controls.

 Matches compact-context-prepared-v2/run.py's reviewed kill_failed/first_wait4 policy.
 After failed group kill, only WNOHANG is allowed; unavailable status is NOT success.
 """
 if child is None:return reaped
 if killpg is None:killpg=os.killpg
 if wait4 is None:wait4=os.wait4
 cleanup={};kill_failed=False
 try:killpg(child.pid,signal.SIGKILL);cleanup['group_kill']='SIGKILL sent'
 except ProcessLookupError:cleanup['group_kill']='already absent'
 except BaseException as exc:
  kill_failed=True;cleanup['kill_exception']=repr(exc);record['wrapper_exit']=1
 if not reaped:
  try:
   pid,status,usage=wait4(child.pid,os.WNOHANG if kill_failed else 0)
   if pid:
    reaped=first_wait4(record,child,pid,status,usage,'cleanup',start)
    cleanup.update(reaped_pid=pid,exit_code=child.returncode,user_seconds=usage.ru_utime,
     system_seconds=usage.ru_stime,maxrss_kib=usage.ru_maxrss)
   else:
    cleanup['reap']='child still running after failed group kill; status unavailable'
    record['wrapper_exit']=1
  except BaseException as exc:cleanup['reap_exception']=repr(exc);record['wrapper_exit']=1
 else:cleanup['reap']='first wait4 already retained'
 record['group_cleanup']=cleanup
 return reaped

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=LIMITS);p.add_argument('label',type=label);p.add_argument('--freeze',required=True,type=label);p.add_argument('--build-receipt',type=label);a=p.parse_args()
 E.mkdir(exist_ok=True);prefix=E/a.label
 if list(E.glob(a.label+'.*')):raise SystemExit('immutable attempt label already exists')
 with prefix.with_suffix('.claim').open('x') as f:json.dump(dict(mode=a.mode,pid=os.getpid()),f)
 r=dict(mode=a.mode,label=a.label,runner_version='CP-BOUNDED-EF5-RUNNER02',started_utc=utc(),process_exit=None,wrapper_exit=1,timeout=False,source_pins_unchanged=False,runtime_pins_unchanged=False,private_fixture=False)
 checked={};aliases={};runtime_pins={};child=None;reaped=False;start=None
 def interrupted(signum,_):raise InterruptedError('wrapper signal '+str(signum))
 signal.signal(signal.SIGTERM,interrupted)
 def view_matches():
  return all(path.is_file() and not path.is_symlink() and sha(path)==sha(source)==digest for path,(source,digest) in aliases.items())
 try:
  manifest_path=HERE/('source-pins-'+a.freeze+'.json');m=json.loads(manifest_path.read_text());r['manifest_sha256']=sha(manifest_path)
  checked={ROOT/path:digest for path,digest in m['sources'].items()};checked[manifest_path]=r['manifest_sha256'];checked[ROOT/m['archive']]=m['archive_sha256'];checked.update({Path(path):info['sha256'] for path,info in m['registry_sources'].items()})
  aliases={ROOT/path:(ROOT/info['source'],info['sha256']) for path,info in m['derived_view'].items()}
  for path,digest in checked.items():
   if not path.is_file() or path.is_symlink() or sha(path)!=digest:raise RuntimeError('prelaunch source mismatch: '+str(path))
  if not view_matches():raise RuntimeError('declared regular derived build-view bytes changed')
  lock=HERE/'Cargo.lock'
  if a.mode=='lock':
   if lock.exists() or m['lock_sha256'] is not None:raise RuntimeError('initial offline lock requires absent lock')
  elif not lock.exists() or sha(lock)!=m['lock_sha256'] or not m['registry_closure_complete']:raise RuntimeError('exact archive-equal locked closure required')
  inputs=[manifest_path]
  if a.mode not in ('lock','build'):
   if not a.build_receipt:raise RuntimeError('actual exact build receipt required')
   path=E/(a.build_receipt+'.json');build=json.loads(path.read_text())
   if not success(build) or build.get('mode')!='build' or build['manifest_sha256']!=r['manifest_sha256'] or build.get('binary_sha256')!=sha(BINARY):raise RuntimeError('exact successful build/binary mismatch')
   inputs += [path,BINARY];r['build_receipt_sha256']=sha(path)
  for path in inputs:checked[path]=sha(path)
  snapshot=prefix.with_suffix('.inputs.tar.gz')
  with tarfile.open(snapshot,'x:gz') as tar:
   for path in inputs:tar.add(path,arcname='repository/'+str(path.relative_to(ROOT)),recursive=False)
  r.update(inputs_snapshot_sha256=sha(snapshot),source_archive=m['archive'],source_archive_sha256=m['archive_sha256'],source_files=len(checked),derived_view_files=len(aliases))
  cpu=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu});r['cpu_affinity']=[cpu]
  helper=ROOT/'experiments/compact-payment-v1/runtime_capture03.py'
  if sha(helper)!='1f8f3be83e35ba9eb2e5a43fe6339fd81a46d9b838c5fb355388c8a22a608630':raise RuntimeError('reviewed runtime helper mismatch')
  spec=importlib.util.spec_from_file_location('approved_runtime',helper);runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
  env=runtime.controlled_env();tools,details,runtime_pins=runtime.capture(ROOT,env,BINARY if a.mode not in ('lock','build') else None)
  r.update(runtime_before=runtime_pins,runtime_details=details,controlled_environment=env)
  if a.mode=='lock':cmd=[str(tools['cargo']),'generate-lockfile','--offline','--manifest-path',str(HERE/'Cargo.toml')]
  elif a.mode=='build':cmd=[str(tools['cargo']),'build','--offline','--locked','--release','-j1','--manifest-path',str(HERE/'Cargo.toml')]
  else:cmd=[str(BINARY),a.mode]
  r.update(command=cmd,limits=dict(cpu_count=1,address_space_bytes=LIMITS[a.mode][0],cpu_and_wall_seconds=LIMITS[a.mode][1]),resource_scope='direct child/waited descendants, peak not simultaneous process-tree RSS; experimental allocation, not FP1')
  def limits():
   os.sched_setaffinity(0,{cpu});resource.setrlimit(resource.RLIMIT_AS,(LIMITS[a.mode][0],)*2);resource.setrlimit(resource.RLIMIT_CPU,(LIMITS[a.mode][1],)*2);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  with prefix.with_suffix('.stdout').open('xb') as out,prefix.with_suffix('.stderr').open('xb') as err:
   start=time.monotonic();r['child_started_utc']=utc();child=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=out,stderr=err,preexec_fn=limits,start_new_session=True);r['pid']=child.pid
   while True:
    pid,status,usage=os.wait4(child.pid,os.WNOHANG)
    if pid:reaped=first_wait4(r,child,pid,status,usage,'main',start);break
    if time.monotonic()-start>LIMITS[a.mode][1]:r['timeout']=True;os.killpg(child.pid,signal.SIGKILL);pid,status,usage=os.wait4(child.pid,0);reaped=first_wait4(r,child,pid,status,usage,'timeout',start);break
    time.sleep(.05)
  r['source_pins_unchanged']=all(p.is_file() and not p.is_symlink() and sha(p)==h for p,h in checked.items()) and view_matches()
  r['runtime_after']={p:sha(Path(p)) for p in runtime_pins};r['runtime_pins_unchanged']=r['runtime_after']==runtime_pins
  if a.mode=='lock' and lock.exists():
   r['generated_lock_sha256']=sha(lock)
   with prefix.with_suffix('.Cargo.lock').open('xb') as f:f.write(lock.read_bytes())
  if BINARY.exists() and a.mode!='lock':r['binary_sha256']=sha(BINARY)
  passed=r['process_exit']==0 and not r['timeout'] and r['source_pins_unchanged'] and r['runtime_pins_unchanged']
  if a.mode not in ('lock','build'):
   marker='BOUNDED_EF5_PUBLIC_CONTROL_PASS mode='+a.mode
   r['control_marker_present']=marker in prefix.with_suffix('.stdout').read_text();passed=passed and r['control_marker_present']
  r['wrapper_exit']=0 if passed else 1
 except BaseException as exc:r.update(exception_type=type(exc).__name__,exception=str(exc),traceback=traceback.format_exc())
 finally:
  # Kill even after a reaped zero/nonzero leader; retain original failure separately.
  reaped=cleanup_owned(r,child,reaped,start)
  r['ended_utc']=utc()
  with prefix.with_suffix('.json').open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n')
  print(json.dumps({k:r.get(k) for k in ['mode','label','process_exit','wrapper_exit','source_pins_unchanged','runtime_pins_unchanged','child_wall_seconds','binary_sha256','exception']}))
 raise SystemExit(r['wrapper_exit'])
if __name__=='__main__':main()
