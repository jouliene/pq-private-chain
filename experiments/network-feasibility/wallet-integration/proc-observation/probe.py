#!/usr/bin/env python3
"""One <=10s public observation of unchanged isolation; metadata only, no privilege changes."""
from pathlib import Path
import argparse,ctypes,errno,hashlib,importlib.util,json,os,resource,selectors,signal,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;PARENT=HERE.parent;ROOT=PARENT.parents[2]
spec=importlib.util.spec_from_file_location('fixed_isolation',PARENT/'isolation.py');isolation=importlib.util.module_from_spec(spec);spec.loader.exec_module(isolation)
def need(ok,s):
 if not ok:raise ValueError(s)
def identity(pid):
 raw=Path(f'/proc/{pid}/stat').read_text();tail=raw[raw.rindex(')')+2:].split();return {'starttime_ticks':int(tail[19]),'state':tail[0],'comm':raw[raw.index('(')+1:raw.rindex(')')]}
def probe_identity(pid):
 try:return identity(pid)
 except OSError as e:return {'error_type':type(e).__name__,'errno':e.errno}
def children(pid):
 try:return [int(x)for x in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
 except(FileNotFoundError,ProcessLookupError):return []
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--label',required=True);a=ap.parse_args();need(a.label.isascii()and a.label.replace('-','').isalnum(),'label');work=HERE/a.label;work.mkdir();common=work/'common';common.mkdir();(common/'public.txt').write_text('PUBLIC_ONLY\n');sentinel=work/'unmounted-public-sentinel';sentinel.write_text('PUBLIC_ONLY\n');denied_fd=os.open(sentinel,os.O_RDONLY);os.set_inheritable(denied_fd,True);denied_inode=(os.fstat(denied_fd).st_dev,os.fstat(denied_fd).st_ino)
 node=ROOT/'.tools/node-v24.22.1-linux-x64/bin/node';need(node.is_file(),'existing approved public Node path');child=None;waited=False;sel=selectors.DefaultSelector();buffers={};result={'format':'CP04-PUBLIC-PROC-OBSERVATION01','passed':False,'no_private_data_or_proof_or_key_or_build':True,'child_launch_budget':96,'wall_budget_seconds':10,'same_identity_retry_budget_milliseconds':20,'retry_attempt_cap':16,'records':[],'normal_processes':{},'read_no_FD_targets_or_contents':True};start=time.monotonic();limit=start+10;nodepid=None;ns=None;done=None
 def setup():
  os.sched_setaffinity(0,{0});resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3));resource.setrlimit(resource.RLIMIT_CPU,(10,10));ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)
 def full(pid,expected):
  op='identity';before=None
  try:
   before=identity(pid);need(before['starttime_ticks']==expected,'identity_changed');op='status';fields=dict(line.split(':',1)for line in Path(f'/proc/{pid}/status').read_text().splitlines()if':'in line)
   if before['state']in('Z','X'):return {'ok':False,'confirmed_exit':True,'before':before,'operation':'identity'}
   op='children';children(pid);op='namespace';actual={n:os.readlink(f'/proc/{pid}/ns/{n}')for n in('pid','mnt','net')};need(actual==ns and fields['Seccomp'].strip()=='2','policy_changed');op='denied_mount'
   try:Path(f'/proc/{pid}/root{sentinel}').stat()
   except FileNotFoundError:pass
   else:raise ValueError('unmounted_sentinel_visible')
   op='fd_directory';fds=list(Path(f'/proc/{pid}/fd').iterdir());checked=0
   for fd in fds:
    op='fd_identity'
    try:st=fd.stat()
    except FileNotFoundError:continue
    need((st.st_dev,st.st_ino)!=denied_inode,'inherited_sentinel_visible');checked+=1
   op='mountinfo';mounts={p[4]:p[5].split(',')for line in Path(f'/proc/{pid}/mountinfo').read_text().splitlines()if len(p:=line.split())>=6};need('ro'in mounts.get('/usr',[])and'ro'in mounts.get(str(common),[]),'readonly_policy');op='identity_recheck';after=identity(pid);need(after['starttime_ticks']==expected,'identity_changed');return {'ok':True,'before':before,'after':after,'FD_identity_checks':checked,'full_namespace_seccomp_mount_FD_identity_pass':True}
  except OSError as e:return {'ok':False,'operation':op,'error_type':type(e).__name__,'errno':e.errno,'before':before,'after':probe_identity(pid)}
  except ValueError as e:return {'ok':False,'operation':op,'policy_failure':str(e),'before':before,'after':probe_identity(pid)}
 try:
  with isolation.network_filter()as filterfd:
   cmd=isolation.command(readonly_trees=[common],readonly_files=[HERE/'inner.mjs',node,Path('/etc/ld.so.cache')],writable_public_trees=[],cwd=Path('/tmp'),filter_fd=filterfd,argv=[str(node),'--disable-sigusr1',str(HERE/'inner.mjs')]);child=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(filterfd,),start_new_session=True,preexec_fn=setup,env={'PATH':'/usr/bin:/bin','LANG':'C'})
  for f in(child.stdout,child.stderr):os.set_blocking(f.fileno(),False);sel.register(f,selectors.EVENT_READ);buffers[f]=bytearray()
  seen=set();parent_only=True
  while time.monotonic()<limit:
   for key,_ in sel.select(.0002):
    f=key.fileobj;b=os.read(f.fileno(),4096)
    if not b:sel.unregister(f)
    else:buffers[f].extend(b);need(len(buffers[f])<16384,'public_output_cap')
   need(not buffers[child.stderr],'public_actor_stderr');out=buffers[child.stdout]
   while b'\n'in out:
    line,_,rest=out.partition(b'\n');out[:]=rest;message=json.loads(line)
    if message['kind']=='ready':
     ns=message['namespaces'];pending=[child.pid]
     while pending:
      pid=pending.pop();pending.extend(children(pid))
      try:
       fields=dict(x.split(':',1)for x in Path(f'/proc/{pid}/status').read_text().splitlines()if':'in x)
       if int(fields.get('NSpid','0').split()[-1])==message['pid']and os.readlink(f'/proc/{pid}/ns/pid')==ns['pid']:nodepid=pid
      except FileNotFoundError:pass
     need(nodepid is not None,'actual_node_pid');initial=full(nodepid,identity(nodepid)['starttime_ticks']);need(initial['ok'],'initial_full_policy');result['baseline_full_policy']=initial;result['namespace_ids']=ns;result['actual_node_pid']=nodepid;child.stdin.write(b'GO\n');child.stdin.flush()
    elif message['kind']=='done':done=message
   if nodepid:
    for pid in children(nodepid):
     try:first=identity(pid)
     except(FileNotFoundError,ProcessLookupError):continue
     key=(pid,first['starttime_ticks']);sample=full(pid,key[1]);normal=result['normal_processes'].setdefault(str(pid),{'starttime_ticks':key[1],'full_samples':0,'first_comm':first['comm']})
     if sample.get('ok'):normal['full_samples']+=1;normal['last_comm']=sample['after']['comm'];continue
     if sample.get('errno')!=errno.EACCES:
      if 'policy_failure'in sample:result['records'].append({'pid':pid,'expected_starttime_ticks':key[1],'first':sample,'disposition':'policy_failure'});raise ValueError('public_policy_failure')
      continue
     if key in seen:continue
     seen.add(key);record={'pid':pid,'expected_starttime_ticks':key[1],'first':sample,'observed_seconds':time.monotonic()-start,'attempts':[]};t=time.monotonic();deadline=min(limit,t+.020);disposition='persistent_or_unresolved'
     for attempt in range(16):
      if time.monotonic()>=deadline:break
      now=full(pid,key[1]);record['attempts'].append({'elapsed_ms':(time.monotonic()-t)*1000,**now})
      if now.get('ok'):disposition='same_identity_full_policy_later';normal['full_samples']+=1;break
      current=probe_identity(pid)
      if current.get('starttime_ticks')not in(None,key[1]):disposition='identity_changed';break
      if current.get('starttime_ticks')==key[1]and current['state']in('Z','X'):disposition='same_identity_confirmed_exit';break
      if current.get('errno')in(errno.ENOENT,errno.ESRCH):
       try:Path(f'/proc/{pid}').stat()
       except(FileNotFoundError,ProcessLookupError):disposition='identity_and_directory_absent';break
       except OSError:pass
      time.sleep(.0002)
     record['disposition']=disposition;record['elapsed_ms']=(time.monotonic()-t)*1000;record['final_identity']=probe_identity(pid);result['records'].append(record)
   terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
   if terminal is not None:
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    _,status,u=os.wait4(child.pid,0);waited=True;child.returncode=os.waitstatus_to_exitcode(status);result['terminal']={'exit':child.returncode,'first_wait4':True,'wrapper_user_seconds':u.ru_utime,'wrapper_system_seconds':u.ru_stime};need(child.returncode==0 and done is not None and done['completed']==96,'all_public_launches_complete');result['passed']=True;break
  need(waited,'10second_budget');result['child_actor']=done
 except BaseException as e:result['failure']={'type':type(e).__name__,'message':str(e)}
 finally:
  if child is not None and not waited:
   try:os.killpg(child.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   _,status,_=os.wait4(child.pid,0);result['cleanup_exit']=os.waitstatus_to_exitcode(status)
  os.close(denied_fd);sel.close();result['wall_seconds']=time.monotonic()-start;result['sampled_child_pid_count']=len(result['normal_processes']);result['EACCES_records']=len(result['records']);result['dispositions']={k:sum(x['disposition']==k for x in result['records'])for k in sorted({x['disposition']for x in result['records']})};result['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in[HERE/'probe.py',HERE/'inner.mjs',PARENT/'isolation.py']};(work/'RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'passed':result['passed'],'wall_seconds':result['wall_seconds'],'sampled_child_pid_count':result['sampled_child_pid_count'],'EACCES_records':result['EACCES_records'],'dispositions':result['dispositions'],'failure':result.get('failure')}))
if __name__=='__main__':main()
