#!/usr/bin/env python3
"""One public nested-PID identity discriminator; no wallet execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
CLONE = Path('/tmp/pq-gate5-20261117-01')

INNER = r'''
import errno,json,os,socket,threading
from pathlib import Path
config=json.loads(__import__('sys').argv[1]); source=__import__('sys').argv[2]
released=threading.Event(); ready=threading.Event(); thread_id=[]
def hold():
 thread_id.append(threading.get_native_id());ready.set();released.wait(2)
t=threading.Thread(target=hold);t.start();ready.wait(1)
def identity(pid):
 p=Path('/proc')/str(pid)
 try:
  status=dict(line.split(':',1) for line in (p/'status').read_text().splitlines() if ':' in line)
  raw=(p/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
  return {'pid':pid,'tgid':int(status['Tgid']),'reported_pid':int(status['Pid']),
   'starttime_ticks':int(fields[19]),'pid_namespace':os.readlink(p/'ns/pid'),
   'mnt_namespace':os.readlink(p/'ns/mnt'),'root_stat':[os.stat(p/'root').st_dev,os.stat(p/'root').st_ino]}
 except OSError as e:return {'pid':pid,'errno':e.errno}
checks=[]
for p in config['denied_files']:
 try:fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK)
 except OSError as e:checks.append({'check':'denied_file','path':p,'errno':e.errno,'passed':e.errno in (errno.ENOENT,errno.EACCES,errno.EPERM)})
 else:os.close(fd);checks.append({'check':'denied_file','path':p,'passed':False})
for name in os.listdir('/proc/self/fd'):
 try:s=os.fstat(int(name))
 except OSError as e:checks.append({'check':'fd_stat','fd':int(name),'errno':e.errno,'passed':e.errno==errno.EBADF});continue
 checks.append({'check':'inherited_fd','fd':int(name),'identity':[s.st_dev,s.st_ino],
  'passed':[s.st_dev,s.st_ino] not in config['denied_inodes']})
for family in (socket.AF_INET,socket.AF_INET6,socket.AF_UNIX):
 try:s=socket.socket(family,socket.SOCK_STREAM)
 except OSError as e:checks.append({'check':'socket_family','family':int(family),'errno':e.errno,'passed':e.errno==errno.EPERM})
 else:s.close();checks.append({'check':'socket_family','family':int(family),'passed':False})
numeric=identity(config['host_pid']); exists=Path('/proc/'+str(config['host_pid'])+'/root').exists()
checks.append({'check':'original_forbidden_root_assertion','numeric_pid':config['host_pid'],'exists':exists,'passed':not exists})
module={'__name__':'reviewed_public_probe'};exec(compile(source,'frozen-isolation_probe.py','exec'),module)
try:value=module['inspect'](config);actual={'passed':True,'value':value}
except BaseException as e:actual={'passed':False,'type':type(e).__name__,'reason':str(e)}
result={'inner_self':identity(os.getpid()),'inner_pid1':identity(1),'inner_thread':identity(thread_id[0]),
 'numeric_controller_candidate':numeric,'controller_identity':config['controller_identity'],
 'checks':checks,'frozen_inspect':actual,'seccomp':next(l.split(':',1)[1].strip() for l in Path('/proc/self/status').read_text().splitlines() if l.startswith('Seccomp:'))}
released.set();t.join(1);print(json.dumps(result,sort_keys=True))
'''

CONTROLLER = r'''
import json,os,sys,subprocess,time
from pathlib import Path
sys.dont_write_bytecode=True
payload=json.loads(sys.argv[1]);config=payload['config']; module={'__name__':'reviewed_isolation'}
exec(compile(payload['isolation'],'frozen-isolation.py','exec'),module)
raw=Path('/proc/self/stat').read_text();fields=raw[raw.rfind(')')+2:].split()
config['host_pid']=os.getpid();config['controller_identity']={'pid':os.getpid(),'starttime_ticks':int(fields[19]),'pid_namespace':os.readlink('/proc/self/ns/pid'),'mnt_namespace':os.readlink('/proc/self/ns/mnt')}
fd=os.open(config['denied_files'][1],os.O_RDONLY);s=os.fstat(fd);config['denied_inodes']=[[s.st_dev,s.st_ino]];os.set_inheritable(fd,True)
with module['network_filter']() as filt:
 cmd=module['command'](readonly_trees=[],readonly_files=[],writable_public_trees=[],cwd='/usr',argv=['/usr/bin/python3','-I','-B','-c',payload['inner'],json.dumps(config),payload['probe']],filter_fd=filt)
 started=time.monotonic();p=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(filt,),close_fds=True,timeout=3,env={'PATH':'/usr/bin:/bin','LANG':'C'})
os.close(fd)
print(json.dumps({'controller_identity':config['controller_identity'],'inner_exit':p.returncode,'inner_wall_seconds':time.monotonic()-started,'inner_stdout':json.loads(p.stdout) if p.returncode==0 else None,'inner_stderr':p.stderr.decode(),'actual_isolation_command':True},sort_keys=True))
'''

def main():
    outer = json.loads((CLONE/'.work/gate5-supervision/small01-command.json').read_text())
    base = CLONE/'experiments/network-feasibility/wallet-integration'
    probe = (base/'isolation_probe.py').read_text()
    isolation = (base/'isolation.py').read_text()
    config = json.loads((base/'.work/reviewer-small01/common/original-probe.json').read_text())
    payload = {'config':config,'isolation':isolation,'probe':probe,'inner':INNER}
    # Preserve the reviewer's actual outer argv; replace only its public payload.
    public = 'import subprocess,json\np=subprocess.run('+repr(['/usr/bin/python3','-I','-B','-c',CONTROLLER,json.dumps(payload)])+',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)\nprint(json.dumps({"controller_exit":p.returncode,"controller":json.loads(p.stdout) if p.returncode==0 else None,"controller_stderr":p.stderr.decode()},sort_keys=True))\n'
    started = time.monotonic()
    p = subprocess.run(outer['argv'],input=public.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
    result = {'format':'PUBLIC-NESTED-PID-DISCRIMINATOR01','outer_exit':p.returncode,
      'wall_seconds':time.monotonic()-started,'outer_stderr':p.stderr.decode(),
      'result':json.loads(p.stdout) if p.returncode==0 else None,
      'explicit_subprocess_launches':3,'thread_launches':1,
      'budget':'10 seconds / at most 4 explicit subprocess launches; bubblewrap internal namespace/reaper processes inherent',
      'source_sha256':{n:hashlib.sha256((base/n).read_bytes()).hexdigest() for n in ('isolation.py','isolation_probe.py')},
      'actual_outer_argv_preserved':True,'original_wallet_controller_or_private_config_executed':False}
    path=HERE/'RESULT01.json'
    with path.open('x') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps({'outer_exit':p.returncode,'wall_seconds':result['wall_seconds'],'result':str(path)}))

if __name__=='__main__':main()
