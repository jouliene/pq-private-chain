"""Run node and wallet roles with explicit mounts. Record observed data-directory high water."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from threading import Event, Thread
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'archive-recovery'))
# Use the prior devnet's bounded framing and long-timeout harness client without its role launcher.
import importlib.util
spec=importlib.util.spec_from_file_location('archive_role_helpers',HERE.parent/'archive-recovery/roles.py')
helpers=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
call=helpers.call


def command(deployment, script, args, mounts):
    cmd=['bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--clearenv',
         '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C','--setenv','RAYON_NUM_THREADS','2',
         '--dev','/dev','--proc','/proc','--tmpfs','/tmp','--ro-bind','/usr','/usr']
    for name in ('lib','lib64','bin','sbin'):
        host=Path('/')/name
        if host.is_symlink():
            cmd+=['--symlink',os.readlink(host),str(host)]
        elif host.is_dir():
            cmd+=['--ro-bind',str(host),str(host)]
    cmd+=['--ro-bind',str(deployment),'/deployment']
    for name in {script,'peer.py'}:
        cmd+=['--ro-bind',str(HERE/name),'/code/'+name]
    for path,target,write in mounts:
        cmd+=['--bind' if write else '--ro-bind',str(path),target]
    return cmd+['--remount-ro','/','--chdir','/tmp','--','/usr/bin/python3','-IB','/code/'+script,*args]


def usage(path):
    sizes=[0,0]
    for entry in path.iterdir():
        try:
            st=entry.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode):
            sizes[0]+=st.st_size
            sizes[1]+=st.st_blocks*512
    return sizes


class Measure:
    def __init__(self,path):
        self.path=path
        self.peak=[0,0]
        self.end=Event()
        self.thread=Thread(target=self.sample,daemon=True)
        self.start=time.monotonic()
        self.thread.start()

    def observe(self):
        now=usage(self.path)
        self.peak=[max(a,b) for a,b in zip(self.peak,now)]
        return now

    def sample(self):
        while not self.end.wait(.001):
            self.observe()

    def finish(self):
        self.end.set()
        self.thread.join()
        current=self.observe()
        return dict(elapsed_s=time.monotonic()-self.start,observed_peak_logical_B=self.peak[0],
                    observed_peak_allocated_B=self.peak[1],end_logical_B=current[0],end_allocated_B=current[1])


class Role:
    def __init__(self,dep,portdir,name,store,*,fixture=None,source=None,pin=None):
        self.portdir=portdir/name
        self.portdir.mkdir(exist_ok=True)
        self.store=store
        store.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.public=self.portdir/'public'
        self.control=self.portdir/'control'
        if fixture:
            args=['/deployment','/fixture','/ports/public','/ports/control']
            mounts=[(fixture,'/fixture',False)]
            script='peer.py'
        else:
            args=['/deployment','/store','/source','/pin','/ports/public','/ports/control']
            mounts=[(store,'/store',True),(source,'/source',False)]
            if pin:
                mounts.append((pin,'/pin',False))
            script='receiver.py'
        mounts.append((self.portdir,'/ports',True))
        log=store.parent/(name+'-process.log')
        with log.open('ab') as stream:
            self.proc=subprocess.Popen(command(dep,script,args,mounts),stdout=stream,stderr=stream)
        for _ in range(450):
            if self.proc.poll() is not None:
                raise RuntimeError('role exited during startup: '+str(log))
            try:
                self.rpc('status')
                return
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(.05)
        self.stop()
        raise RuntimeError('role startup timed out')

    def rpc(self,op,**fields):
        return call(self.control,op,**fields)[0]

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.rpc('stop')
            finally:
                self.proc.wait(timeout=60)


def wallet(dep,home,endpoint,target,action,*,backup=None,address=None,origin=None,intent=None):
    home.mkdir(mode=0o700,parents=True,exist_ok=True)
    args=['/deployment','/wallet',action,'--socket','/node','--tip',target]
    mounts=[(home,'/wallet',True),(endpoint,'/node',False)]
    if backup:
        args+=['--backup','/backup']
        mounts.append((backup,'/backup',False))
    if address:
        args+=['--address','/address','--funding-tx',origin,'--intent',intent]
        mounts.append((address,'/address',False))
    start=time.monotonic()
    data=subprocess.check_output(command(dep,'wallet.py',args,mounts),timeout=300)
    return dict(json.loads(data),process_elapsed_s=time.monotonic()-start)
