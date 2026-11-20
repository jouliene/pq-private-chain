"""Disposable operator services for the loopback and two-physical-host demonstrations."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


class Meter(socketserver.ThreadingTCPServer):
    daemon_threads=True

    def __init__(self, target):
        self.target=target
        self.rows=[]
        self.lock=threading.Lock()
        super().__init__(('127.0.0.1',0), ObserveRPC)


def read_rpc(stream):
    hdr=stream.read(4)
    if len(hdr)!=4:
        raise ValueError('truncated RPC prefix')
    n,=struct.unpack('!I',hdr)
    if not 5<=n<=2**21:
        raise ValueError('invalid RPC size')
    data=stream.read(n)
    if len(data)!=n:
        raise ValueError('truncated RPC frame')
    return hdr+data


class ObserveRPC(socketserver.StreamRequestHandler):
    timeout=35

    def handle(self):
        packet=read_rpc(self.rfile)
        size=int.from_bytes(packet[4:8],'big')
        op=json.loads(packet[8:8+size])['op']
        row={'op':op,'request_B':len(packet)}
        if op=='submit':
            row.update(id=sha256(packet[8+size:]).hexdigest(),packet_B=len(packet)-8-size)
        with self.server.lock:
            self.server.rows.append(row)
        with socket.create_connection(('127.0.0.1',self.server.target),timeout=35) as peer:
            peer.sendall(packet)
            with peer.makefile('rb') as stream:
                reply=read_rpc(stream)
        row['reply_B']=len(reply)
        self.wfile.write(reply)


def free_ports(n):
    sockets=[socket.socket() for _ in range(n)]
    try:
        for sock in sockets:
            sock.bind(('127.0.0.1',0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


class Service:
    def __init__(self, command, logfile):
        self.logfile=logfile
        with logfile.open('w') as log:
            self.p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)

    def ready(self, interval=45):
        end=time.monotonic()+interval
        while time.monotonic()<end and self.p.poll() is None:
            for line in self.logfile.read_text(errors='replace').splitlines():
                try:
                    row=json.loads(line)
                    if row.get('ready'):
                        return row
                except (ValueError,AttributeError):
                    pass
            time.sleep(.1)
        raise RuntimeError('service failed to start; see '+str(self.logfile))

    def stop(self):
        if self.p.poll() is None:
            os.killpg(self.p.pid,signal.SIGTERM)
            try:
                self.p.wait(8)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid,signal.SIGKILL)
                self.p.wait()


class Remote:
    """Forward test ports to loopback only. Remote role keys are generated on their host."""
    def __init__(self, host, config):
        if not host or host.startswith('-') or any(c.isspace() for c in host):
            raise ValueError('expected an SSH-config host')
        self.host=host
        self.scratch=tempfile.TemporaryDirectory(prefix='pqm-ssh-')
        self.socket=str(Path(self.scratch.name)/'master')
        self.opts=['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oConnectTimeout=8']
        if config:
            self.opts+=['-F',str(config.resolve(strict=True))]
        self.opts+=['-S',self.socket]
        self.procs=[]
        self.master=subprocess.Popen([*self.opts,'-MN',host],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
        until=time.monotonic()+12
        while not Path(self.socket).exists() and self.master.poll() is None and time.monotonic()<until:
            time.sleep(.1)
        if not Path(self.socket).exists():
            self.close()
            raise ValueError('SSH control connection unavailable')
        self.base=Path(self.run(['mktemp','-d','/tmp/pq-stranger-XXXXXXXX']).stdout.strip())

    def run(self, argv, **kwargs):
        return subprocess.run([*self.opts,self.host,shlex.join(list(map(str,argv)))],text=True,
                              capture_output=True,check=True,timeout=kwargs.pop('timeout',150),**kwargs)

    def forward(self, direction, source_port, target_port):
        subprocess.run([*self.opts,'-O','forward',direction,
                        f'127.0.0.1:{source_port}:127.0.0.1:{target_port}',self.host],check=True,
                       capture_output=True,timeout=15)

    def sync(self, source, target, flags=()):
        subprocess.run(['rsync','-az','--chmod=go-rwx',*flags,'-e',shlex.join(self.opts),str(source),
                        self.host+':'+str(target)],check=True,stdout=subprocess.DEVNULL,timeout=300)

    def prepare(self, repo, deployment, node):
        self.run(['mkdir','-p','-m','0700',self.base/'repo',self.base/'maker',self.base/'bin'])
        # Only source, fixed binaries and public verifier registrations are provisioned.
        self.sync(str(repo)+'/',str(self.base/'repo')+'/',(
            '--exclude=.git/','--exclude=.work/','--exclude=.tools/','--exclude=target/','--exclude=vendor/',
            '--exclude=__pycache__/','--include=*/','--include=pqd','--include=*.py','--include=*.mjs','--exclude=*','--prune-empty-dirs'))
        self.sync(str(deployment),self.base/'maker')
        self.sync(node,self.base/'bin/node')
        result=self.run([self.base/'bin/node','-p','process.versions.openssl'])
        if result.stdout.strip()!='3.5.9':
            raise ValueError('remote transport runtime differs')

    def command(self, *args):
        return ['env','STRANGER_NODE='+str(self.base/'bin/node'),self.base/'repo/pqd',*args]

    def service(self, args, name, log):
        # The remote process group belongs exclusively to this scratch directory and role.
        script='import os,sys;from pathlib import Path;os.setpgid(0,0) if os.getpgrp()!=os.getpid() else None;Path(sys.argv[1]).write_text(str(os.getpid()));os.execvp(sys.argv[2],sys.argv[2:])'
        cmd=['python3','-c',script,self.base/(name+'.pid'),*self.command(*args)]
        proc=Service([*self.opts,self.host,shlex.join(list(map(str,cmd)))],log)
        self.procs.append((name,proc))
        return proc

    def close(self):
        for name,proc in reversed(self.procs):
            script='import os,signal,sys;from pathlib import Path;p=Path(sys.argv[1]);\nif p.exists():\n try: os.killpg(int(p.read_text()),signal.SIGTERM)\n except ProcessLookupError: pass'
            try:
                self.run(['python3','-c',script,self.base/(name+'.pid')],timeout=8)
            finally:
                proc.stop()
        if self.master.poll() is None:
            self.master.terminate()
            self.master.wait(timeout=10)
        self.scratch.cleanup()


class CiphertextLink(socketserver.ThreadingTCPServer):
    """Independent TCP forwarding observer. Retain byte counts, never wallet messages."""
    daemon_threads=True
    def __init__(self,target):
        self.target=target
        self.rows=[]
        super().__init__(('127.0.0.1',0),CiphertextCopy)


class CiphertextCopy(socketserver.BaseRequestHandler):
    def handle(self):
        import select
        row={'to_maker_B':0,'to_taker_B':0}
        self.server.rows.append(row)
        try:
            upstream=socket.create_connection(('127.0.0.1',self.server.target),timeout=5)
        except OSError:
            # The test may deliberately disconnect the maker before sending a quote continuation.
            self.request.settimeout(2)
            try:
                row['to_maker_B']=len(self.request.recv(65536))
            except OSError:
                pass
            row['upstream_unavailable']=True
            return
        with upstream:
            peers=(self.request,upstream)
            live=list(peers)
            while live:
                readable,_,_=select.select(live,[],[],155)
                if not readable:
                    break
                for src in readable:
                    i=peers.index(src)
                    try:
                        raw=src.recv(65536)
                        if raw:
                            row[('to_maker_B','to_taker_B')[i]]+=len(raw)
                            peers[1-i].sendall(raw)
                        else:
                            live.remove(src)
                            peers[1-i].shutdown(socket.SHUT_WR)
                    except OSError:
                        if src in live:
                            live.remove(src)
