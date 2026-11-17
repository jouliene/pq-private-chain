"""Finite opaque durable archive. No proof, signature or admission cache exists here."""
import argparse,hashlib,json,os,resource,signal,socket,struct,threading,time
from pathlib import Path
MAX=256*1024*1024
CHUNK=65536
RATE=12_500_000
HEADER=struct.Struct('<8sBBHQ32s')
ACK=struct.Struct('<8sB3xQ32s')

def need(ok,message):
 if not ok:raise ValueError(message)
def usage():
 a=resource.getrusage(resource.RUSAGE_SELF)
 return {'user_seconds':a.ru_utime,'system_seconds':a.ru_stime,'maxrss_kib_cumulative':a.ru_maxrss,'linux_self_io':{k:int(v)for k,v in (line.split(':')for line in Path('/proc/self/io').read_text().splitlines())}}
class Counted:
 def __init__(self,s):self.socket=s;self.received=0;self.sent=0
 def __getattr__(self,k):return getattr(self.socket,k)
 def recv(self,n):
  b=self.socket.recv(n);self.received+=len(b);return b
 def sendall(self,b):
  at=0
  while at<len(b):
   n=self.socket.send(b[at:]);need(n>0,'send made no progress');self.sent+=n;at+=n

def exact(s,n):
 out=bytearray()
 while len(out)<n:
  b=s.recv(min(CHUNK,n-len(out)))
  if not b:raise EOFError('interrupted bounded transfer')
  out.extend(b)
 return bytes(out)
def send(s,parts):
 start=time.monotonic();n=0
 for part in parts:
  for i in range(0,len(part),CHUNK):
   b=part[i:i+CHUNK];n+=len(b);time.sleep(max(0,n/RATE-(time.monotonic()-start)));s.sendall(b)
 return n
def digest(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for b in iter(lambda:f.read(CHUNK),b''):h.update(b)
 return h.digest()
def buffers(s):
 for opt in (socket.SO_RCVBUF,socket.SO_SNDBUF):s.setsockopt(socket.SOL_SOCKET,opt,CHUNK)
 return {'requested_each':CHUNK,'receive':s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),'send':s.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--port',type=int,default=0);p.add_argument('--allow-publication-crash',action='store_true');a=p.parse_args()
 root=Path(a.root).resolve();root.mkdir(exist_ok=True)
 need(root.is_dir()and not root.is_symlink(),'archive root')
 # Only this dedicated root is controlled; abandoned partials have no durable ACK.
 for f in root.glob('*.part'):need(f.is_file()and not f.is_symlink(),'partial kind');f.unlink()
 dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dirfd)
 parentfd=os.open(root.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(parentfd);os.close(parentfd)
 stop=threading.Event();lock=threading.Lock();put=threading.Semaphore(1);get=threading.Semaphore(1);connections=threading.Semaphore(2);threads=[]
 counters={'requests':0,'sent':0,'received':0,'active':0,'connection_peak':0,'incomplete_spools':0,'incomplete_spools_peak':0,'full_bytes_written':0,'proof_attempts':0,'source_signature_attempts':0}
 def emit(v):
  with lock:print(json.dumps(v,sort_keys=True),flush=True)
 def handler(s):
  s=Counted(s);begin=time.monotonic();begin_ns=time.monotonic_ns();row={'role':'archive','started_monotonic_ns':begin_ns};slot=None;acquired=False;part=None;sent=received=0;spooling=False;latency_done=False;valid_request=False
  try:
   s.settimeout(120);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);row['socket_buffers']=buffers(s)
   request=exact(s,HEADER.size);received+=len(request);magic,op,kind,reserved,size,h=HEADER.unpack(request)
   need(magic==b'CPNWR004'and op in(1,2,3)and kind in(1,2)and reserved==0 and 0<size<=MAX,'request framing')
   need(kind!=1 or size<=339320,'genesis byte cap')
   need(op!=3 or a.allow_publication_crash,'crash control not enabled')
   slot=get if op==2 else put;acquired=slot.acquire(blocking=False);need(acquired,'one operation slot')
   valid_request=True
   final=root/(h.hex()+'.blob');row.update(op=op,kind=kind,object_sha256=h.hex(),object_bytes=size)
   if op in(1,3):
    part=root/(str(threading.get_ident())+'.part')
    with lock:counters['incomplete_spools']+=1;counters['incomplete_spools_peak']=max(counters['incomplete_spools_peak'],counters['incomplete_spools']);spooling=True
    hasher=hashlib.sha256();remaining=size
    with part.open('xb')as f:
     while remaining:
      b=exact(s,min(CHUNK,remaining));received+=len(b);f.write(b);hasher.update(b);remaining-=len(b)
     f.flush();os.fsync(f.fileno())
    need(s.recv(1)==b'','PUT trailing bytes');need(hasher.digest()==h,'PUT byte digest')
    if final.exists():need(final.is_file()and not final.is_symlink()and final.stat().st_size==size and digest(final)==h,'existing object identity');part.unlink()
    else:os.link(part,final);part.unlink()
    part=None;os.fsync(dirfd)
    with lock:counters['full_bytes_written']+=size
    time.sleep(.040);latency_done=True # One additional RTT at response boundary.
    if op==3:
     emit({'publication_crash_before_ack':True,'started_monotonic_ns':begin_ns,'finished_monotonic_ns':time.monotonic_ns(),'object_sha256':h.hex(),'object_bytes':size,'application_sent':s.sent,'application_received':s.received,'counters_before_exit':dict(counters),'resources':usage()});os._exit(79)
    sent+=send(s,[ACK.pack(b'CPACK004',0,size,h)])
   else:
    need(s.recv(1)==b'','GET trailing request');need(final.is_file()and not final.is_symlink()and final.stat().st_size==size,'GET object')
    # Read checksum is explicit archive work, never a payment-validity check.
    need(digest(final)==h,'GET durable bytes corrupted')
    def parts():
     yield ACK.pack(b'CPACK004',0,size,h)
     with final.open('rb')as f:
      yield from iter(lambda:f.read(CHUNK),b'')
    time.sleep(.040);latency_done=True
    sent+=send(s,parts())
   row['complete']=True
  except BaseException as e:row.update(complete=False,error_type=type(e).__name__,error=str(e))
  finally:
   if valid_request and not latency_done:time.sleep(.040)
   if part is not None and part.exists():part.unlink()
   if spooling:
    with lock:counters['incomplete_spools']-=1
   if acquired:slot.release()
   s.close();sent=s.sent;received=s.received
   with lock:
    counters['requests']+=1;counters['sent']+=sent;counters['received']+=received;counters['active']-=1;snapshot=dict(counters)
   row.update(finished_monotonic_ns=time.monotonic_ns(),wall_seconds=time.monotonic()-begin,application_sent=sent,application_received=received,resources_cumulative=usage(),counters=snapshot)
   emit(row);connections.release()
 server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(('127.0.0.1',a.port));server.listen(2);server.settimeout(.2)
 signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())
 emit({'ready':True,'role':'archive','pid':os.getpid(),'port':server.getsockname()[1],'limits':{'connections':2,'put':1,'get':1,'chunk':CHUNK,'spool_max_each':MAX},'initial_resources':usage()})
 while not stop.is_set():
  if not connections.acquire(timeout=.2):continue
  try:s,_=server.accept()
  except socket.timeout:connections.release();continue
  with lock:counters['active']+=1;counters['connection_peak']=max(counters['connection_peak'],counters['active'])
  t=threading.Thread(target=handler,args=(s,),daemon=False);threads.append(t);t.start()
  threads[:]=[t for t in threads if t.is_alive()]
 server.close()
 for t in threads:t.join()
 os.fsync(dirfd);os.close(dirfd);emit({'stopped':True,'counters':counters,'resources':usage()})
if __name__=='__main__':main()
