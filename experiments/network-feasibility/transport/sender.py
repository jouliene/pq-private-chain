"""One-inflight bounded producer transport role; reads public bytes only."""
import argparse,json,os,resource,socket,struct,time
from pathlib import Path
import archive

def main():
 p=argparse.ArgumentParser();p.add_argument('--object',required=True);p.add_argument('--sha256',required=True);p.add_argument('--bytes',required=True,type=int);p.add_argument('--kind',required=True,type=int,choices=[1,2]);p.add_argument('--port',required=True,type=int);p.add_argument('--mode',choices=['put','interrupt','crash'],default='put');a=p.parse_args()
 start=time.monotonic();path=Path(a.object);archive.need(path.is_file()and path.stat().st_size==a.bytes and 0<a.bytes<=archive.MAX,'sender bound');archive.need(archive.digest(path).hex()==a.sha256,'sender identity')
 raw=socket.create_connection(('127.0.0.1',a.port),timeout=120);raw.settimeout(120);raw.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);s=archive.Counted(raw);buf=archive.buffers(s)
 header=archive.HEADER.pack(b'CPNWR004',3 if a.mode=='crash'else 1,a.kind,0,a.bytes,bytes.fromhex(a.sha256))
 def parts():
  yield header
  with path.open('rb')as f:
   if a.mode=='interrupt':yield f.read(min(65536,a.bytes-1))
   else:yield from iter(lambda:f.read(65536),b'')
 archive.send(s,parts());s.shutdown(socket.SHUT_WR)
 ack=bytearray()
 while len(ack)<archive.ACK.size:
  b=s.recv(archive.ACK.size-len(ack))
  if not b:break
  ack.extend(b)
 if a.mode=='put':archive.need(bytes(ack)==archive.ACK.pack(b'CPACK004',0,a.bytes,bytes.fromhex(a.sha256)),'durable archive ACK')
 else:archive.need(not ack,'control must not receive ACK')
 s.close();print(json.dumps({'role':'producer-transport','mode':a.mode,'complete':True,'durable_archive_ack':a.mode=='put','application_sent':s.sent,'application_received':s.received,'socket_buffers':buf,'inflight_frames_peak':1,'wall_seconds':time.monotonic()-start,'resources':archive.usage(),'object_sha256':a.sha256,'object_bytes':a.bytes,'scope':'actual public frame read/hash/send and archive ACK; proving separately priced'},sort_keys=True))
if __name__=='__main__':main()
