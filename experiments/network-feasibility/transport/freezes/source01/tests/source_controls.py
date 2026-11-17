"""Tiny Python structural controls, not a native/proof/network throughput run."""
import importlib.util,os,sqlite3,sys,tempfile,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
import archive,campaign,oracle
class Socket:
 def __init__(self):self.parts=[b'ab',b'c',b''];self.out=bytearray()
 def recv(self,n):return self.parts.pop(0)
 def send(self,b):self.out.extend(b[:1]);return 1
s=archive.Counted(Socket());assert archive.exact(s,3)==b'abc'and s.received==3;s.sendall(b'xyz');assert s.sent==3
with tempfile.TemporaryDirectory(prefix='cp04-source-control-')as t:
 p=Path(t)/'missing.sqlite';d=sqlite3.connect(p);d.execute('CREATE TABLE meta(x)');d.commit();d.close()
 try:oracle.snapshot(p)
 except ValueError as e:assert str(e)=='exact14 ledger table set'
 else:raise AssertionError('missing-table snapshot accepted')
 r=campaign.Role('public-failure-unit',[sys.executable,'-I','-c','import sys;print(\'{"public_unit":true}\',flush=True);print("PUBLIC_UNIT_DIAGNOSTIC",file=sys.stderr);sys.exit(7)'],min(os.sched_getaffinity(0)),dict(os.environ),Path(t),time.monotonic()+5,lambda:None)
 try:r.finish()
 except ValueError as e:assert 'role terminal exit'in str(e)
 else:raise AssertionError('failed role accepted')
 receipt=r.cleanup();assert receipt['exit']==7 and receipt['first_wait4']and receipt['rows']==[{'public_unit':True}]and'PUBLIC_UNIT_DIAGNOSTIC'in receipt['public_stderr']and os.waitstatus_to_exitcode(receipt['raw_wait_status'])==7
print('{"scope":"tiny Python source/cleanup controls, no native/payment/network run","checks":3,"passed":true}')
