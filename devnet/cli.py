"""Local proof-of-work devnet operator and private wallet client."""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import hmac
import subprocess
import tempfile
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import runtime
from transport import control, rpc
from wallet import Wallet, private_directory

NODES=("a","b","c","d")
DEFAULT_HOME=runtime.ROOT/".work/local-pow-devnet"


def wait(read, predicate, label, seconds=180):
    end = time.monotonic()+seconds
    last=None
    while time.monotonic()<end:
        try:
            last=read()
            if predicate(last):
                return last
        except (FileNotFoundError,ConnectionError,OSError):
            pass
        time.sleep(.15)
    raise RuntimeError("timeout waiting for "+label+"; last="+str(last)[:550])


def label(value):
    if re.fullmatch("[a-z][a-z0-9-]{0,39}",value) is None:
        raise ValueError("invalid wallet name")
    return value


def write_exclusive(path, data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


class Lab:
    def __init__(self,home,runtime_dir):
        self.home=Path(home).resolve()
        self.runtime=Path(runtime_dir).resolve()
        self._cfg=None
        self._native=None

    @property
    def native(self):
        if self._native is None:
            self._native=runtime.prepare(self.runtime)
        return self._native

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg=json.loads((self.home/"network.json").read_bytes())
        return self._cfg

    def admin(self,node,op,**kw):
        return rpc(control(self.home,node),op,**kw)[0]

    def request(self,node,op,body=b"",**kw):
        return rpc(self.cfg["ports"][node],op,body,**kw)

    def status(self,node):
        return self.request(node,"status")[0]

    def walletdir(self,name):
        return self.home/"wallets"/label(name)

    def wallet(self,name,mode="restore"):
        n=self.native
        return Wallet(n.binary,n.binary_sha,n.keys,self.walletdir(name),mode)

    def install_wallet(self,name,seed=None):
        target=self.walletdir(name)
        native=self.native
        private_directory(target.parent,create=True)
        with (target.parent/".wallet.lock").open("a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if os.path.lexists(target):
                raise ValueError("wallet already exists: "+name)
            with tempfile.TemporaryDirectory(prefix=".pending-",dir=target.parent) as staged:
                stage=Path(staged)
                if seed is not None:
                    if len(seed)!=32:
                        raise ValueError("expected 32-byte wallet seed")
                    write_exclusive(stage/"seed",seed)
                with Wallet(native.binary,native.binary_sha,native.keys,stage,"restore" if seed is not None else "create") as w:
                    write_exclusive(stage/"address",w.address)
                    info=dict(wallet=name,spend_pk=w.spend_pk.hex())
                os.rename(stage,target)
        return info

    def new_wallet(self,name):
        return self.install_wallet(name)

    def address(self,name):
        a=(self.walletdir(name)/"address").read_bytes()
        if len(a)!=1601:
            raise ValueError("public address size")
        return a

    def export_address(self,name,path):
        from chain import NETWORK
        data=b"PQDADDR1"+NETWORK+self.address(name)
        write_exclusive(path,data+hashlib.sha256(data).digest())
        return dict(public_address_file=str(path),bytes=len(data)+32)

    def destination(self,value):
        if not value.startswith("@"):
            return self.address(value)
        from chain import NETWORK
        with Path(value[1:]).open("rb") as f:
            raw=f.read(1674)
        if (len(raw)!=1673 or raw[:40]!=b"PQDADDR1"+NETWORK or raw[40]!=1
                or not hmac.compare_digest(raw[-32:],hashlib.sha256(raw[:-32]).digest())):
            raise ValueError("invalid public address file, checksum or devnet network")
        return raw[40:-32]

    @contextmanager
    def locked_wallet(self,name):
        directory=private_directory(self.walletdir(name))
        with (directory/"operation.lock").open("a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            yield directory

    def backup(self,name,path):
        seed=self.walletdir(name)/"seed"
        if seed.is_symlink() or seed.stat().st_mode & 0o077:
            raise ValueError("unsafe seed permissions")
        write_exclusive(path,seed.read_bytes())
        return dict(backup=str(path))

    def restore(self,name,path,node="c",max_blocks=None):
        if path.is_symlink() or not path.is_file() or path.stat().st_mode&0o077:
            raise ValueError("seed backup must be a private regular file (0600)")
        if path.stat().st_size!=32:
            raise ValueError("expected 32-byte wallet seed")
        seed=path.read_bytes()
        directory=self.walletdir(name)
        if directory.exists():
            if not hmac.compare_digest((private_directory(directory)/"seed").read_bytes(),seed):
                raise ValueError("destination holds a different wallet")
        else:
            self.install_wallet(name,seed)
        return self.balance(name,node,max_blocks=max_blocks)

    def initialize(self):
        private_directory(self.home,create=True)
        self.native
        with (self.home/"init.lock").open("a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            config=self.home/"network.json"
            if not config.exists():
                with ExitStack() as ctx:
                    ports={}
                    for name in NODES:
                        s=ctx.enter_context(socket.socket())
                        s.bind(("127.0.0.1",0))
                        ports[name]=s.getsockname()[1]
                    tmp=self.home/"network.new"
                    tmp.write_text(json.dumps(dict(version=1,ports=ports)))
                    os.replace(tmp,config)
            for name in ("miner-a","miner-b"):
                if not (self.walletdir(name)/"seed").exists():
                    self.new_wallet(name)
                elif not (self.walletdir(name)/"address").exists():
                    with self.wallet(name) as w:
                        write_exclusive(self.walletdir(name)/"address",w.address)
            for name in NODES:
                directory=self.home/"nodes"/name
                directory.mkdir(mode=0o700,parents=True,exist_ok=True)
                if not (directory/"miner.pk").exists():
                    pk=self.address("miner-b" if name=="b" else "miner-a")[1:33]
                    (directory/"miner.pk").write_text(pk.hex())
                if not (directory/"peers.json").exists():
                    peers=[self.cfg["ports"][p] for p in "abc" if p!=name] if name!="d" else []
                    (directory/"peers.json").write_text(json.dumps(peers))

    def launch(self,name,continuous=False):
        endpoint=control(self.home,name)
        try:
            return rpc(endpoint,"status")[0]
        except (FileNotFoundError,ConnectionRefusedError):
            pass
        directory=self.home/"nodes"/name
        cmd=[sys.executable,"-IB",str(HERE/"node.py"),"--home",str(self.home),"--runtime",str(self.runtime),"--node",name]
        if continuous:
            cmd.append("--continuous")
        with (directory/"node.log").open("ab") as log:
            proc=subprocess.Popen(cmd,stdout=log,stderr=log,stdin=subprocess.DEVNULL,start_new_session=True)
        def ready():
            if proc.poll() is not None:
                raise RuntimeError("node "+name+" exited; see "+str(directory/"node.log"))
            return rpc(endpoint,"status")[0]
        return wait(ready,lambda s:s["node"]==name,"node "+name,45)

    def start(self,manual=False):
        self.initialize()
        return {n:self.launch(n,n in "ab" and not manual) for n in "abc"}

    def stop(self):
        stopped=[]
        for n in NODES:
            try:
                self.admin(n,"stop")
                stopped.append(n)
            except (FileNotFoundError,ConnectionRefusedError):
                pass
        for n in stopped:
            wait(lambda:control(self.home,n).exists(),lambda present:not present,"stopped "+n,30)
        return dict(stopped=stopped)

    def links(self,name,neighbors):
        return self.admin(name,"peers",ports=[self.cfg["ports"][p] for p in neighbors])

    def mining(self,name,count,pay_to=None):
        key={} if pay_to is None else dict(pk=self.address(pay_to)[1:33].hex())
        return self.admin(name,"mining",count=count,**key)

    def mine(self,name,count=1,pay_to=None):
        self.mining(name,count,pay_to)
        return wait(lambda:self.status(name),lambda s:s["remaining"]==0,"real nonce search on "+name,900)

    def snapshot(self,node):
        for attempt in range(8):
            st=self.status(node)
            header=bytes.fromhex(st["header"])
            outputs=[]
            try:
                for kind,stride in (("leaves",32),("rewards",104),("receipts",1824),("nfs",32)):
                    gathered=bytearray()
                    start=0
                    while True:
                        meta,body=self.request(node,"page",kind=kind,start=start,limit=96,tip=st["tip"])
                        if len(body)%stride or len(body)>96*stride:
                            raise ValueError("invalid wallet page")
                        gathered.extend(body)
                        nxt=meta["next"]
                        if nxt is None:
                            break
                        if nxt!=start+96 or len(body)!=stride*96:
                            raise ValueError("invalid wallet continuation")
                        start=nxt
                    outputs.append(gathered)
                return st,(header,*map(bytes,outputs))
            except ValueError as e:
                if str(e)!="wallet tip changed":
                    raise
        raise ValueError("wallet could not obtain a consistent selected history; retry")

    def balance(self,name,node,max_blocks=None):
        from wallet_sync import synced_wallet
        with self.locked_wallet(name) as directory, self.wallet(name) as w:
            with synced_wallet(self,node,w,directory,max_blocks=max_blocks) as (state,stats):
                result=dict(wallet=name,tip=state.tip.hex(),height=state.height,
                            sync=stats,**state.inventory())
        result["wallet_metrics"]=w.metrics
        return result

    def send(self,name,to,amount,node,intent=None,wait_seconds=0):
        from intents import default_id
        address=self.destination(to)
        return self._outgoing(name,node,intent or default_id(address,amount),wait_seconds,address,amount)

    def resume(self,name,intent,node,wait_seconds=0):
        return self._outgoing(name,node,intent,wait_seconds)

    def _outgoing(self,name,node,ident,wait_seconds,address=None,amount=None):
        from intents import Outbox
        from wallet_sync import synced_wallet
        if type(wait_seconds) is not int or not 0<=wait_seconds<=3600:
            raise ValueError("wait must be 0..3600 seconds")
        with self.locked_wallet(name) as directory, Outbox(directory) as out:
            if address is not None:
                out.register(ident,address,amount)
            else:
                out.get(ident)
            with self.wallet(name) as w, synced_wallet(self,node,w,directory) as (state,stats):
                syncs=[stats]
                result=out.drive(self,node,state,ident,syncs,wait_seconds)
        result.update(syncs=syncs,wallet_metrics=w.metrics)
        return result

    def intents(self,name):
        from intents import Outbox
        with self.locked_wallet(name) as directory, Outbox(directory) as out:
            return [out.summary(r[0]) for r in out.db.execute("SELECT id FROM intents ORDER BY rowid")]


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home",type=Path)
    p.add_argument("--runtime",type=Path,default=runtime.DEFAULT,help="local pinned source build directory")
    subs=p.add_subparsers(dest="op",required=True)
    subs.add_parser("start").add_argument("--manual",action="store_true",help="mine only on explicit request")
    subs.add_parser("stop")
    subs.add_parser("status")
    subs.add_parser("walkthrough")
    subs.add_parser("wallet-walkthrough")
    c=subs.add_parser("export-address");c.add_argument("name");c.add_argument("path",type=Path)
    c=subs.add_parser("intents");c.add_argument("name")
    c=subs.add_parser("resume");c.add_argument("sender");c.add_argument("intent");c.add_argument("--wait",type=int,default=0);c.add_argument("--node",choices=NODES,default="c")
    c=subs.add_parser("create");c.add_argument("name")
    c=subs.add_parser("backup");c.add_argument("name");c.add_argument("path",type=Path)
    c=subs.add_parser("restore");c.add_argument("name");c.add_argument("path",type=Path);c.add_argument("--node",choices=NODES,default="c");c.add_argument("--max-blocks",type=int)
    c=subs.add_parser("balance");c.add_argument("name");c.add_argument("--node",choices=NODES,default="c")
    c=subs.add_parser("send");c.add_argument("--intent");c.add_argument("--wait",type=int,default=0);c.add_argument("sender");c.add_argument("recipient");c.add_argument("amount",type=int);c.add_argument("--node",choices=NODES,default="c")
    c=subs.add_parser("mine");c.add_argument("node",choices=NODES);c.add_argument("count",type=int,nargs="?",default=1);c.add_argument("--pay-to")
    args=p.parse_args()
    home=args.home or DEFAULT_HOME
    if args.op in ("walkthrough","wallet-walkthrough") and args.home is None:
        DEFAULT_HOME.parent.mkdir(parents=True,exist_ok=True)
        home=Path(tempfile.mkdtemp(prefix="pow-walkthrough-",dir=DEFAULT_HOME.parent))
    lab=Lab(home,args.runtime)
    if args.op=="wallet-walkthrough":
        from wallet_walkthrough import exercise
        result=exercise(lab)
    elif args.op=="export-address":
        result=lab.export_address(args.name,args.path)
    elif args.op=="intents":
        result=lab.intents(args.name)
    elif args.op=="resume":
        result=lab.resume(args.sender,args.intent,args.node,args.wait)
    elif args.op=="walkthrough":
        from walkthrough import exercise
        result=exercise(lab)
    elif args.op=="start":
        result=lab.start(args.manual)
    elif args.op=="stop":
        result=lab.stop()
    elif args.op=="status":
        result={n:lab.status(n) for n in "abc"}
    elif args.op=="mine":
        if not 1<=args.count<=1000:
            p.error("count must be 1..1000")
        result=lab.mine(args.node,args.count,args.pay_to)
    elif args.op=="balance":
        result=lab.balance(args.name,args.node)
    elif args.op=="send":
        result=lab.send(args.sender,args.recipient,args.amount,args.node,args.intent,args.wait)
    elif args.op=="create":
        result=lab.new_wallet(args.name)
    elif args.op=="backup":
        result=lab.backup(args.name,args.path)
    elif args.op=="restore":
        result=lab.restore(args.name,args.path,args.node,args.max_blocks)
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=="__main__":
    try:
        main()
    except (ValueError,OSError,RuntimeError) as err:
        sys.exit(str(err))
