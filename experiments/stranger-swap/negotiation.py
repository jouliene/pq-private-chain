"""Private firm quotes and selected settlement using the registered two-owner swap wallet."""
import base64
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "atomic-swap/wallet"))
from terms import LIMIT, ZERO, Party, Terms, asset_id, need
from swap_wallet import MAX_LEG, SIGNATURE, emit as emit_immutable, frame

VERSION = 1
PREFIX = b"SSW1/firm-quote/v1\0"
MAX_HISTORY = 256
QUOTE_KEYS = {"version","advert","request","holder","quote","network","maker","taker","asset","quantity",
              "native","payer","fee","expiry_height","expires","nonce"}
REQUEST_KEYS = {"op","advert","request","cap","taker","asset","quantity"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("ascii")


def word(value, length=32):
    need(isinstance(value,str) and len(value)==2*length and re.fullmatch(r"[0-9a-f]+",value) is not None,
         "invalid private protocol identifier")
    return bytes.fromhex(value)


def integer(value, low, high):
    need(type(value) is int and low <= value <= high,"private protocol numeric bound")
    return value


def unb64(value, maximum):
    need(isinstance(value,str) and 0 < len(value) <= 4*((maximum+2)//3), "private frame width")
    raw = base64.b64decode(value,validate=True)
    need(len(raw)<=maximum and b64(raw)==value,"noncanonical private frame")
    return raw


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def advert_id(ad):
    from directory import validate
    result = validate(ad)
    value = result.hex() if isinstance(result,bytes) else result
    word(value)
    return value


def quote_terms(q,ad,req):
    need(isinstance(q,dict) and set(q)==QUOTE_KEYS and type(q["version"]) is int and q["version"]==VERSION,
         "incorrect firm quote fields")
    need((q["advert"],q["network"],q["request"],q["holder"],q["taker"],q["asset"],q["quantity"]) ==
         (req["advert"],ad["network"],req["request"],sha256(word(req["cap"])).hexdigest(),
          req["taker"],req["asset"],req["quantity"]),"quote differs from the private request")
    need(q["payer"]=="b" and integer(q["fee"],3,3)==3,"wrong fee policy")
    integer(q["quantity"],1,LIMIT)
    integer(q["native"],1,LIMIT)
    integer(q["expiry_height"],1,2**32-1)
    integer(q["expires"],ad["issued"]+1,ad["expires"])
    word(q["quote"])
    word(q["nonce"])
    asset = asset_id(q["asset"])
    need(asset!=ZERO,"expected token for native")
    blind = sha256(PREFIX+canonical(q)).digest()
    return Terms(word(q["network"]),blind,q["expiry_height"],
                 (Party(word(q["taker"],1601),asset,q["quantity"]),Party(word(q["maker"],1601),ZERO,q["native"])),1)


def sync_dir(folder):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def emit(path,data):
    emit_immutable(path,data)
    sync_dir(Path(path).parent)


def write_state(folder, value):
    # fsync+replace allows replay after an interrupted handshake or an ambiguous network reply.
    fd, name = tempfile.mkstemp(dir=folder)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(canonical(value))
            out.flush()
            os.fsync(out.fileno())
        os.replace(name,folder/"session.json")
        dirfd = os.open(folder, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        Path(name).unlink(missing_ok=True)


def read_state(folder):
    return json.loads((folder/"session.json").read_bytes())


def materialize(folder,terms,side):
    emit(folder/"terms",terms.encode())
    content = b"PQDADDR1"+terms.network+terms.parties[1-side].address
    emit(folder/"peer.addr",content+sha256(content).digest())


def view(st):
    q = st["firm"]
    fields=("quote","advert","asset","quantity","fee","payer","expiry_height","expires")
    fields+=("offer","take","lot","price","payment") if "offer" in q else ("native",)
    result = {k:q[k] for k in fields}
    result["state"] = st["state"]
    result["delivery"] = st.get("delivery","none")
    return result


class Local:
    def __init__(self, home, wallet, node, side):
        self.home = Path(home).resolve(strict=True)
        need(isinstance(wallet,str) and re.fullmatch(r"[a-z][a-z0-9-]{0,39}",wallet) and
             node in ("a","b","c","d"),"invalid local wallet or node")
        need(self.home.is_dir() and not self.home.stat().st_mode & 0o077,"use a private operator home")
        self.wallet, self.node = wallet, node
        base = self.home
        for part in ("stranger-private",wallet,side):
            base = base/part
            base.mkdir(mode=0o700,exist_ok=True)
            sync_dir(base.parent)
            need(not base.is_symlink() and base.is_dir() and not base.stat().st_mode & 0o077,"unsafe negotiation store")
        self.base = base

    @contextmanager
    def locked(self):
        fd = os.open(self.base/"lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            yield

    def folders(self):
        return [p for p in self.base.iterdir() if p.is_dir() and not p.is_symlink() and (p/"session.json").is_file()]

    def folder(self,rid):
        word(rid)
        return self.base/rid

    def create(self,folder,st):
        # A bounded issued advertisement cannot create unbounded retained sessions. Previously
        # signed records can be kept for recovery across independent advertisement lifetimes.
        count = sum(read_state(p)["ad"]==st["ad"] for p in self.folders())
        need(count<MAX_HISTORY,"session limit reached for this advertisement")
        folder.mkdir(mode=0o700,exist_ok=True)
        sync_dir(folder.parent)
        need(not folder.is_symlink() and not (folder/"session.json").exists(),"session already exists")
        write_state(folder,st)

    def local(self,op,folder=None,incoming=None):
        args = [sys.executable,"-IB",str(HERE/"wallet_local.py"),str(self.home),self.wallet,self.node,op,str(folder or self.base)]
        if incoming is not None:
            args.append(str(incoming))
        try:
            result = subprocess.run(args,capture_output=True,timeout=180,check=False)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("local wallet unavailable for "+op) from exc
        if result.returncode:
            # The private role may emit internal paths or funding details. Never send them to a peer.
            raise ValueError("local wallet refused "+op)
        return json.loads(result.stdout)

    def active(self,st,info):
        q = st["firm"]
        return info["network"]==q["network"] and int(time.time())<q["expires"] and info["height"]+1<=q["expiry_height"]


class Maker(Local):
    def __init__(self,home,wallet,node,advert,policy):
        super().__init__(home,wallet,node,"maker")
        self.ad = dict(advert)
        self.ad_id = advert_id(self.ad)
        self.asset = policy["asset"]
        need(asset_id(self.asset)!=ZERO,"native cannot be the offered payment token")
        self.quantity = integer(policy["quantity"],1,LIMIT)
        self.native = integer(policy["native"],1,LIMIT)
        self.ttl = integer(policy.get("ttl",120),1,600)
        self.blocks = integer(policy.get("blocks",8),1,128)
        self.max_open = integer(policy.get("max_open",4),1,16)

    def recover(self,folder,st):
        if st["state"]=="signing" and self.local("journal",folder)["state"]=="released":
            st["state"]="signed"
            write_state(folder,st)

    def cleanup(self,info):
        released = 0
        for folder in self.folders():
            st=read_state(folder)
            if st["state"] in ("allocating","quoted","signing") and not self.active(st,info):
                materialize(folder,quote_terms(st["firm"],st["ad"],st["req"]),1)
                result = self.local("abort",folder)
                st["state"] = "signed" if result["state"]=="released" else "expired"
                write_state(folder,st)
                released += result["state"]=="aborted"
        return released

    def sweep(self):
        with self.locked():
            return {"released":self.cleanup(self.local("info"))}

    def quote(self,body):
        need(set(body)==REQUEST_KEYS and body["advert"]==self.ad_id and body["asset"]==self.asset and
             integer(body["quantity"],1,LIMIT)==self.quantity,"unavailable quote policy")
        word(body["taker"],1601)
        word(body["cap"])
        folder = self.folder(body["request"])
        info = self.local("info")
        self.cleanup(info)
        if (folder/"session.json").is_file():
            st=read_state(folder)
            need(st["req"]==body and st["state"] in ("allocating","quoted"),"offer request already used")
        else:
            count = sum(read_state(p)["state"] in ("allocating","quoted","signing") for p in self.folders())
            need(count<self.max_open,"maker quote capacity")
            now = int(time.time())
            need(self.ad["issued"]<=now<self.ad["expires"] and info["network"]==self.ad["network"],"inactive advertisement")
            q = dict(version=VERSION,advert=self.ad_id,request=body["request"],holder=sha256(word(body["cap"])).hexdigest(),
                     quote=secrets.token_hex(32),network=info["network"],maker=info["address"],taker=body["taker"],
                     asset=self.asset,quantity=self.quantity,native=self.native,payer="b",fee=3,
                     expiry_height=info["height"]+self.blocks,expires=min(self.ad["expires"],now+self.ttl),
                     nonce=secrets.token_hex(32))
            quote_terms(q,self.ad,body)
            st = dict(state="allocating",firm=q,req=body,ad=self.ad)
            self.create(folder,st)
        materialize(folder,quote_terms(st["firm"],self.ad,body),1)
        try:
            self.local("leg",folder)
        except ValueError:
            if self.local("journal",folder)["state"]=="empty":
                st["state"]="declined"
                write_state(folder,st)
            raise
        need(self.active(st,self.local("info")),"quote expired during preparation")
        st["state"]="quoted"
        write_state(folder,st)
        return dict(firm=st["firm"],leg=b64((folder/"leg-b").read_bytes()))

    def handle(self,body):
        need(isinstance(body,dict) and body.get("op") in ("quote","cancel","status","final"),"unknown private request")
        with self.locked():
            if body["op"]=="quote":
                return self.quote(body)
            final = body["op"]=="final"
            fields={"op","request","quote","cap","advert"}
            need(set(body)==(fields|{"leg","signature"} if final else fields),"incorrect continuation fields")
            folder = self.folder(body["request"])
            need((folder/"session.json").is_file(),"unknown quote")
            st=read_state(folder)
            need(body["advert"]==self.ad_id==st["firm"]["advert"] and body["quote"]==st["firm"]["quote"] and
                 hmac.compare_digest(word(body["cap"]),word(st["req"]["cap"])),"incorrect quote capability")
            self.recover(folder,st)
            if body["op"]=="status":
                if st["state"] in ("quoted","signing") and not self.active(st,self.local("info")):
                    self.cleanup(self.local("info"))
                    st=read_state(folder)
                return {"quote":body["quote"],"state":st["state"]}
            if not final:
                if st["state"] in ("cancelled","expired"):
                    return {"state":st["state"]}
                need(st["state"] in ("quoted","allocating"),"maker authorization may already exist")
                materialize(folder,quote_terms(st["firm"],self.ad,st["req"]),1)
                result = self.local("abort",folder)
                need(result["state"] in ("aborted","empty"),"maker authorization already released")
                st["state"]="cancelled"
                write_state(folder,st)
                return {"state":"cancelled"}
            leg, sig = unb64(body["leg"],MAX_LEG), unb64(body["signature"],SIGNATURE)
            frame(leg)
            need(len(sig)==SIGNATURE and st["state"] in ("quoted","signing","signed"),"quote not available")
            if st["state"] in ("signing","signed"):
                need((folder/"leg-a").read_bytes()==leg and (folder/"sig-a").read_bytes()==sig,
                     "different final request for pinned quote")
            if st["state"]!="signed":
                need(self.active(st,self.local("info")),"firm quote expired")
                with tempfile.TemporaryDirectory(dir=folder) as temp:
                    incoming=Path(temp)
                    emit(incoming/"leg",leg)
                    emit(incoming/"sig",sig)
                    self.local("peer",folder,incoming)
                emit(folder/"leg-a",leg)
                emit(folder/"sig-a",sig)
                st["state"]="signing"
                write_state(folder,st)
                need(self.active(st,self.local("info")),"firm quote expired before authorization")
                self.local("authorize",folder)
                st["state"]="signed"
                write_state(folder,st)
            return dict(quote=body["quote"],signature=b64((folder/"sig-b").read_bytes()))


class Taker(Local):
    def __init__(self,home,wallet,node):
        super().__init__(home,wallet,node,"taker")

    def find(self,handle):
        word(handle)
        for folder in self.folders():
            st=read_state(folder)
            if st.get("firm",{}).get("quote")==handle:
                return folder,st
        raise ValueError("unknown private quote")

    def quote(self,advert,request,*,asset,quantity,request_id=None):
        ident=advert_id(advert)
        need(asset_id(asset)!=ZERO,"expected nonzero token ID")
        integer(quantity,1,LIMIT)
        with self.locked():
            info=self.local("info")
            need(advert["network"]==info["network"],"wrong maker network")
            if request_id is None:
                # The ordinary CLI can lose the first network reply before learning the maker's handle.
                # Resume that exact outstanding request with its durable capability across process restarts.
                for path in self.folders():
                    pending = read_state(path)
                    req = pending["req"]
                    if (pending["state"]=="requested" and pending["ad"]==advert and
                        (req["asset"],req["quantity"],req["taker"])==(asset,quantity,info["address"])):
                        request_id=path.name
                        break
            folder=self.folder(request_id if request_id is not None else secrets.token_hex(32))
            if (folder/"session.json").is_file():
                st=read_state(folder)
                req=st["req"]
                need(st["ad"]==advert and (req["asset"],req["quantity"],req["taker"])==
                     (asset,quantity,info["address"]),"request replay differs")
                need(st["state"]!="refused","request previously refused")
                if "firm" in st:
                    if st["state"] in ("quoted","prepared"):
                        need(self.active(st,info),"previous firm quote expired")
                    return view(st)
            else:
                req=dict(op="quote",advert=ident,request=folder.name,cap=secrets.token_hex(32),
                         taker=info["address"],asset=asset,quantity=quantity)
                st=dict(state="requested",ad=advert,req=req)
                self.create(folder,st)
            try:
                reply=request(advert,dict(req))
            except ValueError as error:
                # Older transport adapters report a generic failure. Conservatively retain the
                # same request unless the pinned live endpoint definitively rejected it.
                import market_transport
                if isinstance(error,getattr(market_transport,"MakerRejected",())):
                    st["state"]="refused"
                    write_state(folder,st)
                raise
            need(isinstance(reply,dict) and set(reply)=={"firm","leg"},"incorrect quote response")
            q, leg = reply["firm"], unb64(reply["leg"],MAX_LEG)
            terms=quote_terms(q,advert,req)
            frame(leg)
            need(not any(read_state(other).get("firm",{}).get("quote")==q["quote"]
                         for other in self.folders() if other!=folder), "quote handle already belongs to a different session")
            need(self.active({"firm":q},info),"received expired quote")
            # Verify the prospective incoming payment before showing the quote as funded.
            # Each temporary wallet preflight is scoped to the same taker. No reservation or signature exists yet.
            with tempfile.TemporaryDirectory(dir=self.base) as temp:
                tmp=Path(temp)
                materialize(tmp,terms,0)
                emit(tmp/"leg",leg)
                self.local("peer",tmp,tmp)
            need(self.active({"firm":q},self.local("info")),"quote expired during verification")
            materialize(folder,terms,0)
            emit(folder/"leg-b",leg)
            st.update(state="quoted",firm=q)
            write_state(folder,st)
            return view(st)

    @staticmethod
    def continuation(st,op):
        req=st["req"]
        return dict(op=op,advert=req["advert"],request=req["request"],cap=req["cap"],quote=st["firm"]["quote"])

    def recover(self,folder,st):
        if st["state"]=="releasing" and self.local("journal",folder)["state"]=="released":
            st["state"]="released"
            write_state(folder,st)
        if (folder/"packet").is_file() and st["state"]=="released":
            st.update(state="complete",delivery="acknowledged")
            write_state(folder,st)

    def status(self,quote):
        with self.locked():
            folder,st=self.find(quote)
            self.recover(folder,st)
            return view(st)

    def cancel(self,quote,request=None):
        with self.locked():
            folder,st=self.find(quote)
            self.recover(folder,st)
            need(st["state"] in ("quoted","prepared","releasing","cancelled"),"previously released authorization")
            if st["state"]!="cancelled":
                outcome=self.local("abort",folder)
                need(outcome["state"] in ("aborted","empty"),"previously released authorization")
                st["state"]="cancelled"
                write_state(folder,st)
            remote="not-contacted"
            if request is not None:
                try:
                    answer=request(st["ad"],self.continuation(st,"cancel"))
                    need(answer.get("state") in ("cancelled","expired"),"peer cancel refused")
                    remote=answer["state"]
                except (ValueError,OSError,subprocess.TimeoutExpired):
                    remote="unconfirmed"
            return {**view(st),"remote":remote}

    def settle(self,quote,request,*,asset,quantity,native,expiry,stage="complete"):
        expected = {"asset":asset,"quantity":integer(quantity,1,LIMIT),"native":integer(native,1,LIMIT),
                    "expiry_height":integer(expiry,1,2**32-1)}
        return self.settle_selected(quote,request,expected,stage)

    def before_delivery(self,folder,st):
        pass

    def settle_selected(self,quote,request,expected,stage):
        need(stage in ("prepared","released","complete"),"unknown settlement stage")
        with self.locked():
            folder,st=self.find(quote)
            q=st["firm"]
            need(all(q.get(k)==v for k,v in expected.items()),"selected quote differs from local economic instructions")
            self.recover(folder,st)
            need(st["state"] in ("quoted","prepared","releasing","released","complete"),"selected quote closed")
            if st["state"] in ("quoted","prepared","releasing"):
                need(self.active(st,self.local("info")),"selected quote expired")
                if st["state"]=="quoted":
                    self.local("leg",folder)
                    st["state"]="prepared"
                    write_state(folder,st)
                if stage=="prepared":
                    return view(st)
                # Confirm the maker is reachable before creating an irrevocable taker authorization.
                # The peer can still disconnect immediately after this reply.
                alive=request(st["ad"],self.continuation(st,"status"))
                need(alive=={"quote":quote,"state":"quoted"},"firm maker quote unavailable")
                need(self.active(st,self.local("info")),"selected quote expired before authorization")
                st["state"]="releasing"
                write_state(folder,st)
                self.local("authorize",folder)
                st["state"]="released"
                write_state(folder,st)
            if st["state"]=="released" and stage=="complete":
                self.before_delivery(folder,st)
                msg=self.continuation(st,"final")
                msg["leg"]=b64((folder/"leg-a").read_bytes())
                msg["signature"]=b64((folder/"sig-a").read_bytes())
                st["delivery"]="attempted"
                write_state(folder,st)
                reply=request(st["ad"],msg)
                need(isinstance(reply,dict) and set(reply)=={"quote","signature"} and reply["quote"]==quote,
                     "final reply differs from selection")
                raw=unb64(reply["signature"],SIGNATURE)
                need(len(raw)==SIGNATURE,"invalid maker signature width")
                # A malformed response must not pin the maker's signature before the complete public checks succeed.
                with tempfile.TemporaryDirectory(dir=folder) as temp:
                    tmp=Path(temp)
                    for name in ("terms","leg-a","leg-b","sig-a"):
                        emit(tmp/name,(folder/name).read_bytes())
                    emit(tmp/"sig-b",raw)
                    self.local("combine",tmp)
                    emit(folder/"sig-b",raw)
                    emit(folder/"packet",(tmp/"packet").read_bytes())
                st.update(state="complete",delivery="acknowledged")
                write_state(folder,st)
            result=view(st)
            if st["state"]=="complete":
                packet=folder/"packet"
                result.update(packet=str(packet),sha256=sha256(packet.read_bytes()).hexdigest())
            return result
