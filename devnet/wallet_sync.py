"""Private incremental selected history, sparse quaternary membership paths and atomic rollback."""
from collections import deque
from contextlib import contextmanager, nullcontext
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import resource
import stat
import time

import chain
from history import decode_range
from wallet import FEE, MAX_VALUE, _wire, private_directory

ZERO=bytes(32)
KEEP=8
CAPACITY=4**20
KINDS=("reward","incoming","change")
EMPTY_BALANCE=dict(balance=0,notes=0,reward_notes=0,receipt_notes=0,incoming_notes=0,change_notes=0)


def require(ok,msg):
    if not ok:
        raise ValueError(msg)


def split(raw,n):
    require(len(raw)%n==0,"private state record")
    return [raw[i:i+n] for i in range(0,len(raw),n)]


def path_rows(raw):
    return [tuple(split(s,32)) for s in split(raw,96)]


def flatten(rows):
    return b"".join(b"".join(row) for row in rows)


class Tree:
    """The right edge, with complete subtrees in base-four digit order."""
    def __init__(self,n,front,node_hash):
        require(type(n) is int and 0<=n<=CAPACITY,"invalid frontier size")
        self.n=n
        self.hash=node_hash
        self.rows=[]
        digits=n
        while digits:
            k=digits%4
            self.rows.append(split(front[:32*k],32))
            require(len(self.rows[-1])==k,"incomplete frontier")
            front=front[32*k:]
            digits//=4
        require(not front,"invalid frontier")

    def append(self,cm):
        i=self.n
        require(i<CAPACITY and _wire.canonical(cm) and cm!=ZERO,"invalid funded leaf")
        depth=max(1,(i.bit_length()+1)//2)
        value=cm
        carry=True
        groups=[]
        for level in range(depth):
            if level==len(self.rows):
                self.rows.append([])
            done=self.rows[level]
            index=(i>>(2*level))%4
            require(len(done)==index,"frontier digit")
            children=done+[value]+[ZERO]*(3-index)
            groups.append((index,children))
            if carry:
                if index==3:
                    self.rows[level]=[]
                else:
                    self.rows[level]=done+[value]
                    carry=False
            value=self.hash(children)
        if carry:
            self.rows.append([value])
        self.n+=1
        return groups,value

    def encode(self):
        return flatten(self.rows)


def extend_path(path,pos,i,groups):
    # Only one sibling changes: the highest differing base-four digit. All lower
    # levels are in a different subtree, all higher levels are on the same path.
    level=((pos^i).bit_length()-1)//2
    require(0<=level<len(groups) and level<=len(path),"witness growth")
    index,children=groups[level]
    own=(pos>>(2*level))%4
    require(index!=own,"witness divergence")
    if level==len(path):
        path.append(tuple(children[:own]+children[own+1:]))
    else:
        updated=list(path[level])
        updated[index-int(index>own)]=children[index]
        path[level]=tuple(updated)


def tally(balance,kind,value,sign):
    if not value:
        return
    balance["balance"]+=sign*value
    balance["notes"]+=sign
    balance[kind+"_notes"]+=sign
    if kind!="reward":
        balance["receipt_notes"]+=sign


def role_sample(role):
    """Linux process counters for this role's bubblewrap process subtree, without reading process arguments."""
    queue=[role.proc.pid]
    ticks=0
    peak=0
    while queue:
        pid=queue.pop()
        proc=Path("/proc")/str(pid)
        children=proc/"task"/str(pid)/"children"
        try:
            queue.extend(map(int,children.read_text().split()))
            stats=(proc/"stat").read_text().rsplit(")",1)[1].split()
            ticks+=int(stats[11])+int(stats[12])
            for line in (proc/"status").read_text().splitlines():
                if line.startswith("VmHWM:"):
                    peak=max(peak,int(line.split()[1]))
                    break
        except (FileNotFoundError,ProcessLookupError):
            continue
    return ticks/os.sysconf("SC_CLK_TCK"),peak,tuple(role.sizes)


class WalletSync:
    def __init__(self,wallet,private_dir,network,genesis,genesis_header,keep=KEEP):
        self.wallet=wallet
        self.directory=private_directory(private_dir)
        self.network,self.genesis,self.keep=network,genesis,keep
        expected=ZERO+chain.u32(0)+chain.digest(b"dev-genesis-state",chain.NETWORK)+chain.digest(b"dev-genesis-body",chain.NETWORK)+ZERO
        require((network,genesis,genesis_header)==(chain.NETWORK,chain.GENESIS,expected),"wrong wallet network")
        require(1<=keep<=62,"checkpoint window")
        self.last_payment=None
        self.path=self.directory/"wallet-state.sqlite"
        fd=os.open(self.path,os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o077,
                    "private wallet db permissions")
        finally:
            os.close(fd)
        self.db=sqlite3.connect(self.path,timeout=30,isolation_level=None)
        self.db.row_factory=sqlite3.Row
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            with self.transaction():
                if self.db.execute("PRAGMA user_version").fetchone()[0]==0:
                    for sql in (
                        "CREATE TABLE identity(id INTEGER PRIMARY KEY,owner BLOB,network BLOB,genesis BLOB,keep INTEGER,target BLOB,target_h INTEGER)",
                        "CREATE TABLE heads(h INTEGER PRIMARY KEY,id BLOB UNIQUE,header BLOB,n INTEGER,front BLOB,fees INTEGER,balance TEXT)",
                        "CREATE TABLE owned(cm BLOB PRIMARY KEY,nf BLOB UNIQUE,pos INTEGER UNIQUE,amount INTEGER,kind TEXT,origin BLOB,created INTEGER,creator BLOB,spent INTEGER,spender BLOB,path BLOB)",
                        "CREATE INDEX owned_live ON owned(amount,pos) WHERE spent IS NULL AND amount>0",
                        "CREATE TABLE payments(tx BLOB PRIMARY KEY,h INTEGER)",
                        "CREATE TABLE undo(h INTEGER,cm BLOB,path BLOB,spent INTEGER,spender BLOB,PRIMARY KEY(h,cm)) WITHOUT ROWID"):
                        self.db.execute(sql)
                    self.db.execute("INSERT INTO identity VALUES(1,?,?,?,?,NULL,NULL)",(wallet.address,network,genesis,keep))
                    self.db.execute("INSERT INTO heads VALUES(0,?,?,0,?,0,?)",(genesis,genesis_header,b"",json.dumps(EMPTY_BALANCE)))
                    self.db.execute("PRAGMA user_version=1")
                if self.db.execute("PRAGMA user_version").fetchone()[0]==1:
                    # A pre-release cursor can be retained, but its old frozen-target metadata
                    # did not persist the authenticated endpoint header. Capture that target anew.
                    for field in ("target_header BLOB","target_count INTEGER","target_anchor BLOB"):
                        self.db.execute("ALTER TABLE identity ADD COLUMN "+field)
                    self.db.execute("UPDATE identity SET target=NULL,target_h=NULL,target_header=NULL,target_count=NULL,target_anchor=NULL")
                    self.db.execute("PRAGMA user_version=2")
                require(self.db.execute("PRAGMA user_version").fetchone()[0]==2,"wallet schema")
                identity=self.db.execute("SELECT * FROM identity WHERE id=1").fetchone()
                require(identity is not None and (identity["owner"],identity["network"],identity["genesis"],identity["keep"])==
                        (wallet.address,network,genesis,keep),"wallet identity mismatch")
            self.hashes=_wire.Role(wallet.binary,wallet.binary_sha,["hash"])
            self.hashes.times=deque(maxlen=1)
        except BaseException:
            self.db.close()
            raise
        self.stats=None

    @contextmanager
    def transaction(self,write=True):
        self.db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def head(self):
        return self.db.execute("SELECT * FROM heads ORDER BY h DESC LIMIT 1").fetchone()

    @property
    def tip(self):
        return self.head()["id"]

    @property
    def height(self):
        return self.head()["h"]

    @property
    def header(self):
        return self.head()["header"]

    @property
    def history(self):
        return [dict(commitment=row["cm"].hex(),amount=row["amount"],source=row["kind"],spent=row["spent"] is not None)
                for row in self.db.execute("SELECT cm,amount,kind,spent FROM owned ORDER BY pos")]

    def inventory(self):
        return json.loads(self.head()["balance"])

    def has_payment(self,txid):
        return self.db.execute("SELECT 1 FROM payments WHERE tx=?",(txid,)).fetchone() is not None

    def input_status(self,cms):
        result={}
        for cm in cms:
            row=self.db.execute("SELECT spent FROM owned WHERE cm=?",(bytes.fromhex(cm),)).fetchone()
            result[cm]="missing" if row is None else "unspent" if row[0] is None else "spent"
        return result

    def witness(self,cmhex):
        row=self.db.execute("SELECT pos,path FROM owned WHERE cm=? AND spent IS NULL",(bytes.fromhex(cmhex),)).fetchone()
        require(row is not None and row[1] is not None,"no current positive funding witness")
        return row[0],path_rows(row[1])

    def select(self,amount,exclude=()):
        require(type(amount) is int and 0<amount<=MAX_VALUE,"invalid amount")
        excluded=exclude if callable(exclude) else set(exclude).__contains__
        needed=amount+FEE
        candidates=[(r[0].hex(),r[1]) for r in self.db.execute(
            "SELECT cm,amount FROM owned WHERE spent IS NULL AND amount>0 ORDER BY amount,pos") if not excluded(r[0].hex())]
        for cm,value in candidates:
            if value>=needed:
                return (cm,)
        lo,hi=0,len(candidates)-1
        best=None
        while lo<hi:
            total=candidates[lo][1]+candidates[hi][1]
            if total<needed:
                lo+=1
            else:
                if total-needed<=MAX_VALUE and (best is None or total<best[0]):
                    best=total,candidates[lo][0],candidates[hi][0]
                hi-=1
        require(best is not None,"insufficient funds within two unreserved inputs")
        return best[1:]

    def pay(self,amount,to,pinned):
        self.last_payment=None
        require(type(amount) is int and 0<amount<=MAX_VALUE and len(pinned) in (1,2) and len(set(pinned))==len(pinned),"invalid pinned selection")
        with self.transaction(False):
            header=self.header
            notes=[]
            nfs=[]
            total=0
            for cm in pinned:
                row=self.db.execute("SELECT origin,amount,nf,path FROM owned WHERE cm=? AND spent IS NULL AND amount>0",(bytes.fromhex(cm),)).fetchone()
                require(row is not None,"pinned input unavailable on selected branch")
                notes.append((row["origin"],path_rows(row["path"])))
                nfs.append(row["nf"].hex())
                total+=row["amount"]
            require(0<=total-amount-FEE<=MAX_VALUE,"insufficient pinned input total")
        packet=self.wallet.compact_payment(header,amount,to,notes)
        self.last_payment=dict(amount=amount,fee=FEE,input_total=total,change=total-amount-FEE,
                               real_inputs=len(pinned),input_commitments=list(pinned),real_nullifiers=nfs)
        self.wallet.last_payment=self.last_payment
        return packet

    def add_count(self,key,value=1):
        if self.stats is not None:
            self.stats[key]+=value

    def combine(self,children):
        self.add_count("tree_hashes")
        raw=self.hashes.call(b"N"+b"".join(children))
        require(_wire.canonical(raw),"hash role failed")
        return raw

    def apply(self,block):
        with nullcontext() if self.db.in_transaction else self.transaction():
            tip=self.head()
            h,bid,parent,header,reward,slots=(block[k] for k in ("height","id","parent","header","reward","slots"))
            require(h==tip["h"]+1 and parent==tip["id"] and len(bid)==32 and int.from_bytes(bid,"big")<=chain.TARGET,"noncontiguous wallet block")
            require(len(header)==132 and header[:32]==self.hashes.call(b"H"+tip["header"]) and header[32:36]==chain.u32(h)
                    and header[68:100]==chain.digest(b"dev-seal",self.network,bid),"wrong selected header")
            require(len(reward)==104 and len(slots)<=chain.MAX_TX,"wallet block payload")
            fee=sum(FEE for _ in slots)
            require(int.from_bytes(reward[64:72],"little")==chain.SUBSIDY+fee,"wallet reward schedule")
            transitions=[]
            tree=Tree(tip["n"],tip["front"],self.combine)
            balance=json.loads(tip["balance"])
            live={r["cm"]:(r["pos"],path_rows(r["path"])) for r in self.db.execute(
                "SELECT cm,pos,path FROM owned WHERE spent IS NULL AND amount>0")}
            self.db.execute("INSERT INTO undo SELECT ?,cm,path,spent,spender FROM owned WHERE spent IS NULL AND amount>0",(h,))
            all_nfs=set()
            all_cms=set()
            root=ZERO
            def add(row,cm,tx):
                nonlocal root
                require(cm not in all_cms,"duplicate block commitment")
                all_cms.add(cm)
                i=tree.n
                groups,root=tree.append(cm)
                for pos,path in live.values():
                    extend_path(path,pos,i,groups)
                    self.add_count("witness_updates")
                hit=self.wallet.open_row(row)
                if hit is None:
                    return False
                nf,amount,kind=hit
                siblings=[tuple(children[:slot]+children[slot+1:]) for slot,children in groups]
                self.db.execute("INSERT INTO owned VALUES(?,?,?,?,?,?,?,?,NULL,NULL,?)",
                    (cm,nf,i,amount,kind,row,h,tx,flatten(siblings) if amount else None))
                if amount:
                    live[cm]=(i,siblings)
                tally(balance,kind,amount,1)
                return True
            for slot in slots:
                tx=slot["txid"]
                nfs,cms,cts=slot["nfs"],slot["cms"],slot["cts"]
                require(len(tx)==32 and len(nfs)==len(cms)==len(cts)==2 and all(_wire.canonical(w) for w in (*nfs,*cms))
                        and all(len(ct)==1792 for ct in cts),"wallet slot")
                related=False
                for nf in nfs:
                    require(nf not in all_nfs,"duplicate block nullifier")
                    all_nfs.add(nf)
                    known=self.db.execute("SELECT cm,kind,amount,spent FROM owned WHERE nf=?",(nf,)).fetchone()
                    if known is not None:
                        require(known["spent"] is None,"already spent owned note")
                        self.db.execute("INSERT OR IGNORE INTO undo SELECT ?,cm,path,spent,spender FROM owned WHERE cm=? AND created<?",(h,known["cm"],h))
                        self.db.execute("UPDATE owned SET spent=?,spender=?,path=NULL WHERE nf=?",(h,tx,nf))
                        live.pop(known["cm"],None)
                        tally(balance,known["kind"],known["amount"],-1)
                        related=True
                for cm,ct in zip(cms,cts,strict=True):
                    if add(cm+ct,cm,tx):
                        related=True
                    self.add_count("receipt_rows")
                if related:
                    self.db.execute("INSERT INTO payments VALUES(?,?)",(tx,h))
                transitions.append(b"".join((*nfs,*cms,chain.u64(FEE))))
            add(reward,reward[-32:],None)
            state=chain.digest(b"dev-state",self.network,tip["header"][36:68],chain.u64(tree.n),chain.u64(h*chain.SUBSIDY),
                               chain.u64(tip["fees"]+fee),reward,b"".join(transitions))
            require(header[100:]==root and header[36:68]==state,"wallet funded root or transition mismatch")
            self.db.executemany("UPDATE owned SET path=? WHERE cm=?",((flatten(path),cm) for cm,(_,path) in live.items()))
            self.db.execute("INSERT INTO heads VALUES(?,?,?,?,?,?,?)",(h,bid,header,tree.n,tree.encode(),tip["fees"]+fee,json.dumps(balance)))
            self.db.execute("DELETE FROM heads WHERE h>0 AND h<?",(h-self.keep,))
            self.db.execute("DELETE FROM undo WHERE h<=?",(h-self.keep,))

    def rewind(self,height,tip):
        with self.transaction():
            current=self.height
            chosen=self.db.execute("SELECT id FROM heads WHERE h=?",(height,)).fetchone()
            require(chosen is not None and chosen[0]==tip,"unavailable retained wallet checkpoint")
            retained=self.db.execute("SELECT count(*) FROM heads WHERE h BETWEEN ? AND ?",(height,current)).fetchone()[0]
            if height==0 and (current>self.keep or retained!=current+1):
                for table in ("undo","owned","payments"):
                    self.db.execute("DELETE FROM "+table)
                self.db.execute("DELETE FROM heads WHERE h>0")
                self.add_count("deep_resets")
            else:
                for h in range(current,height,-1):
                    self.db.execute("DELETE FROM owned WHERE created=?",(h,))
                    for row in self.db.execute("SELECT * FROM undo WHERE h=?",(h,)):
                        self.db.execute("UPDATE owned SET path=?,spent=?,spender=? WHERE cm=?",
                                        (row["path"],row["spent"],row["spender"],row["cm"]))
                    self.db.execute("DELETE FROM payments WHERE h=?",(h,))
                    self.db.execute("DELETE FROM undo WHERE h=?",(h,))
                    self.db.execute("DELETE FROM heads WHERE h=?",(h,))
            self.db.execute("UPDATE identity SET target=NULL,target_h=NULL,target_header=NULL,target_count=NULL,target_anchor=NULL")
            self.add_count("rewound_blocks",current-height)

    def synchronize(self,lab,node,*,max_blocks=None):
        require(max_blocks is None or type(max_blocks) is int and max_blocks>=0,"invalid sync block bound")
        stats=dict(start_height=self.height,blocks=0,public_requests=0,request_B=0,reply_B=0,
                   public_body_B=0,tree_hashes=0,witness_updates=0,receipt_rows=0,rewound_blocks=0,
                   deep_resets=0,branch_changes=0,node_reads={},requests_by_op={},catchup_heads=0,completed_prefixes=[])
        def request(op,**params):
            meter={}
            stats["public_requests"]+=1
            counts=stats["requests_by_op"].setdefault(op,dict(count=0,request_B=0,reply_B=0))
            counts["count"]+=1
            try:
                meta,body=lab.request(node,op,meter=meter,**params)
            finally:
                for k in ("request_B","reply_B"):
                    counts[k]+=meter.get(k,0)
                    stats[k]+=meter.get(k,0)
            for key,count in meta["reads"].items():
                require(type(count) is int and count>=0,"invalid serving count")
                stats["node_reads"][key]=stats["node_reads"].get(key,0)+count
            stats["public_body_B"]+=len(body)
            return meta,body
        def checked(target,height):
            meta,body=request("history_check",target=target.hex())
            require(not body and meta["height"]==height and meta["tip"]==target.hex(),"invalid frozen target")
        roles={"native_wallet":self.wallet.role,"native_hash":self.hashes}
        samples={name:role_sample(role) for name,role in roles.items()}
        start=time.perf_counter()
        cpu=time.process_time()
        with (self.directory/"sync.lock").open("a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            stats["start_height"]=self.height
            self.stats=stats
            try:
                followup=False
                while True:
                    try:
                        target,height,header,n,anchor=self.db.execute(
                            "SELECT target,target_h,target_header,target_count,target_anchor FROM identity").fetchone()
                        fresh=target is None
                        if fresh:
                            locator=[[r[0],r[1].hex()] for r in self.db.execute("SELECT h,id FROM heads ORDER BY h DESC")]
                            meta,body=request("history_head",locator=locator)
                            g=self.db.execute("SELECT header FROM heads WHERE h=0").fetchone()[0]
                            require(not body and (meta["network"],meta["profile"],meta["genesis"],meta["genesis_header"])==
                                (self.network.hex(),chain.PROFILE.hex(),self.genesis.hex(),g.hex()),"wrong selected network")
                            height,target=meta["height"],bytes.fromhex(meta["tip"])
                            header,n,anchor=bytes.fromhex(meta["header"]),meta["notes"],bytes.fromhex(meta["anchor"])
                            common=meta["common_height"]
                            require(type(height) is int and 0<=height<=2**32-1 and len(target)==32 and
                                    type(common) is int and 0<=common<=height and [common,meta["common"]] in locator,
                                    "invalid selected locator result")
                            require(type(n) is int and height<=n<=CAPACITY and len(header)==132 and
                                    header[32:36]==chain.u32(height) and self.hashes.call(b"H"+header)==anchor and
                                    (height==0 and header==g and target==self.genesis or height>0 and
                                     int.from_bytes(target,"big")<=chain.TARGET and header[68:100]==chain.digest(b"dev-seal",self.network,target)),
                                    "invalid frozen target descriptor")
                            if common!=self.height:
                                self.rewind(common,bytes.fromhex(meta["common"]))
                            if self.height!=height:
                                self.db.execute("UPDATE identity SET target=?,target_h=?,target_header=?,target_count=?,target_anchor=?",
                                                (target,height,header,n,anchor))
                        else:
                            checked(target,height)
                        def endpoint():
                            head=self.head()
                            require(head["id"]==target and head["header"]==header and head["n"]==n and
                                    self.hashes.call(b"H"+head["header"])==anchor,"selected target header mismatch")
                        prefix_start=self.height
                        while self.height<height and (max_blocks is None or stats["blocks"]<max_blocks):
                            first=self.height+1
                            base=self.tip.hex()
                            count=min(16,height-first+1)
                            if max_blocks is not None:
                                count=min(count,max_blocks-stats["blocks"])
                            page,body=request("history_range",target=target.hex(),start=first,base=base,limit=count)
                            end=first+count-1
                            require((page["start"],page["base"],page["target"],page["end"],page["next"])==
                                    (first,base,target.hex(),end,end+1 if end<height else None),"invalid selected range")
                            blocks=decode_range(body)
                            require(len(blocks)==count and blocks[0]["height"]==first and blocks[0]["parent"]==self.tip and
                                    blocks[-1]["height"]==end and (end!=height or blocks[-1]["id"]==target),
                                    "invalid range endpoints")
                            # Commit the whole validated page, including the endpoint descriptor. A
                            # malformed later record or changed terminal state cannot advance the cursor.
                            with self.transaction():
                                for block in blocks:
                                    self.apply(block)
                                if end==height:
                                    endpoint()
                            stats["blocks"]+=count
                        finished=self.height==height
                        if finished:
                            endpoint()
                            if prefix_start<height:
                                checked(target,height)
                            self.db.execute("UPDATE identity SET target=NULL,target_h=NULL,target_header=NULL,"
                                            "target_count=NULL,target_anchor=NULL WHERE target IS NOT NULL")
                            stats["completed_prefixes"].append(height)
                            if not followup and (not fresh or prefix_start<height):
                                # Capture current selected head once, then bound the catch-up to
                                # that prefix even if the miners continue to extend it.
                                followup=True
                                stats["catchup_heads"]+=1
                                continue
                        stats.update(complete=finished,end_height=self.height,target_height=height,target_tip=target.hex())
                        break
                    except ValueError as err:
                        if str(err)=="selected target header mismatch":
                            # The persisted descriptor could itself have been erroneous.
                            # Keep the last committed prefix, allow the next call to reselect.
                            self.db.execute("UPDATE identity SET target=NULL,target_h=NULL,target_header=NULL,target_count=NULL,target_anchor=NULL")
                        if str(err)!="history branch changed":
                            raise
                        self.db.execute("UPDATE identity SET target=NULL,target_h=NULL,target_header=NULL,target_count=NULL,target_anchor=NULL")
                        stats["branch_changes"]+=1
                        require(stats["branch_changes"]<=8,"selected history changed repeatedly")
            finally:
                self.stats=None
        head=self.head()
        depth=max(1,((max(0,head["n"]-1)).bit_length()+1)//2) if head["n"] else 0
        resources=resource.getrusage(resource.RUSAGE_SELF)
        stats.update(frontier_B=len(head["front"]),witness_B=self.inventory()["notes"]*depth*96,
                     wallet_db_B=self.path.stat().st_size,wall_s=time.perf_counter()-start,
                     controller_cpu_s=time.process_time()-cpu,controller_peak_rss_KiB=resources.ru_maxrss)
        for name,role in roles.items():
            before,after=samples[name],role_sample(role)
            stats[name]=dict(cpu_s=after[0]-before[0],peak_rss_KiB=after[1],
                             to_role_B=after[2][0]-before[2][0],from_role_B=after[2][1]-before[2][1])
        return stats

    def close(self):
        try:
            self.hashes.close()
        finally:
            self.db.close()


@contextmanager
def synced_wallet(lab,node,wallet,private_dir,*,max_blocks=None):
    genesis_header=ZERO+chain.u32(0)+chain.digest(b"dev-genesis-state",chain.NETWORK)+chain.digest(b"dev-genesis-body",chain.NETWORK)+ZERO
    state=WalletSync(wallet,private_dir,chain.NETWORK,chain.GENESIS,genesis_header)
    try:
        yield state,state.synchronize(lab,node,max_blocks=max_blocks)
    finally:
        state.close()
