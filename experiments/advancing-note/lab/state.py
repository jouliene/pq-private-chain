"""Public-only research ledger, ordered fixed-depth tree and exact atomic fee accounting."""
from collections import Counter, deque
import ctypes
import fcntl
import os
import resource
import sqlite3
import tempfile
import json
from pathlib import Path
import struct
import time
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import *

ANCHOR_DEPTH = 64
UNDO_DEPTH = 8
MINER = b'N7 devnet miner!'
MAX_BLOCK = 180 + 2 * MAX_PACKET + 12


class Tree:
    def __init__(self, arithmetic, keep_paths=False):
        self.arithmetic=arithmetic
        self.keep_paths=keep_paths
        self.empty=[arithmetic.call('empty')]
        self.layers=[{} for _ in range(DEPTH+1)]
        for level in range(DEPTH):
            z=self.empty[-1]
            self.empty.append(self.parent(level,z,z))
        self.count=0

    def parent(self, level, a, b):
        return self.arithmetic.call('parent',level=level,left=a,right=b)

    def get(self, level, i):
        return self.layers[level].get(i,self.empty[level])

    def put(self, level, index, value, undo):
        if undo is not None:
            undo.setdefault((level,index),self.layers[level].get(index))
        layer=self.layers[level]
        if not self.keep_paths and index not in layer and len(layer)==2:
            # Consecutive append can only ask for its immediate left sibling.
            old_index=min(layer)
            old_value=layer.pop(old_index)
            if undo is not None:
                undo.setdefault((level,old_index),old_value)
        layer[index]=value

    def append(self, cm, undo=None):
        need(self.count<MAX_COUNT,'tree full')
        i=self.count
        self.count+=1
        self.put(0,i,cm,undo)
        for level in range(DEPTH):
            parent=i//2
            self.put(level+1,parent,self.parent(level,self.get(level,2*parent),self.get(level,2*parent+1)),undo)
            i=parent

    @property
    def root(self):
        return self.get(DEPTH,0)

    def path(self,index):
        need(self.keep_paths,'public node retains append frontier only')
        need(0<=index<self.count,'invalid occurrence')
        return [self.get(j,(index>>j)^1) for j in range(DEPTH)]


def unframe(raw):
    need(raw[:4]==b'N7B2' and 180<=len(raw)<=MAX_BLOCK,'block framing')
    header=raw[:176]
    size,=struct.unpack_from('<I',raw,176)
    packet=raw[180:]
    need(len(packet)==size and size<=2*MAX_PACKET+12,'block payload')
    need(header[104:152]==digest('N7B2/body',raw[176:]),'block body binding')
    need(int.from_bytes(digest('N7B2/work',header)[:2],'big')<64,'block work')
    return header,packet


class BranchIndex:
    """Derived, uniquely keyed branch state. The protected block log is the commit record."""

    def __init__(self,path=None):
        self.path=path
        self.db=None

    def __enter__(self):
        self.reset()
        return self

    def clean(self):
        if self.db is not None:
            self.db.close()
            self.db=None
        if self.path is not None:
            # No existing index can authorize a transaction, even after an unclean stop.
            for suffix in ('','-journal'):
                Path(str(self.path)+suffix).unlink(missing_ok=True)

    def __exit__(self,*_):
        self.clean()

    def reset(self):
        self.clean()
        self.db=sqlite3.connect(self.path or ':memory:')
        if self.path is not None:
            self.db.execute('PRAGMA hard_heap_limit=33554432')
            self.db.execute('PRAGMA journal_mode=PERSIST')
            self.db.execute('PRAGMA synchronous=OFF')
            self.db.execute('PRAGMA mmap_size=0')
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.executescript("""
            CREATE TABLE spent (key BLOB PRIMARY KEY) WITHOUT ROWID;
            CREATE TABLE commitments (key BLOB PRIMARY KEY) WITHOUT ROWID;
            CREATE TABLE miner_fees (miner TEXT PRIMARY KEY, fee INTEGER NOT NULL) WITHOUT ROWID;
        """)

    def contains(self,table,keys):
        need(table in ('spent','commitments'),'index selector')
        return any(self.db.execute(f'SELECT 1 FROM {table} WHERE key=?',(key,)).fetchone()
                   is not None for key in keys)

    def change(self,nfs,cms,miner,fees,remove=False):
        for table,keys in (('spent',nfs),('commitments',cms)):
            if not keys:
                continue
            sql=f'DELETE FROM {table} WHERE key=?' if remove else f'INSERT INTO {table} VALUES (?)'
            changed=self.db.executemany(sql,((key,) for key in keys)).rowcount
            if changed!=len(keys):
                raise RuntimeError('derived branch index disagreement')
        if fees:
            if remove:
                changed=self.db.execute('UPDATE miner_fees SET fee=fee-? WHERE miner=? AND fee>=?',
                                        (fees,miner,fees)).rowcount
                if changed!=1:
                    raise RuntimeError('derived fee index disagreement')
                self.db.execute('DELETE FROM miner_fees WHERE miner=? AND fee=0',(miner,))
            else:
                self.db.execute('INSERT INTO miner_fees VALUES (?,?) ON CONFLICT(miner) '
                                'DO UPDATE SET fee=fee+excluded.fee',(miner,fees))

    def spent_hash(self):
        h=sha3_384(b'N7B2/spent\0')
        for key, in self.db.execute('SELECT key FROM spent ORDER BY key'):
            h.update(key)
        return h.hexdigest()

    def fees(self):
        return dict(self.db.execute('SELECT miner,fee FROM miner_fees ORDER BY miner'))

    def journal_size(self):
        if self.path is None:
            return 0
        journal=Path(str(self.path)+'-journal')
        try:
            return journal.stat().st_size
        except FileNotFoundError:
            return 0

    def stat(self):
        return dict(cache_target_KiB=2048,sqlite_heap_limit_B=33554432 if self.path else None,
                    database_file_B=self.path.stat().st_size if self.path else 0,
                    database_pages=self.db.execute('PRAGMA page_count').fetchone()[0],
                    page_B=self.db.execute('PRAGMA page_size').fetchone()[0],
                    journal_file_B=self.journal_size())


class Ledger:
    def __init__(self,arith,genesis,verifier,index,wallet=False,record_metrics=False):
        self.verifier=verifier
        self.arith=arith
        self.tree=Tree(arith,keep_paths=wallet)
        self.net=bytes.fromhex(genesis['network'])
        self.tip=self.genesis=genesis_id(genesis)
        need(self.genesis.hex()==Path('/founding-id').read_text().strip(),'unapproved founding genesis')
        self.scope=digest('N7G2/key-scope',bytes.fromhex(genesis['nonce']))
        need(genesis['profile']=='N7P2' and self.net==funding_policy(bytes.fromhex(genesis['nonce']),genesis['credits']),'new genesis domain')
        self.height=0
        self.index=index
        self.spent_count=0
        self.history=[] if wallet else None
        self.supply=Counter()
        for i,row in enumerate(genesis['credits']):
            n={k:row[k] for k in ('owner','asset','native','token')}
            n['salt']=credit_salt(self.net,i)
            need(0<=n['native']<2**62 and 0<=n['token']<2**62 and bool(n['token'])==any(n['asset']),'genesis note')
            self.supply['native']+=n['native']
            if n['token']: self.supply[struct.pack('<8I',*n['asset']).hex()]+=n['token']
            cm=self.arith.call('note',note=n)
            ct=bytes.fromhex(row['receipt'])
            need(row['cm']==cm and len(ct)==CT and not self.index.contains('commitments',[pack(cm)]),'genesis credit')
            self.add(cm,ct,i%2)
        need(dict(self.supply)==genesis['issued'],'founding quantities')
        self.index.db.commit()
        self.metrics=[] if record_metrics else None
        self.anchors=deque([(pack(self.tree.root),self.tree.count)],maxlen=ANCHOR_DEPTH)
        self.undo=deque(maxlen=UNDO_DEPTH)

    def add(self,cm,ct,slot):
        self.tree.append(cm)
        self.index.change([],[pack(cm)],'',0)
        if self.history is not None:
            self.history.append((cm,ct,slot))

    def has_anchor(self, statement):
        return (pack(statement['root']),statement['count']) in self.anchors

    def validate(self,packet):
        if not packet:
            return [],[],0,[]
        if packet[:4]==b'N7S2':
            frames=split_bundle(packet,self.genesis)
            (_,a,_),(_,b,_)=frames
            need((a['expiry'],a['terms'],a['payer'])==(b['expiry'],b['terms'],b['payer']) and
                 a['auth']!=b['auth'] and self.height+1<=a['expiry'],'swap agreement or expiry')
            decision=swap_digest(frames[0][0],frames[1][0])
            for _,leg,sig in frames:
                need(crypto('verify',leg['auth']+decision+sig)==bytes([1]),'owner authorization')
            legs=[a,b]
        else:
            leg=parse(packet,self.genesis); need(leg['kind']==0,'incomplete swap')
            legs=[leg]
        nfs=[]; cms=[]; fees=0
        for leg in legs:
            s=leg['statement']
            need(leg['net']==self.net,'foreign network')
            nfs.extend(map(pack,s['nullifiers'])); cms.extend(map(pack,s['outputs']));fees+=s['fee']
        need(len(set(nfs))==len(nfs) and not self.index.contains('spent',nfs),'spent or repeated nullifier')
        need(len(set(cms))==len(cms) and not self.index.contains('commitments',cms),'previous or duplicate output')
        need(self.tree.count+len(cms)<=MAX_COUNT and fees==3,'capacity or fee')
        meters=[]
        for leg in legs:
            s=leg['statement']
            need(self.has_anchor(s),'wrong branch root/count')
            meters.append(self.verifier.verify(s,leg['proof']))
        return legs,nfs,fees,meters

    def mine(self,packet,miner):
        # The test driver has no authority to set a root or declare a proof valid.
        need(len(miner)==16 and len(packet)<=MAX_BLOCK-180,'miner or payload width')
        body=struct.pack('<I',len(packet))+packet
        core=(b'N7B2'+self.net+struct.pack('<I',self.height+1)+self.tip+digest('N7B2/body',body)+miner+struct.pack('<I',3 if packet else 0))
        need(len(core)==172,'header layout')
        for n in range(2**32):
            header=core+struct.pack('<I',n)
            if int.from_bytes(digest('N7B2/work',header)[:2],'big')<64:
                return header+body
        raise ValueError('nonce exhausted')

    def accept(self, raw, persist=None):
        start=time.monotonic_ns()
        cpu=self.cpu_ns()
        header,packet=unframe(raw)
        need(header[4:52]==self.net and int.from_bytes(header[52:56],'little')==self.height+1
             and header[56:104]==self.tip,'block ancestry')
        legs,nfs,fees,meters=self.validate(packet)
        need(int.from_bytes(header[168:172],'little')==fees,'fee credit')
        miner=header[152:168].hex()
        appended=[(cm,ct,i) for leg in legs for i,(cm,ct) in
                  enumerate(zip(leg['statement']['outputs'],leg['cts'],strict=True))]
        old_count=self.tree.count
        nodes={}
        cm_keys=[pack(cm) for cm,_,_ in appended]
        # Single-threaded role. Arithmetic and disk errors cannot expose a partially applied tree.
        try:
            for cm,_,_ in appended:
                self.tree.append(cm,nodes)
            with self.index.db:
                self.index.change(nfs,cm_keys,miner,fees)
                journal_before_commit=self.index.journal_size()
                if persist:
                    persist(raw,self.height+1)
        except BaseException:
            self.restore_tree(nodes,old_count)
            raise
        expired=self.anchors[0] if len(self.anchors)==ANCHOR_DEPTH else None
        self.undo.append((self.tip,old_count,nodes,nfs,cm_keys,miner,fees,expired))
        self.anchors.append((pack(self.tree.root),self.tree.count))
        self.spent_count+=len(nfs)
        if self.history is not None:
            self.history.extend(appended)
        self.height+=1
        self.tip=digest('N7B2/work',header)
        index_stat=self.index.stat()
        index_stat['journal_before_commit_B']=journal_before_commit
        end=time.monotonic_ns()
        metric=dict(height=self.height,legs=meters,index_stat=index_stat,packet_B=len(packet),block_B=len(raw),
                    elapsed_s=(end-start)*1e-9,full_cpu_s=(self.cpu_ns()-cpu)*1e-9,
                    start_ns=start,end_ns=end,durable=bool(persist),signatures=2 if len(legs)==2 else 0)
        if self.metrics is not None:
            self.metrics.append(metric)
        return metric

    def cpu_ns(self):
        # Linux supports process CPU clocks for another visible PID, including worker threads.
        # Node signature processes are reaped by subprocess.run and appear in RUSAGE_CHILDREN.
        if not hasattr(self,'clocks'):
            getclock=ctypes.CDLL(None).clock_getcpuclockid
            ids=[]
            for worker in (self.arith.proc,self.verifier.proc):
                clock=ctypes.c_int()
                if getclock(worker.pid,ctypes.byref(clock))!=0:
                    raise RuntimeError('child CPU clock unavailable')
                ids.append(clock.value)
            self.clocks=ids
        child=resource.getrusage(resource.RUSAGE_CHILDREN)
        return time.process_time_ns()+sum(time.clock_gettime_ns(c) for c in self.clocks)+int(
            (child.ru_utime+child.ru_stime)*1e9)

    def restore_tree(self,nodes,count):
        for (level,index),old in nodes.items():
            if old is None:
                self.tree.layers[level].pop(index,None)
            else:
                self.tree.layers[level][index]=old
        self.tree.count=count

    def revert(self,store):
        need(self.height>0,'cannot revert genesis')
        if not self.undo:
            # Explicit test-only deep disconnect. Reconstruct the authorized prefix before unlink.
            self.index.reset()
            try:
                parent=replay(self.arith,store.folder,self.verifier,self.index,limit=self.height-1)
            except Exception as error:
                raise RuntimeError('cannot rebuild branch index') from error
            store.remove(self.height)
            self.__dict__.update(parent.__dict__)
            return
        tip,count,nodes,nfs,cm_keys,miner,fees,expired=self.undo[-1]
        with self.index.db:
            self.index.change(nfs,cm_keys,miner,fees,remove=True)
            store.remove(self.height)
        self.restore_tree(nodes,count)
        self.spent_count-=len(nfs)
        if self.history is not None:
            del self.history[count:]
        self.undo.pop()
        self.anchors.pop()
        if expired is not None:
            self.anchors.appendleft(expired)
        if self.metrics is not None:
            self.metrics.pop()
        self.height-=1
        self.tip=tip

    def counters(self):
        return dict(height=self.height,tip=self.tip.hex(),root=pack(self.tree.root).hex(),count=self.tree.count,
                    spent=self.spent_count)

    def summary(self):
        return dict(**self.counters(),spent_hash=self.index.spent_hash(),
                    miner_fees=self.index.fees(),issued=dict(self.supply))


def replay(arith,folder,verifier,index,limit=None,wallet=False,record_metrics=False):
    db=Ledger(arith,data(folder/'genesis.json'),verifier,index,wallet,record_metrics)
    with os.scandir(folder) as entries:
        count=sum(e.name.startswith('block-') and e.name.endswith('.bin') for e in entries)
    if limit is not None:
        need(type(limit) is int and 0<=limit<=count,'unavailable replay height')
        count=limit
    for height in range(1,count+1):
        p=folder/f'block-{height:04}.bin'
        need(p.is_file() and 180<=p.stat().st_size<=MAX_BLOCK,'wrong block file')
        db.accept(p.read_bytes())
    return db


class BlockStore:
    """A durable block is the commit record for every effect. Restart independently replays it."""
    def __init__(self,folder):
        self.folder=folder

    def __enter__(self):
        self.fd=os.open(self.folder,os.O_RDONLY|os.O_DIRECTORY)
        try:
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            raise
        return self

    def __exit__(self,*_):
        os.close(self.fd)

    def publish(self,raw,height):
        target=self.folder/f'block-{height:04}.bin'
        with tempfile.NamedTemporaryFile(prefix='.incoming-',dir=self.folder) as staging:
            staging.write(raw)
            staging.flush()
            os.fsync(staging.fileno())
            os.link(staging.name,target)
        # Failure here stops the service. Replay determines which complete block reached disk.
        os.fsync(self.fd)

    def remove(self,height):
        (self.folder/f'block-{height:04}.bin').unlink()
        os.fsync(self.fd)


def reply(**fields):
    print(json.dumps(fields,separators=(',',':')),flush=True)


def serve(db,store,test_forks):
    stream=sys.stdin.buffer
    limit=2*MAX_BLOCK+512
    while line:=stream.readline(limit+1):
        if len(line)>limit:
            while line and not line.endswith(b'\n'):
                line=stream.readline(limit+1)
            reply(ok=False,error='oversize command',state=db.counters())
            continue
        try:
            req=json.loads(line)
            op=req['op']
            if op=='mine':
                miner=bytes.fromhex(req['miner']) if 'miner' in req else MINER
                block=db.mine(bytes.fromhex(req['packet']),miner)
                reply(ok=True,block=block.hex())
            elif op=='accept':
                metric=db.accept(bytes.fromhex(req['block']),store.publish)
                reply(ok=True,state=db.counters(),metric=metric)
            elif op=='revert':
                need(test_forks,'fork test control disabled')
                db.revert(store)
                reply(ok=True,state=db.summary())
            elif op=='summary':
                reply(ok=True,state=db.summary(),index_stat=db.index.stat())
            elif op=='quit':
                reply(ok=True)
                return
            else:
                raise ValueError('unknown public operation')
        except (ValueError,KeyError,TypeError,struct.error) as err:
            reply(ok=False,error=str(err),state=db.counters())


def main(mode):
    folder=Path('/public')
    started=time.monotonic()
    if mode in ('serve','serve-test-forks'):
        with (BlockStore(folder) as store, BranchIndex(folder/'.n7-index.sqlite') as index,
              Arithmetic() as arith, PublicVerifier() as verifier):
            db=replay(arith,folder,verifier,index)
            reply(ready=True,state=db.summary(),index_stat=index.stat(),verifier=verifier.ready,startup_s=time.monotonic()-started,
                  startup_cpu_s=db.cpu_ns()*1e-9,replayed_blocks=db.height)
            serve(db,store,mode=='serve-test-forks')
        return
    with Arithmetic() as arith, PublicVerifier() as verifier, BranchIndex() as index:
        db=replay(arith,folder,verifier,index,record_metrics=(mode=='verify'))
        if mode=='verify':
            print(json.dumps(dict(state=db.summary(),verification=db.metrics,verifier=verifier.ready)))
        elif mode=='mine':
            block=db.mine(Path('/item').read_bytes(),MINER)
            db.accept(block)
            sys.stdout.buffer.write(block)
        elif mode=='controls':
            before=db.summary()
            try:
                db.accept(db.mine(Path('/item').read_bytes(),MINER))
            except ValueError as err:
                need(before==db.summary(),'failed candidate changed state')
                print(str(err))
            else:
                raise ValueError('invalid transaction admitted')
        else:
            raise ValueError('unknown node operation')


if __name__=='__main__':
    main(sys.argv[1])
