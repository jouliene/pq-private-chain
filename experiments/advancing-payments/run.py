"""Build a fresh independently funded campaign or replay the complete published public trace."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sqlite3
import struct
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from wire import CT,LIMIT,Role,check_genesis,digest,need,packet_width,pieces,sha,split_block,u32
from state import Frontier,Ledger,PublicBackend,UNDO,WINDOW
from ingress import BATCH_WAIT,Endpoint,admit_queue,create_pool,upload


def put(path,raw):
    with path.open("xb") as dest:
        dest.write(raw)


def save(path,data):
    put(path,(json.dumps(data,sort_keys=True,indent=2)+"\n").encode())


def verify_keys(keys,approved):
    metadata=(keys/"profile.json").read_bytes()
    need(sha(metadata)==approved,"trusted profile digest")
    profile=json.loads(metadata)
    need((profile["suite"], profile["security_bits"],profile["extension_degree"],profile["query_rounds"],
          profile["challenges"],profile["rate_bits"],profile["cap_height"],profile["grinding_bits"])==
         ("APV2",128,2,43,2,3,4,0),"profile registration")
    expected={"profile.json"}
    for k,(record,name) in enumerate(zip(profile["layers"],["leaf","wallet","outer2","outer3","outer4"],strict=True)):
        need(record["name"]==name and record["public_inputs"]==(26 if k<2 else 2+26*k),"verifier entry")
        for ext in ["vk","common","only"]:
            fn=f"{name}.{ext}"
            fp=keys/fn
            need(fp.is_file() and not fp.is_symlink() and hashlib.blake2b(fp.read_bytes()).hexdigest()==record[ext+"_blake2b512"],"fixed verifier material")
            expected.add(fn)
    need({p.name for p in keys.iterdir()}==expected,"complete registry")
    return profile


def register(args):
    args.keys.mkdir(mode=0o700,parents=True,exist_ok=False)
    role=Role(args.binary,args.binary_sha,["register","/keys"],args.keys,keys_writable=True)
    try:
        out,_=role.proc.communicate(timeout=360)
        profile=json.loads(out)
        meter=role.close(graceful=False)
        digest=sha((args.keys/"profile.json").read_bytes())
        need(profile==verify_keys(args.keys,digest),"registered bytes")
        print(json.dumps(dict(profile_sha256=digest,profile=profile,meters=meter),indent=2))
    finally:
        role.abort()


def pages(raw,stride):
    step=(192*1024//stride)*stride
    return [raw[i:i+step] for i in range(0,len(raw),step)]+[b""]


def payment(actor,pair,header,leaves,dest):
    packet=actor.call(b"P"+struct.pack("<H",pair)+header,*pages(leaves,32),dest)
    need(packet_width(packet)==1,"wallet-created payment")
    return packet


def rescan(actor,rows,nfs):
    result=actor.call(b"S",*pages(rows,32+CT),*pages(nfs,32))
    need(len(result)==4,"receipt scan")
    return int.from_bytes(result,"little")


class Resources:
    def __init__(self,args):
        self.a=args
        self.roles={}
        self.finished={}
        self.profile=verify_keys(args.keys,args.profile_sha)
        self.h=self.role("hash",["hash"],use_keys=False)
        self.v=self.role("verifier",["verify","/keys"])
        self.backend=PublicBackend(self.h,self.v,args.profile_sha)

    def role(self,name,cmd,private=None,use_keys=True):
        need(name not in self.roles,"role exists")
        r=Role(self.a.binary,self.a.binary_sha,cmd,self.a.keys if use_keys else None,private=private)
        self.roles[name]=r
        return r

    def finish(self,name):
        r=self.roles.pop(name)
        meters=r.close()
        stored=self.finished.setdefault(name,dict(meters=[],to_role_B=0,from_role_B=0))
        stored["meters"].extend(meters)
        stored["to_role_B"]+=r.sizes[0]
        stored["from_role_B"]+=r.sizes[1]
        return self.finished[name]

    def close(self):
        for r in list(self.roles.values()):
            r.abort()


class Records:
    def __init__(self,directory):
        self.dir=directory
        self.packets=directory/"packets"
        self.packets.mkdir()
        self.blocks={}
        self.submissions={}

    def packet(self,p):
        if not p:
            return None
        name=sha(p)
        file=self.packets/(name+".bin")
        if not file.exists():
            put(file,p)
        return name

    def block(self,raw):
        hdr,nonce,p=split_block(raw)
        key=sha(raw)
        self.blocks[key]=dict(prefix=raw[:152].hex(),packet=self.packet(p),size=len(raw))
        return key

    def submission(self,name,p):
        self.submissions[name]=self.packet(p)
        return p


def public_block(directory,record):
    p=b"" if record["packet"] is None else (directory/"packets"/(record["packet"]+".bin")).read_bytes()
    need(not p or sha(p)==record["packet"],"packet identity")
    raw=bytes.fromhex(record["prefix"])+p
    need(len(raw)==record["size"],"record length")
    return raw


def snapshot(node):
    h=node.head()
    return dict(height=h["h"],id=h["id"].hex(),header=h["header"].hex(),count=h["n"],fees=h["fees"],
                rollback_floor=node.db.execute("SELECT floor FROM config WHERE id=1").fetchone()[0],
                spent=node.db.execute("SELECT count(*) FROM spent").fetchone()[0],
                nullifier_set_sha256=sha(node.nfs()),ordered_commitments_sha256=sha(node.leaves()),
                frontier_sha256=sha(h["frontier"]))


def reject(node,label,fn,reason):
    before=snapshot(node)
    try: fn()
    except ValueError as error:
        need(str(error)==reason,f"{label}: {error}")
    else: raise ValueError("unexpected acceptance "+label)
    need(snapshot(node)==before,"atomic rejection "+label)
    return dict(case=label,reason=reason,preserved_head=before["id"])


def roots(hashes):
    targets=(1,3,4,5,15,16,17,63,64,65,255,256,257,1024,4096,16384)
    result=[]
    frontier=Frontier(0,b"",hashes)
    leaves=bytearray()
    for i in range(max(targets)):
        word=struct.pack("<4Q",*(i*731+j+1 for j in range(4)))
        frontier.append(word)
        leaves.extend(word)
        if i+1 in targets:
            start=time.monotonic()
            root=frontier.root()
            active=time.monotonic()-start
            rebuilt=hashes.call(b"R"+leaves)
            need(rebuilt==root==Frontier(i+1,frontier.encode(),hashes).root(),"independent tree root")
            result.append(dict(count=i+1,root=root.hex(),frontier_B=len(frontier.encode()),incremental_root_wall_s=active))
    return result


def replay(args,res):
    p=args.evidence
    trace=json.loads((p/"TRACE.json").read_bytes())
    genesis=(p/"genesis.bin").read_bytes()
    check_genesis(genesis,args.genesis_sha)
    need(trace["genesis_sha256"]==args.genesis_sha and trace["profile_sha256"]==args.profile_sha,"selected trace identity")
    output=args.work
    output.mkdir(parents=True,exist_ok=False)
    archived=Ledger(output/"archive.sqlite",res.backend,genesis,args.genesis_sha,True)
    pruned=Ledger(output/"pruned.sqlite",res.backend,genesis,args.genesis_sha,True,True)
    values={}
    try:
        for role,node in [("archive",archived),("pruned",pruned)]:
            times=[]
            for event in trace["events"]:
                start=time.monotonic()
                if event["op"]=="extend":
                    raw=public_block(p,trace["blocks"][event["block"]])
                    need(sha(raw)==event["block"],"block digest")
                    node.accept(raw)
                elif event["op"] in ("switch","reject_switch"):
                    new=[public_block(p,trace["blocks"][x]) for x in event["blocks"]]
                    need(all(sha(b)==s for b,s in zip(new,event["blocks"])),"replacement identities")
                    switch=lambda:node.switch(bytes.fromhex(event["base"]),new)
                    if event["op"]=="switch": switch()
                    else: reject(node,"invalid public switch",switch,event["reason"])
                elif event["op"]=="reject":
                    packet=(p/"packets"/(event["packet"]+".bin")).read_bytes()
                    need(sha(packet)==event["packet"],"submitted identity")
                    reject(node,event["reason"],lambda:node.produce(packet,0),event["reason"])
                else: raise ValueError("unknown event")
                times.append(time.monotonic()-start)
                need(snapshot(node)==event["state"],"branch state mismatch")
            values[role]=dict(events=len(times),seconds=sum(times),selected=snapshot(node),
                stored_body_B=node.db.execute("SELECT coalesce(sum(length(body)),0) FROM blocks").fetchone()[0],
                sqlite_B=node.path.stat().st_size,active_pages_B=(node.db.execute("PRAGMA page_count").fetchone()[0]-node.db.execute("PRAGMA freelist_count").fetchone()[0])*node.db.execute("PRAGMA page_size").fetchone()[0])
            need(node.db.execute("PRAGMA integrity_check").fetchone()[0]=="ok","durable database")
        need(values["archive"]["selected"]==values["pruned"]["selected"],"pruned state")
    finally:
        archived.close();pruned.close()
    return values


def replay_direct(args, res, expected_count=4):
    directory = args.evidence
    trace = json.loads((directory/"TRACE.json").read_bytes())
    genesis = (directory/"genesis.bin").read_bytes()
    need(trace["genesis_sha256"] == args.genesis_sha and trace["profile_sha256"] == args.profile_sha,
         "selected direct trace identity")
    check_genesis(genesis, args.genesis_sha)
    args.work.mkdir(parents=True, exist_ok=False)
    node = Ledger(args.work/"direct.sqlite", res.backend, genesis, args.genesis_sha, True)
    occupied = []
    try:
        for identity in trace["order"]:
            raw = public_block(directory, trace["blocks"][identity])
            need(sha(raw) == identity, "direct block digest")
            node.accept(raw)
            packet = split_block(raw)[2]
            if packet:
                need(packet_width(packet) == 1, "direct singleton required")
                occupied.append(node.head()["h"])
        selected = snapshot(node)
        need(len(occupied) == expected_count and selected == trace["final"], "public direct replay")
        return dict(verified_heights=occupied, blocks=len(trace["order"]), selected=selected)
    finally:
        node.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=["register","campaign","replay","replay-direct","replay-paced","roots"])
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--binary-sha",required=True)
    parser.add_argument("--keys",type=Path,required=True)
    parser.add_argument("--profile-sha")
    parser.add_argument("--genesis-sha")
    parser.add_argument("--evidence",type=Path)
    parser.add_argument("--work",type=Path)
    args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError("experiment timeout")))
    signal.alarm(2700)
    if args.mode=="register":
        register(args);return
    res=Resources(args)
    try:
        if args.mode=="campaign":
            from campaign import campaign
            output=campaign(args,res)
        elif args.mode=="replay": output=replay(args,res)
        elif args.mode=="replay-direct": output=replay_direct(args,res)
        elif args.mode=="replay-paced": output=replay_direct(args,res,12)
        else: output=roots(res.h)
        print(json.dumps(output,sort_keys=True,indent=2))
    finally:
        res.close()


if __name__=="__main__":
    main()
