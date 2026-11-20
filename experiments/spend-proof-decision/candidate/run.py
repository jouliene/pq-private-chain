"""Fresh funded 2x2 ordinary and bilateral K384 leg proofs, actual inputs, backup restore and public verification."""
import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import shutil
import struct
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path[:0]=[str(HERE),str(ROOT/"experiments/advancing-payments")]
from packet import ZERO, bundle, decode, require, statement
from wire import Role
sys.path[0:0]=[str(ROOT/"experiments/managed-assets"),str(ROOT/"experiments/user-assets")]
import managed_ops
from managed_ledger import SupplyRegistry, ManagedSlot
from asset_ledger import issue_id


def approved(build,reference):
    s=json.loads((build/"BUILD.json").read_bytes())
    pins=json.loads(reference.read_bytes())
    require(all(s[k]==pins[k] for k in ("upstream","lock_sha256","generated_sources")),"approved sources")
    require(sha256((build/"native").read_bytes()).hexdigest()==s["binary_sha256"],"installed native identity")
    return s["binary_sha256"]


class Trial:
    def __init__(self,build,baseline,out):
        self.out=out
        self.network=sha256(b"K384/isolated-network/v1").digest()
        self.roles={"ordinary":build/"ordinary","leg":build/"leg","old":baseline}
        self.identity={}
        for name,path in self.roles.items():
            key="swap.vk" if name=="leg" else "managed.vk"
            if name=="old":
                p=ROOT/"experiments/managed-assets/native"
                reference=p/"BUILD.json"; vk=p/"registry"/key
            else:
                reference=HERE/"registry"/(name+"-BUILD.json")
                vk=HERE/"registry"/key
            self.identity[name]=approved(path,reference)
            require((path/"registered"/key).read_bytes()==vk.read_bytes(),"operator verifier bytes")
        self.meters={}
        self.leaves=[]
        self.spent=set()
        self.registry=SupplyRegistry()
        self.registry.db=sqlite3.connect(":memory:")
        self.registry.db.row_factory=sqlite3.Row
        self.registry.db.execute("CREATE TABLE assets(id BLOB,sequence INTEGER,mode TEXT,authority BLOB,supply INTEGER,h INTEGER,tx BLOB,PRIMARY KEY(id,sequence))")

    @contextmanager
    def role(self,suite,args,label,private=None):
        path=self.roles[suite]
        start=time.perf_counter()
        r=Role(path/"native",self.identity[suite],args,path/"registered",private=private)
        try:
            yield r
            meters=r.close()
            self.meters[label]=dict(native=meters,call_wall_s=r.times,
                                    complete_process_wall_s=time.perf_counter()-start,
                                    ipc_request_B=r.sizes[0],ipc_reply_B=r.sizes[1])
        finally:
            r.abort()

    def wallet(self,suite,home,mode,commands,label):
        with self.role(suite,["wallet","/keys","/private/seed",mode],label,home) as r:
            address=r.get()
            return address,[r.call(cmd) for cmd in commands]

    def prepare(self,indices):
        level=self.leaves[:]
        paths=[[] for _ in indices]
        positions=indices[:]
        while True:
            padded=level+[ZERO]*((-len(level))%4)
            parents=[]
            for j in range(0,len(padded),4):
                parents.append(self.hash.call(b"N"+b"".join(padded[j:j+4])))
            for p,i in zip(paths,positions):
                siblings=padded[(i//4)*4:(i//4)*4+4]
                p.append(b"".join(siblings[:i%4]+siblings[i%4+1:]))
            if len(parents)==1:
                return ZERO+struct.pack("<I",1)+ZERO*2+parents[0],paths
            level=parents
            positions=[i//4 for i in positions]

    def sources(self,inputs):
        h,paths=self.prepare([idx for idx,row in inputs])
        desc=bytes([len(inputs)])
        for (_,row),levels in zip(inputs,paths):
            desc+=struct.pack("<HB",len(row),len(levels))+row+b"".join(levels)
        return h,desc

    def insert(self,cm,row):
        require(len(cm)==32 and cm not in self.leaves,"unique public commitment")
        idx=len(self.leaves)
        self.leaves.append(cm)
        return idx,row

    def check(self,suite,raw,label,repeats=1):
        with self.role(suite,["verify","/keys"],label) as r:
            verdicts=[r.call(raw) for _ in range(repeats)]
        require(all(x==verdicts[0] for x in verdicts) and verdicts[0][:1]==b"1","fresh public verification")
        return verdicts[0]

    def settle(self,fx,h,real):
        require(fx[1:33]==self.hash.call(b"H"+h) and fx[33:37]==h[32:36], "funded anchor")
        nfs=fx[37:69],fx[69:101]
        require(len(set(nfs))==2 and not self.spent.intersection(nfs) and list(nfs[:len(real)])==real,"nullifiers")
        self.spent.update(nfs)
        return [self.insert(fx[101+i*32:133+i*32],fx[101+i*32:133+i*32]+fx[173+i*1792:173+(i+1)*1792]) for i in (0,1)]

    def hits(self,suite,home,rows,label):
        _,hits=self.wallet(suite,home,"restore",[b"D"+row for _,row in rows],label)
        return [None if h==b"MISS" else self.open(h) for h in hits]

    @staticmethod
    def open(h):
        require(len(h)==84 and h[:3]==b"HIT","funded receipt")
        return h[3:35],*struct.unpack_from("<QQ",h,35),h[51:83],h[-1]

    def ordinary(self,suite,home,to,ins,n,t,id_,supply,label,op="transfer"):
        h,source=self.sources(ins)
        real=[p[0] for p in self.hits(suite,home,ins,label+"_funding")]
        cmd=b"K"+h+struct.pack("<QQ",n,t)+id_+struct.pack("<Q",supply)+to+source
        _,(packet,)=self.wallet(suite,home,"restore",[cmd],label+"_prove")
        require(packet[:5] in (b"MNG1\x01",b"K3M1\x01"),"ordinary wallet proof")
        fx=self.check(suite,packet,label+"_verify",3 if suite=="ordinary" else 1)
        require(fx[-40:]==(id_ if supply else ZERO)+struct.pack("<Q",supply),"public delta")
        require(int.from_bytes(fx[165:173],"little")==3,"native fee")
        if suite=="old" and op!="transfer":
            authority=b""; sequence=0; previous=ZERO; signer=None
            if op in managed_ops.SIGNED:
                authority=self.wallet("old",home,"restore",[b"J"],label+"_authority")[1][0]
                if op=="mint":
                    record=self.registry.latest_asset(id_)
                    sequence,previous=record["sequence"],record["tx"]
                def signer(msg):
                    return self.wallet("old",home,"restore",[b"L"+msg],label+"_sign")[1][0]
            tx=managed_ops.wrap(packet,op,self.network,public_key=authority,sequence=sequence,previous=previous,sign=signer)
            env=managed_ops.parse(tx)
            if op in managed_ops.SIGNED:
                digest=managed_ops.authorization_digest(env.inner,env.operation,self.network,env.public_key,env.sequence,env.previous)
                with self.role("old",["verify","/keys"],label+"_verify_signature") as r:
                    require(r.call(b"V"+env.public_key+digest+env.signature)==b"1","issuer authorization")
            slot=ManagedSlot(fx[1:33],1,(fx[37:69],fx[69:101]),(fx[101:133],fx[133:165]),3,
                             (fx[173:1965],fx[1965:3757]),id_,supply,op,authority,sequence,previous,sha256(tx).digest())
            self.registry.check_issuance(slot,self.network)
            self.registry.record_event(slot,1,sha256(tx).digest())
            (self.out/(label+".bin")).write_bytes(tx)
        return packet,self.settle(fx,h,real)

    def run(self,private):
        names=[private/x for x in ("alice","bob","alice-restored","bob-restored","fixed-issuer","managed-issuer","forward")]
        for name in names:name.mkdir(mode=0o700)
        a,b,ar,br,fi,mi,forward=names
        roles=[a,b,fi,mi,forward]
        addrs={name:self.wallet("old",name,"create",[],"create"+str(i))[0] for i,name in enumerate(roles)}
        for source,dest in ((a,ar),(b,br)):shutil.copy2(source/"seed",dest/"seed")
        addresses=[addrs[a],addrs[b]]
        def reward(holder,amount):
            body=os.urandom(32)+addrs[holder][1:33]+struct.pack("<QQ",amount,0)
            cm=self.hash.call(b"C"+body)
            return self.insert(cm,body+cm)
        def find(home,rows,n,t,asset,label):
            hits=self.hits("old",home,rows,label+"_open")
            return rows[next(i for i,h in enumerate(hits) if h and h[1:4]==(n,t,asset))]
        ids=[];class_funding=[]
        for i,(issuer,cap) in enumerate(((fi,70),(mi,300))):
            funds=reward(issuer,100)
            nf=self.hits("old",issuer,[funds],f"issuer{i}")[0][0]
            if i:
                issuer_key=self.wallet("old",issuer,"restore",[b"J"],"registered_auth")[1][0]
                aid=managed_ops.managed_id(self.network,issuer_key,nf)
            else:
                aid=issue_id(self.network,nf)
            ids.append(aid)
            _,out=self.ordinary("old",issuer,addrs[issuer],[funds],0,cap,aid,cap,f"issue{i}",
                                "register" if i else "fixed")
            class_funding.append([find(issuer,out,0,cap,aid,f"stock{i}"),find(issuer,out,97,0,ZERO,f"gas{i}")])
        # The established registration/sequence/authority checks authorize +40; proof of holder funds burns ten.
        _,minted=self.ordinary("old",mi,addrs[mi],[reward(mi,100)],0,40,ids[1],40,"mint","mint")
        _,burnfund=self.ordinary("old",mi,addrs[mi],[find(mi,minted,0,40,ids[1],"minted"),
                  find(mi,minted,97,0,ZERO,"mint_gas")],3,10,ids[1],0,"fund_burn")
        self.ordinary("old",mi,addrs[mi],[find(mi,burnfund,3,10,ids[1],"burn_funded")],
                      0,0,ids[1],(1<<62)|10,"burn","burn")
        require([(r["mode"],r["supply"]) for r in map(self.registry.latest_asset,ids)]==
                [("fixed",70),("managed",330)],"historical asset registry")
        ins=[]; fee_notes=[]
        for i,(home,issuer,n,t) in enumerate(((a,fi,20,15),(b,mi,18,80))):
            _,out=self.ordinary("old",issuer,addrs[home],class_funding[i],n,t,ids[i],0,f"fund{i}")
            ins.append([find(home,out,n,t,ids[i],f"mixed{i}")])
            _,cash=self.ordinary("old",issuer,addrs[home],[reward(issuer,100)],9,0,ZERO,0,f"fee{i}")
            fee_notes.append(find(home,cash,9,0,ZERO,f"separate_fee{i}"))
        homes=[a,b]
        nonces=[os.urandom(32),os.urandom(32)]
        legs=[]; effects=[]; funding=[]; headers=[]; pubs=[]
        for i,home in enumerate(homes):
            h,source=self.sources(ins[i]);headers.append(h)
            funding.append([hit[0] for hit in self.hits("leg",home,ins[i],f"leg{i}_funding")])
            qty=[7,30][i]; fee=[3,0][i]
            cmd=b"P"+nonces[i]+bytes([fee])+h+struct.pack("<QQ",0,qty)+ids[i]+addresses[1-i]+source
            _,(pk,leg)=self.wallet("leg",home,"restore",[b"E"+nonces[i],cmd],f"leg{i}_prove")
            require(leg[:5]==b"K3L1\x01","leg wallet proof")
            fx=self.check("leg",leg,f"leg{i}_verify")
            require(fx[-32:]==pk and int.from_bytes(fx[165:173],"little")==fee,"leg authority and fee")
            legs.append(leg);effects.append(fx);pubs.append(pk)
        for i,fx in enumerate(effects):
            rows=[(0,fx[101+32*j:133+32*j]+fx[173+1792*j:173+1792*(j+1)]) for j in (0,1)]
            received=self.hits("leg",homes[1-i],[rows[0]],f"counterparty{i}")[0]
            change=self.hits("leg",homes[i],[rows[1]],f"change{i}")[0]
            require(received[1:]==(0,[7,30][i],ids[i],2) and change[1:]==([17,18][i],[8,50][i],ids[i],3),
                    "authorized economics and spendable receipts")
        terms=sha256(b"K384/private-terms/v1\0"+os.urandom(32)+b"".join(addresses+ids)+struct.pack("<QQ",7,30)).digest()
        joint=statement(self.network,terms,4,0,legs)
        sigs=[self.wallet("leg",homes[i],"restore",[b"S"+nonces[i]+joint],f"sign{i}")[1][0] for i in (0,1)]
        swap=bundle(self.network,terms,4,0,legs,sigs)
        checked,signatures,digest_,payer=decode(swap)
        with self.role("leg",["verify","/keys"],"complete_swap_verify") as r:
            for _ in range(3):
                seen=[]; keys=[]
                for i,leg in enumerate(checked):
                    fx=r.call(leg)
                    require(fx[:1]==b"1" and fx==effects[i] and int.from_bytes(fx[165:173],"little")==(3 if i==payer else 0)
                            and r.call(b"V"+fx[-32:]+digest_+signatures[i])==b"1","both proofs and authorizations")
                    seen.extend((fx[37:69],fx[69:101]))
                    keys.append(fx[-32:])
                require(len(set(seen))==4 and len(set(keys))==2,"distinct funding/keys")
        all_outputs=[self.settle(effects[i],headers[i],funding[i]) for i in (0,1)]
        (self.out/"swap.bin").write_bytes(swap)
        # Open receipts using new processes and backups saved before funding. No signing nonce or old state is needed.
        restored_holders=[ar,br]
        for i,restored in enumerate(restored_holders):
            h=self.hits("old",restored,[all_outputs[1-i][0]],f"restored_incoming{i}")[0]
            require(h[1:4]==(0,[30,7][i],ids[1-i]),"restored swap receipt")
        packet,forwarded=self.ordinary("ordinary",ar,addrs[forward],[all_outputs[1][0],fee_notes[0]],
                                          0,30,ids[1],0,"ordinary")
        (self.out/"ordinary.bin").write_bytes(b"K3P1\x01\x00"+packet)
        spend,_=self.ordinary("old",br,addrs[forward],[all_outputs[0][0],fee_notes[1]],0,7,ids[0],0,"fixed_respend")
        # Consume the new managed output after the fresh candidate 30-unit transfer under the original verifier.
        managed_row=find(forward,forwarded,0,30,ids[1],"forward_managed")
        onward,_=self.ordinary("old",forward,addrs[fi],[managed_row,reward(forward,3)],0,30,ids[1],0,"managed_respend")
        with self.role("ordinary",["verify","/keys"],"negative_ordinary") as r:
            size=int.from_bytes(packet[5:9],"little")
            start_pi=9+size-31*8
            require(int.from_bytes(packet[start_pi+21*8:start_pi+22*8],"little")==3,"known fee field")
            changed=bytearray(packet)
            changed[start_pi+21*8:start_pi+22*8]=struct.pack("<Q",2)
            require(r.call(changed)==b"0","changed public monetary statement")
            changed=bytearray(packet);changed[9]^=1
            require(r.call(changed)==b"0","changed proof")
        with self.role("leg",["verify","/keys"],"negative_signatures") as r:
            require(all(r.call(b"V"+pubs[i]+sha256(joint).digest()+sigs[i])==b"0" for i in (0,1)),"altered joint")
            changed=bytearray(legs[0]);changed[-1]^=1
            require(r.call(changed)==b"0","receipt tamper")
        with self.role("old",["verify","/keys"],"negative_profile") as r:
            require(r.call(b"MNG1"+packet[4:])==b"0","old verifier accepted candidate")
        return {"ordinary_B":len(packet)+6, "ordinary_inner_B":len(packet),"ordinary_proof_B":len(packet)-3593,
                "inputs_ordinary_and_both_legs":[2,1,1],"fixed_supply":70,"managed_supply":330,
                "isolated_registry_issuer_signed_register_and_mint":True,"backup_to_forward_fixed":7,
                "backup_to_forward_managed":30,"old_managed_onward_B":len(onward),
                "changed_public_fee_rejected":True,"corrupt_ordinary_proof_rejected":True,"legs_B":list(map(len,legs)),"swap_B":len(swap),
                "swap_physical_frame_B":[len(x)+17195 for x in legs],"live_bound_B":262144,
                "backup_respend_MNG1_B":len(spend),"four_receipts_checked_before_signatures":True,
                "both_altered_authorizations_rejected":True,"tampered_receipt_rejected":True,
                "old_verifier_rejected_retagged_candidate":True}


def run(build,baseline,out):
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    t=Trial(build,baseline,out)
    with tempfile.TemporaryDirectory(dir="/dev/shm") as tmp:
        with t.role("old",["hash"],"public_merkle") as h:
            t.hash=h
            result=t.run(Path(tmp))
    result["meters"]=t.meters
    result["binary_sha256"]=t.identity
    result["packets_sha256"]={name:sha256((out/name).read_bytes()).hexdigest() for name in ("ordinary.bin","swap.bin")}
    (out/"RESULT.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("build","baseline_mng1","new_public"):
        p.add_argument(arg,type=Path)
    a=p.parse_args()
    run(a.build.resolve(),a.baseline_mng1.resolve(),a.new_public.resolve())
