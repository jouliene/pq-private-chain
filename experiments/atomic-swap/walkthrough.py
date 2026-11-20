"""Run two private wallets, their ordinary peers and three competing CPU-mined PoW histories."""
import fcntl
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
HOME=Path(sys.argv[1]).resolve()
PUBLIC=HOME/"public"
N=HOME/"negotiation"
BACKUPS=HOME/"owner-backups"
sys.path.insert(0,str(HOME/"deployment/devnet"))
from chain import GENESIS, NETWORK, PROFILE, block_id, decode_block
from cli import Lab, wait
from managed_inventory import inventory
from swap_wire import BUNDLE, assemble, bundle, pair, split

lab=Lab(HOME,HOME/"deployment/runtime")
FIELDS=("tip","height","work","anchor","header","issued","fees","notes","spent","spent_set_sha256")
r=dict(network=NETWORK.hex(),genesis=GENESIS.hex(),managed_vk=PROFILE.hex(),tips={},registries={},balances={},
       ordinary={},checks={},wallets={},controls={},branch_events={})


def expect(condition,msg):
    if not condition:
        raise ValueError(msg)


def cmd(*args,error=None):
    p=subprocess.run([ROOT/"pqd","swap","--home",HOME,*map(str,args)],capture_output=True,text=True,timeout=240)
    if error:
        expect(p.returncode and error in p.stderr,"expected "+error+" from "+str(args[0])+": "+p.stderr[-400:])
        return error
    if p.returncode:
        raise RuntimeError(str(args[0])+" failed: "+p.stderr[-650:])
    return json.loads(p.stdout)


def state(n):
    st=lab.status(n)
    return {k:st[k] for k in FIELDS}


def agree(nodes):
    return wait(lambda:[state(n) for n in nodes],lambda ss:all(s==ss[0] for s in ss),"common mined tip "+nodes)[0]


def retain(n,tip):
    while tip!=GENESIS.hex():
        dest=PUBLIC/"blocks"/(tip+".bin")
        if dest.exists():
            break
        raw=lab.request(n,"block",id=tip)[1]
        expect(block_id(raw).hex()==tip,"changed public block")
        dest.write_bytes(raw)
        b=decode_block(raw)
        for packet in b.packets:
            (PUBLIC/"packets"/(sha256(packet).hexdigest()+".bin")).write_bytes(packet)
        tip=b.parent.hex()


def holdings(owner,n):
    q=cmd("balance",owner,"--node",n)
    return dict(native=q["balance"],assets=q["assets"])


def snapshot(label,n,names=("alice","bob")):
    st=state(n)
    retain(n,st["tip"])
    r["tips"][label]=st
    r["registries"][label]=inventory(lab,n,st["tip"])
    r["balances"][label]={name:holdings(name,n) for name in names}
    return st


def ordinary(label,args,n="a",group="abc"):
    # An ordinary proof is created while the node is live; seal its actual mempool.
    p=cmd(*args,"--node",n,"--intent",label,"--wait",0)
    tx=p["tx"]
    wait(lambda:lab.request(n,"pending")[0],lambda ids:tx in ids,"ordinary offer")
    lab.mine(n,1)
    if len(group)>1:
        agree(group)
    current=state(n)
    block=decode_block(lab.request(n,"block",id=current["tip"])[1])
    expect(tx in [sha256(packet).hexdigest() for packet in block.packets],"ordinary packet missed")
    r["ordinary"][label]={k:p[k] for k in ("tx","asset_id","fee","packet_B","real_inputs","operation")}
    return p


def reject(label,n,raw,reason):
    before=state(n)
    pool=lab.request(n,"pending")[0]
    try:
        lab.request(n,"submit",raw)
    except ValueError as e:
        expect(str(e)==reason,label+" received "+str(e))
    else:
        raise ValueError(label+" unexpectedly admitted")
    expect(before==state(n) and pool==lab.request(n,"pending")[0],label+" mutated state or pool")
    (PUBLIC/"controls"/(label+".bin")).write_bytes(raw)
    r["controls"][label]=dict(reason=reason,tip=before["tip"],fees=before["fees"],spent=before["spent"],unchanged=True,
                              sha256=sha256(raw).hexdigest())


def terms(label,expiry,f,u,qty=30):
    path=N/(label+".terms")
    cmd("terms","alice","@"+str(N/"bob.addr"),f,7,u,qty,expiry,path)
    return path


def leg(label,who,side,file,f,u,qty,expiry):
    other="bob" if side=="a" else "alice"
    give=(f,7,u,qty) if side=="a" else (u,qty,f,7)
    path=N/(label+".leg")
    m=cmd("leg",who,side,file,*give,path,"--counterparty","@"+str(N/(other+".addr")),
          "--fee",3 if side=="a" else 0,"--expiry",expiry)
    return path,m


def capacity_fixture():
    """Prepare three distinct genuine native payments for a separate, non-mined packing test."""
    from managed_wallet import Request
    from wallet_sync import synced_wallet
    folder=PUBLIC/"capacity"
    folder.mkdir()
    req=Request(1,bytes(32),0)
    records=[]
    for miner in ("miner-a","miner-b"):
        with lab.locked_wallet(miner) as directory, lab.wallet(miner) as w:
            with synced_wallet(lab,"c",w,directory) as (state,_):
                rows=state.db.execute("SELECT cm FROM owned WHERE spent IS NULL AND kind='reward' AND amount>=4 ORDER BY pos").fetchall()
                for row in rows[:3-len(records)]:
                    body=state.pay(req,lab.address("forward"),[row["cm"].hex()])
                    fname=str(len(records))+".bin"
                    (folder/fname).write_bytes(body)
                    records.append(dict(file=fname,sha256=sha256(body).hexdigest(),packet_B=len(body)))
        if len(records)==3:
            break
    expect(len(records)==3,"not enough eligible independent mined rewards for capacity fixture")
    return records


def isolate():
    for node in "abc":
        lab.links(node,[])


def link(nodes):
    for n in nodes:
        lab.links(n,[other for other in nodes if other!=n])


def run():
    start=lab.start(manual=True)
    r["miner_keys"]={name:(HOME/"nodes"/n/"miner.pk").read_text().strip() for n,name in (("a","miner-a"),("b","miner-b"),("c","miner-c"))}
    for name in ("alice","bob","forward","rival","burner"):
        cmd("create",name)
    for name in ("alice","bob"):
        cmd("export-address",name,N/(name+".addr"))
        owner_backup=BACKUPS/name
        owner_backup.mkdir(mode=0o700,parents=True)
        cmd("backup",name,owner_backup/"seed")
        expect((owner_backup/"seed").stat().st_size==32,"backup size")
    for n in "ab":
        lab.mine(n,3)
        agree("abc")
    fixed=ordinary("fixed",("issue","miner-a",70))
    f=fixed["asset_id"]
    usd=ordinary("managed",("register","miner-b",300),"b")
    u=usd["asset_id"]
    ordinary("mint",("mint","miner-b","miner-b",u,40),"b")
    burnfund=ordinary("fund-burn",("send","miner-b","burner",3,u,10),"b")
    ordinary("burn",("burn","burner",u,10,burnfund["tx"]))
    ordinary("fixed-funding",("send","miner-a","alice",20,f,15))
    ordinary("usd-funding",("send","miner-b","bob",18,u,80),"b")
    for owner in ("alice","bob"):
        ordinary("fee-"+owner,("send","miner-a",owner,9,"native",0))
    r["asset_ids"]={"fixed":f,"managed":u}
    initial=snapshot("funded","c")
    expect(r["balances"]["funded"]=={"alice":dict(native=29,assets={f:15}),"bob":dict(native=27,assets={u:80})},"funding mismatch")
    expect(r["registries"]["funded"][u]["supply"]==330,"managed historical mint/burn")
    cmd("restore","bob-rival",BACKUPS/"bob"/"seed")
    expiry=initial["height"]+5
    t=terms("accepted",expiry,f,u)
    # Pre-approval abort genuinely releases the real input for the subsequent agreement.
    discarded=terms("withdrawn",expiry,f,u)
    lx,_=leg("withdrawn","alice","a",discarded,f,u,30,expiry)
    r["checks"]["abort"]=cmd("abort","alice","a",discarded)
    a,ma=leg("a","alice","a",t,f,u,30,expiry)
    # Real mining after the first offer while the second wallet builds its proof.
    lab.mining("b",1)
    b,mb=leg("b","bob","b",t,f,u,30,expiry)
    wait(lambda:lab.status("b"),lambda st:st["remaining"]==0,"negotiation block")
    moving=agree("abc")
    expect(moving["height"]>initial["height"],"chain did not advance during negotiation")
    sig_a,sig_b=N/"a.sig",N/"b.sig"
    r["checks"]["aborted_authorization"]=cmd("authorize","alice","a",discarded,lx,b,N/"aborted.sig",
                     error="proposal differs from the locally offered leg or negotiation was aborted")
    # A properly proved wrong delivery can only be detected by the intended receiver.
    short=terms("short-offer",expiry,f,u,29)
    bad,_=leg("short","bob-rival","b",short,f,u,29,expiry)
    r["checks"]["short_delivery"]=cmd("authorize","alice","a",t,a,bad,N/"wrong.sig",error="wallet cannot open")
    expect(not (N/"wrong.sig").exists(),"released authorization for short delivery")
    cmd("abort","bob-rival","b",short)
    sig1=cmd("authorize","alice","a",t,a,b,sig_a)
    r["checks"]["missing_counter_authority"]=cmd("combine",t,a,b,sig_a,sig_a,N/"half.bin",error="proposal lacks")
    r["checks"]["post_release_abort"]=cmd("abort","alice","a",t,error="cannot be revoked")
    sig2=cmd("authorize","bob","b",t,a,b,sig_b)
    expect(sig1["digest"]==sig2["digest"],"owners authorized different terms")
    target=PUBLIC/"SWAP.bin"
    joined=cmd("combine",t,a,b,sig_a,sig_b,target)
    raw=target.read_bytes()
    fs=split(raw)
    left,right=pair(fs)
    r["swap"]=dict(joined,expiry=expiry,payer="a",leg_B=[a.stat().st_size,b.stat().st_size],
                   frame_B=list(map(len,fs)),wallet_A=ma,wallet_B=mb,physical_block_slots=2)
    # All intermediate negotiated files stay in the private home. Retain byte counts, not terms.
    r["negotiation_B"]={s:p.stat().st_size for s,p in dict(terms=t,offer_A=a,offer_B=b,
                                                    auth_A=sig_a,auth_B=sig_b).items()}
    reject("incomplete","c",fs[0],"incomplete atomic swap")
    changed=bytes([left.terms[0]^1])+left.terms[1:]
    forged=assemble(NETWORK,changed,expiry,left.payer,(left.leg,right.leg),(left.signature,right.signature))
    reject("changed-terms","c",forged,"invalid swap authorization")
    snapshot("common","c")
    r["capacity_fixture"]=capacity_fixture()
    isolate()
    # The assembler submits previously released authorizations with both wallet commands exited.
    before=state("a")
    r["swap"]["upload"]=cmd("submit",target,"--node","a")
    from transport import rpc
    advert,fetch={},{}
    ids,_=rpc(lab.cfg["ports"]["a"],"pending",meter=advert)
    expect(ids==[joined["bundle_sha256"]],"incomplete relay inventory")
    _,relayed=rpc(lab.cfg["ports"]["a"],"tx",id=ids[0],meter=fetch)
    expect(relayed==raw,"relay did not return both exact signed legs")
    r["swap"]["relay_readback"]={"public_inventory":advert,"whole_bundle_fetch":fetch}
    expect(cmd("submit",target,"--node","a")["duplicate"],"duplicate bundle queued twice")
    lab.mine("a",1)
    first=snapshot("swap_included","a")
    observations=lab.request("a","supply-observation",txs=joined["frame_ids"])[0]["events"]
    expect(all(e and e["op"]=="swap" and e["quantity"]==0 for e in observations),"history lookup did not identify both swap legs")
    expect(first["fees"]==before["fees"]+3 and first["spent"]==before["spent"]+4,"atomic fee or debits")
    expect(r["balances"]["swap_included"]=={"alice":dict(native=26,assets={f:8,u:30}),
                                             "bob":dict(native=27,assets={u:50,f:7})},"swap recipient or change")
    # The competing standard spend uses the second participant's real input. Their independent
    # seed restore carries no outbox reservations and represents deliberate conflicting authority.
    rival=ordinary("competing-ordinary",("send","bob-rival","rival",0,u,5),"b","b")
    reject("ordinary-conflict","b",raw,"spent nullifier")
    # An independent branch reaches the inclusive deadline with both original inputs still unspent.
    lab.mine("c",expiry-state("c")["height"])
    c=state("c")
    expect(c["spent"]==before["spent"] and c["fees"]==before["fees"],"expiry branch changed inputs")
    reject("expired","c",raw,"swap expired")
    r["checks"]["expired_local_release"]=cmd("abort","bob","b",t,"--release-after-expiry","--node","c")
    snapshot("expiry_branch","c")
    # C first selects A's live swap, then unwinds it in favor of B's heavier conflict.
    lab.mine("a",expiry+1-state("a")["height"])
    link("ac")
    agree("ac")
    snapshot("before_reorg","c")
    isolate()
    lab.mine("b",expiry+3-state("b")["height"])
    link("bc")
    agree("bc")
    loser=snapshot("swap_detached","c",("alice","bob","rival"))
    expect(r["balances"]["swap_detached"]=={"alice":dict(native=29,assets={f:15}),
            "bob":dict(native=24,assets={u:75}),"rival":dict(native=0,assets={u:5})},"partial effects after reorg")
    expect(loser["fees"]==before["fees"]+3 and loser["spent"]==before["spent"]+2,"detachment fee or spent accounting")
    # A kept its independently mined valid payment; all peers now select that longer history.
    lab.mine("a",expiry+5-state("a")["height"])
    link("abc")
    agree("abc")
    snapshot("swap_restored","c",("alice","bob","rival"))
    expect(r["balances"]["swap_restored"]["alice"]==r["balances"]["swap_included"]["alice"] and
           r["balances"]["swap_restored"]["bob"]==r["balances"]["swap_included"]["bob"] and
           r["balances"]["swap_restored"]["rival"]==dict(native=0,assets={}),"winning-branch accounting")
    for name in ("alice","bob"):
        dest=name+"-restored"
        expect(not lab.walletdir(dest).exists(),"warm restore")
        q=cmd("restore",dest,BACKUPS/name/"seed")
        expect(dict(native=q["balance"],assets=q["assets"])==r["balances"]["swap_restored"][name],"cold restore mismatch")
    ordinary("respend-a",("send","alice-restored","forward",0,u,30))
    ordinary("respend-b",("send","bob-restored","forward",0,f,7),"b")
    final=agree("abc")
    expect(not (HOME/"nodes/d/chain.sqlite").exists(),"fourth node already initialized")
    genesis=lab.launch("d")
    expect(genesis["height"]==0 and genesis["tip"]==GENESIS.hex(),"cold node not empty")
    lab.links("d",["c"])
    expect(agree("cd")==final,"fresh replay mismatch")
    names=("miner-a","miner-b","alice-restored","bob-restored","rival","burner","forward")
    snapshot("final","d",names)
    h=r["balances"]["final"]
    expect(h["forward"]["assets"]=={f:7,u:30} and h["alice-restored"]["assets"]=={f:8} and
           h["bob-restored"]["assets"]=={u:50},"subsequent payments or change")
    expect(all(sum(v["assets"].get(aid,0) for v in h.values())==s==r["registries"]["final"][aid]["supply"]
               for aid,s in ((f,70),(u,330))),"independent supply tally")
    expect(sum(v["native"] for v in h.values())==final["issued"] and final["fees"]==before["fees"]+9,"native reconciliation")
    r["fresh_node"]={"initial_height":0,"final_height":final["height"],"winning_tip":final["tip"]}
    r["peer_pids_preserved"]=all(lab.status(n)["pid"]==start[n]["pid"] for n in "abc")
    r["moving"]={"before_first_leg":initial["height"],"after_second_leg":moving["height"],
                 "inclusion_height":first["height"]}
    r["gross_miner_credits"]=final["issued"]+final["fees"]
    (PUBLIC/"RUN.json").write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
    return dict(height=final["height"],fees=final["fees"],swap_fee=3,packet_B=len(raw),public=str(PUBLIC))


if __name__=="__main__":
    with (HOME/".walkthrough.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        expect(not any((HOME/k).exists() for k in ("nodes","network.json","public","negotiation","owner-backups")),"walkthrough needs unused node stores")
        N.mkdir()
        for s in ("blocks","packets","controls"):
            (PUBLIC/s).mkdir(parents=True)
        try:
            print(json.dumps(run(),indent=2))
        finally:
            if (HOME/"network.json").exists():
                lab.stop()
