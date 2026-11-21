"""Run funded A/B to C payments, issuer operations and a signed swap on real competing PoW branches."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIELDS = ("tip","height","work","anchor","header","issued","fees","notes","spent","spent_set_sha256")
ACCOUNTS = ("miner-a","miner-b","alice","bob","conflict","forward","offline","recipient")
METERS = ("packet_B","real_inputs","fee","asset_id","operation","anchor_height","change","token_change",
          "proving_wall_s","prover_cpu_s","prover_role_peak_rss_KiB","submission_frame")


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def save(path, data):
    tmp = path.with_suffix(".new")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n")
    tmp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("home",type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    home = args.home.resolve(strict=True)
    config = json.loads((home/"public/SCENARIO.json").read_bytes())
    need(config["tips"]["initial"]["height"] == 24 and config["tips"]["initial"]["notes"] == 44, "wrong funding anchor")
    sys.path.insert(0, str(home/"deployment/devnet"))
    from chain import GENESIS, block_id, decode_block
    from cli import Lab, wait
    from managed_inventory import inventory
    from swap_wire import split

    lab = Lab(home, home/"deployment/runtime")
    public = home/"public/membership"
    public.mkdir(mode=0o700)
    for name in ("blocks","packets","controls"):
        (public/name).mkdir()
    private = home/"membership-negotiation"
    private.mkdir(mode=0o700)
    report = dict(tips={},operations={},registries={},balances={},asset_ids=dict(config["asset_ids"]),
                  controls={},recovery={},genesis=GENESIS.hex())
    fixed, managed = (report["asset_ids"][k] for k in ("fixed","managed"))
    def checkpoint():
        save(home/"membership-progress.json", report)

    def wallet(node, action, *arguments):
        command = [ROOT/"pqd","upgrade","--home",home,"--node",node,"--suite","C",action,*map(str,arguments)]
        return json.loads(subprocess.check_output(command,timeout=360))

    def state(node):
        data = lab.status(node)
        return {k:data[k] for k in FIELDS}

    def links(nodes):
        for node in nodes:
            lab.links(node,[n for n in nodes if n != node])

    def agree(nodes):
        return wait(lambda:[state(n) for n in nodes],lambda rows:all(r == rows[0] for r in rows),
                    "independent funded C selection " + nodes)[0]

    def retain(node, tip):
        while tip != GENESIS.hex():
            dest = public/"blocks"/(tip+".bin")
            if dest.exists():
                break
            raw = lab.request(node,"block",id=tip)[1]
            need(block_id(raw).hex() == tip, "wrong block identity")
            dest.write_bytes(raw)
            block = decode_block(raw)
            for packet in block.packets:
                (public/"packets"/(sha256(packet).hexdigest()+".bin")).write_bytes(packet)
            tip = block.parent.hex()

    def snap(label, node, *, payer="c-payer", recipient=None):
        st = state(node)
        retain(node, st["tip"])
        report["tips"][label] = st
        registry = inventory(lab,node,st["tip"])
        report["registries"][label] = registry
        rows = {}
        for name in ACCOUNTS:
            alias = payer if name == "offline" else recipient if name == "recipient" else name
            if alias is None:
                # No receipt exists before its payment; this explicitly
                # disclosed zero is reconciled by total supply, without
                # starting the fresh receiver before the backup restoration.
                rows[name] = dict(native=0,assets={})
            else:
                row = wallet(node,"balance",alias)
                rows[name] = dict(native=row["balance"],assets=row["assets"])
        need(sum(r["native"] for r in rows.values()) == st["issued"], "native holdings differ at "+label)
        for aid, entry in registry.items():
            need(sum(v["assets"].get(aid,0) for v in rows.values()) == entry["supply"],
                 "token holdings differ at "+label)
        report["balances"][label] = rows
        checkpoint()
        return st

    def admitted(node, tx, action):
        raw = lab.request(node,"tx",id=tx)[1]
        need(raw.startswith(b"MSP3") and sha256(raw).hexdigest()==tx, "wrong admitted C "+action)
        return raw

    def mine(label,node,raw,meter,*,miner="miner-a",swap=False):
        tip = lab.mine(node,1,pay_to=miner)["tip"]
        full = lab.request(node,"block",id=tip)[1]
        block = decode_block(full)
        frames = tuple(split(raw)) if swap else (raw,)
        need(block.packets == frames and block.amount == 103, "incorrect confirmed packet or fee at "+label)
        txs = [sha256(f).hexdigest() for f in frames]
        events = lab.request(node,"supply-observation",txs=txs)[0]["events"]
        report["operations"][label] = dict(meter,tx=sha256(raw).hexdigest(),block=tip,height=block.height,
                                           fee=3,packet_B=len(raw),frame_B=list(map(len,frames)),
                                           frames=txs,nfs=[nf for e in events for nf in e["nfs"]])
        retain(node,tip)
        checkpoint()
        return events

    def prepare(label,node,action,*arguments):
        start = time.monotonic()
        row = wallet(node,action,*arguments,"--intent","membership-"+label)
        raw = admitted(node,row["tx"],action)
        return raw, dict({k:row[k] for k in METERS if k in row},wallet_command_s=time.monotonic()-start)

    def pay(label,node,action,*arguments,miner="miner-a"):
        raw, meter = prepare(label,node,action,*arguments)
        mine(label,node,raw,meter,miner=miner)
        return raw

    def reject(label,node,op,raw,expected):
        st, pool = state(node), lab.request(node,"pending")[0]
        try:
            lab.request(node,op,raw)
        except ValueError as exc:
            reason = str(exc)
            need(reason == expected, "unexpected refusal at " + label + ": " + reason)
        else:
            raise ValueError("unexpected admission: "+label)
        need(state(node)==st and lab.request(node,"pending")[0]==pool, "rejection changed state")
        report["controls"][label] = dict(reason=reason,tip=st["tip"],unchanged=True)

    def exchange(node):
        keyfile = {name:"@"+str(private/(name+".addr")) for name in ("alice","bob")}
        for name in keyfile:
            lab.export_address(name,private/(name+".addr"))
        terms = private/"c.terms"
        expiry=state(node)["height"]+8
        wallet(node,"terms","alice",keyfile["bob"],fixed,2,managed,3,expiry,terms)
        offers = [private/"alice.leg",private/"bob.leg"]
        approvals = [private/"alice.sig",private/"bob.sig"]
        legs = []
        for i,(owner,other,give,take,fee) in enumerate((("alice","bob",(fixed,2),(managed,3),3),
                                                      ("bob","alice",(managed,3),(fixed,2),0))):
            start=time.monotonic()
            row=wallet(node,"leg",owner,"ab"[i],terms,*give,*take,offers[i],
                       "--counterparty",keyfile[other],"--expiry",expiry,"--fee",fee)
            legs.append(dict({k:row[k] for k in METERS if k in row},wallet_command_s=time.monotonic()-start))
        for i,owner in enumerate(("alice","bob")):
            start=time.monotonic()
            wallet(node,"authorize",owner,"ab"[i],terms,*offers,approvals[i])
            legs[i].update(authorization_s=time.monotonic()-start,authorization_file_B=approvals[i].stat().st_size,
                           offer_file_B=offers[i].stat().st_size)
        wallet(node,"combine",terms,*offers,*approvals,public/"SWAP.bin")
        raw = (public/"SWAP.bin").read_bytes()
        need(raw.startswith(b"SWB3") and all(f.startswith(b"SWF3") for f in split(raw)),"signed C swap profile")
        meter={}
        reply,_ = lab.request(node,"submit",raw,meter=meter)
        need(reply["id"]==sha256(raw).hexdigest(),"C swap admission")
        mine("swap",node,raw,dict(legs=legs,submission_frame=meter,terms_B=terms.stat().st_size,
                                 negotiation_B=sum(p.stat().st_size for p in (terms,*offers,*approvals))),swap=True)

    # Isolated original B node reconstructs its own H24 selected chain and
    # recovers only the original payer backup. Its H25 block is a retirement
    # control and belongs outside the set of valid A/B/C blocks.
    previous = json.loads(subprocess.check_output([sys.executable,"-IB",HERE/"scenario_b.py",home,
                          home/"membership-legacy",public/"controls"],timeout=540))
    report["controls"]["legacy_B"] = previous
    checkpoint()
    try:
        lab.start(manual=True)
        for node in "abc":
            lab.links(node,[])
        need(agree("abc")["tip"] == config["tips"]["initial"]["tip"], "C opening H24")
        backup=home/"owner-backups/offline"
        for alias, node in (("c-payer","a"),("c-alternate","c")):
            row=wallet(node,"restore",alias,backup)
            need((row["balance"],row["assets"],row["notes"])==(34,{managed:28},2),"A+B backup holdings")
        lab.new_wallet("c-receiver")
        recv_backup=private/"receiver.backup"
        lab.backup("c-receiver",recv_backup)
        receiver_file=private/"receiver.addr"
        lab.export_address("c-receiver",receiver_file)
        snap("prefix","a")
        reject("retired_B_at_H25","a","submit",(public/"controls/legacy-b.bin").read_bytes(),"inactive proof suite")
        reject("retired_B_block_at_H25","a","publish",(public/"controls/legacy-b-block.bin").read_bytes(),"inactive proof suite")
        pay("alternate","c","send","c-alternate","forward",27,managed,24,miner="miner-b")
        snap("alternate","c",payer="c-alternate")
        pay("paid","a","send","c-payer","@"+str(receiver_file),28,managed,25)
        events=[report["operations"][key] for key in ("alternate","paid")]
        need(all(e["real_inputs"]==2 and set(e["nfs"])==set(previous["nfs"]) for e in events),"B/C one-spend IDs")
        need(len({previous["tx"],*(e["tx"] for e in events)})==3,"independent funded payments")
        need(set(p.name for p in lab.walletdir("c-receiver").iterdir())=={"address","seed"}
             and not lab.walletdir("c-recovered").exists(),"receiving wallet was previously synchronized")
        recovered=wallet("a","restore","c-recovered",recv_backup)
        need((recovered["balance"],recovered["assets"],recovered["notes"])==(28,{managed:25},1)
             and recovered["sync"]["start_height"]==0 and recovered["sync"]["complete"],"C output recovery")
        report["recovery"]=dict(native=28,assets={managed:25},notes=1,backup_B=recv_backup.stat().st_size,
                                sync={k:recovered["sync"][k] for k in ("start_height","end_height","blocks",
                                  "request_B","reply_B","public_body_B","wall_s")})
        snap("paid","a",recipient="c-recovered")
        pay("onward","a","send","c-recovered","forward",20,managed,16)
        links("abc")
        agree("abc")
        snap("onward","c",recipient="c-recovered")
        need(report["balances"]["onward"]["recipient"]==dict(native=5,assets={managed:9}),"restored onward change")
        alternate_tx=report["operations"]["alternate"]["tx"]
        reject("orphan_double_spend","c","submit",(public/"packets"/(alternate_tx+".bin")).read_bytes(),"spent nullifier")
        exchange("a")
        agree("abc")
        snap("swap","a",recipient="c-recovered")
        for label,action,arguments in (("mint","mint",("miner-b","forward",managed,6)),
                                       ("fixed","issue",("miner-a",13)),("register","register",("miner-a",15))):
            pay(label,"a",action,*arguments)
            agree("abc")
            snap(label,"a",recipient="c-recovered")
        need(state("a")["notes"]==64 and state("a")["height"]==30,"H30 occupied depth boundary")
        for node in "abc":
            lab.links(node,[])
        raw,meter=prepare("burn","b","burn","forward",managed,16,report["operations"]["onward"]["tx"])
        need(meter["anchor_height"]==30,"burn was not anchored at 64 notes")
        crossed=lab.mine("a",1,pay_to="miner-a")
        tip=crossed["tip"]
        retain("a",tip)
        need(crossed["height"]==31 and crossed["notes"]==65 and not decode_block(lab.request("a","block",id=tip)[1]).packets,
             "isolated H31 was not an empty depth-crossing block")
        snap("crossed","a",recipient="c-recovered")
        need(lab.request("a","submit",raw)[0]["id"]==sha256(raw).hexdigest(),"old d3 anchor at d4")
        mine("burn","a",raw,meter)
        snap("burn","a",recipient="c-recovered")
        pay("final","a","send","c-recovered","forward",1,managed,1)
        links("abc")
        agree("abc")
        final=snap("final","c",recipient="c-recovered")
        need((final["height"],final["issued"],final["fees"])==(33,3300,51),"final PoW economics")
        rows=report["balances"]["final"]
        for owner,n,assets in (("offline",3,{managed:3}),("recipient",1,{managed:8}),("forward",18,{managed:14}),
                               ("alice",34,{fixed:21,managed:12}),("bob",24,{fixed:9,managed:38}),
                               ("miner-b",842,{managed:22}),("conflict",20,{})):
            need(rows[owner]==dict(native=n,assets=assets),"final disclosed wallet "+owner)
        registry=report["registries"]["final"]
        new_fixed=report["operations"]["fixed"]["asset_id"]
        new_managed=report["operations"]["register"]["asset_id"]
        need(rows["miner-a"]==dict(native=2358,assets={fixed:50,new_fixed:13,new_managed:15}),"final miner-a")
        need(registry[managed]["supply"]==97 and registry[fixed]["supply"]==80 and
             registry[managed]["authority"]==report["registries"]["prefix"][managed]["authority"],
             "historical managed authority or supply changed")
        report["asset_ids"].update(new_fixed=new_fixed,new_managed=new_managed)
        save(public/"RUN.json",report)
        print(json.dumps(dict(final=final["tip"],height=final["height"],fees=final["fees"])))
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
