"""Replay archived supply events, then test the missing ceiling, zero and branch transition on funded C."""
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from openings import (BURN, NETWORK, TIP, WireReader, chain_to, check_store, historical, open_inventory,
                      parse_blocks, read_block, reconcile, require, selected_ledger)
sys.path.insert(0, str(HERE.parent/"partial-fills"))
from prepare import agree, cli, load_lab

MAX = BURN-1


def replay_history(lab, graph, bodies, archive_run):
    historical_chain = chain_to(graph,bytes.fromhex(TIP))
    alternate = bytes.fromhex(archive_run["tips"]["alternate"]["tip"])
    require(graph[alternate].parent == historical_chain[23].id and graph[alternate].height == 25,
            "released competing H25 branch")
    for b in historical_chain:
        if b.height == 25:
            lab.request("a","publish",bodies[alternate])
            agree(lab,alternate.hex())
        lab.request("a","publish",bodies[b.id])
    agree(lab,TIP)


def run(out):
    home, public = out/"network", out/"history/public"
    lab = load_lab(home)
    from chain import decode_block
    from managed_inventory import inventory
    historical_public = historical(public)
    original = json.loads((HERE/"original.json").read_bytes())
    archive_run = json.loads((public/"RUN.json").read_bytes())
    require(all(original[k]==v for k,v in historical_public.items()), "original public disclosure differs from replay")
    graph = parse_blocks(public/"blocks")
    reader = WireReader()
    bodies = {b:(public/"blocks"/(b.hex()+".bin")).read_bytes() for b in graph}
    database = lambda node: home/"nodes"/node/"chain.sqlite"

    def capture(node, tip):
        bid = bytes.fromhex(tip)
        while bid not in graph:
            raw = lab.request(node, "block", id=bid.hex())[1]
            block = read_block(raw, bid, NETWORK, reader)
            graph[bid], bodies[bid] = block, raw
            bid = block.parent

    def mine(node, count, peers):
        tip = lab.mine(node, count, pay_to="miner-"+node)["tip"]
        agree(lab,tip,peers)
        capture(node,tip)
        return tip

    def confirm(operation, owner, *args, stage, peers):
        receipt = cli(home,"a",operation,owner,*args,"--intent",stage)
        tip = mine("a",1,peers)
        packet, = decode_block(bodies[bytes.fromhex(tip)]).packets
        require(sha256(packet).hexdigest()==receipt["tx"] and packet.startswith(b"MSP3"),"confirmed C operation")
        return tip,receipt["tx"]

    def node_view(node):
        state = lab.status(node)
        reg = inventory(lab,node,state["tip"])
        return (state["tip"], state["spent_set_sha256"], state["fees"], reg, lab.request(node,"pending")[0])

    def rejected(node, packet, message):
        before=node_view(node)
        try:
            lab.request(node,"submit",packet)
        except ValueError as exc:
            require(str(exc)==message, "unexpected admission rejection: "+str(exc))
        else:
            raise ValueError("ineligible mint was accepted")
        require(node_view(node)==before, "rejection changed node ledger or pool")

    try:
        lab.start(manual=True)
        replay_history(lab,graph,bodies,archive_run)
        base_registry = inventory(lab,"c",TIP)
        require({a:r["supply"] for a,r in base_registry.items()}==original["registry"],"funded base replay")
        lab.new_wallet("holder")
        lab.backup("holder",out/"holder.backup")
        lab.backup("miner-a",out/"issuer.backup")
        mine("a",4,"abc")

        reg_tip, register = confirm("register","miner-a",MAX,stage="register-limit",peers="abc")
        minted = inventory(lab,"c",reg_tip)
        asset, = minted.keys()-base_registry.keys()
        policy = minted[asset]
        require(policy["supply"]==MAX and policy["mode"]=="managed" and policy["sequence"]==1,
                "initial ceiling registration")
        parent, transfer = confirm("send","miner-a","holder",3,asset,MAX,stage="pay-holder",peers="abc")
        # A properly signed mint with otherwise eligible funding reaches the registry cap check.
        before = node_view("a")
        try:
            cli(home,"a","mint","miner-a","holder",asset,1,"--intent","over-limit")
        except ValueError as exc:
            require("outstanding supply overflow" in str(exc), "expected cap failure: "+str(exc))
        else:
            raise ValueError("mint at the ceiling was accepted")
        require(node_view("a")==before, "first cap rejection changed node ledger or mempool")
        with closing(sqlite3.connect((home/"wallets/miner-a/mng1-intents.sqlite").as_uri()+"?mode=ro",uri=True)) as db:
            attempt, = db.execute("SELECT packet FROM attempts WHERE intent='over-limit'").fetchall()
        (over_limit,) = attempt
        rejected("a",over_limit,"outstanding supply overflow")
        for n,peers in (("a",[]),("b",["c"]),("c",["b"])):
            lab.links(n,peers)

        zero_tip, burn = confirm("burn","holder",asset,MAX,transfer,stage="full-burn",peers="a")
        zero = inventory(lab,"a",zero_tip)[asset]
        require(zero["sequence"]==2 and zero["supply"]==0 and zero["authority"]==policy["authority"] and
                zero["tx"]==burn, "full burn must retain the managed row")
        require(cli(home,"a","balance","holder")["assets"].get(asset,0)==0, "burned holder balance")
        rejected("a",over_limit,"stale issuer state")
        old_tip, remint = confirm("mint","miner-a","holder",asset,1,stage="mint-after-zero",peers="a")
        again = inventory(lab,"a",old_tip)[asset]
        require(again["supply"]==1 and again["sequence"]==3 and again["authority"]==policy["authority"] and
                again["tx"]==remint, "mint after zero")
        old_view=check_store(database("a"),graph)
        require(cli(home,"a","balance","holder")["assets"]=={asset:1}, "holder on losing branch")
        require(lab.status("b")["tip"]==parent and lab.request("b","pending")[0]==[], "isolated fork parent")
        new_tip=mine("b",3,"bc")
        # Retransmit only public original bodies. Node A evaluates work and performs the reorg itself.
        lab.links("a",["b","c"])
        lab.links("b",["a","c"])
        lab.links("c",["a","b"])
        agree(lab,new_tip)
        restored=inventory(lab,"a",new_tip)
        require(restored==minted and restored[asset]==policy,"rollback of both ledger revisions")
        require(cli(home,"a","balance","holder")["assets"]=={asset:MAX},"restored holder funds")
        winning=chain_to(graph,bytes.fromhex(new_tip))
        require(not database("d").exists(),"reference must start empty")
        lab.launch("d",False)
        for b in winning:
            lab.request("d","publish",bodies[b.id])
        agree(lab,new_tip,"abcd")
        winner_view=check_store(database("a"),graph)
        require(winner_view==check_store(database("d"),graph) and
                inventory(lab,"d",new_tip)==restored,"reorg vs independent verifying node from genesis")

        # Every encrypted output after H33 in these two suffixes belongs to this new two-wallet roster.
        suffix = {bid:b for bid,b in graph.items() if b.height>33}
        notes = open_inventory(home/"deployment",suffix.values(),[out/"issuer.backup",out/"holder.backup"])
        snapshots={}
        for label,tip,expected in (("registration",reg_tip,MAX),("pre_burn",parent,MAX),("full_burn",zero_tip,0),
                                   ("remint",old_tip,1),("winning",new_tip,MAX)):
            branch=chain_to(graph,bytes.fromhex(tip))
            events, owned_supply = reconcile([b for b in branch if b.height>33],notes)
            public_regs = selected_ledger(branch).assets
            public_rows = {a.hex():r.public(a) for a,r in public_regs.items()}
            require(owned_supply=={asset:expected} and public_rows.pop(asset)["supply"]==expected and
                    public_rows==base_registry, "new-asset openings or historical registry mismatch")
            snapshots[label]=dict(tip=tip,height=branch[-1].height,opened_face_value=expected,events=events)
        report=dict(historical_public=historical_public,asset=asset,registration=register,holder_transfer=transfer,
                    original_burn=burn,remint=remint,scanned_new_receipt_commitments=len(notes),
                    rejection_checks=["outstanding supply overflow","stale issuer state"],issuance_ceiling=MAX,
                    losing=old_view,winning=winner_view,genesis_validator_agreed=True,stages=snapshots)
        (out/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        print(json.dumps(dict(asset=asset,ceiling=MAX,zero=zero["supply"],remint=again["supply"],
                              reorg_supply=restored[asset]["supply"],tip=new_tip)),flush=True)
    finally:
        lab.stop()


if __name__=="__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve())
