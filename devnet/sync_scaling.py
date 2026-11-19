"""Matched small/large wallet scaling measurements on separately selected manual-mining branches."""

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE/"wallet-review"))
from chain import block_id, decode_block
from history import BLOCK_BYTES, SLOT_BYTES
from wire_meter import summary


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def measured(meter, action):
    with meter.lock:
        start = len(meter.rows)
    value = action()
    with meter.lock:
        rows = list(meter.rows[start:])
    require(all(r["response_ok"] and not r["dropped_reply"] for r in rows),"unexpected scaling transport failure")
    return value,summary(rows)


def full_reference(client, node, wallet, height):
    """Read the retained full public view from the same metered node; compare openings only inside this client."""
    started = time.monotonic()
    st,view = client.snapshot(node)
    require(st["height"] == height,"fixed legacy reference height")
    with client.wallet(wallet) as legacy:
        account = legacy.scan(*view)
        baseline = sorted((n["commitment"],n["amount"],n["source"],n["spent"]) for n in legacy.history)
    file = (client.walletdir(wallet)/"wallet-state.sqlite").resolve(strict=True)
    db = sqlite3.connect(file.as_uri()+"?mode=ro",uri=True)
    try:
        db.execute("BEGIN")
        tip, totals = db.execute("SELECT id,balance FROM heads ORDER BY h DESC LIMIT 1").fetchone()
        local = sorted((r[0].hex(),r[1],r[2],r[3] is not None) for r in
                       db.execute("SELECT cm,amount,kind,spent FROM owned"))
        require(tip.hex() == st["tip"] and account == json.loads(totals) and local == baseline,
                "full scan differs from incrementally recovered notes, spentness or balance")
    finally:
        db.close()
    strides = (132,32,104,1824,32)
    kinds = ("header","leaves","rewards","receipts","nullifiers")
    sizes = {k:len(blob) for k,blob in zip(kinds,view,strict=True)}
    records = {k:len(blob)//stride for k,blob,stride in zip(kinds,view,strides,strict=True)}
    own,children = (resource.getrusage(k) for k in (resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN))
    return dict(height=height,tip=st["tip"],balance=account["balance"],matching_all_owned_rows=True,
                full_wallet_input_B=sum(sizes.values()),stream_bytes=sizes,stream_records=records,
                native_wallet=legacy.metrics,wall_s=time.monotonic()-started,
                controller_cpu_s=own.ru_utime+own.ru_stime,controller_peak_rss_kib=own.ru_maxrss,
                child_cpu_s=children.ru_utime+children.ru_stime,child_peak_rss_kib=children.ru_maxrss)


def legacy_measure(client, meter, node, name, height):
    command = [sys.executable,"-I","-B",str(Path(__file__).resolve()),"--legacy",
               "--home",str(client.home),"--runtime",str(client.runtime),"--node",node,
               "--wallet",name,"--height",str(height)]
    ref,wire = measured(meter,lambda:json.loads(subprocess.check_output(command,timeout=180)))
    require(set(wire["operations"]) == {"status","page"} and wire["operations"]["status"] == 1,
            "legacy measurement must use full snapshot endpoints")
    expected = ref["full_wallet_input_B"]-ref["stream_bytes"]["header"]
    require(wire["observed"]["reply_payload_B"] == expected,"legacy full page bytes")
    ref["wire"] = wire
    return ref


def archive(lab, node, last):
    """Capture unfiltered complete public blocks outside measurement windows."""
    folder = lab.home/"evidence"/"blocks"
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    order,sizes,widths,txs = [],[],[],[]
    while len(order) < last:
        ids,_ = lab.request(node,"selected",start=len(order)+1,limit=min(128,last-len(order)))
        require(ids, "short selected history while archiving")
        for ident in ids:
            raw = lab.request(node,"block",id=ident)[1]
            b = decode_block(raw)
            require(block_id(raw).hex() == ident and b.height == len(order)+1
                    and (not order or b.parent.hex()==order[-1]), "captured block identity/ancestry")
            file = folder/(ident+".bin")
            if file.exists():
                require(file.read_bytes() == raw,"existing public capture changed")
            else:
                with file.open("xb") as out:
                    out.write(raw)
            order.append(ident)
            sizes.append(len(raw))
            widths.append(len(b.packets))
            txs.append([hashlib.sha256(p).hexdigest() for p in b.packets])
    return dict(order=order,sizes=sizes,widths=widths,packet_ids=txs,complete_block_B=sum(sizes))


def scale_branch(lab, client, meter, node, base_height, name, seed, recipient_file, run_cli):
    """Perform one comparison arm. The caller owns the fixed starting branch and the offline recipient."""
    require(not (client.walletdir(name)/"wallet-state.sqlite").exists(),"scaling requires a cold wallet")
    status = lab.status(node)
    require(status["height"] == base_height and not status["mempool"],"fixed starting height and empty pool")
    require(Path(seed).is_file(),"missing restore seed")
    target = str(recipient_file)
    if not target.startswith("@"):
        target = "@"+str(Path(recipient_file).resolve())
    observed = {}

    def wallet_step(label, arguments, blocks, slots, height, balance=None):
        pair,wire = measured(meter,lambda:run_cli(client,*arguments))
        value,cost = pair
        reads = wire["server_reported"]
        actual = wire["observed"]
        syncs = value.get("syncs") or [value["sync"]]
        allowed = {"history_head","history_range","history_check"}
        if label == "send":
            allowed.add("submit")
        require(set(wire["operations"]).issubset(allowed),"wallet disclosed a non-common history query")
        require(wire["operations"].get("submit",0) == int(label == "send"),"unexpected submission count")
        require(actual.get("blocks",0) == reads["payload_rows"] == reads["blocks"] == blocks,
                "wallet reread beyond its expected suffix")
        require(actual.get("transactions",0) == reads["transactions"] == slots
                and reads["receipts"] == reads["nullifiers"] == 2*slots and reads["rewards"] == blocks,
                "served record cardinalities")
        require(reads["payload_B"] == blocks*BLOCK_BYTES+slots*SLOT_BYTES
                and actual.get("history_payload_B",0) == reads["payload_B"]+9*wire["operations"].get("history_range",0),
                "archive payload or wire framing mismatch")
        if not blocks:
            require("history_range" not in wire["operations"] and reads["payload_queries"] == 0,
                    "unchanged wallet performed a history read")
        if blocks == 1:
            require(wire["operations"]["history_range"] == reads["payload_queries"] == 1, "suffix fetched more than once")
        reported = Counter()
        for sync in syncs:
            reported.update(sync["node_reads"])
        require(dict(reported) == reads and sum(s["blocks"] for s in syncs) == blocks
                and sum(s["public_body_B"] for s in syncs) == actual.get("history_payload_B",0),
                "client/relay/node measurements diverged")
        if balance is not None:
            require(value["height"] == height and value["balance"] == balance, "selected balance")
        result = dict(height=height,wire=wire,cli_resources=cost,native_wallet=value["wallet_metrics"],sync=syncs)
        if balance is not None:
            result.update(balance=balance,tip=value["tip"])
        observed[label] = result
        return value

    initial = archive(lab,node,base_height)
    cold_slots = sum(initial["widths"])
    wallet_step("cold",("restore",name,str(seed),"--node",node),base_height,cold_slots,base_height,100)
    wallet_step("unchanged",("balance",name,"--node",node),0,0,base_height,100)
    legacy_base = legacy_measure(client,meter,node,name,base_height)

    def mine_empty(h):
        state = lab.mine(node,1,"neutral")
        require(state["height"] == h and not state["mempool"],"unexpected manual block or pending payment")
        raw = lab.request(node,"block",id=state["tip"])[1]
        b = decode_block(raw)
        require(b.height == h and not b.packets and b.amount == 100 and b.pk == lab.address("neutral")[1:33],
                "expected one neutral-beneficiary empty block")
        return state

    mine_empty(base_height+1)
    wallet_step("append",("balance",name,"--node",node),1,0,base_height+1,100)
    mine_empty(base_height+2)
    payment = wallet_step("send",("send",name,target,"17","--intent","scale-"+name,"--wait","0","--node",node),
                          1,0,base_height+2)
    require(payment["status"] == "submitted" and payment["anchor_height"] == base_height+2
            and payment["amount"] == 17 and payment["fee"] == 3 and payment["change"] == 80
            and payment["input_total"] == 100 and payment["real_inputs"] == 1,
            "unexpected amount, input value, fee or anchor")
    require(observed["send"]["wire"]["observed"]["request_payload_B"] == payment["packet_B"],
            "payment wire byte count")
    state = lab.mine(node,1,"neutral")
    require(state["height"] == base_height+3 and not state["mempool"],"final single payment")
    confirmed = wallet_step("confirmed",("balance",name,"--node",node),1,1,base_height+3,80)
    require(confirmed["change_notes"] == 1 and confirmed["reward_notes"] == 0,
            "change not received or spent coinbase still spendable")
    legacy_final = legacy_measure(client,meter,node,name,base_height+3)
    complete = archive(lab,node,base_height+3)
    require(complete["order"][:base_height] == initial["order"] and complete["widths"][-3:] == [0,0,1]
            and complete["packet_ids"][-1] == [payment["tx"]] and complete["order"][-1] == confirmed["tip"],
            "scaled payment not uniquely included in captured block")
    public_payment = {k:payment[k] for k in ("tx","packet_B","amount","fee","change","anchor_height","proving_wall_s","status")}
    return dict(name=name,node=node,base_height=base_height,tx=payment["tx"],**observed,payment=public_payment,
                legacy=dict(base=legacy_base,final=legacy_final),archive=complete)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy",action="store_true",required=True)
    parser.add_argument("--home",required=True,type=Path)
    parser.add_argument("--runtime",required=True,type=Path)
    parser.add_argument("--node",required=True)
    parser.add_argument("--wallet",required=True)
    parser.add_argument("--height",required=True,type=int)
    a = parser.parse_args()
    from cli import Lab
    print(json.dumps(full_reference(Lab(a.home,a.runtime),a.node,a.wallet,a.height),sort_keys=True))
