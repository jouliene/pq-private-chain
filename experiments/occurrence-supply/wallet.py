"""Check one offline profile-C receipt and its real onward spend. Export aggregate observations only."""
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EXPS = HERE.parent


def run(out):
    home = out / "network"
    deployment = home / "deployment"
    # Load the shipped modules first, as the node's own entry point does.
    sys.path.insert(0, str(deployment/"devnet"))
    from chain import GENESIS, block_id, decode_block
    from wallet_sync import path_rows
    sys.path.insert(0, str(EXPS/"partial-fills"))
    from prepare import agree, cli, load_lab, need
    sys.path.insert(0, str(EXPS/"funded-supply"))
    from openings import check_store, parse_blocks, read_block, WireReader, NETWORK
    from audit import opened, public_inputs, public_proof, Tree, path_root
    from reference import parent

    lab = load_lab(home)
    backup, addr = out/"offline.backup", out/"offline.addr"
    offline = out/"disconnected"
    # This command uses the wallet creation role without any node socket or network configuration.
    init = subprocess.run([sys.executable,"-IB",EXPS/"snapshot-bootstrap/wallet.py",deployment,offline,"init",
                           "--backup",backup,"--address",addr], check=True,capture_output=True,text=True)
    need(json.loads(init.stdout)["offline"] and backup.stat().st_size == 32, "cold address generation")
    source_dir = offline/"wallets/recovered"
    need({p.name for p in source_dir.iterdir()} == {"seed","address"}, "offline wallet was scanned")
    graph = parse_blocks(out/"history/public/blocks") | parse_blocks(out/"fixed/suffix")
    pinned = json.loads((EXPS/"supply-refinement/fixed.json").read_bytes())

    def mine():
        tip = lab.mine("a",1,pay_to="miner-a")["tip"]
        agree(lab,tip)
        raw = lab.request("c","block",id=tip)[1]
        bid = bytes.fromhex(tip)
        parsed = decode_block(raw)
        need(block_id(raw) == bid, "selected mined block")
        graph[bid] = read_block(raw,bid,NETWORK,WireReader())
        return parsed

    def confirm(wallet_home, op, owner, *args, label):
        tx = cli(wallet_home,"c",op,owner,*args,"--intent",label)
        block = mine()
        packet, = block.packets
        need(packet.startswith(b"MSP3\x01") and sha256(packet).hexdigest()==tx["tx"] and
             block.amount==103, "registered C packet and credited fee")
        return tx,packet,block

    try:
        lab.start(manual=True)
        target = bytes.fromhex(pinned["tip"])
        chain = []
        while target != GENESIS:
            name = target.hex()+".bin"
            path = out/"fixed/suffix"/name
            raw = (path if path.exists() else out/"history/public/blocks"/name).read_bytes()
            need(block_id(raw)==target,"released public ancestry")
            chain.append(raw)
            target=decode_block(raw).parent
        for raw in reversed(chain):
            lab.request("a","publish",raw)
        agree(lab,pinned["tip"])
        need(len(chain)==42 and lab.status("c")["fees"]==69,"verified inherited prefix")
        lab.new_wallet("payee")
        lab.export_address("payee",out/"payee.addr")
        lab.backup("payee",out/"payee.backup")
        for _ in range(3):
            mine()
        issue,_,_ = confirm(home,"issue","miner-a",40,label="issue")
        asset = issue["asset_id"]
        _, receipt_packet, _ = confirm(home,"send","miner-a","@"+str(addr),9,asset,19,label="offline-receipt")
        need({p.name for p in source_dir.iterdir()}=={"seed","address"}, "receiving role accessed chain before restore")

        # Fresh CLI process and fresh home. Only public software, RPC locations and the 32-byte seed enter.
        restored = out/"restored"
        restored.mkdir(mode=0o700)
        shutil.copytree(deployment, restored/"deployment")
        (restored/"network.json").write_bytes((home/"network.json").read_bytes())
        need(not (restored/"wallets").exists(), "restore requires an empty wallet store")
        balance = cli(restored,"c","restore","owner",backup)
        need(balance["sync"]["complete"] and balance["sync"]["start_height"]==0 and balance["notes"]==1
             and (balance["balance"],balance["assets"])==(9,{asset:19}),"seed-only confirmed receipt")
        dbfile = home/"nodes/c/chain.sqlite"
        with closing(sqlite3.connect(dbfile.resolve().as_uri()+"?mode=ro",uri=True)) as db:
            before = {r[0] for r in db.execute("SELECT nf FROM spent")}
        wallet_db = restored/"wallets/owner/mng1-wallet-state.sqlite"
        with closing(sqlite3.connect(wallet_db.resolve().as_uri()+"?mode=ro",uri=True)) as db:
            wallet_cm, wallet_path = only(db.execute("SELECT cm,path FROM owned WHERE spent IS NULL AND token>0"))
        sent, packet, block = confirm(restored,"send","owner","@"+str(out/"payee.addr"),4,asset,7,label="onward")
        need(sent["real_inputs"]==1, "one actual input")
        _, pi = public_inputs(packet)
        need(packet.startswith(b"MSP3\x01\x00") and pi[208:248]==bytes(40), "ordinary spend")
        public_proof(packet,pi)
        nfs = (pi[40:72],pi[72:104])
        need(len(set(nfs))==2 and not before.intersection(nfs), "two distinct fresh public marks")
        with closing(sqlite3.connect(dbfile.resolve().as_uri()+"?mode=ro",uri=True)) as db:
            anchor_height = int.from_bytes(pi[32:40],"little")
            ap,header,count = db.execute("SELECT ap,header,n FROM sel JOIN blocks USING(id) WHERE sel.h=?",
                                          (anchor_height,)).fetchone()
            need(1<=block.height-anchor_height<=8 and pi[:32]==ap and len(header)==132 and
                 int.from_bytes(header[32:36],"little")==anchor_height,"selected header")
            leaves = [r[0] for r in db.execute("SELECT cm FROM outs WHERE h<=? ORDER BY pos",(anchor_height,))]
            tree = Tree(leaves)
            need(tree.count==count and tree.root==header[-32:] and
                 len(tree.path(0))==int.from_bytes(pi[-8:],"little"), "independent funded root and depth")
            receipts = list(db.execute("SELECT pos,cm,ct FROM outs WHERE ct IS NOT NULL AND h<=? ORDER BY pos",
                                       (anchor_height,)))
            origins = opened(deployment,backup,receipts)
            matches = [(cm,v) for cm,v in origins.items() if v[1] in nfs]
            cm, (pos,_,cash,aid,qty,kind) = only(matches)
            # Reconstruct the actual private ordered vectors as the released wallet does.
            # Only the private example consumed by the Lean checker receives the leaf or path.
            current = wallet_cm
            quads = []
            for siblings in path_rows(wallet_path):
                quad = sorted([current,*siblings])
                quads.append([int.from_bytes(v,"little") for v in quad])
                current = parent(quad)
            need(wallet_cm==cm and current==tree.root, "restored wallet path vs selected root")
            anchor_case = dict(leaves=[int.from_bytes(v,"little") for v in leaves],
                               count=count, depth=int.from_bytes(pi[-8:],"little"),
                               root=int.from_bytes(current,"little"), leaf=int.from_bytes(cm,"little"), quads=quads,
                               parentHash=int.from_bytes(header[:32],"little"),
                               stateHash=int.from_bytes(header[36:68],"little"),
                               extrinsicsHash=int.from_bytes(header[68:100],"little"),
                               anchor=int.from_bytes(pi[:32],"little"), anchorHeight=anchor_height,
                               spendHeight=block.height)
            (out/"anchor.private.json").write_text(json.dumps(anchor_case))
            _, source_pi = public_inputs(receipt_packet)
            need(cm in (source_pi[104:136],source_pi[136:168]) and (cash,aid.hex(),qty,kind)==(9,asset,19,"incoming")
                 and leaves.count(cm)==1 and leaves[pos]==cm and path_root(cm,tree.path(pos),count)==tree.root,
                 "exact historical receipt and unique eligible occurrence")
            after = {r[0] for r in db.execute("SELECT nf FROM spent")}
            need(after==before.union(nfs), "real and dummy inserted as public marks")
            rows = list(db.execute("SELECT pos,cm,ct FROM outs WHERE h=? AND ct IS NOT NULL ORDER BY pos",(block.height,)))
            need([v[1] for v in rows]==[pi[104:136],pi[136:168]],"selected onward outputs")
            change = only(opened(deployment,backup,rows).values())
            received = only(opened(deployment,out/"payee.backup",rows).values())
            need((change[2],change[3].hex(),change[4],change[5])==(2,asset,12,"change") and
                 (received[2],received[3].hex(),received[4],received[5])==(4,asset,7,"incoming"),
                 "reopened confirmed onward outputs")
            supply, = db.execute("SELECT supply FROM assets WHERE id=? ORDER BY sequence DESC LIMIT 1",
                                 (bytes.fromhex(asset),)).fetchone()
        quantities = [cli(location,"c","balance",owner)["assets"].get(asset,0)
                      for location,owner in ((home,"miner-a"),(restored,"owner"),(home,"payee"))]
        need(quantities==[21,12,7] and sum(quantities)==supply==40,"fresh asset inventory")
        stores = [check_store(home/"nodes"/node/"chain.sqlite",graph) for node in "abc"]
        need(all(v==stores[0] for v in stores) and stores[0]["fees"]==78,"three selected ledgers")
        result = dict(inherited_blocks=len(chain), offline_restore_seed_bytes=backup.stat().st_size,
                      recovered_notes=balance["notes"], recovered_native=cash, recovered_tokens=qty,
                      real_inputs=1, public_marks=2, unique_eligible_occurrence=True,
                      native_paid=received[2], native_change=change[2], fee=sent["fee"],
                      token_paid=received[4],token_change=change[4],registry_supply=supply,
                      total_opened_holdings=sum(quantities),selected_nodes=len(stores),
                      selected_height=stores[0]["height"],cumulative_fees=stores[0]["fees"])
        need(result["fee"]==3,"confirmed sender fee")
        (out/"wallet-result.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result),flush=True)
    finally:
        lab.stop()


def only(xs):
    item, = xs
    return item


if __name__=="__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve())
