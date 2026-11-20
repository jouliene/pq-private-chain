"""One owner's funded proving and authorization process. Its mount namespace contains one seed."""
from contextlib import ExitStack,closing
import json
import os
from pathlib import Path
import secrets
from hashlib import sha256
import struct
import sys
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),"/deploy/devnet",str(HERE.parent/"relation")]
from fixtures import (CT,ZERO,Inventory,actor,candidate,commitment,compact,inputs,metered,need,prove_source,
                      selected_blocks,swap_policy,tail_statement)
import chain
import history
import managed_ops
import runtime
swap_wallet=swap_policy()
import swap_wire
from run import Resources
from asset_wallet import AssetWallet


def ordinary_receipt(holder,effect,kind,native,asset,quantity):
    """MNG1 shuffles outputs. Ask the ordinary wallet for the authenticated memo role."""
    wallet=SimpleNamespace(role=holder)
    opened=[AssetWallet.open_row(wallet,cm+ct) for cm,ct in zip(effect.cms,effect.cts,strict=True)]
    mine=[hit for hit in opened if hit is not None]
    need(len(mine)==1 and mine[0][0]!=ZERO and mine[0][1:]==(native,asset,quantity,kind),
         "ordinary receipt ownership, amount, currency or authenticated role differs")


def step(command):
    need(sys.stdin.readline().strip()==command,"unexpected owner session step")


def run(name,suite):
    from wallet_sync import role_sample
    side={"ordinary":0,"leg-a":1,"leg-b":2}[name]
    owner=("miner-a","alice","bob")[side]
    recipient=("alice","bob","alice")[side]
    source,own=Path("/exchange"),Path("/own")
    roster={n:(Path("/peers")/n).read_bytes() for n in ("miner-a","alice","bob")}
    header_info=json.loads((source/"SOURCE.json").read_text())
    common=header_info["common"]
    network=bytes.fromhex(header_info["network"])
    expiry=header_info["expiry"]
    asset=bytes.fromhex(header_info["disposable_fixture_agreement"]["token_asset"])
    terms=commitment(network,asset,expiry,bytes.fromhex(sys.stdin.readline().strip()),roster)
    need(network==chain.NETWORK and expiry==common["height"]+4 and header_info["payer"]==1
         and terms.hex()==header_info["terms"],"wrong private agreement")
    own_seed=Path("/owner/seed")
    config=runtime.config(Path("/deploy/runtime"))
    swap_binary=Path("/deploy/swap-runtime/native")
    swap_keys=Path("/deploy/swap-keys")
    need(sha256(swap_binary.read_bytes()).hexdigest()==Path("/deploy/devnet/approved-swap-native.sha256").read_text().strip(),
         "released swap native identity")
    with ExitStack() as stack:
        roles=stack.enter_context(closing(Resources(config)))
        check=stack.enter_context(swap_wallet.actor("verify"))
        holder,address=stack.enter_context(actor(config.binary,config.keys,own_seed))
        need(address==roster[owner],"seed backup controls a different spending address")
        note=Inventory(roles.h,{owner:holder})
        ledger=stack.enter_context(closing(chain.Chain(Path("/tmp/public.sqlite"),roles.backend)))
        for page in selected_blocks(ledger,Path("/origin"),common):
            for block in history.decode_range(page):
                note.apply(block)
        header=block["header"]
        anchor=roles.h.call(b"H"+header)
        need(block["id"].hex()==common["tip"] and header.hex()==common["header"] and
             anchor.hex()==common["anchor"],"wrong selected branch")
        rows=inputs(note.live[owner],"ordinary" if side==0 else owner,asset)
        paid_native,paid_token,fee=(5,(10 if any(r["token"] for r in rows) else 0),3) if side==0 else (
            (0,20,0) if side==1 else (8,0,3))
        native_change=sum(r["value"] for r in rows)-paid_native-fee
        token_change=sum(r["token"] for r in rows)-paid_token
        nonce=secrets.token_bytes(32)
        data=(b"K" if side==0 else b"P"+nonce+bytes([fee]))+header+struct.pack("<QQ",paid_native,paid_token)+(
              asset if paid_token else ZERO)+(bytes(8) if side==0 else b"")+roster[recipient]+compact(rows)
        verify=lambda p: swap_wallet.verify(check,p) if side else roles.backend.verify(managed_ops.wrap(p,"transfer",network))[0]
        fifo_path=Path("/tmp/assignment")
        os.mkfifo(fifo_path,0o600)
        fifo=os.open(fifo_path,os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
        stack.callback(os.close,fifo)
        with actor(Path("/capture/native"),swap_keys if side else config.keys,own_seed,fifo_path) as (wallet,address):
            need(address==roster[owner],"instrumented role controls a different spending address")
            raw,z,effect,metric=prove_source(name,suite,wallet,data,fifo,rows,own,Path("/constants.rs"),verify,
                                            Path("/matrix")/(suite+".r1cs"))
        change_asset=asset if token_change else ZERO
        if side:
            swap_wallet.opened(holder,effect,1,native_change,change_asset,token_change)
        else:
            ordinary_receipt(holder,effect,"change",native_change,change_asset,token_change)
        need(effect.anchor==anchor and effect.height==common["height"] and effect.fee==fee,"funding anchor or fee")
        pkt,work=candidate(Path("/candidate"),Path("/matrix")/(suite+".r1cs"),suite,own/(name+".statement"),
                           own/(name+".receipts"),own/(name+".candidate"),z)
        del z
        metric.update(candidate=work,candidate_packet_B=len(pkt),candidate_packet_sha256=sha256(pkt).hexdigest(),
                      funded_source_anchor_matches=True,own_change_opened=True,ordinary_token_quantity=paid_token if not side else None)
        (own/"metrics.json").write_text(json.dumps(metric))
        print("prepared",flush=True)
        if not side:
            return
        step("authorize")
        sys.path.insert(0,str(HERE.parent))
        import packet
        released=[(source/(n+".released")).read_bytes() for n in ("leg-a","leg-b")]
        proposed=[(source/(n+".candidate")).read_bytes() for n in ("leg-a","leg-b")]
        need(released[side-1]==raw and proposed[side-1]==pkt,"own offer was substituted")
        effects=[]
        for i,(old,new) in enumerate(zip(released,proposed,strict=True)):
            need(len(new)+packet.HEADER+packet.SIG<=packet.LIMIT,"oversize funded swap authorization frame")
            e=swap_wallet.verify(check,old)
            path=source/(("leg-a","leg-b")[i]+".candidate")
            metered(["/candidate","verify","SLG1","/matrix/SLG1.r1cs",str(path)])
            need(struct.pack("<34Q",*packet.fields(new))==tail_statement(old,"SLG1") and new[-2*CT:]==b"".join(e.cts)
                 and e.anchor==anchor and e.height==common["height"] and e.fee==(0,3)[i],"different final terms or public effects")
            effects.append(e)
        need(len({e.public for e in effects})==2 and len({nf for e in effects for nf in e.nfs})==4 and
             len({cm for e in effects for cm in e.cms})==4,"duplicate key/nullifier/output across final owners")
        need(common["height"]+1<=expiry and all(ledger.db.execute("SELECT 1 FROM spent WHERE nf=?",(nf,)).fetchone() is None
             for effect in effects for nf in effect.nfs),"funding already spent at the selected tip or swap expired")
        incoming=effects[2-side]
        swap_wallet.opened(holder,incoming,0,8 if side==1 else 0,ZERO if side==1 else asset,0 if side==1 else 20)
        swap_wallet.opened(holder,effects[side-1],1,native_change,change_asset,token_change)
        if side==1:
            ordinary=(source/"ordinary.released").read_bytes()
            oe,=roles.backend.verify(managed_ops.wrap(ordinary,"transfer",network))
            metered(["/candidate","verify","MNG1","/matrix/MNG1.r1cs",str(source/"ordinary.candidate")])
            other=(source/"ordinary.candidate").read_bytes()
            qty=header_info.get("profiles",{}).get("ordinary",{}).get("ordinary_token_quantity")
            need(qty in (0,10) and other[9:9+31*8]==tail_statement(ordinary,"MNG1") and
                 other[-2*CT:]==b"".join(oe.cts),"ordinary public statement mismatch")
            ordinary_receipt(holder,oe,"incoming",5,asset if qty else ZERO,qty)
        with actor(swap_binary,swap_keys,own_seed) as (signer,address):
            need(address==roster[owner] and signer.call(b"E"+nonce)==effects[side-1].public,"proof-bound signing authority")
            for kind,legs in (("released",released),("candidate",proposed)):
                digest=swap_wire.digest(network,terms,expiry,1,legs)
                sig=signer.call(b"S"+nonce+digest)
                need(check.call(b"V"+effects[side-1].public+digest+sig)==b"1","own joint authorization signature")
                (own/(kind+".signature")).write_bytes(sig)
        print("signed",flush=True)



def restore():
    """Start from the original backup after every swap authorizing process has exited."""
    source,own=Path("/exchange"),Path("/own")
    recorded=json.loads((source/"SOURCE.json").read_text())
    network=bytes.fromhex(recorded["network"])
    common=recorded["common"]
    need(network==chain.NETWORK,"restore network")
    config=runtime.config(Path("/deploy/runtime"))
    seed=Path("/owner/seed")
    with ExitStack() as stack:
        roles=stack.enter_context(closing(Resources(config)))
        ledger=stack.enter_context(closing(chain.Chain(Path("/tmp/restored.sqlite"),roles.backend)))
        holder,address=stack.enter_context(actor(config.binary,config.keys,seed))
        need(address==Path("/peers/alice").read_bytes(),"recipient backup identity")
        inventory=Inventory(roles.h,{"alice":holder})
        for page in selected_blocks(ledger,Path("/origin"),common):
            for block in history.decode_range(page):
                inventory.apply(block)
        selected=ledger.accept((source/"released-swap.block").read_bytes())
        need(selected["selected"],"restore replay refused settlement")
        tip=ledger.status()["tip"]
        _,page=ledger.history_range(tip,common["height"]+1,common["tip"],1)
        mined,=history.decode_range(page)
        need(page==(source/"onward.history").read_bytes(),"onward projection differs from replay")
        inventory.apply(mined)
        leg=(source/"leg-b.released").read_bytes()
        proposed=(source/"leg-b.candidate").read_bytes()
        verifier=stack.enter_context(swap_wallet.actor("verify"))
        e=swap_wallet.verify(verifier,leg)
        metered(["/candidate","verify","SLG1","/matrix/SLG1.r1cs",str(source/"leg-b.candidate")])
        need(proposed[9:9+34*8]==tail_statement(leg,"SLG1") and proposed[-2*CT:]==b"".join(e.cts),
             "restored leg parity")
        swap_wallet.opened(holder,e,0,8,ZERO,0)
        origin=e.cms[0]+e.cts[0]
        opened=holder.call(b"D"+origin)
        nf=opened[3:35]
        need(nf in inventory.live["alice"] and inventory.live["alice"][nf]["origin"]==origin and
             holder.call(b"D"+e.cms[0]+proposed[-2*CT:-CT])==opened,"different restored spent identity")
        rows=[inventory.live["alice"][nf]]
        request=b"K"+mined["header"]+struct.pack("<QQ",5,0)+ZERO+bytes(8)+Path("/peers/bob").read_bytes()+compact(rows)
        fifo_path=Path("/tmp/channel")
        os.mkfifo(fifo_path,0o600)
        fifo=os.open(fifo_path,os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
        stack.callback(os.close,fifo)
        verify=lambda raw:roles.backend.verify(managed_ops.wrap(raw,"transfer",network))[0]
        with actor(Path("/capture/native"),config.keys,seed,fifo_path) as (worker,restored_address):
            need(restored_address==address,"capture restore identity")
            raw,z,slot,metric=prove_source("onward","MNG1",worker,request,fifo,rows,own,Path("/constants.rs"),verify,
                                         Path("/matrix/MNG1.r1cs"))
        need(slot.nfs[0]==nf and slot.fee==3 and slot.height==mined["height"],"restored ordinary spend effects")
        proposed,work=candidate(Path("/candidate"),Path("/matrix/MNG1.r1cs"),"MNG1",own/"onward.statement",
                                own/"onward.receipts",own/"onward.candidate",z)
        normal=managed_ops.wrap(raw,"transfer",network)
        need(ledger.offer(normal)["id"]==sha256(normal).hexdigest(),"fresh restored ledger refused onward spend")
        metric.update(candidate=work,candidate_packet_B=len(proposed),candidate_packet_sha256=sha256(proposed).hexdigest(),
                      original_and_candidate_same_recovered_nullifier=True)
        (own/"metrics.json").write_text(json.dumps(metric))
        (own/"restored-onward.transfer").write_bytes(normal)
        print("restored",flush=True)


if __name__=="__main__":
    if sys.argv[1]=="restore-a":
        restore()
    else:
        run(*sys.argv[1:])
