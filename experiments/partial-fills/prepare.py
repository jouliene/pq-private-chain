"""Replay the published funded profile-C chain, then create and fund five fresh independent wallets."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HISTORIC_TIP = "000003b3161779eafe382ebf82daa4a23769d92dfcb3c104d646313f52320f16"
ROLES = ("seller","buyer-one","buyer-two","full-seller","full-buyer")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def cli(home, node, action, *args):
    result = subprocess.run([ROOT/"pqd","upgrade","--home",home,"--node",node,"--suite","C",
                             action,*map(str,args)],capture_output=True,text=True,timeout=300)
    if result.returncode:
        raise ValueError(f"profile-C wallet {action} failed: "+result.stderr[-1200:])
    return json.loads(result.stdout)


def load_lab(home):
    sys.path.insert(0,str(home/"deployment/devnet"))
    from cli import Lab
    return Lab(home,home/"deployment/runtime")


def agree(lab, tip, nodes="abc"):
    from cli import wait
    return wait(lambda:[lab.status(n)["tip"] for n in nodes],lambda tips:all(t==tip for t in tips),
                "profile C peers select the expected branch",seconds=180)


def fund(home, public):
    os.umask(0o077)
    lab=load_lab(home)
    from chain import GENESIS, block_id, decode_block
    from cli import Lab
    try:
        lab.start(manual=True)
        # Use only the historical public bodies. Validators execute each original block.
        blocks=[]
        tip=bytes.fromhex(HISTORIC_TIP)
        while tip!=GENESIS:
            raw=(public/"blocks"/(tip.hex()+".bin")).read_bytes()
            need(block_id(raw)==tip,"historical block ID mismatch")
            blocks.append(raw)
            tip=decode_block(raw).parent
        for raw in reversed(blocks):
            lab.request("a","publish",raw)
        agree(lab,HISTORIC_TIP)
        need(lab.status("a")["fees"]==51 and len(blocks)==33,"historical fee/height mismatch")
        for role in ROLES:
            base=home/"participants"/role
            base.mkdir(mode=0o700,parents=True)
            shutil.copytree(home/"deployment",base/"deployment")
            (base/"network.json").write_text(json.dumps(lab.cfg))
            wallet=Lab(base,base/"deployment/runtime")
            wallet.new_wallet(role)
            wallet.export_address(role,base/"address.pub")

        # Fresh mining rewards pay every setup fee. Grants use normal profile C issuance and transfer.
        funded=lab.mine("a",4,pay_to="miner-a")
        agree(lab,funded["tip"])
        def confirm(action,*arguments,label):
            result=cli(home,"a",action,"miner-a",*arguments,"--intent","partial-"+label)
            mined=lab.mine("a",1,pay_to="miner-a")
            raw=lab.request("a","block",id=mined["tip"])[1]
            block=decode_block(raw)
            need(len(block.packets)==1 and sha256(block.packets[0]).hexdigest()==result["tx"]
                 and block.amount==103 and block.packets[0].startswith(b"MSP3"),"fresh C funding/fee mismatch")
            return result
        a=confirm("issue",200,label="issue-a")["asset_id"]
        b=confirm("issue",20,label="issue-b")["asset_id"]
        need(a!=b,"distinct assets required")
        for role,asset,qty,cash in (("seller",a,90,0),("seller",a,10,0),("full-seller",a,90,0),
                                   ("full-seller",a,10,0),("buyer-one",b,5,3),
                                   ("buyer-two",b,5,3),("full-buyer",b,10,3)):
            destination="@"+str(home/"participants"/role/"address.pub")
            confirm("send",destination,cash,asset,qty,label=f"{role}-{qty}")
        state=lab.status("a")
        agree(lab,state["tip"])
        for role in ROLES:
            balance=cli(home/"participants"/role,"c","balance",role)
            expected={a:100} if "seller" in role else {b:10 if role=="full-buyer" else 5}
            need(balance["assets"]==expected and balance["balance"]==(0 if "seller" in role else 3)
                 and balance["notes"]==(2 if "seller" in role else 1),"independent opening inventory")
        need(state["fees"]==51+9*3,"incorrect funding fee total")
        data=dict(asset_a=a,asset_b=b,setup_fees=27,tip=state["tip"],height=state["height"],fees=state["fees"],
                  historical_tip=HISTORIC_TIP,historical_fees=51,starting_funds_verified=True)
        (home/"funding.json").write_text(json.dumps(data,indent=2)+"\n")
        print(json.dumps(dict(funded=True,height=state["height"],setup_fees=27)),flush=True)
    finally:
        lab.stop()


if __name__=="__main__":
    fund(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
