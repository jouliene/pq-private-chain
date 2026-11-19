"""Observe a published walkthrough's surviving recipient payment and two successors on the original network."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def observe(a):
    sys.path.insert(0,str(a.product/"devnet"))
    from cli import Lab,wait
    from chain import decode_block,block_id
    lab=Lab(a.home,a.runtime)
    capture=a.home/"evidence"
    data=json.loads((capture/"WALLET.json").read_bytes())
    want=data["offline_recipient"]["spend_tx"]
    selected=data["selected_chain"]
    where=[]
    def occurrences(raw):
        return sum(hashlib.sha256(p).hexdigest()==want for p in decode_block(raw).packets)
    for h,bid in enumerate(selected,1):
        raw=(capture/"blocks"/(bid+".bin")).read_bytes()
        assert block_id(raw).hex()==bid
        where.extend([h]*occurrences(raw))
    assert len(where)==1,"original capture does not contain exactly one recipient spend"
    height=where[0]
    initial=len(selected)-height
    needed=max(0,2-initial)
    a.output.mkdir(parents=True,exist_ok=False)
    try:
        initial_state=lab.start(manual=True)
        assert all(v["tip"]==selected[-1] for v in initial_state.values())
        if needed:
            lab.mine("a",needed,"neutral")
        def statuses():
            return [lab.status(n) for n in "abc"]
        all_nodes=wait(statuses,lambda rows:len({(x["tip"],x["height"]) for x in rows})==1
                       and rows[0]["height"]==len(selected)+needed,"supplemental confirmations",45)
        final=all_nodes[0]
        prior=lab.request("c","selected",start=len(selected),limit=1)[0]
        assert prior==[selected[-1]]
        ids=lab.request("c","selected",start=len(selected)+1,limit=needed)[0] if needed else []
        assert len(ids)==needed
        parent=selected[-1]
        for bid in ids:
            raw=lab.request("c","block",id=bid)[1]
            block=decode_block(raw)
            assert block.parent.hex()==parent and block_id(raw).hex()==bid and occurrences(raw)==0
            (a.output/(bid+".bin")).write_bytes(raw)
            parent=bid
        receiver=Lab(a.home/"receiver",a.runtime)
        # The walkthrough's transparent test relays stopped; connect to the original node's real loopback TCP.
        receiver._cfg=lab.cfg
        balance=receiver.balance("recipient","c")
        assert balance["balance"]==6 and balance["height"]==final["height"] and balance["tip"]==final["tip"]
        return dict(original_height=len(selected),original_successors=initial,added_ordinary_mined_successors=needed,
                    new_public_blocks=ids,
                    final_height=final["height"],final_tip=final["tip"],selected_recipient_payment_occurrences=1,
                    recipient_spend_height=height,observed_successors=final["height"]-height,
                    final_wallet_balance=balance["balance"],peers_in_agreement=len(all_nodes))
    finally:
        lab.stop()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("home","runtime","output"):
        p.add_argument(name,type=lambda x:Path(x).resolve())
    p.add_argument("--product",type=lambda x:Path(x).resolve(),default=Path(__file__).resolve().parents[2])
    a=p.parse_args()
    print(json.dumps(observe(a),indent=2,sort_keys=True))
