"""Reverify a wallet walkthrough's public PoW blocks, singleton attempts and final selected effects."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from chain import Chain, block_id, decode_block
from runtime import config
from run import Resources


def check(capture,runtime):
    evidence=json.loads((capture/"WALLET.json").read_bytes())
    bank={p.stem:p.read_bytes() for p in (capture/"blocks").glob("*.bin")}
    if not bank or any(block_id(raw).hex()!=i for i,raw in bank.items()):
        raise ValueError("public block identity")
    ordered=sorted(bank,key=lambda i:(decode_block(bank[i]).height,i))
    live=evidence["live_intent"]
    recipient=evidence["offline_recipient"]
    res=Resources(config(runtime))
    try:
        with tempfile.TemporaryDirectory() as tmp:
            db=Chain(Path(tmp)/"verify.sqlite",res.backend)
            try:
                for i in ordered:
                    db.accept(bank[i])
                state=db.status()
                if state["tip"]!=evidence["final_tip"] or state["height"]!=evidence["final_height"]:
                    raise ValueError("replayed greatest-work tip differs")
                selected=[]
                for start in range(1,state["height"]+1,100):
                    selected.extend(db.selected(start,100))
                if selected!=evidence["selected_chain"]:
                    raise ValueError("replayed selected chain differs")
            finally:
                db.close()
        common=None
        for tx in live["attempts"]:
            raw=(capture/"attempts"/(tx+".bin")).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=tx:
                raise ValueError("attempt identity")
            [slot]=res.backend.verify(raw)
            common=set(slot.nfs) if common is None else common.intersection(slot.nfs)
        occurrences=[]
        recipient_heights=[]
        for i in selected:
            b=decode_block(bank[i])
            for raw in b.packets:
                tx=hashlib.sha256(raw).hexdigest()
                if tx in live["attempts"]:
                    occurrences.append(tx)
                if tx==recipient["spend_tx"]:
                    recipient_heights.append(b.height)
        if len(live["attempts"])<2 or not common or occurrences!=[live["confirmed"]] or len(recipient_heights)!=1:
            raise ValueError("attempt exclusivity or canonical recipient spend")
        return dict(tip=state["tip"],height=state["height"],issued=state["issued"],fees=state["fees"],
            archive_blocks=len(bank),public_valid_attempts=len(live["attempts"]),
            shared_nullifiers=len(common),canonical_intent_payments=1,
            recipient_spend_height=recipient_heights[0],recipient_spend_successors=state["height"]-recipient_heights[0])
    finally:
        res.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence",type=Path)
    p.add_argument("runtime",type=Path)
    a=p.parse_args()
    print(json.dumps(check(a.evidence,a.runtime),indent=2,sort_keys=True))
