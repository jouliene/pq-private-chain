"""Check same-tip TCP reannouncement of an eligible payment known only in a losing block."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from cli import Lab,wait
sys.path.insert(0,str(HERE))
from network_oracle import decode,examine
from peer_view import check_peer


def run(args):
    observed=json.loads((args.evidence/"RESULT.json").read_bytes())
    def captured(h):
        ident=observed["winning"][h-1]
        raw=(args.evidence/"blocks"/(ident+".bin")).read_bytes()
        assert decode(raw)["id"].hex()==ident
        return raw
    prefix=[captured(1),captured(2)]
    losing=captured(3)
    pay,=decode(losing)["packets"]
    txid=hashlib.sha256(pay).hexdigest()
    assert txid==observed["payments"]["lone"]["tx"]
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="pqdev-side-reannounce-") as tmp:
        demo=Lab(tmp,args.runtime)
        try:
            demo.initialize()
            for n in "ab":
                (demo.home/"nodes"/n/"peers.json").write_text("[]\n")
                demo.launch(n)
                for raw in prefix:
                    demo.request(n,"publish",raw)
            demo.mine("a",2)
            candidate_ids=demo.request("a","selected",start=3,limit=2)[0]
            alternative=[demo.request("a","block",id=i)[1] for i in candidate_ids]
            assert len(alternative)==2 and all(not decode(b)["packets"] for b in alternative)
            for b in alternative:
                demo.request("b","publish",b)
            assert demo.status("a")["tip"]==demo.status("b")["tip"]==candidate_ids[-1]
            disposition=demo.request("a","publish",losing)[0]
            assert not disposition["changed"] and not disposition["selected"]
            assert demo.request("a","block",id=decode(losing)["id"].hex())[1]==losing
            assert not demo.request("a","pending")[0]
            try:demo.request("a","tx",id=txid)
            except ValueError as e:assert str(e)=="unknown transaction"
            else:raise AssertionError("side-only payment masqueraded as selected/pending")
            demo.request("b","submit",pay)
            assert demo.request("b","pending")[0]==[txid] and not demo.request("a","pending")[0]
            demo.links("a",["b"])
            wait(lambda:demo.request("a","pending")[0],lambda v:v==[txid],"legitimate side-only reannouncement")
            assert demo.request("a","tx",id=txid)[1]==pay
            demo.mine("a",1)
            confirmed=demo.status("a")
            block=demo.request("a","block",id=confirmed["tip"])[1]
            assert decode(block)["packets"]==[pay] and confirmed["fees"]==3 and confirmed["spent"]==2
            audit=examine(prefix+alternative+[block],args.reference,args.reward)
            assert audit["tip"]==confirmed["tip"] and audit["payments"]==1
            assert check_peer(demo.cfg["ports"]["a"],args.reference,args.reward)["selected"]["tip"]==audit["tip"]
            return dict(accepted_payment=txid,archived_losing=decode(losing)["id"].hex(),common_height=2,
                        preannounce_selected_tip=candidate_ids[-1],selected_height=5,received_from_other_peer=True,
                        included_tip=audit["tip"],fees=audit["fees"],total_issuance=audit["issued"],
                        registered_nullifier_slots=audit["spent"],repeated_economic_effects=0)
        finally:demo.stop()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ["evidence","runtime","reference","reward"]:
        p.add_argument("--"+name,type=lambda x:Path(x).resolve(),required=True)
    print(json.dumps(run(p.parse_args()),indent=2,sort_keys=True))
