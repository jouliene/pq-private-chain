"""Test correctly sealed invalid genesis-child rewards on an isolated empty chain using fixed public inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from network_oracle import GENESIS,NETWORK,ZERO,counted_hash,decode,reference,sha,u32,u64
sys.path.insert(0,str(HERE.parent))
from chain import Chain
sys.path.insert(0,str(HERE.parents[1]/"experiments/advancing-payments"))
from run import Resources


def seal(template):
    base=b"PQDEV1/work\0"+sha(b"PQDEV1/template\0"+template)
    target=(1<<234).to_bytes(32,"big")
    for n in range(1<<64):
        encoded=u64(n)
        if sha(base+encoded)<target:
            return template+encoded
    raise ValueError("nonce space exhausted")


def material(first,reference_exe,reward_exe):
    valid=decode(first)
    assert valid["parent"]==GENESIS and valid["h"]==1 and valid["reward"]==100 and not valid["packets"]
    prefix=first[:109]
    owner=valid["miner"]
    prior=counted_hash(b"dev-genesis-state",NETWORK)
    context=valid["reward_body"][:32]
    # Two independent assertions are tested, the scheduled amount and the value secured inside the funded note.
    denominations=[100,101]
    words=reference(reward_exe,[],b"".join(context+owner+u64(x) for x in denominations))
    commitments={v:bytes.fromhex(w) for v,w in zip(denominations,words,strict=True)}
    assert commitments[100]==valid["cm"] and commitments[100]!=commitments[101]
    cases={}
    for label,claim,funded,issued in [
            ("excess-subsidy",101,101,101),("wrong-note-denomination",100,101,100),("incorrect-tree",100,100,100)]:
        cm=commitments[funded]
        record=context+owner+u64(claim)+cm
        state=counted_hash(b"dev-state",NETWORK,prior,u64(1),u64(issued),u64(0),record,b"")
        root=bytes.fromhex(reference(reference_exe,["1"],cm)[0].split()[2])
        if label=="incorrect-tree":
            root=ZERO
        template=prefix+u64(claim)+cm+state+root+b"\0"
        assert template!=first[:-8]
        cases[label]=seal(template)
    return cases


def fingerprint(c):
    h=hashlib.sha256()
    for table,key in [("config","id"),("metrics","id"),("blocks","id"),("sel","h"),("outs","pos"),("spent","nf"),("pool","seq"),("txloc","tx,bid")]:
        for row in c.execute(f"SELECT * FROM {table} ORDER BY {key}"):
            for v in row:
                data=v if isinstance(v,bytes) else str(v).encode()
                h.update(type(v).__name__.encode()+u64(len(data))+data)
    return h.hexdigest()


def check(a):
    first=a.valid_first.read_bytes()
    a.bank.mkdir(mode=0o700,parents=True,exist_ok=True)
    names=("excess-subsidy","wrong-note-denomination","incorrect-tree")
    if a.mine:
        if any(a.bank.iterdir()):
            raise ValueError("new empty economic control bank required")
        for name,body in material(first,a.reference,a.reward).items():
            (a.bank/(name+".bin")).write_bytes(body)
    assert {p.name for p in a.bank.iterdir()}=={name+".bin" for name in names}
    resources=Resources(a)
    try:
        with tempfile.TemporaryDirectory() as t:
            ledger=Chain(Path(t)/"temporary.sqlite",resources.backend)
            try:
                before=ledger.status()
                whole=fingerprint(ledger.db)
                observed={}
                for name in names:
                    b=(a.bank/(name+".bin")).read_bytes()
                    decoded=decode(b)
                    assert decoded["parent"]==GENESIS and decoded["h"]==1
                    try:
                        ledger.accept(b)
                    except ValueError as err:
                        assert str(err)=="invalid reward or state commitment"
                    else:
                        raise AssertionError("incorrect reward accepted")
                    assert ledger.status()==before and fingerprint(ledger.db)==whole
                    observed[name]=dict(id=decoded["id"].hex(),bytes=len(b),claimed=decoded["reward"],
                                        file_sha256=sha(b).hex(),work_threshold_passed=True,unchanged_all_tables=True)
                ledger.accept(first)
                actual=ledger.status()
                assert actual["issued"]==100 and actual["fees"]==0 and actual["notes"]==1
                return dict(cases=observed,valid_positive_tip=actual["tip"],valid_first_sha256=sha(first).hex(),
                            valid_positive_issuance=actual["issued"])
            finally:
                ledger.close()
    finally:
        resources.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ["valid-first","reference","reward","bank","binary","keys"]:
        p.add_argument("--"+name,required=True,type=lambda x:Path(x).resolve())
    for name in ["profile-sha","binary-sha"]:
        p.add_argument("--"+name,required=True)
    p.add_argument("--mine",action="store_true",help="generate exactly three devnet-only invalid conformance fixtures")
    print(json.dumps(check(p.parse_args()),indent=2,sort_keys=True))
