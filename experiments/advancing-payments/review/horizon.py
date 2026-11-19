"""Exercise an advancing and then shortened empty public chain with authentic upstream hashes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent))
from public_chain import check, reference
from state import Ledger,PublicBackend


class ReferenceHashes:
    def __init__(self, exe):
        self.exe = exe

    def call(self, frame):
        if frame[:1] == b"H":
            return bytes.fromhex(reference(self.exe,["--header-ids"],frame[1:])[0].split()[1])
        assert frame[:1] == b"N" and len(frame)==129
        return bytes.fromhex(reference(self.exe,["4"],frame[1:])[0].split()[2])


def attempt(fn):
    try:
        fn()
    except ValueError as err:
        return str(err)
    return "accepted"


def test(exe):
    # All bytes are public; empty blocks do not invoke a payment verifier.
    genesis = b"APGEN001"+struct.pack("<I8Q",2,*range(1,9))
    approved = hashlib.sha256(genesis).hexdigest()
    profile = "11"*32
    backend = PublicBackend(ReferenceHashes(exe),None,profile)
    result = {}
    with tempfile.TemporaryDirectory() as root:
        for name,pruned in [("archive",False),("pruned",True)]:
            path = Path(root)/name
            ledger = Ledger(path,backend,genesis,approved,True,pruned)
            try:
                blocks = [ledger.produce(b"",i) for i in range(12)]
                original = check(genesis,approved,profile,blocks,exe,path)
                ids = dict(ledger.db.execute("SELECT h,id FROM blocks"))
                a = attempt(lambda:ledger.switch(ids[4],[]))
                assert a=="accepted" and ledger.head()["id"]==ids[4]
            finally:
                ledger.close()
            # The monotonic undo floor must survive an actual close and reopen.
            ledger = Ledger(path,backend,genesis,approved,False,pruned)
            try:
                b = attempt(lambda:ledger.switch(ids[1],[]))
                assert b=="rollback horizon" and ledger.head()["id"]==ids[4]
                ledger.switch(ids[4],blocks[4:])
                rebuilt = check(genesis,approved,profile,blocks,exe,path)
                assert original == rebuilt
                c = attempt(lambda:ledger.switch(ids[3],[]))
                assert c=="rollback horizon"
                result[name] = dict(twelve_to_four=a,four_to_one_after_restart=b,
                                    replayed_height=rebuilt["blocks"],twelve_to_three=c,
                                    restored_tip=rebuilt["head_id"])
            finally:
                ledger.close()
            # Canonical-only late join has not observed the abandoned height 12.
            late = Ledger(Path(root)/(name+"_canonical_prefix"),backend,genesis,approved,True,pruned)
            try:
                for raw in blocks[:4]:
                    late.accept(raw)
                assert late.head()["id"]==ids[4]
                floor = late.db.execute("SELECT floor FROM config").fetchone()[0]
                assert floor==0
                later = attempt(lambda:late.switch(ids[1],[]))
                assert later=="accepted" and late.head()["id"]==ids[1]
                result[name]["canonical_only_height_four_floor"] = floor
                result[name]["same_tip_canonical_only_four_to_one"] = later
            finally:
                late.close()
    assert result["archive"] == result["pruned"]
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("reference",type=Path)
    print(json.dumps(test(p.parse_args().reference.resolve()),indent=2,sort_keys=True))
