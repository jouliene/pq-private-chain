"""Prove two fresh legs, check reciprocal spend authority and spend a resulting note with MNG1."""
import argparse
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]/"managed-assets/native"))
from check_issuer import invoke
sys.path.insert(0, str(HERE.parent))
from swap_wire import digest

ZERO = bytes(32)


def wallet(build, private, mode, commands):
    return invoke(build/"native", ["wallet", build/"registered", private, mode], commands)


def need(test, label):
    if not test:
        raise ValueError(label)


def check(new, managed):
    def hash_call(cmd):
        return invoke(new/"native", ["hash"], [cmd])[0]

    def verify(build, cmds):
        return invoke(build/"native", ["verify", build/"registered"], cmds)

    def header(cms):
        return ZERO + struct.pack("<I", 1) + ZERO*2 + hash_call(b"R"+b"".join(cms))

    def source(row, siblings):
        return struct.pack("<BHB",1,len(row),1) + row + b"".join(siblings)

    with tempfile.TemporaryDirectory(dir="/dev/shm") as tmp:
        seeds = [Path(tmp)/name for name in ("alice","bob")]
        addresses = [wallet(new, seed, "create", [])[0] for seed in seeds]
        nonces = [os.urandom(32),os.urandom(32)]
        rewards = [os.urandom(32)+addr[1:33]+struct.pack("<QQ",30,0) for addr in addresses]
        cms = [hash_call(b"C"+r) for r in rewards]
        pay = [9,11]
        fees = [3,0]
        public = []
        legs = []
        for i in (0,1):
            req = (b"P"+nonces[i]+bytes([fees[i]])+header(cms)+struct.pack("<QQ",pay[i],0)
                   +ZERO+addresses[1-i]+source(rewards[i]+cms[i], [cms[1-i],ZERO,ZERO]))
            _, pk, leg = wallet(new,seeds[i],"restore",[b"E"+nonces[i],req])
            need(len(pk)==32 and leg[:5]==b"SLG1\x01", "native proof construction")
            public.append(pk)
            legs.append(leg)
        effects = verify(new,legs)
        expected = [(pay[0],30-pay[0]-fees[0]), (pay[1],30-pay[1]-fees[1])]
        all_cms = []
        received = []
        for i, fx in enumerate(effects):
            need(len(fx)==3789 and fx[:1]==b"1" and fx[-32:]==public[i], "public effect key")
            need(int.from_bytes(fx[165:173],"little")==fees[i], "public fee")
            rows = [fx[101+32*j:133+32*j]+fx[173+1792*j:173+1792*(j+1)] for j in range(2)]
            all_cms += [row[:32] for row in rows]
            for j, holder in enumerate([1-i, i]):
                _, hit = wallet(new,seeds[holder],"restore",[b"D"+rows[j]])
                _, old_hit = wallet(managed,seeds[holder],"restore",[b"D"+rows[j]])
                need(hit==old_hit and len(hit)==84 and hit[:3]==b"HIT" and
                     struct.unpack_from("<QQ",hit,35)==(expected[i][j],0) and hit[-1]==2+j,
                     "reciprocal receipt and change")
            received.append(rows[0])
        need(len(set(all_cms))==4 and public[0]!=public[1], "distinct leg commitments and keys")
        # Only the separately tagged versioned roles may parse these complete leg proofs.
        invalid = verify(managed, [legs[0], b"AST1"+legs[0][4:], b"MNG1"+legs[0][4:]])
        need(invalid==[b"0"]*3, "standalone ordinary admission")
        network, terms = os.urandom(32), os.urandom(32)
        binding = digest(network,terms,6,0,legs)
        changed = digest(network,terms,7,0,legs)
        sigs = [wallet(new,seeds[i],"restore",[b"S"+nonces[i]+binding])[1] for i in (0,1)]
        actual = verify(new, [b"V"+pk+binding+sig for pk,sig in zip(public,sigs)]
                            +[b"V"+public[1]+binding+sigs[0], b"V"+public[0]+changed+sigs[0]])
        need(actual==[b"1",b"1",b"0",b"0"], "joint signature verification")
        # This is a standalone funded-root fixture. The network walkthrough supplies actual block inclusion.
        req = (b"K"+header(all_cms)+struct.pack("<QQ",4,0)+ZERO+bytes(8)+addresses[0]+
               source(received[0], all_cms[1:]))
        _, spend = wallet(managed,seeds[1],"restore",[req])
        fx = verify(managed,[spend])[0]
        need(len(fx)==3797 and fx[:1]==b"1" and fx[37:69]==wallet(
             managed, seeds[1], "restore", [b"D"+received[0]])[1][3:35], "ordinary respend nullifier")
    return {"legs":2, "leg_bytes":list(map(len,legs)), "proof_bytes":[len(p)-3593 for p in legs],
            "fees":fees, "reciprocal_receipts_and_change_opened_by_both_profiles":True,
            "ordinary_respend_same_received_nullifier":True, "ordinary_respend_bytes":len(spend),
            "standalone_raw_and_retagged_legs_rejected":True, "two_signatures_verified":True,
            "wrong_key_and_expiry_rejected":True}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("leg_build",type=Path)
    p.add_argument("mng1_build",type=Path)
    args = p.parse_args()
    print(json.dumps(check(args.leg_build.resolve(),args.mng1_build.resolve()),sort_keys=True))
