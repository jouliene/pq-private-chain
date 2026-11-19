"""Decode complete selected-branch blocks independently; use the registered node separately for proof verification."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

AP_REVIEW = Path(__file__).resolve().parents[2]/"experiments/advancing-payments/review"
sys.path.insert(0,str(AP_REVIEW))
from public_chain import P, ZERO, counted_hash, proof_public, reference

BIN_PROFILE = bytes.fromhex("af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1")
PARAMETERS = struct.pack("<BBBIQ",22,8,4,8,100)
sha = lambda s: hashlib.sha256(s).digest()
NETWORK = sha(b"PQDEV1/network\0"+BIN_PROFILE+PARAMETERS)
GENESIS = sha(b"PQDEV1/genesis\0"+NETWORK)
u32 = lambda n: struct.pack("<I",n)
u64 = lambda n: struct.pack("<Q",n)


def canonical(word):
    return len(word)==32 and all(f<P for f in struct.unpack("<4Q",word))


def decode(raw):
    assert 222<=len(raw)<=222+4*(4+256*1024) and raw[:8]==b"PQDEVBL1" and raw[8:40]==NETWORK and raw[40]==22
    solution = sha(b"PQDEV1/work\0"+sha(b"PQDEV1/template\0"+raw[:-8])+raw[-8:])
    assert int.from_bytes(solution,"big") < 1<<234
    parent = raw[41:73]
    h, = struct.unpack_from("<I",raw,73)
    miner = raw[77:109]
    value, = struct.unpack_from("<Q",raw,109)
    cm,state,root = raw[117:149],raw[149:181],raw[181:213]
    assert canonical(miner) and miner!=ZERO and canonical(cm) and canonical(state) and canonical(root)
    count = raw[213]
    assert count<=4
    packets = []
    off = 214
    for _ in range(count):
        n, = struct.unpack_from("<I",raw,off)
        off += 4
        assert 0<n<=min(256*1024,len(raw)-off-8)
        packet = raw[off:off+n]
        assert packet[:5]==b"APV2\x01" and len(proof_public(packet))==1
        packets.append(packet)
        off += n
    assert off==len(raw)-8
    context = sha(b"PQDEV1/reward-context\0"+NETWORK+parent+u32(h)+miner+sha(raw[213:off]))
    return dict(id=solution,parent=parent,h=h,miner=miner,reward=value,cm=cm,state=state,root=root,
                reward_body=context+miner+u64(value),packets=packets)


def best(chains):
    # All valid devnet blocks have the same independently verified target.
    assert chains
    return min(chains,key=lambda c:(-c["work"],bytes.fromhex(c["tip"])))


def examine(raws, roots_exe, reward_exe):
    records = [decode(raw) for raw in raws]
    reward_rows = b"".join(b["reward_body"] for b in records)
    reward_cms = subprocess.check_output([str(reward_exe)],input=reward_rows,timeout=60).decode().splitlines()
    assert [b["cm"].hex() for b in records]==reward_cms
    state = counted_hash(b"dev-genesis-state",NETWORK)
    gh = ZERO+u32(0)+state+counted_hash(b"dev-genesis-body",NETWORK)+ZERO
    def anchor(header):
        return bytes.fromhex(reference(roots_exe,["--header-ids"],header)[0].split()[1])
    anchors = [anchor(gh)]
    ids = [GENESIS]
    leaves,spent,expected_funded,expected_ct = [],set(),{},[]
    seen = set()
    previews = []
    total_subsidy,fees_paid,paid_to_miners = 0,0,0
    for h,b in enumerate(records,1):
        assert b["h"]==h and b["parent"]==ids[-1] and 0<=h<=2**32-1
        transition = bytearray()
        txfees = 0
        for packet in b["packets"]:
            (slot,) = proof_public(packet)
            parent,when,nfs,cms,fee,ct,pair = slot
            assert 1<=h-when<=8 and parent==anchors[when] and fee==3
            assert len(set(nfs))==2 and spent.isdisjoint(nfs)
            assert len(set(cms))==2 and seen.isdisjoint(cms) and ZERO not in cms
            spent.update(nfs)
            leaves.extend(cms)
            seen.update(cms)
            txfees+=fee
            expected_ct.append((ct.hex(),pair))
            transition.extend(b"".join((*nfs,*cms,u64(fee))))
        assert b["reward"]==100+txfees and b["cm"] not in seen and b["cm"]!=ZERO
        seen.add(b["cm"])
        leaves.append(b["cm"])
        total_subsidy+=100
        fees_paid+=txfees
        paid_to_miners+=b["reward"]
        assert paid_to_miners-fees_paid==total_subsidy==100*h
        state = counted_hash(b"dev-state",NETWORK,state,u64(len(leaves)),u64(total_subsidy),u64(fees_paid),
                             b["reward_body"]+b["cm"],bytes(transition))
        assert state==b["state"]
        hdr = anchors[-1]+u32(h)+state+counted_hash(b"dev-seal",NETWORK,b["id"])+b["root"]
        ids.append(b["id"])
        anchors.append(anchor(hdr))
        expected_funded[len(leaves)]=b["root"].hex()
        previews.append(dict(height=h,id=b["id"].hex(),work=h*(1<<22),width=len(b["packets"]),reward=b["reward"],
                             reward_commitment=b["cm"].hex(),miner=b["miner"].hex(),anchor=anchors[-1].hex(),
                             funded_root=b["root"].hex(),issued=total_subsidy,fees=fees_paid))
    if leaves:
        # Exact upstream full-tree roots, including each coinbase, ordered private outputs and literal zero padding.
        hashes = reference(roots_exe,[str(n) for n in expected_funded],b"".join(leaves))
        assert {int(n):d for n,_,d in (r.split() for r in hashes)}==expected_funded
    if expected_ct:
        assert reference(roots_exe,["--ciphertext-digests"],b"".join(ct for _,ct in expected_ct))==[d for d,_ in expected_ct]
    return dict(network=NETWORK.hex(),genesis=GENESIS.hex(),height=len(records),tip=ids[-1].hex(),work=len(records)*(1<<22),
                registered_profile=BIN_PROFILE.hex(),anchor=anchors[-1].hex(),issued=total_subsidy,fees=fees_paid,
                miners_credited=paid_to_miners,funded=len(leaves),spent=len(spent),payments=len(expected_ct),
                body_B=sum(map(len,raws)),headers=previews)


if __name__=="__main__":
    args=argparse.ArgumentParser(description=__doc__)
    args.add_argument("reference",type=Path)
    args.add_argument("reward",type=Path)
    args.add_argument("blocks",type=Path,nargs="*")
    cfg=args.parse_args()
    print(json.dumps(examine([p.read_bytes() for p in cfg.blocks],cfg.reference.resolve(),cfg.reward.resolve()),indent=2))
