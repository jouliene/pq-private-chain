"""Compare funded old/new public payloads and signatures; evaluate complete native verification separately."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from tape import read,words

OLD_NETWORK=bytes.fromhex('7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac')
SLH=HERE.parents[1]/'managed-assets/review/verify_slh.mjs'


def digest(value):
    return sha256(value).digest()


def split(raw,new):
    assert raw[:5]==(b'FWB1\1' if new else b'SWB1\1')
    off=5;frames=[]
    for side in range(2):
        size,=struct.unpack_from('<I',raw,off);off+=4
        assert 17195+3593 <size<=262144
        frame=raw[off:off+size];off+=size
        assert len(frame)==size and frame[:6]==(b'FWF1\1' if new else b'SWF1\1')+bytes([side])
        frames.append(frame)
    assert off==len(raw) and frames[0][6:75]==frames[1][6:75]
    payer=frames[0][6];expiry,=struct.unpack_from('<I',frames[0],7)
    net,terms=frames[0][11:43],frames[0][43:75]
    assert payer in (0,1) and expiry and net!=bytes(32) and terms!=bytes(32)
    legs=[f[17195:] for f in frames]
    assert all(f[75:107]==digest(legs[1-i]) for i,f in enumerate(frames))
    joint=digest(b'SWP1/joint-authorization/v1\0'+net+terms+struct.pack('<IB',expiry,payer)+b''.join(map(digest,legs)))
    return frames,legs,joint


def legacy_public(raw,count):
    tag=b'SLG1\x01' if count==34 else b'MNG1\x01'
    assert raw.startswith(tag)
    size,=struct.unpack_from('<I',raw,5)
    assert len(raw)==9+size+3584
    end=9+size
    assert struct.unpack_from('<Q',raw,end-8*(1+count))==(count,)
    return raw[end-8*count:end]


def check(old_ordinary,old_swap,new_ordinary,new_swap,node):
    old=old_ordinary.read_bytes()
    if old.startswith(b'MSP1\x01\x00'):
        old=old[6:]
    current=new_ordinary.read_bytes()
    assert current.startswith(b'FWT1\x01')
    oldraw=old_swap.read_bytes();newraw=new_swap.read_bytes()
    oldframes,oldlegs,olddigest=split(oldraw,False)
    frames,legs,newdigest=split(newraw,True)
    assert oldframes[0][6:75]==frames[0][6:75] and newdigest!=olddigest
    valid=[];wrong=[];reports=[]
    pairs=[(old,current,31),*[(a,b,34) for a,b in zip(oldlegs,legs,strict=True)]]
    for i,(a,b,count) in enumerate(pairs):
        pi=legacy_public(a,count)
        assert b[9:9+8*count]==pi and a[-3584:]==b[-3584:]
        reports.append(read(b))
        if i:
            idx=i-1;public=words(pi);key=struct.pack('<8I',*public[26:])
            assert public[21]==(3 if frames[0][6]==idx else 0)
            sig=frames[idx][107:17195];oldsig=oldframes[idx][107:17195]
            valid.extend((key+newdigest+sig,key+olddigest+oldsig))
            wrong.extend((key+olddigest+sig,key+newdigest+oldsig))
    assert valid[0][:32]!=valid[2][:32]
    onward=(new_ordinary.parent/'onward.candidate').read_bytes()
    released_onward=(old_ordinary.parent/'restored-onward.transfer').read_bytes()
    assert released_onward[:6]==b'MSP1\1\0' and onward[:5]==b'FWT1\1'
    assert legacy_public(released_onward[6:],31)==onward[9:257] and released_onward[-3584:]==onward[-3584:]
    reports.append(read(onward))
    res=subprocess.check_output([node,SLH],input=b''.join(valid+wrong))
    assert res==b'11110000'
    return dict(matched_public_field_count=130,ordinary_plus_swap_field_count=99,identical_ordered_ciphertexts=8,
                onward_candidate_B=len(onward),onward_reference_B=len(released_onward),
                ordinary_candidate_bytes=new_ordinary.stat().st_size,ordinary_reference_bytes=6+len(old),ordinary_legacy_inner_B=len(old),
                swap_candidate_bytes=len(newraw),swap_reference_bytes=len(oldraw),complete_frame_B=[len(f) for f in frames],
                old_and_new_signatures_verified=4,cross_wrapper_old_and_new_signatures_rejected=4,
                local_262144B_frame_admission=all(len(f)<=262144 for f in frames),candidate_proofs=reports,
                bundle_SHA256=sha256(newraw).hexdigest(),proof_reader_scope='all outer sums, adjacent inner sums, Merkle openings and terminal RS combinations; full statement verification is separate')


if __name__=='__main__':
    if not __debug__:raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('old_ordinary','old_swap','new_ordinary','new_swap','node'):
        p.add_argument(name,type=Path)
    a=p.parse_args()
    print(json.dumps(check(a.old_ordinary,a.old_swap,a.new_ordinary,a.new_swap,a.node),sort_keys=True,indent=2))
