"""Public, passive TKQ1 layout and arithmetic check, with opaque Keccak hash encodings."""
import argparse
import json
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from effects import reference, VK
from direct_wire import Wire, fri

KEY_PIN = '74fa3fb56350de946797b7b68e925ae2193efe6b0257ad62e474225d650cd68c'


def inspect(key,packet,reference_roots):
    r=Wire(key)
    assert sha256(key).hexdigest() == KEY_PIN and r.integer() == 4
    r.take(32*17)
    assert [r.integer() for _ in range(6)] == [135,60,2,128,2,8]
    assert r.take(2) == b'\1\1'
    profile = fri(r)
    assert profile == [5,4,64,0,1,2,3]
    degree = r.integer()
    assert degree == 14 and fri(r) == profile
    folds = [r.integer() for _ in range(r.integer())]
    assert folds == [2]*6 and r.integer()==degree and r.integer(1)==1 and r.integer()==degree
    r.take(r.integer()*8)
    r.take(r.integer()*16)
    qfac, _, constants, npi = [r.integer() for _ in range(4)]
    assert npi==26 and r.integer()==60
    r.words(60)
    partial = r.integer()
    assert [r.integer() for _ in range(3)]==[0]*3
    r=Wire(packet)
    assert r.take(5)==b'TKQ1\1'
    proof_size=r.integer(4)
    proof=Wire(r.take(proof_size))
    receipts=r.take(3584)
    assert not r.read()
    widths = [constants+60,135,2*(1+partial),2*qfac]
    proof.take(3*16*32)
    proof.words(2*(sum(widths)+2))
    proof.take(len(folds)*16*32)
    salts=[]
    for _ in range(64):
        depth=degree+5-4
        for i,width in enumerate(widths):
            proof.words(width)
            if i:
                salt=proof.words(4)
                assert any(salt)
                salts.append(salt)
            assert proof.integer(1)==depth
            proof.take(depth*32)
        for fold in folds:
            proof.words(2*(1<<fold))
            depth-=fold
            assert proof.integer(1)==depth
            proof.take(depth*32)
    proof.words(2*(1<<(degree-sum(folds)))+1)
    assert proof.integer()==26
    public=proof.words(26)
    assert public[21]==3 and not proof.read()
    assert reference(reference_roots,['--ciphertext-digests'],receipts)==[struct.pack('<4Q',*public[-4:]).hex()]
    assert len(packet)==9+proof_size+3584
    return dict(vk_sha256=KEY_PIN,tkn1_vk_sha256=VK,packet_sha256=sha256(packet).hexdigest(),
                packet_B=len(packet),proof_B=proof_size,receipt_B=len(receipts),queries=64,
                opaque_authentication_paths=64*(4+len(folds)),folds=folds,observed_salt_tuples=len(salts),
                distinct_salt_tuples=len(set(salts)),registered_domain=1<<(degree+5),
                over_existing_peer_packet_ceiling_B=len(packet)-256*1024)


if __name__ == '__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('key','packet','roots'):
        ap.add_argument(name,type=Path)
    args=ap.parse_args()
    print(json.dumps(inspect(args.key.read_bytes(),args.packet.read_bytes(),args.roots.resolve()),indent=2,sort_keys=True))
