"""Cross-check public effects, ordered receipts, both final signatures and profile separation."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from measure_public import BASELINE, K384, ROOT, GOLDILOCKS, frames


def flip(x):
    return bytes([x[0]^1])+x[1:]


def validate(ordinary,swap,profile,roots,node):
    base=BASELINE if profile=='baseline' else K384
    assert ordinary[:6]==base.ordinary+b'\x01\x00'
    a,b=frames(swap,base)
    assert a[5:7]==bytes([0,a[6]]) and b[5]==1 and a[6:75]==b[6:75] and a[11:43]==base.network
    legs=a[17195:],b[17195:]
    assert all(r[:5]==base.frame+b'\x01' for r in (a,b))
    digests=[sha256(x).digest() for x in legs]
    assert a[75:107]==digests[1] and b[75:107]==digests[0]
    pks=[]; descriptions=[]
    for i,raw in enumerate((ordinary[6:],*legs)):
        n=31 if i==0 else 34
        length,=struct.unpack_from('<I',raw,5)
        assert raw[:5]==(base.ordinary_inner if i==0 else base.swap_inner)+b'\x01' and len(raw)==length+3593
        end=len(raw)-3584
        encoded=raw[end-8*n:end]
        words=struct.unpack('<'+str(n)+'Q',encoded)
        assert all(v<GOLDILOCKS for v in words) and struct.unpack_from('<Q',raw,end-8*n-8)==(n,)
        returned=subprocess.check_output([roots,'--ciphertext-digests'],input=raw[-3584:],timeout=30).decode().splitlines()
        assert returned==[encoded[176:208].hex()]
        if i==0:
            assert words[21]==3 and words[26:]==(0,0,0,0,0)
        else:
            assert words[21]==(3 if i-1==a[6] else 0)
            pks.append(struct.pack('<8I',*words[26:34]))
        descriptions.append(dict(anchor_height=words[4],nullifier_count=2,output_count=2,
                                 fee=words[21],registered_public_inputs=n,encrypted_receipt_pair_B=3584))
    assert len(set(pks))==2
    common=dict(net=a[11:43],terms=a[43:75],expiry=a[7:11],payer=a[6:7],first=digests[0],second=digests[1])
    def statement(**changes):
        row=common|changes
        return sha256(base.authorization_domain+b''.join(row[k] for k in ('net','terms','expiry','payer','first','second'))).digest()
    signed=[r[107:17195] for r in (a,b)]
    valid=[]
    invalid=[]
    for i,key in enumerate(pks):
        sig=signed[i]; valid.append(key+statement()+sig)
        invalid.extend(key+statement(**{n:flip(x)})+sig for n,x in common.items())
        invalid.extend((key+statement(first=digests[1],second=digests[0])+sig,
                        pks[1-i]+statement()+sig,key+statement()+flip(sig)))
    answer=subprocess.check_output([node,ROOT/'experiments/managed-assets/review/verify_slh.mjs'],
                                   input=b''.join(valid+invalid),timeout=60)
    assert answer==b'1'*2+b'0'*len(invalid)
    return dict(profile=profile,public_inputs=descriptions,valid_openssl_authorizations=2,
                changed_authorizations_rejected=len(invalid),independent_receipt_pair_checks=3,
                wire_sizes=[len(ordinary),len(a),len(b)],bounded_262144_each=[len(x)<=262144 for x in (ordinary,a,b)])


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('profile',choices=['baseline','k384'])
    for k in ('ordinary','swap','roots','node'):p.add_argument(k,type=Path)
    a=p.parse_args();print(json.dumps(validate(a.ordinary.read_bytes(),a.swap.read_bytes(),a.profile,a.roots,a.node),sort_keys=True,indent=2))
