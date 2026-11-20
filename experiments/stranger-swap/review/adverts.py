"""Independently decode the two public advertisements and verify ML-DSA-65 with a second implementation."""
import argparse
from base64 import b64decode,b64encode
from hashlib import sha256
from ipaddress import IPv4Address
import json
from pathlib import Path
import sys
import tempfile
from zipfile import ZipFile

WHEEL_SHA='dda3ae43e6e3d212ae1fe1b30d5b6dffe5e25a1f389d1fea26faad4afdc33ff8'
SPKI=bytes.fromhex('308207b2300b0609608648016503040312038207a100')
DOMAIN=b'PQD/stranger-advert/v1\0'
NETWORK='7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac'
FIELDS={'version','network','service','issued','expires','endpoint','identity','cert_sha256','signature'}


def canonical(obj):
    return json.dumps(obj,separators=(',',':'),sort_keys=True,ensure_ascii=True,allow_nan=False).encode('ascii')


def unique(pairs):
    result=dict(pairs)
    assert len(result)==len(pairs)
    return result


def unpack(ad):
    assert isinstance(ad,dict) and set(ad)==FIELDS and type(ad['version'])==int and ad['version']==1
    assert ad['network']==NETWORK and ad['service']=='token-for-native'
    assert type(ad['issued'])==type(ad['expires'])==int and 0<ad['expires']-ad['issued']<=600
    host,port=ad['endpoint'].split(':')
    assert str(IPv4Address(host))==host and str(int(port))==port and 1024<=int(port)<=65535
    pin=bytes.fromhex(ad['cert_sha256'])
    assert len(pin)==32 and pin.hex()==ad['cert_sha256']
    spki=b64decode(ad['identity'],validate=True);sig=b64decode(ad['signature'],validate=True)
    assert spki.startswith(SPKI) and len(spki)==1974 and len(sig)==3309
    assert b64encode(spki).decode('ascii')==ad['identity'] and b64encode(sig).decode('ascii')==ad['signature']
    unsigned={k:v for k,v in ad.items() if k!='signature'}
    return spki[len(SPKI):],sig,unsigned


def check(adverts,wheel):
    assert sha256(wheel.read_bytes()).hexdigest()==WHEEL_SHA
    # The wheel contains a namespace subdirectory that Python's zip importer cannot traverse.
    with tempfile.TemporaryDirectory() as local:
        with ZipFile(wheel) as archive:
            archive.extractall(local)
        sys.path.insert(0,local)
        try:
            from dilithium_py.ml_dsa import ML_DSA_65
        finally:
            sys.path.remove(local)
    assert len(adverts)==2
    pairs=[unpack(ad) for ad in adverts]
    assert len({pair[0] for pair in pairs})==len({ad['cert_sha256'] for ad in adverts})==len({ad['endpoint'] for ad in adverts})==2
    rows=[]
    for i,(pk,sig,unsigned) in enumerate(pairs):
        msg=canonical(unsigned)
        assert ML_DSA_65.verify(pk,DOMAIN+msg,sig)
        verify=ML_DSA_65.verify
        changes=dict(network='00'*32,service='other',version=2,issued=unsigned['issued']-1,expires=unsigned['expires']+1,
                     endpoint=pairs[1-i][2]['endpoint'],identity=pairs[1-i][2]['identity'],cert_sha256=pairs[1-i][2]['cert_sha256'])
        for k,value in changes.items():
            assert value!=unsigned[k] and not verify(pk,DOMAIN+canonical(unsigned|{k:value}),sig)
        assert not verify(pairs[1-i][0],DOMAIN+msg,sig)
        sig_alt=sig[:-1]+bytes([sig[-1]^1])
        assert not verify(pk,DOMAIN+msg,sig_alt)
        raw=canonical(adverts[i])
        rows.append(dict(id=sha256(raw).hexdigest(),advert_canonical_B=len(raw),SPKI_B=len(pk)+len(SPKI),
                         signature_B=len(sig),TTL_s=unsigned['expires']-unsigned['issued'],valid_fips204=True))
    return dict(adverts=rows,independent_verifier='dilithium-py 1.4.0',verifier_wheel_sha256=WHEEL_SHA,
                verification_context='FIPS 204 pure ML-DSA-65, empty context, application domain in message',
                selected_schema=sorted(FIELDS),modified_signatures_keys_or_fields_rejected=20)


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('provider_wheel',type=Path);p.add_argument('advert',nargs=2,type=Path)
    a=p.parse_args();adverts=[json.loads(path.read_bytes(),object_pairs_hook=unique) for path in a.advert]
    print(json.dumps(check(adverts,a.provider_wheel),sort_keys=True,indent=2))
