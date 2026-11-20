"""Fast private quote codec, consent and durable state checks. No nodes or proving roles."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json
import secrets
import socket
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from negotiation import (PREFIX,Taker,Maker,Terms,MAX_LEG,ZERO,b64,unb64,advert_id,quote_terms,
                         materialize,write_state,read_state)
from directory import NETWORK, SERVICE
import market_transport
from market_transport import make_advert


def refuses(fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("private control accepted unexpectedly")


def token():
    return secrets.token_hex(32)


def address():
    return (b"\x01"+secrets.token_bytes(1600)).hex()


def offline_retry(home, ad, asset):
    # Simulate only an already-open wallet's public address and chain view. The real transport
    # attempts TLS against a bound, non-listening localhost socket. No proof role is replaced.
    own=address()
    class Client(Taker):
        def local(self,op,folder=None,incoming=None):
            assert op=="info"
            return dict(network=NETWORK,address=own,height=5)
    def call(transport):
        client=Client(home,"offline","c")
        client.quote(ad,transport,asset=asset,quantity=20)
    attempts=[]
    def failed(ad,req):
        meter={}
        attempts.append((req.copy(),meter))
        return market_transport.request(ad,req,meter=meter)
    for _ in range(2):
        refuses(lambda:call(failed))
    assert attempts[0][0]==attempts[1][0] and len(attempts)==2
    assert all(not m["authenticated"] and m["request_B"]==0 for _,m in attempts)
    if hasattr(market_transport,"MakerRejected"):
        def refused(ad,req):
            assert req==attempts[0][0]
            raise market_transport.MakerRejected("maker rejected request")
        refuses(lambda:call(refused))
        refuses(lambda:call(failed))
        assert attempts[2][0]["request"]!=attempts[0][0]["request"]
        assert attempts[2][0]["cap"]!=attempts[0][0]["cap"]


def run(home,endpoint):
    now=int(time.time())
    ad=make_advert(home/"id",endpoint,dict(version=1,network=NETWORK,service=SERVICE,issued=now,expires=now+90))
    asset=(b"\x14"*32).hex()
    offline_retry(home,ad,asset)
    req=dict(op="quote",advert=advert_id(ad),request=token(),cap=token(),taker=address(),asset=asset,quantity=20)
    q=dict(version=1,advert=req["advert"],request=req["request"],holder=sha256(bytes.fromhex(req["cap"])).hexdigest(),
           quote=token(),network=NETWORK,maker=address(),taker=req["taker"],asset=asset,quantity=20,native=8,
           payer="b",fee=3,expiry_height=40,expires=now+60,nonce=token())
    terms=quote_terms(q,ad,req)
    encoded=json.dumps(q,sort_keys=True,separators=(",",":")).encode("ascii")
    assert terms.blind==sha256(PREFIX+encoded).digest()
    assert terms.parties[1].give==ZERO and terms.parties[1].native==8 and terms.fee(1)==3
    assert terms.parties[0].give.hex()==asset and terms.parties[0].token==20 and terms.fee(0)==0
    assert terms.encode()[:8]==b"SWPTER02" and Terms.decode(terms.encode())==terms
    for k,v in [("advert",token()),("holder",token()),("request",token()),("network",token()),("taker",address()),
                ("asset","00"*32),("quantity",19),("maker",req["taker"]),("payer","a"),("fee",0),
                ("native",True),("native",0),("version",True),("expires",ad["expires"]+1),("expiry_height",0)]:
        refuses(lambda:quote_terms(dict(q,**{k:v}),ad,req))
    for k,v in [("native",7),("nonce",token()),("quote",token()),("expires",now+41),("expiry_height",39),
                ("maker",address())]:
        assert quote_terms(dict(q,**{k:v}),ad,req).commitment()!=terms.commitment()
    for change in [dict(cap=token()),dict(taker=address())]:
        refuses(lambda:quote_terms(q,ad,dict(req,**change)))
    raw=secrets.token_bytes(99)
    assert unb64(b64(raw),99)==raw
    refuses(lambda:unb64(b64(raw),98))
    refuses(lambda:unb64("x="*(MAX_LEG+1),MAX_LEG))

    client=Taker(home,"alice","c")
    maker=Maker(home,"buyer","a",ad,dict(asset=asset,quantity=20,native=8))
    state=dict(state="quoted",firm=deepcopy(q),req=req,ad=ad)
    for side,owner in enumerate((client,maker)):
        folder=owner.folder(q["request"])
        owner.create(folder,state)
        materialize(folder,terms,side)
        assert not (folder/"session.json").stat().st_mode & 0o077
        raw=(folder/"peer.addr").read_bytes()
        assert raw[:8]==b"PQDADDR1" and sha256(raw[:-32]).digest()==raw[-32:]
        assert raw[40:-32]==terms.parties[1-side].address
    client=Taker(home,"alice","c")
    assert client.status(q["quote"])["state"]=="quoted"
    def no_network(*args):
        raise AssertionError("rejected local intent contacted peer")
    for over in [dict(native=7),dict(expiry=39),dict(asset=(b"\x28"*32).hex()),dict(quantity=21)]:
        expected=dict(asset=asset,quantity=20,native=8,expiry=40)
        expected.update(over)
        refuses(lambda:client.settle(q["quote"],no_network,**expected))
    assert client.status(q["quote"])["state"]=="quoted"
    cont=client.continuation(state,"status")
    for k,v in [("cap",token()),("advert",token()),("quote",token()),("request",token())]:
        refuses(lambda:maker.handle(dict(cont,**{k:v})))
    f=client.folder(req["request"])
    state.update(state="released",delivery="attempted")
    write_state(f,state)
    refuses(lambda:client.cancel(q["quote"],no_network))
    assert read_state(f)["delivery"]=="attempted"
    assert (f/"terms").read_bytes()==terms.encode()
    assert client.active(state,dict(network=NETWORK,height=39)) and not client.active(state,dict(network=NETWORK,height=40))
    assert not client.active(dict(firm=dict(q,expires=int(time.time()))),dict(network=NETWORK,height=39))


if __name__=="__main__":
    if not __debug__:
        raise SystemExit("run without -O")
    with tempfile.TemporaryDirectory() as temp:
        home=Path(temp)
        (home/"id").mkdir(mode=0o700)
        with socket.socket() as stopped:
            stopped.bind(("127.0.0.1",0))
            run(home,"127.0.0.1:"+str(stopped.getsockname()[1]))
    print("PASS signed-ad quote binding, currency/fee/amount/expiry, funding address identities, capability scope, durable consent, offline retry and local pin checks")
