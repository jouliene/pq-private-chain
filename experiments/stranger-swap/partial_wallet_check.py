"""Exercise private request retry and the bounded cross-store reservation handoff without proving."""
from hashlib import sha256
from pathlib import Path
import secrets
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from directory import NETWORK,PARTIAL,Directory,validate
from market_transport import make_advert,MakerRejected
from negotiation import canonical,read_state,write_state
from partial_state import Book,Order
from partial_wallet import Buyer,Seller,firm_terms,economics

def address():
    return (b"\x01"+secrets.token_bytes(1600)).hex()

def check(home):
    now=int(time.time())
    ad=make_advert(home/"tls","127.0.0.1:23456",dict(network=NETWORK,version=1,service=PARTIAL,
                                                     issued=now,expires=now+300))
    aid=validate(ad)
    directory=Directory()
    assert directory.dispatch({"op":"register","ad":ad})["id"]==aid
    assert directory.dispatch({"op":"list","network":NETWORK,"service":PARTIAL})["ads"]==[ad]
    assert not directory.dispatch({"op":"list","network":NETWORK,"service":"token-for-native"})["ads"]
    seller,buyer=address(),address()
    give,take=(bytes([i])*32 for i in (1,2))
    give,take=give.hex(),take.hex()
    order=secrets.token_hex(32)
    class OfflineBuyer(Buyer):
        def local(self,op,*args):
            assert op=="info"
            return {"network":NETWORK,"address":buyer,"height":32}
    client=OfflineBuyer(home,"buyer","c")
    requests=[]
    def ambiguous(ad,req):
        requests.append(req.copy())
        raise MakerRejected("maker rejected request")
    def retry(ad,req):
        requests.append(req.copy())
        return {"offer":order,"request":req["request"],"reservation":"retry"}
    def declined(ad,req):
        return dict(retry(ad,req),reservation="declined")
    for channel in (ambiguous,retry,declined):
        try:
            client.reserve(ad,channel,order,give,take,50,10,1,3)
        except ValueError:
            pass
        else:
            raise RuntimeError("unexpected reservation")
    assert requests[0]==requests[1]==requests[2]
    request=requests[0]
    rows=client.list_fills(order)["fills"]
    assert len(rows)==1 and rows[0]["state"]=="refused" and rows[0]["request"]==request["request"]
    cfg=dict(offer=order,advert=ad,asset=give,take=take,total=100,lot=10,price=1,fee=3,blocks=8,quote_ttl=240)
    store=home/"order"
    store.mkdir(mode=0o700)
    worker=Seller(home,"seller","c",store,cfg)
    expected=dict(state="allocating",req=request,ad=ad)
    q={k:v for k,v in request.items() if k not in ("op","cap")}
    q.update(version=2,holder=sha256(bytes.fromhex(request["cap"])).hexdigest(),maker=seller,network=NETWORK,
             payment=5,payer="a",expiry_height=40,expires=now+180,nonce=secrets.token_hex(32),quote=secrets.token_hex(32))
    expected["firm"]=q
    terms=firm_terms(q,ad,request)
    assert [p.qty for p in terms.parties]==[5,50] and [terms.fee(i) for i in (0,1)]==[3,0]
    for bad in (1,11,49,51):
        try:
            economics(give,take,bad,10,1,3)
        except ValueError:
            continue
        raise RuntimeError("accepted non-lot quantity")
    alloc=store/"allocation"
    alloc.mkdir(mode=0o700)
    tip="11"*32
    with Book(store/"book.sqlite") as book:
        book.create(Order(order,NETWORK,seller,give,take,100,10,1))
        book.sync(order,{"network":NETWORK,"height":32,"tip":tip,"bundles":{}})
        write_state(alloc,expected)
        worker.restore_allocation(book)
        assert not worker.folders() and not read_state(alloc)
        write_state(alloc,expected)
        book.reserve(order,request["request"],sha256(canonical(request)).hexdigest(),50,40,tip,agreement=terms.encode())
    with Book(store/"book.sqlite") as book:
        worker.restore_allocation(book)
        worker.restore_allocation(book)
        assert len(worker.folders())==1 and read_state(worker.folders()[0])==expected
        assert book.status(order)["reserved"]==50 and not read_state(alloc)

if __name__=="__main__":
    if not __debug__:
        raise SystemExit("run without -O")
    with tempfile.TemporaryDirectory() as d:
        check(Path(d))
    print("PASS signed service separation, lot/fee economics, ambiguous retry capability, local response-loss lookup and both allocation crash boundaries")
