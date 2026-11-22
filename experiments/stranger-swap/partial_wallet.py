"""Durable private lot orders using the funded profile-C swap wallets and a selected-chain inventory."""
from contextlib import contextmanager
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

from negotiation import (HERE,LIMIT,MAX_LEG,SIGNATURE,Local,Taker,Party,Terms,advert_id,asset_id,
                         b64,canonical,emit,integer,materialize,need,read_state,unb64,view,word,write_state,sync_dir,MAX_HISTORY)
from directory import PARTIAL
import market_transport


def positive(v):
    return integer(v,1,LIMIT)


def economics(give,take,quantity,lot,price,fee):
    need(give!="native" and take!="native" and asset_id(give)!=asset_id(take),"two distinct token IDs required")
    positive(quantity); positive(lot); positive(price); integer(fee,3,3)
    need(quantity%lot==0,"fill is not a whole number of lots")
    return positive(quantity//lot*price)


def firm_terms(q,ad,req):
    fixed=("offer","advert","asset","take","quantity","lot","price","fee","request","taker")
    need(set(q)==set(fixed)|{"holder","version","quote","maker","network","payment","payer","expires","expiry_height","nonce"},
         "invalid firm fill fields")
    need(all(q[k]==req[k] for k in fixed) and ad["service"]==PARTIAL and q["version"]==2 and
         q["network"]==ad["network"] and q["holder"]==sha256(word(req["cap"])).hexdigest(),"changed firm fill")
    for k in ("offer","advert","request","quote","nonce"):
        word(q[k])
    payment=economics(q["asset"],q["take"],q["quantity"],q["lot"],q["price"],q["fee"])
    need(q["payer"]=="a" and type(q["payment"]) is int and q["payment"]==payment,"incorrect fill price or payer")
    integer(q["expires"],ad["issued"]+1,ad["expires"])
    integer(q["expiry_height"],1,2**32-1)
    parties=(Party(word(q["taker"],1601),asset_id(q["take"]),payment),
             Party(word(q["maker"],1601),asset_id(q["asset"]),q["quantity"]))
    return Terms(word(q["network"]),sha256(b"SWP3/private-lot/v1\0"+canonical(q)).digest(),q["expiry_height"],parties,0)


def check_leg(raw):
    need(raw.startswith(b"SLG3\x01") and 9+int.from_bytes(raw[5:9],"little")+3584==len(raw)<=MAX_LEG,
         "expected a funded profile-C leg")


class CLocal:
    def local(self,op,folder=None,incoming=None):
        result=super().local("partial-"+op,folder,incoming)
        if folder is not None and op in ("leg","authorize","combine","journal","selected"):
            sync_dir(folder)
        return result


class Buyer(CLocal,Taker):
    def __init__(self,home,wallet,node):
        Local.__init__(self,home,wallet,node,"partial-taker")

    def reserve(self,ad,request,order,give,take,quantity,lot,price,fee,request_id=None):
        economics(give,take,quantity,lot,price,fee)
        word(order)
        ident=advert_id(ad)
        with self.locked():
            info=self.local("info")
            need(ad["network"]==info["network"] and ad["service"]==PARTIAL,"wrong service or network")
            base=dict(op="reserve",offer=order,advert=ident,taker=info["address"],asset=give,take=take,
                      quantity=quantity,lot=lot,price=price,fee=fee)
            candidates=self.folders() if request_id is None else [self.folder(request_id)]
            for folder in candidates:
                if not (folder/"session.json").exists():
                    continue
                st=read_state(folder)
                same=all(st["req"].get(k)==v for k,v in base.items())
                if request_id is not None:
                    need(same,"request ID already belongs to other terms")
                    if "firm" in st:
                        return {**view(st),"request":folder.name}
                    need(st["state"]=="requested","request is retired")
                if not same:
                    continue
                if st["state"]=="requested":
                    break
                if st["state"] in ("quoted","prepared") and self.active(st,info):
                    remote=request(ad,self.continuation(st,"status"))
                    if remote=={"quote":st["firm"]["quote"],"state":"quoted"}:
                        return {**view(st),"request":folder.name}
            else:
                folder=self.folder(request_id or secrets.token_hex(32))
                st=dict(state="requested",ad=ad,req=dict(base,request=folder.name,cap=secrets.token_hex(32)))
                self.create(folder,st)
            req=st["req"]
            # A generic transport refusal can follow an already durable seller reservation. Retain
            # its capability unless this authenticated endpoint explicitly reports a definitive outcome.
            reply=request(ad,req)
            if reply.get("reservation") in ("declined","retry"):
                outcome=reply["reservation"]
                need(reply=={"offer":order,"request":folder.name,"reservation":outcome},"changed reservation outcome")
                if outcome=="declined":
                    st["state"]="refused"
                    write_state(folder,st)
                    raise ValueError("maker declined this reservation")
                raise ValueError("reservation outcome pending; retry the same request")
            need(set(reply)=={"firm","leg"},"incorrect private reservation reply")
            q=reply["firm"]
            terms=firm_terms(q,ad,req)
            need(self.active({"firm":q},info),"expired reservation")
            need(not any(read_state(p).get("firm",{}).get("quote")==q["quote"] for p in self.folders() if p!=folder),
                 "fill handle already assigned")
            leg=unb64(reply["leg"],MAX_LEG)
            check_leg(leg)
            materialize(folder,terms,0)
            with tempfile.TemporaryDirectory(dir=folder) as tmp:
                incoming=Path(tmp)
                emit(incoming/"leg",leg)
                self.local("peer",folder,incoming)
            need(self.active({"firm":q},self.local("info")),"reservation expired during verification")
            emit(folder/"leg-b",leg)
            st.update(state="quoted",firm=q)
            write_state(folder,st)
            return {**view(st),"request":folder.name}

    def list_fills(self,order=None):
        if order is not None:
            word(order)
        with self.locked():
            rows=[]
            for folder in sorted(self.folders()):
                st=read_state(folder)
                req=st["req"]
                if order is None or req["offer"]==order:
                    fields={k:req[k] for k in ("offer","quantity","asset","take","lot","price","fee")}
                    rows.append(dict(fields,request=folder.name,quote=st.get("firm",{}).get("quote"),state=st["state"]))
            return {"fills":rows}

    def recover(self,folder,st):
        if st["state"]=="releasing" and self.local("journal",folder)["state"]=="released":
            st["state"]="released"
            write_state(folder,st)
        if st["state"]=="released" and (folder/"packet").is_file():
            # Preserve "attempted" until a lost acknowledgement has been reconciled with the selected chain.
            st["state"]="complete"
            write_state(folder,st)

    def selected_status(self,folder,st):
        self.recover(folder,st)
        if st["state"] not in ("released","complete"):
            return view(st)
        match=self.local("selected",folder)
        observed={k:match[k] for k in ("selected_tip","selected_height","active_c")}
        if match["found"]:
            recovered=st.get("recovered",False) or st.get("delivery")=="attempted"
            st.update(state="complete",delivery="included",observed=match,recovered=recovered)
            write_state(folder,st)
            return {**view(st),**observed,"state":"confirmed","settlement":"confirmed","packet":str(folder/"packet"),
                    "sha256":match["id"],"ack":match["id"],"height":match["height"],"block":match["block"],
                    "recovered":recovered}
        if st.pop("observed",None):
            st["delivery"]="detached"
            write_state(folder,st)
        settlement="detached" if st.get("delivery")=="detached" else "unconfirmed"
        return {**view(st),**observed,"settlement":settlement,
                "beyond_signed_expiry":match["selected_height"]+1>st["firm"]["expiry_height"]}

    def status(self,quote):
        with self.locked():
            folder,st=self.find(quote)
            return self.selected_status(folder,st)

    def before_delivery(self,folder,st):
        need(self.active(st,self.local("info")),"fill expired before signature delivery")
        self.local("recheck",folder)

    def fill(self,quote,request,a):
        payment=economics(a.give,a.take,a.quantity,a.lot,a.price,a.fee)
        expected=dict(offer=a.offer,asset=a.give,take=a.take,quantity=a.quantity,lot=a.lot,price=a.price,
                      payment=payment,fee=a.fee,expiry_height=integer(a.expiry,1,2**32-1))
        with self.locked():
            folder,st=self.find(quote)
            need(all(st["firm"].get(k)==v for k,v in expected.items()),"selected quote differs from buyer instructions")
            result=self.selected_status(folder,st)
            if result["state"]=="confirmed":
                return result
            if result.get("settlement")=="detached":
                self.local("recheck",folder)
        return self.settle_selected(quote,request,expected,"prepared" if a.prepare_only else "complete")


class Seller(CLocal,Local):
    def __init__(self,home,wallet,node,storage,config):
        super().__init__(home,wallet,node,"partial-maker")
        self.storage,self.config=storage,config
        self.order=config["offer"]
        self.ad=config["advert"]

    @contextmanager
    def book(self):
        dev=str(self.home/"deployment/devnet")
        if dev not in sys.path:
            sys.path.insert(0,dev)
        from partial_state import Book
        with Book(self.storage/"inventory.sqlite") as book:
            yield book

    def sync(self,book):
        from partial_chain import snapshot
        snap=snapshot(self.home,self.node)
        book.sync(self.order,snap)
        return snap

    def setup(self):
        from partial_state import Order
        c=self.config
        with self.locked(), self.book() as book:
            info=self.local("info")
            order=Order(order_id=self.order,network=info["network"],maker=info["address"],
                        asset=c["asset"],take=c["take"],total=c["total"],lot=c["lot"],price=c["price"],fee=c["fee"])
            book.create(order)
            sync_dir(self.storage)
            self.sync(book)

    def restore_allocation(self,book):
        # Only one request can be between the two durable stores under the maker lock.
        pending=self.storage/"allocation"
        pending.mkdir(mode=0o700,exist_ok=True)
        sync_dir(self.storage)
        if not (pending/"session.json").is_file():
            return
        intended=read_state(pending)
        if not intended:
            return
        folder=self.folder(intended["req"]["request"])
        try:
            row=book.record(self.order,folder.name)
        except ValueError as exc:
            if str(exc)!="unknown private reservation":
                raise
            row=None
        if row is not None:
            need(row["request_hash"]==sha256(canonical(intended["req"])).hexdigest(),
                 "conflicting durable reservation")
            if (folder/"session.json").is_file():
                need(read_state(folder)["req"]==intended["req"],"changed durable request")
            else:
                self.create(folder,intended)
        write_state(pending,{})

    def reconcile(self,book):
        snap=self.sync(book)
        self.restore_allocation(book)
        # Unsigned reservations may release their actual coins after a branch/clock expiry or cancellation.
        for folder in self.folders():
            st=read_state(folder)
            if st["req"].get("offer")!=self.order or st["state"] not in ("allocating","quoted"):
                continue
            try:
                row=book.record(self.order,folder.name)
            except ValueError as exc:
                if str(exc)!="unknown private reservation":
                    raise
                continue
            if row is None:
                continue
            if row["state"]=="reserved" and int(time.time())>=st["firm"]["expires"]:
                book.cancel(self.order,folder.name)
                row=book.record(self.order,folder.name)
            if row["state"] in ("cancelled","expired"):
                materialize(folder,firm_terms(st["firm"],st["ad"],st["req"]),1)
                self.local("abort",folder)
                st["state"]=row["state"]
                write_state(folder,st)
        return snap

    def status(self,close=False):
        with self.locked(),self.book() as book:
            self.reconcile(book)
            if close:
                book.close(self.order)
                self.reconcile(book)
            return book.status(self.order)

    def recover_packet(self,quote):
        """Retrieve only a packet for which both owners' exact signatures exist locally."""
        word(quote)
        with self.locked(),self.book() as book:
            snap=self.reconcile(book)
            for folder in self.folders():
                st=read_state(folder)
                if st["req"].get("offer")==self.order and st["firm"]["quote"]==quote:
                    break
            else:
                raise ValueError("unknown private fill")
            row=book.record(self.order,folder.name)
            q=st["firm"]
            if row["state"]!="confirmed":
                need(snap["height"]+1<=q["expiry_height"],"outside signed branch deadline")
                self.local("recheck",folder)
            if not row["signed_id"]:
                # Crash after the native wallet journal commit but before inventory publication.
                # Recovery cannot create a signature or revive an unsigned offer.
                need(row["state"]=="pinned" and self.local("journal",folder)["state"]=="released",
                     "both signatures are not available")
                self.local("combine",folder)
                terms=firm_terms(q,st["ad"],st["req"])
                need(self.sync(book)["tip"]==snap["tip"],"selected chain changed during recovery")
                book.pin(self.order,folder.name,terms.commitment(),(folder/"leg-a").read_bytes(),
                         (folder/"leg-b").read_bytes(),(folder/"sig-a").read_bytes(),0,snap["tip"],
                         agreement=terms.encode())
                book.release(self.order,folder.name,(folder/"packet").read_bytes(),snap["tip"])
            packet=book.packet(self.order,folder.name)
            need(self.sync(book)["tip"]==snap["tip"],"selected chain changed before packet retrieval")
            emit(folder/"packet",packet)
            return {"offer":self.order,"quote":quote,"packet":str(folder/"packet"),"sha256":sha256(packet).hexdigest(),
                    "state":book.record(self.order,folder.name)["state"]}

    def reserve(self,b,book,snap):
        need(set(b)=={"op","offer","advert","request","cap","taker","asset","take","quantity","lot","price","fee"},
             "invalid reservation fields")
        c=self.config
        need(b["offer"]==self.order and all(b[k]==c[k] for k in ("asset","take","lot","price","fee")),"wrong offer")
        payment=economics(b["asset"],b["take"],b["quantity"],b["lot"],b["price"],b["fee"])
        need(b["quantity"]<=c["total"],"fill exceeds order")
        holder=sha256(word(b["cap"])).hexdigest()
        word(b["taker"],1601)
        folder=self.folder(b["request"])
        if (folder/"session.json").is_file():
            st=read_state(folder)
            need(st["req"]==b and st["state"] in ("allocating","quoted"),"incompatible earlier request")
            q=st["firm"]
        else:
            state=book.status(self.order)
            need(not state["closed"] and b["quantity"]<=state["available"],"insufficient open quantity")
            q={k:v for k,v in b.items() if k not in ("op","cap")}
            q.update(version=2,holder=holder,quote=secrets.token_hex(32),maker=state["order"]["maker"],
                     network=snap["network"],payment=payment,payer="a",expiry_height=snap["height"]+c["blocks"],
                     expires=min(self.ad["expires"],int(time.time())+c["quote_ttl"]),nonce=secrets.token_hex(32))
            st=dict(state="allocating",firm=q,req=b,ad=self.ad)
        terms=firm_terms(q,self.ad,b)
        need(self.active(st,snap),"expired fill request")
        fresh=not (folder/"session.json").exists()
        if fresh:
            need(sum(read_state(p)["ad"]==self.ad for p in self.folders())<MAX_HISTORY,"advert history limit")
            write_state(self.storage/"allocation",st)
        row=book.reserve(self.order,folder.name,sha256(canonical(b)).hexdigest(),q["quantity"],q["expiry_height"],snap["tip"],
                         agreement=terms.encode())
        need(row["state"]=="reserved","reservation is closed")
        if fresh:
            self.restore_allocation(book)
        materialize(folder,terms,1)
        try:
            self.local("leg",folder)
        except ValueError:
            if self.local("journal",folder)["state"]=="empty":
                book.cancel(self.order,folder.name)
                st["state"]="declined"
                write_state(folder,st)
            raise
        current=self.sync(book)
        need(self.active(st,current) and book.record(self.order,folder.name)["state"]=="reserved","reservation expired")
        st["state"]="quoted"
        write_state(folder,st)
        return dict(firm=q,leg=b64((folder/"leg-b").read_bytes()))

    def handle(self,b):
        need(isinstance(b,dict) and b.get("advert")==market_transport.verify_advert(self.ad),"unknown advertised service")
        with self.locked(),self.book() as book:
            snap=self.reconcile(book)
            op=b.get("op")
            if op=="inspect":
                need(set(b)=={"op","advert"},"invalid inspection")
                state=book.status(self.order)
                c=self.config
                return {**{k:c[k] for k in ("offer","asset","take","lot","price","fee","total")},
                        "available":state["available"],"closed":state["closed"],"payer":"a"}
            if op=="reserve":
                try:
                    return self.reserve(b,book,snap)
                except ValueError:
                    rid=b.get("request")
                    word(rid)
                    try:
                        row=book.record(self.order,rid)
                    except ValueError as exc:
                        if str(exc)!="unknown private reservation":
                            raise
                        row=None
                    if row is not None:
                        need(row["request_hash"]==sha256(canonical(b)).hexdigest(),"wrong reservation capability")
                    terminal=row is None or row["state"] in ("expired","cancelled")
                    return {"request":rid,"offer":self.order,"reservation":"declined" if terminal else "retry"}
            keys={"op","advert","cap","quote","request"}
            need(op in ("cancel","status","final") and set(b)==(keys|{"leg","signature"} if op=="final" else keys),
                 "invalid continuation")
            folder=self.folder(b["request"])
            st=read_state(folder); q=st["firm"]
            need(q["offer"]==self.order and q["advert"]==b["advert"] and q["quote"]==b["quote"] and
                 hmac.compare_digest(word(b["cap"]),word(st["req"]["cap"])),"wrong fill capability")
            row=book.record(self.order,folder.name)
            if op=="status":
                return {"quote":q["quote"],"state":"quoted" if row["state"]=="reserved" else row["state"]}
            if op=="cancel":
                if row["state"] not in ("cancelled","expired"):
                    book.cancel(self.order,folder.name)
                self.reconcile(book)
                return {"state":book.record(self.order,folder.name)["state"]}
            leg,sig=unb64(b["leg"],MAX_LEG),unb64(b["signature"],SIGNATURE)
            check_leg(leg)
            need(len(sig)==SIGNATURE,"incorrect buyer signature width")
            if row["signed_id"]:
                import swap_wire_c as wire
                packet=book.packet(self.order,folder.name)
                first,second=wire.pair(wire.split(packet))
                need(first.leg==leg and first.signature==sig and sha256(packet).hexdigest()==row["signed_id"],
                     "changed final request")
                if row["state"]!="confirmed":
                    need(self.active(st,snap) and row["state"]=="signed","fill no longer eligible for redisclosure")
                    self.local("recheck",folder)
                    need(self.sync(book)["tip"]==snap["tip"],"selected chain changed before retransmission")
                return {"quote":q["quote"],"signature":b64(second.signature)}
            need(self.active(st,snap) and row["state"] in ("reserved","pinned"),"fill is closed")
            with tempfile.TemporaryDirectory(dir=folder) as tmp:
                incoming=Path(tmp)
                emit(incoming/"leg",leg); emit(incoming/"sig",sig)
                self.local("peer",folder,incoming)
            emit(folder/"leg-a",leg); emit(folder/"sig-a",sig)
            terms=firm_terms(q,self.ad,st["req"])
            before=self.sync(book)
            need(before["tip"]==snap["tip"] and self.active(st,before),"selected chain changed; retry")
            if row["state"]=="pinned":
                self.local("recheck",folder)
            book.pin(self.order,folder.name,terms.commitment(),leg,(folder/"leg-b").read_bytes(),sig,0,
                     before["tip"],agreement=terms.encode())
            if book.status(self.order)["closed"]:
                need(self.local("journal",folder)["state"]=="released","closed order cannot sign a new fill")
            self.local("authorize",folder)
            self.local("combine",folder)
            after=self.sync(book)
            need(after["tip"]==before["tip"],"selected chain changed before release; retry")
            book.release(self.order,folder.name,(folder/"packet").read_bytes(),after["tip"])
            st["state"]="signed"
            write_state(folder,st)
            return {"quote":q["quote"],"signature":b64((folder/"sig-b").read_bytes())}


def add_commands(subs):
    for op in ("offer","serve-offer","offer-status","cancel-offer","recover-fill","inspect-offer","reserve","fill","cancel-fill","fill-status","list-fills"):
        p=subs.add_parser(op)
        p.add_argument("wallet")
        p.add_argument("--node",choices=list("abcd"),default="c")
        if op in ("serve-offer","offer-status","cancel-offer","recover-fill"):
            p.add_argument("offer")
        if op in ("reserve","inspect-offer"):
            p.add_argument("advert")
        if op in ("fill","cancel-fill","fill-status","recover-fill"):
            p.add_argument("quote")
        if op in ("reserve","fill"):
            p.add_argument("--offer",required=True)
            p.add_argument("--quantity",type=int,required=True)
        if op in ("offer","reserve","fill"):
            for label in ("give","take","lot","price","fee"):
                p.add_argument("--"+label,required=True,type=int if label in ("lot","price","fee") else str,
                               help={"give":"token sold by the maker and received by the buyer",
                                     "take":"token paid by the buyer per lot","lot":"maker token units per lot",
                                     "price":"buyer token units per lot","fee":"native fee paid by the buyer"}[label])
        if op=="reserve":
            p.add_argument("--request-id",help="repeat this private 32-byte request ID on an ambiguous reply")
        if op=="list-fills":
            p.add_argument("--offer",help="show only fills for this local order ID")
        if op=="offer":
            p.add_argument("--total",type=int,required=True)
            p.add_argument("--endpoint",required=True)
            p.add_argument("--lifetime",type=int,default=600)
            p.add_argument("--quote-ttl",type=int,default=300)
            p.add_argument("--blocks",type=int,default=8)
        if op in ("serve-offer","offer"):
            p.add_argument("--listen")
        if op=="fill":
            p.add_argument("--expiry",type=int,required=True)
            group=p.add_mutually_exclusive_group()
            group.add_argument("--prepare-only",action="store_true")
            group.add_argument("--sign-only","--no-submit",dest="no_submit",action="store_true")
        if op=="recover-fill":
            p.add_argument("--submit",action="store_true",help="submit the already signed packet to this validating node")
        if op=="cancel-fill":
            p.add_argument("--offline",action="store_true")


def durable_advert(path,endpoint,fields):
    advert=market_transport.make_advert(path,endpoint,fields)
    keys=path/"transport-identity"
    for child in keys.iterdir():
        with child.open("rb") as stream:
            os.fsync(stream.fileno())
    for folder in (keys,path,path.parent):
        sync_dir(folder)
    return advert


def commands(a,home,folder,relays,publish):
    from directory import MAX_TTL,NETWORK,directory_round,validate
    op=a.op
    if op in ("offer","serve-offer","offer-status","cancel-offer","recover-fill"):
        if op=="offer":
            economics(a.give,a.take,a.total,a.lot,a.price,a.fee)
            integer(a.lifetime,5,MAX_TTL); integer(a.blocks,1,128); integer(a.quote_ttl,1,MAX_TTL)
            order=secrets.token_hex(32)
            store=folder/"partial-orders"/order
            store.mkdir(mode=0o700,parents=True)
            sync_dir(folder)
            sync_dir(store.parent)
            now=int(time.time())
            ad=durable_advert(store,a.endpoint,dict(network=NETWORK,version=1,service=PARTIAL,
                                                                   issued=now,expires=now+a.lifetime))
            cfg=dict(offer=order,advert=ad,asset=a.give,take=a.take,total=a.total,lot=a.lot,price=a.price,
                     fee=a.fee,blocks=a.blocks,quote_ttl=a.quote_ttl,listen=a.listen,lifetime=a.lifetime,identity=".")
            write_state(store,cfg)
        else:
            word(a.offer)
            store=folder/"partial-orders"/a.offer
            cfg=read_state(store)
            need(cfg["offer"]==a.offer,"wrong order")
            ad=cfg["advert"]
        seller=Seller(home,a.wallet,a.node,store,cfg)
        if op=="recover-fill":
            result=seller.recover_packet(a.quote)
            if a.submit and result["state"]!="confirmed":
                submit(home,a.node,result)
            publish(result)
            return
        if op in ("offer-status","cancel-offer"):
            publish(seller.status(close=op=="cancel-offer"))
            return
        seller.setup()
        # A new advert/identity never changes the order or any pinned fill context.
        with seller.locked(),seller.book() as book:
            cfg=read_state(store)
            ad=cfg["advert"]
            if ad["expires"]<=int(time.time()):
                need(not book.status(cfg["offer"])["closed"],"closed order cannot be readvertised")
                now=int(time.time())
                identity="advert-"+secrets.token_hex(16)
                ad=durable_advert(store/identity,ad["endpoint"],dict(network=NETWORK,version=1,
                    service=PARTIAL,issued=now,expires=now+cfg["lifetime"]))
                cfg.update(advert=ad,identity=identity)
                write_state(store,cfg)
            seller.config=cfg
            seller.ad=ad
        ident=validate(ad)
        def ready():
            _,meters=directory_round(relays,ad)
            publish({"ready":True,"offer":cfg["offer"],"advert":ident,"discovery":meters})
        return market_transport.serve(store/cfg["identity"],ad,seller.handle,listen=a.listen or cfg.get("listen"),ready=ready)
    buyer=Buyer(home,a.wallet,a.node)
    meters=[]
    def request(ad,body):
        meter={}
        meters.append(meter)
        return market_transport.request(ad,body,meter=meter)
    if op=="list-fills":
        publish(buyer.list_fills(a.offer))
        return
    if op in ("inspect-offer","reserve"):
        ad=json.loads((folder/"partial-directory.json").read_text()).get(a.advert)
        need(ad is not None and validate(ad)==a.advert and ad["service"]==PARTIAL,"unknown maker")
        if op=="inspect-offer":
            result=request(ad,{"op":"inspect","advert":a.advert})
        else:
            result=buyer.reserve(ad,request,a.offer,a.give,a.take,a.quantity,a.lot,a.price,a.fee,a.request_id)
    elif op=="cancel-fill":
        result=buyer.cancel(a.quote,None if a.offline else request)
    elif op=="fill-status":
        result=buyer.status(a.quote)
    else:
        result=buyer.fill(a.quote,request,a)
        if not a.prepare_only and not a.no_submit and result["state"]!="confirmed":
            submit(home,a.node,result)
    publish(dict(result,private_transport=meters))



def submit(home,node,result):
    sys.path.insert(0,str(home/"deployment/devnet"))
    from transport import rpc
    wire=Path(result["packet"]).read_bytes()
    ident=sha256(wire).hexdigest()
    need(result["sha256"]==ident,"wrong recovered bundle identity")
    meter={}
    port=json.loads((home/"network.json").read_bytes())["ports"][node]
    reply,_=rpc(port,"submit",wire,meter=meter)
    need(reply["id"]==ident,"unexpected node acknowledgement")
    result.update(submit=meter,ack=ident)
