"""Mine proof-independent experimental cores and replay them from genuine direct or detached APV2 evidence."""
import argparse
from dataclasses import dataclass, replace
from hashlib import sha256, sha3_256
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from build import CAPTURE, Resources, chain, runtime, selected
from state import Frontier
from wire import canonical, need, u32, u64
from transport import frame

MAGIC=b"PQANNX01"
ARCHIVE=b"PQANNAR1"
ZERO=bytes(32)


def word(domain,*parts):
    return sha256(domain+b"\0"+b"".join(parts)).digest()


def statement(network,s):
    return sha3_256(b"PQANN1/statement\0"+network+s.anchor+u32(s.height)+s.transition()+
                    sha3_256(b"".join(s.cts)).digest()).digest()


def catalog(public,network,packets):
    certs={}
    for p in packets:
        for s in public.verify(p):
            certs[statement(network,s)]=s
    return certs


@dataclass(frozen=True)
class State:
    height: int
    tip: bytes
    header: bytes
    anchors: dict
    cms: frozenset
    spent: frozenset
    count: int
    frontier: bytes
    fees: int


def prefix(public):
    """Every preactivation ancestor is a fully verified original block, starting at original genesis."""
    winning=json.loads((CAPTURE/"RESULT.json").read_bytes())["winning"]
    with tempfile.TemporaryDirectory() as d:
        node=chain.Chain(Path(d)/"node.sqlite",public)
        try:
            for h in winning[:3]:
                raw=(CAPTURE/"blocks"/(h+".bin")).read_bytes()
                assert chain.block_id(raw).hex()==h
                node.accept(raw)
            hd=node.db.execute("SELECT * FROM blocks JOIN sel USING(id) ORDER BY sel.h DESC LIMIT 1").fetchone()
            anchors=dict(node.db.execute("SELECT s.h,b.ap FROM sel s JOIN blocks b USING(id)"))
            return State(3,hd["id"],hd["header"],anchors,
                         frozenset(r[0] for r in node.db.execute("SELECT cm FROM outs")),
                         frozenset(r[0] for r in node.db.execute("SELECT nf FROM spent")),
                         hd["n"],hd["front"],hd["fees"])
        finally:
            node.close()


class Fork:
    def __init__(self,bits,activation,backend):
        need(bits in (8,22),"supported test difficulty")
        self.bits,self.backend=bits,backend
        self.network=word(b"PQANN1/network",chain.NETWORK,chain.PROFILE,activation.tip,u32(4),bytes([bits]))
        self.threshold=((1<<(256-bits))-1).to_bytes(32,"big")

    def transition(self,prev,miner,refs,certs):
        need(len(refs)<=chain.MAX_TX and canonical(miner) and miner!=ZERO,"miner or capacity")
        need(all(i in certs for i in refs),"missing verified statement")
        height=prev.height+1
        slots=[certs[i] for i in refs]
        new_nfs=set()
        new_cms=set()
        tree=Frontier(prev.count,prev.frontier,self.backend.hashes)
        for s,i in zip(slots,refs,strict=True):
            need(statement(self.network,s)==i and s.fee==chain.FEE,"statement or fee")
            need(1<=height-s.height<=chain.WINDOW,"inclusion anchor age")
            need(prev.anchors.get(s.height)==s.anchor,"inclusion anchor branch")
            for nf in s.nfs:
                need(nf not in prev.spent and nf not in new_nfs,"spent input")
                new_nfs.add(nf)
            for cm in s.cms:
                need(cm not in prev.cms and cm not in new_cms,"duplicate commitment")
                new_cms.add(cm)
                tree.append(cm)
        fees=sum(s.fee for s in slots)
        gross=chain.SUBSIDY+fees
        total=prev.fees+fees
        need(gross<2**62 and total+height*chain.SUBSIDY<2**63,"issuance bounds")
        vec=bytes([len(refs)])+b"".join(refs)
        ctx=word(b"PQANN1/reward",self.network,prev.tip,u32(height),miner,sha256(vec).digest())
        opening=ctx+miner+u64(gross)
        cm=self.backend.hashes.call(b"C"+opening)
        need(canonical(cm) and cm!=ZERO and cm not in prev.cms and cm not in new_cms,"reward commitment")
        new_cms.add(cm)
        tree.append(cm)
        state=chain.digest(b"annex-state",self.network,prev.header[36:68],u64(tree.count),u64(height*chain.SUBSIDY),
                           u64(total),opening+cm,b"".join(s.transition() for s in slots))
        template=MAGIC+self.network+bytes([self.bits])+prev.tip+u32(height)+miner+u64(gross)+cm+state+tree.root()+vec
        return template,prev.cms|new_cms,prev.spent|new_nfs,tree,total

    def seal(self,template):
        inner=b"PQANN1/work\0"+sha256(template).digest()
        for n in range(2**64):
            nonce=u64(n)
            if sha256(inner+nonce).digest()<=self.threshold:
                return template+nonce
        raise RuntimeError("nonce space exhausted")

    def accept(self,prev,raw,certs):
        need(len(raw)>=222 and raw[213]<=chain.MAX_TX and len(raw)==222+32*raw[213],"core framing")
        bid=word(b"PQANN1/work",sha256(raw[:-8]).digest(),raw[-8:])
        need(bid<=self.threshold,"proof of work")
        refs=[raw[i:i+32] for i in range(214,len(raw)-8,32)]
        expected,cms,spent,tree,total=self.transition(prev,raw[77:109],refs,certs)
        need(raw[:-8]==expected,"consensus core transition")
        h=prev.height+1
        header=prev.anchors[prev.height]+u32(h)+raw[149:181]+chain.digest(b"annex-seal",self.network,bid)+raw[181:213]
        ap=self.backend.header_id(header)
        return State(h,bid,header,{**prev.anchors,h:ap},cms,spent,tree.count,tree.encode(),total)

    def make(self,prev,miner,refs,certs):
        raw=self.seal(self.transition(prev,miner,refs,certs)[0])
        return raw,self.accept(prev,raw,certs)


def pack(cores,sidecars):
    def rows(items):
        return u32(len(items))+b"".join(u32(len(p))+p for p in items)
    return ARCHIVE+rows(cores)+rows(sidecars)


def unpack(raw):
    need(raw.startswith(ARCHIVE),"archive tag")
    at=8
    def rows():
        nonlocal at
        def integer():
            nonlocal at
            need(at+4<=len(raw),"archive truncated")
            n=int.from_bytes(raw[at:at+4],"little")
            at+=4
            return n
        n=integer()
        need(n<=(len(raw)-at)//4,"archive count")
        items=[]
        for _ in range(n):
            size=integer()
            need(0<size<=chain.MAX_BLOCK and at+size<=len(raw),"archive record length")
            items.append(raw[at:at+size])
            at+=size
        return items
    cores,annex=rows(),rows()
    need(at==len(raw),"archive trailing data")
    return cores,annex


def check_archive(fork,initial,blob):
    # No previously checked verdict or singleton packet is supplied to the fresh verifier.
    cores,annex=unpack(blob)
    certs=catalog(fork.backend,fork.network,annex)
    state=initial
    for core in cores:
        state=fork.accept(state,core,certs)
    return state


def rejected(call,reason):
    try:
        call()
    except ValueError as err:
        need(str(err)==reason,"unexpected refusal "+str(err))
        return
    raise AssertionError("unexpected acceptance")


def run(args):
    res=Resources(runtime.config(args.runtime))
    try:
        proof=args.certificate.read_bytes()
        source=selected()
        requested=[r[2] for r in source[1:]]
        start=prefix(res.backend)
        fork=Fork(args.bits,start,res.backend)
        certs=catalog(res.backend,fork.network,requested)
        slots=[res.backend.verify(p)[0] for p in requested]
        a,b=[statement(fork.network,s) for s in slots]
        miners=[chain.decode_block((CAPTURE/"blocks"/(h+".bin")).read_bytes()).pk for h in
                json.loads((CAPTURE/"RESULT.json").read_bytes())["winning"][:2]]
        h4,s4=fork.make(start,miners[0],[a],certs)
        h5,end=fork.make(s4,miners[1],[b],certs)
        cores=[h4,h5]
        cold=pack(cores,[proof])
        direct=pack(cores,requested)
        # Use a newly opened verifier after building the accepted direct chain.
        isolated=Resources(runtime.config(args.runtime))
        try:
            independent_start=prefix(isolated.backend)
            assert independent_start==start
            start=independent_start
            replay=Fork(args.bits,start,isolated.backend)
            assert check_archive(replay,start,cold)==check_archive(replay,start,direct)==end
            rejected(lambda:check_archive(replay,start,pack(cores,[])),"missing verified statement")
            bad=bytearray(proof)
            bad[25]^=1
            rejected(lambda:check_archive(replay,start,pack(cores,[bytes(bad)])),"cryptographic payment rejection")
            bad=bytearray(proof)
            bad[-1]^=1
            rejected(lambda:check_archive(replay,start,pack(cores,[bytes(bad)])),"cryptographic payment rejection")
            # Real matching public nullifiers/commitments/fee, altered anchor or receipt.
            for poisoned in (replace(slots[0],anchor=start.anchors[2]),replace(slots[0],cts=slots[1].cts)):
                assert poisoned.transition()==slots[0].transition()
                sid=statement(fork.network,poisoned)
                if args.bits==8:
                    poison=replay.seal(h4[:214]+sid)
                    rejected(lambda:check_archive(replay,start,pack([poison],[proof])),"missing verified statement")
                else:
                    rejected(lambda:replay.transition(start,miners[0],[sid],catalog(isolated.backend,replay.network,[proof])),
                             "missing verified statement")
            rejected(lambda:replay.transition(end,miners[0],[a],certs),"spent input")
            # A different branch can use a subset from the same valid certificate. Unselected
            # slots do not mark inputs spent. Fork choice follows total work, then lowest tip ID.
            f4,t4=replay.make(start,miners[1],[b],certs)
            f5,t5=replay.make(t4,miners[0],[],certs)
            f6,t6=replay.make(t5,miners[1],[],certs)
            views=[(cores,check_archive(replay,start,cold)),([f4,f5,f6],check_archive(replay,start,pack([f4,f5,f6],[proof])))]
            chosen=max(views,key=lambda v:((v[1].height-start.height)*(1<<args.bits),-int.from_bytes(v[1].tip,"big")))[1]
            assert chosen==t6 and not (set(slots[0].nfs)&chosen.spent) and set(slots[1].nfs)<=chosen.spent
            assert end.tip!=chosen.tip
            _,survivor=replay.make(chosen,miners[0],[a],certs)
            assert set(slots[0].nfs)<=survivor.spent
            if args.bits==8:
                while chosen.height<11:
                    _,chosen=replay.make(chosen,miners[0],[],certs)
                rejected(lambda:replay.transition(chosen,miners[0],[a],certs),"inclusion anchor age")
        finally:
            isolated.close()
        if args.out:
            args.out.mkdir(exist_ok=False,parents=True)
            (args.out/"archive.bin").write_bytes(cold)
        submission=[len(frame(dict(op="submit"),p)) for p in requested]
        acks=[len(frame(dict(ok=True,result=dict(id=sid.hex(),duplicate=False)))) for sid in (a,b)]
        data=dict(fixture_bits=args.bits,original_prefix_H=start.height,original_prefix_tip=start.tip.hex(),
                  standalone_validated_H=[4,5],fallback_after_fork_H=survivor.height,
                  two_payment_final_tip=end.tip.hex(),fees_in_new_two_blocks=end.fees-start.fees,
                  final_root=end.header[-32:].hex(),final_count=end.count,certificate_slots=3,used_slots=2,
                  unaffiliated_certificate_slot_inert=True,fresh_aggregate_and_individual_replays_equal=True,
                  proof_poison_rejected=True,receipt_poison_rejected=True,
                  wrong_anchor_same_effects_rejected=True,wrong_receipt_same_effects_rejected=True,
                  poisoned_cores_resealed=args.bits==8,expired_unspent_refusal=args.bits==8,spent_replay_rejected=True,
                  true_work_fork_reselected=True,missing_archive_evidence_rejected=True,
                  canonical_core_B=list(map(len,cores)),raw_input_packets_B=list(map(len,requested)),
                  modeled_submit_request_B=submission,modeled_submit_reply_B=acks,
                  alternative_direct_archive_B=len(direct),detached_archive_B=len(cold),
                  certificate_B=len(proof),archive_sha256=sha256(cold).hexdigest(),core_hex=[c.hex() for c in cores])
        print(json.dumps(data,indent=2,sort_keys=True))
    finally:
        res.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--certificate",type=Path,required=True)
    p.add_argument("--bits",type=int,choices=(8,22),default=8)
    p.add_argument("--out",type=Path)
    run(p.parse_args())
