"""Check the resident owners' actual coordinator transport, including a funded durable positive."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sgm1-admission"))
import generate
from generate import PublicChannel, funding
from ledger import Ledger
from packets import SIGNATURE, need, parse
from wallet_launcher import run_paired

CASES = (
    "enrollment-kem", "enrollment-identity", "proposal-kem-maker", "proposal-kem-taker",
    "proposal-identity", "descriptor-role-order", "offered-key-order", "different-salts",
    "different-peer-keys", "one-approval", "swapped-approvals", "direct-draft", "prior-session", "unrequested-conflict", "draft-override",
)
DENIED = b'{"error":"rejected"}\n'


def rejected(raw):
    need(raw == DENIED, "unexpected bytes from a denied wallet request")


def probe(frames,role,owner,action,**proposal):
    raw = owner.exchange(action,**proposal)
    rejected(raw)
    frames.append({"role":role,"action":action,"response_bytes":len(raw),"draft_bytes":0})


def denied_drafts(owners,first=None):
    frames = []
    if first:
        action,proposal = first
        for role,owner in enumerate(owners):
            probe(frames,role,owner,action,**proposal)
    for role, owner in enumerate(owners):
        for action in ("draft","conflict") if role==0 else ("draft",):
            probe(frames,role,owner,action)
        owner.writer.close()
        need(owner.reader.read()==b"", "unexpected trailing wallet output")
    return frames


def offchain(public, case, fds):
    public.mkdir()
    with ExitStack() as stack:
        owners = [PublicChannel(r,w) for r,w in zip(fds[::2],fds[1::2],strict=True)]
        for owner in owners:
            stack.callback(owner.close)
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=2))
        pin,_,_,_,desc,_ = funding(public,owners,pool)
        for role, owner in enumerate(owners):
            peer_desc = desc[1-role]
            if case.startswith("enrollment") and role==0:
                proposal = peer_desc[:64]+desc[2][64:] if case=="enrollment-kem" else desc[2]
                rejected(owner.exchange("register",pin=pin.hex(),peer_descriptor=proposal.hex()))
            else:
                owner.call("register",pin=pin.hex(),peer_descriptor=peer_desc.hex())
        if case.startswith("enrollment"):
            owners[1].call("offer",wave=0)
        else:
            offers = [o.call("offer",wave=0) for o in owners]
            authentic = [desc[i].hex() for i in range(2)]
            salt = secrets.token_hex(64)
            attestations = []
            for role, owner in enumerate(owners):
                if case=="direct-draft":
                    break
                descriptors = authentic.copy()
                proposed = [dict(o) for o in offers]
                denied = False
                if case in ("proposal-kem-maker","proposal-kem-taker","proposal-identity"):
                    target = int(case=="proposal-kem-taker")
                    if role==target:
                        peer=1-target
                        descriptors[peer] = ((desc[peer][:64]+desc[2][64:]) if "kem" in case else desc[2]).hex()
                        denied = True
                if case=="descriptor-role-order":
                    descriptors.reverse()
                    denied = True
                if case=="offered-key-order":
                    proposed[0]["key"],proposed[1]["key"] = proposed[1]["key"],proposed[0]["key"]
                    denied = True
                if case=="different-peer-keys":
                    proposed[1-role]["key"] = secrets.token_hex(64)
                view_salt = secrets.token_hex(64) if case=="different-salts" and role==1 else salt
                raw = owner.exchange("agree",descriptors=descriptors,offers=proposed,salt=view_salt)
                if denied:
                    rejected(raw)
                else:
                    a = json.loads(raw)
                    need(set(a)=={"approval","terms"} and len(bytes.fromhex(a["approval"]))==SIGNATURE,
                         "malformed consent")
                    attestations.append(a)
            if len(attestations)==1:
                one = attestations[0]
                for owner in owners:
                    rejected(owner.exchange("unlock",terms=one["terms"],approvals=[one["approval"]]*2))
            if len(attestations)==2:
                consent = [a["approval"] for a in attestations]
                if case=="issue-prior":
                    need(attestations[0]["terms"]==attestations[1]["terms"],"prior session disagreement")
                    (public.parent/"old-consent.json").write_text(json.dumps(consent))
                    return
                if case in ("unrequested-conflict","draft-override"):
                    for i,owner in enumerate(owners):
                        owner.call("unlock",terms=attestations[i]["terms"],approvals=consent)
                    first = ("draft",{"descriptors":authentic[::-1]}) if case=="draft-override" else ("conflict",{})
                    frames = denied_drafts(owners,first)
                    (public/"result.json").write_text(json.dumps({"case":case,"frames":frames,
                        "authorized_terms":True},indent=2)+"\n")
                    return
                if case=="prior-session":
                    consent = json.loads((public.parent/"old-consent.json").read_text())
                elif case=="swapped-approvals":
                    consent.reverse()
                elif case=="one-approval":
                    consent = consent[:1]
                elif case in ("different-salts","different-peer-keys"):
                    need(attestations[0]["terms"]!=attestations[1]["terms"],"split views unexpectedly agree")
                else:
                    raise ValueError("unexpected two-consent case")
                for i,owner in enumerate(owners):
                    rejected(owner.exchange("unlock",terms=attestations[i]["terms"],approvals=consent))
        frames = denied_drafts(owners)
    (public/"result.json").write_text(json.dumps({"case":case,"frames":frames},indent=2)+"\n")


def honest(public,fds,workers):
    observed = []
    class ObservedChannel(PublicChannel):
        def __init__(self,read_fd,write_fd):
            super().__init__(read_fd,write_fd)
            self.role = fds[::2].index(read_fd)

        def exchange(self,action,**kwargs):
            raw = super().exchange(action,**kwargs)
            if action=="draft":
                core = bytes.fromhex(json.loads(raw)["core"])
                need(len(raw)==len(core)*2+len(b'{"core":""}\n'),"unexpected honest response bytes")
                observed.append((self.role,len(raw),hashlib.sha256(core).hexdigest()))
            return raw

    generate.PublicChannel = ObservedChannel
    with redirect_stdout(sys.stderr):
        generate.main(public,workers,2,fds)
    pin = bytes.fromhex((public/"genesis.sha256").read_text().strip())
    database = public.parent/"selected.sqlite"
    db = Ledger(database,public,pin)
    frames = []
    try:
        for height in range(1,21):
            wire = (public/f"op-{height:02}.bin").read_bytes()
            db.admit(wire)
            if height%10==0:
                legs = parse(wire)
                need(len(legs)==2,"honest pair missing")
                for i,leg in enumerate(legs):
                    digest = hashlib.sha256(leg.core).hexdigest()
                    role,raw_size,_ = next(o for o in observed if o[0]==i and o[2]==digest)
                    frames.append({"height":height,"role":role,"draft_bytes":len(leg.core),
                                   "response_bytes":raw_size,"core_sha256":digest})
        tip = db.tip()
        need(tip[0]==20 and len(observed)==len(frames)==4,"incomplete honest evidence")
    finally:
        db.close()
    db = Ledger(database,public,pin)
    try:
        need(db.tip()==tip and db.db.execute("PRAGMA integrity_check").fetchone()==("ok",),"durable reopen failed")
    finally:
        db.close()
    result = {"case":"honest","genesis_sha256":pin.hex(),"height":tip[0],"tip_id":tip[1].hex(),
              "root":tip[2].hex(),"outputs":tip[3],"fees":tip[4],"reopened":True,"frames":frames}
    (public/"result.json").write_text(json.dumps(result,indent=2)+"\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scratch",type=Path)
    p.add_argument("mode",choices=("negative","honest","issue-prior",*CASES))
    p.add_argument("--workers",type=int,choices=range(1,7),default=3)
    p.add_argument("--wallet-fds",nargs=4,type=int,help=argparse.SUPPRESS)
    args = p.parse_args()
    os.umask(0o077)
    scratch = args.scratch.resolve()
    if args.wallet_fds:
        if args.mode=="honest":
            honest(scratch,args.wallet_fds,args.workers)
        else:
            offchain(scratch,args.mode,args.wallet_fds)
        return
    scratch.mkdir()
    cases = ("issue-prior",*CASES) if args.mode=="negative" else (args.mode,)
    if args.mode=="prior-session":
        cases = ("issue-prior","prior-session")
    results = []
    for case in cases:
        public = scratch/case
        run_paired(public,[sys.executable,"-B",Path(__file__).resolve(),public,case,"--workers",str(args.workers)],
                   allow_maker_conflict=(case=="honest"))
        if case!="issue-prior":
            results.append(json.loads((public/"result.json").read_text()))
    if (scratch/"old-consent.json").exists():
        (scratch/"old-consent.json").unlink()
    print(json.dumps(results,indent=2))


if __name__=="__main__":
    main()
