"""Check authenticated public depth and retirement of every historical route on a fresh public role."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import sys


def detached(public, deploy, run):
    import chain
    import runtime
    from run import Resources
    from wire import need
    tip = run["tips"]["alternate"]["tip"]
    ancestry = []
    while tip != chain.GENESIS.hex():
        raw = (public/"blocks"/(tip+".bin")).read_bytes()
        need(chain.block_id(raw).hex()==tip, "invalid control ancestry")
        ancestry.append(raw)
        tip = chain.decode_block(raw).parent.hex()
    with TemporaryDirectory() as temp:
        resources = Resources(runtime.config(deploy/"runtime"))
        try:
            db = chain.Chain(Path(temp)/"fork.sqlite",resources.backend)
            try:
                for raw in reversed(ancestry):
                    need(db.accept(raw)["selected"], "alternate selection")
                good = (public/"packets"/(run["operations"]["onward"]["tx"]+".bin")).read_bytes()
                row, = db.verify_single(good,26)
                need(row.height==25 and row.depth==3,"onward proof independently valid")
                before, pool = db.status(),db.pending()
                try:
                    db.offer(good)
                except ValueError as exc:
                    need(str(exc)=="anchor branch","unexpected rejection reason")
                else:
                    raise ValueError("detached C funding accepted")
                need(db.status()==before and db.pending()==pool,"detached funding changed state")
                return {"proof_valid":True, "wrong_branch_height":row.height,"rejection":"anchor branch",
                        "selected_state_and_pool_preserved":True}
            finally:
                db.close()
        finally:
            resources.close()


def controls(public, deploy):
    sys.path.insert(0,str(deploy/"devnet"))
    from chain import Chain
    from consensus import FIRST_C, funded_depth
    from swap_wire import split, read_frame
    from wire import need
    run = json.loads((public/"RUN.json").read_bytes())
    packet = (public/"packets"/(run["operations"]["paid"]["tx"]+".bin")).read_bytes()
    inner = packet[6:]
    pair = split((public/"SWAP.bin").read_bytes())
    # Use the same native verifier, with identical approved key and proof shape, on both inputs.
    from consensus import role
    checks = {}
    for kind,raw in (("managed",inner),("swap",read_frame(pair[0]).leg)):
        verifier = role(kind)
        try:
            correct = verifier.call(raw)
            need(correct[:1]==b"1" and 1 <= correct[-1] <= 20, "valid depth")
            end = 9+int.from_bytes(raw[5:9],"little")
            need(int.from_bytes(raw[end-8:end],"little")==correct[-1],"public depth and role disagree")
            other = 1 if correct[-1] != 1 else 2
            altered = raw[:end-8]+other.to_bytes(8,"little")+raw[end:]
            need(len(raw)==len(altered) and verifier.call(altered)==b"0", "mutated public depth verified")
            checks[kind] = {"verified_depth":correct[-1],"rejected_canonical_depth":other}
        finally:
            verifier.abort()
    aliases = set()
    for raw in (p.read_bytes() for p in (public/"packets").glob("*.bin")):
        if raw.startswith(b"MSP1"):
            aliases.add(("MSP1",raw[5]))
    # Historical structural dispatch must fail before invoking a verifier on or after H25.
    # The old burn/AST1 may be absent in the fixture. Use only version selectors there;
    # this portion tests the prospective dispatcher, not historical proof validity.
    from consensus import MembershipSupport
    for raw in (b"AST1\1",*(b"MSP1\1"+bytes([op]) for op in range(5)),b"MSP2\1"):
        try:
            MembershipSupport.verify_single(None,raw,FIRST_C)
        except ValueError as exc:
            need(str(exc)=="inactive proof suite","legacy retirement reason")
        else:
            raise ValueError("legacy ordinary route remained open")
    for tag in (b"SWF1\1",b"SWF2\1"):
        try:
            MembershipSupport.verify_swap(None,[tag,tag],FIRST_C)
        except ValueError as exc:
            need(str(exc)=="inactive proof suite","legacy swap retirement reason")
        else:
            raise ValueError("legacy swap route remained open")
    for d in range(1,21):
        need(funded_depth(4**d)==d and funded_depth(4**(d-1)+1)==d,"depth boundary")
    return dict(native_transcript_controls=checks, detached_root=detached(public,deploy,run), legacy_dispatch_selectors=9,
                historical_MSP1_operation_codes_in_graph=sorted(v for k,v in aliases), boundary_levels=20)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("public",type=Path)
    p.add_argument("deployment",type=Path)
    args=p.parse_args()
    print(json.dumps(controls(args.public.resolve(strict=True),args.deployment.resolve(strict=True)),sort_keys=True,indent=2))
