"""Replay a completed native-for-token local lab and compare real assignments inside one-seed namespaces."""
import argparse
from contextlib import closing,ExitStack
import json
import os
from pathlib import Path
import resource
import secrets
import struct
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
EX=HERE.parents[1]
ROLES=("ordinary","leg-a","leg-b","onward")


def worker(name):
    sys.path[:0]=[str(HERE),"/deploy/devnet",str(EX/"funded-whir/wallet")]
    from check import e,full
    from fixtures import Inventory, actor, compact, inputs, private_capture, selected_blocks, swap_policy, tail_statement
    import chain,history,managed_ops,runtime,swap_wire
    from run import Resources
    require=e.require
    cfg=runtime.config(Path("/deploy/runtime"))
    sw=swap_policy()
    seed=Path("/owner/seed")
    profile="SLG1" if name.startswith("leg-") else "MNG1"
    holders={"ordinary":"miner-a","leg-a":"alice","leg-b":"bob","onward":"alice"}
    receiver={"ordinary":"alice","leg-a":"bob","leg-b":"alice","onward":"bob"}[name]
    owner=holders[name]
    metadata=json.loads(Path("/peers/ledger.json").read_text())
    head=metadata["tips"]["swap_included" if name=="onward" else "common"]
    if not __debug__:raise RuntimeError("enable assertions")
    with ExitStack() as stack:
        roles=stack.enter_context(closing(Resources(cfg)))
        ledger=stack.enter_context(closing(chain.Chain(Path("/tmp/public.sqlite"),roles.backend)))
        native,address=stack.enter_context(actor(cfg.binary,cfg.keys,seed))
        require(address==(Path("/peers")/owner).read_bytes(),"wrong private role")
        own=Inventory(roles.h,{owner:native})
        for page in selected_blocks(ledger,Path("/source"),head):
            for blk in history.decode_range(page):
                own.apply(blk)
        hdr=blk["header"]
        assert roles.h.call(b"H"+hdr).hex()==head["anchor"]
        verifier=stack.enter_context(sw.actor("verify"))
        asset=bytes.fromhex(metadata["asset_ids"]["managed"])
        zero=bytes(32)
        if name=="onward":
            parts=swap_wire.pair(swap_wire.split(Path("/source/swap.bin").read_bytes()))
            leg=sw.verify(verifier,parts[1].leg)
            sw.opened(native,leg,0,8,zero,0)
            origin=leg.cms[0]+leg.cts[0]
            nf=native.call(b"D"+origin)[3:35]
            rows=[own.live[owner][nf]]
            assert rows[0]["origin"]==origin
        else:
            rows=inputs(own.live[owner],"ordinary" if name=="ordinary" else owner,asset)
        native_out={"ordinary":5,"leg-a":0,"leg-b":8,"onward":5}[name]
        token_out=20 if name=="leg-a" else 10 if name=="ordinary" and any(r["token"] for r in rows) else 0
        fee=0 if name=="leg-a" else 3
        keys=cfg.keys if profile=="MNG1" else Path("/deploy/swap-keys")
        nonce=secrets.token_bytes(32)
        prefix=b"K" if profile=="MNG1" else b"P"+nonce+bytes([fee])
        req=prefix+hdr+struct.pack("<QQ",native_out,token_out)+(asset if token_out else zero)+(
            bytes(8) if profile=="MNG1" else b"")+(Path("/peers")/receiver).read_bytes()+compact(rows)
        fifo=Path("/tmp/capture")
        os.mkfifo(fifo,0o600)
        fd=os.open(fifo,os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
        stack.callback(os.close,fd)
        with actor(Path("/capture/native"),keys,seed,fifo) as (wallet,restored):
            assert restored==address
            bound_key=wallet.call(b"E"+nonce) if profile=="SLG1" else None
            packet=wallet.call(req)
            w=private_capture(os.read(fd,8192),profile)
        if profile=="MNG1":
            effect,=roles.backend.verify(managed_ops.wrap(packet,"transfer",chain.NETWORK))
        else:
            effect=sw.verify(verifier,packet)
            assert effect.public==bound_key
        assert effect.anchor.hex()==head["anchor"] and effect.height==head["height"] and effect.fee==fee
        assert list(effect.nfs[:len(rows)])==[r["nf"] for r in rows]
        assert tail_statement(packet,profile)==struct.pack(f"<{len(w['public'])}Q",*w["public"])
        assert struct.pack("<4Q",*w["header"][13:17])==hdr[-32:]
        params=e.f.constants(Path("/constants.rs"))
        programs=[e.compile_program(profile,params,e.f.blank(profile),direct,register=True)[1] for direct in (False,True)]
        report=full(profile,params,w,programs,packet[-3584:])
        report.update(released_proof_verified=True,selected_pow_history_replayed=True,
                      preexisting_funded_nullifiers_match=True,one_seed_mount=True)
        # Constant public result schema. Private fields, positions, openings and assignment bytes stay here.
        print(json.dumps(report,sort_keys=True))


def run(a):
    home=a.home.resolve(strict=True)
    meta=json.loads((home/"public/RUN.json").read_text())
    out={}
    for name in ROLES:
        owner="miner-a" if name=="ordinary" else "bob" if name=="leg-b" else "alice"
        seed=home/("wallets" if owner=="miner-a" else "owner-backups")/owner/"seed"
        with tempfile.TemporaryDirectory(prefix="packed-public-peers-") as tmp:
            peer=Path(tmp)
            for who in ("miner-a","alice","bob"):
                (peer/who).write_bytes((home/"wallets"/who/"address").read_bytes())
            # No private inventory, return indices or negotiated addresses in the public metadata.
            (peer/"ledger.json").write_text(json.dumps(dict(tips={k:meta["tips"][k] for k in ("common","swap_included")},
                                                            asset_ids=meta["asset_ids"])))
            mounts={Path("/usr"):"/usr",Path("/lib"):"/lib",Path("/lib64"):"/lib64",Path("/bin"):"/bin",
                    Path("/etc/ld.so.cache"):"/etc/ld.so.cache", HERE:"/src/experiments/packed-tcith/encoding",
                    EX/"funded-whir/wallet":"/src/experiments/funded-whir/wallet",
                    EX/"funded-whir/relation":"/src/experiments/funded-whir/relation",
                    EX/"spend-proof-decision/whir_port.py":"/src/experiments/spend-proof-decision/whir_port.py",
                    EX/"atomic-swap/swap_wire.py":"/src/experiments/atomic-swap/swap_wire.py",
                    EX/"atomic-swap/wallet":"/src/experiments/atomic-swap/wallet",
                    seed:"/owner/seed",home/"deployment":"/deploy",home/"public/blocks":"/source/public/blocks",
                    home/"public/SWAP.bin":"/source/swap.bin",peer:"/peers",a.constants:"/constants.rs",
                    a.capture/("leg" if name.startswith("leg-") else "ordinary")/"native":"/capture/native"}
            cmd=["bwrap","--unshare-all","--die-with-parent","--new-session","--cap-drop","ALL","--clearenv",
                 "--setenv","PATH","/usr/bin:/bin","--setenv","LANG","C","--setenv","RAYON_NUM_THREADS","2",
                 "--proc","/proc","--dev","/dev","--tmpfs","/tmp"]
            for src,dest in mounts.items():
                cmd+=["--ro-bind",str(src.resolve(strict=True)),dest]
            cmd+=["--remount-ro","/","--chdir","/","--","/usr/bin/python3","-IB",
                  "/src/experiments/packed-tcith/encoding/funded.py","--worker",name]
            result=json.loads(subprocess.check_output(cmd))
            expected_flags=("both_frozen_shapes_identical_to_registration","both_accept_all_full_witness_rows",
                            "all_real_paths_match_authenticated_root","direct_and_quadratic_all_path_roots_equal",
                            "both_packed_global_maps_checked","coherent_local_port_substitution_rejected",
                            "nonzero_padded_word_rejected","ordered_receipt_hash_matches","changed_receipt_rejected",
                            "released_proof_verified","selected_pow_history_replayed","preexisting_funded_nullifiers_match",
                            "one_seed_mount")
            assert set(result)=={"public_words","packing_width",*expected_flags}
            assert result["public_words"]==(34 if name.startswith("leg-") else 31) and result["packing_width"]==101
            assert all(result[k] is True for k in expected_flags)
            out[name]=result
            print(f"{name} passed registered and direct constraints on a selected funded input",file=sys.stderr,flush=True)
    return out


if __name__=="__main__":
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if not __debug__:raise SystemExit("enable assertions")
    if sys.argv[1:2]==["--worker"]:
        worker(sys.argv[2])
    else:
        p=argparse.ArgumentParser(description=__doc__)
        for k in ("home","capture","constants"):
            p.add_argument(k,type=Path)
        print(json.dumps(run(p.parse_args()),indent=2))
