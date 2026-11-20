"""Fresh matched ordinary and swap proofs from a replayed, mined funded common branch."""
import argparse
from contextlib import ExitStack, closing, contextmanager
from hashlib import sha256
from itertools import combinations
from pathlib import Path
import io
import json
import os
import resource
import secrets
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ZERO = bytes(32)
CT = 1792


def need(test, message):
    if not test:
        raise ValueError(message)


def private_capture(raw, suite):
    rd = io.BytesIO(raw)

    def take(n):
        data = rd.read(n)
        need(len(data) == n, "truncated anonymous capture")
        return data

    def words(n):
        return list(struct.unpack(f"<{n}Q", take(8*n)))

    def number():
        return words(1)[0]

    need(len(raw) <= 8192 and take(6) == b"FWIT01" and number() == 45, "wallet capture header")
    w = dict(suite=suite, header=words(45), depth=number(), inputs=[], outputs=[])
    for _ in range(2):
        n = {key:words(4) for key in ("ask","nk","rho","raw")}
        n["value"], n["token"], dummy, levels = words(4)
        need(dummy in (0, 1) and levels <= 20, "input dimensions")
        n.update(dummy=bool(dummy), positions=[], siblings=[])
        for _ in range(levels):
            n["positions"].append(number())
            n["siblings"].append([words(4) for _ in range(3)])
        w["inputs"].append(n)
    for _ in range(2):
        w["outputs"].append(dict(pk=words(4), raw=words(4), value=number(), token=number()))
    w["asset_id"] = words(4)
    w["fee"], w["delta"], keylen = words(3)
    need(keylen == (8 if suite=="SLG1" else 0), "auth key dimensions")
    w["auth_key"], w["ct_digest"] = words(keylen), words(4)
    n = number()
    need(n == (34 if suite=="SLG1" else 31), "public vector dimensions")
    w["public"] = words(n)
    need(not rd.read(), "trailing witness data")
    return w


@contextmanager
def actor(binary, keys, seed, fifo=None):
    """Read-only seed mount, bounded kernel FIFO, and no inherited witness descriptor."""
    from wallet import _wire
    role = object.__new__(_wire.Role)
    binary = binary.resolve(strict=True)
    cmd = ["bwrap","--unshare-all","--die-with-parent","--new-session","--cap-drop","ALL",
           "--clearenv","--setenv","LANG","C","--setenv","RAYON_NUM_THREADS","2","--dev","/dev",
           "--proc","/proc","--ro-bind",str(binary),"/native","--ro-bind",str(keys),"/keys",
           "--ro-bind",str(seed.resolve(strict=True)),"/private/seed"]
    for lib in _wire.libraries(binary):
        cmd += ["--ro-bind",str(lib.resolve()),str(lib)]
    if fifo:
        cmd += ["--bind",str(fifo),"/assignment"]
    cmd += ["--remount-ro","/","--chdir","/","--","/native","wallet","/keys","/private/seed","restore"]
    role.errors = tempfile.TemporaryFile()
    role.proc = subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=role.errors)
    role.name,role.sizes,role.times,role.closed = "wallet",[0,0],[],False
    try:
        address = role.get()
        need(len(address)==1601,"restore failed")
        yield role,address
        role.meters=role.close()
    finally:
        role.abort()


class Inventory:
    """In-memory openings and live paths reconstructed from independently validated history."""
    def __init__(self, hash_role, owners):
        from wallet_sync import Tree
        self.tree = Tree(0,b"",lambda children:hash_role.call(b"N"+b"".join(children)))
        self.owners = owners
        self.live = {name:{} for name in owners}

    def apply(self, block):
        from wallet_sync import extend_path
        for slot in block["slots"]:
            for owned in self.live.values():
                for nf in slot["nfs"]:
                    owned.pop(nf,None)

        def append(origin, cm):
            index = self.tree.n
            groups,root = self.tree.append(cm)
            for owner,entries in self.live.items():
                for row in entries.values():
                    extend_path(row["path"],row["pos"],index,groups)
                op = self.owners[owner].call(b"D"+origin)
                if op == b"MISS":
                    continue
                need(op[:3] == b"HIT" and len(op)==84,"restored wallet opening")
                value, token, asset = struct.unpack_from("<QQ32s",op,35)
                if value or token:
                    entries[op[3:35]]=dict(nf=op[3:35],value=value,token=token,asset=asset,origin=origin,pos=index,
                        path=[tuple(children[:s]+children[s+1:]) for s,children in groups])
            return root

        for slot in block["slots"]:
            for cm, ct in zip(slot["cms"],slot["cts"],strict=True):
                append(cm+ct,cm)
        reward=block["reward"]
        need(append(reward[:72]+bytes(8)+reward[72:],reward[-32:]) == block["header"][-32:],
             "opened history rebuilt a different funded tree")


def compact(rows):
    data = bytearray([len(rows)])
    for row in rows:
        origin,levels=row["origin"],row["path"]
        data.extend(struct.pack("<HB",len(origin),len(levels))+origin)
        for siblings in levels:
            data.extend(b"".join(siblings))
    return bytes(data)


def selected_blocks(ledger,home,common):
    from chain import GENESIS, block_id, decode_block
    from history import decode_range
    tip = common["tip"]
    prefix=[]
    while tip != GENESIS.hex():
        block=(home/"public/blocks"/(tip+".bin")).read_bytes()
        need(block_id(block).hex()==tip,"funding archive block identity")
        prefix.append(block)
        tip=decode_block(block).parent.hex()
    for block in reversed(prefix):
        need(ledger.accept(block)["selected"],"funding block rejected")
    status=ledger.status()
    need(all(status[k]==v for k,v in common.items()),"funding branch replay differs")
    pages=[]
    start,base=1,GENESIS.hex()
    while start<=common["height"]:
        meta,page=ledger.history_range(common["tip"],start,base,16)
        tail=decode_range(page)[-1]
        pages.append(page)
        start,base=tail["height"]+1,tail["id"].hex()
    return pages


def inputs(owned,kind,asset):
    rows = list(owned.values())
    if kind=="ordinary":
        for a,b in combinations(rows,2):
            if (a["asset"]==asset or b["asset"]==asset) and {a["asset"],b["asset"]}<={ZERO,asset} and a["value"]+b["value"]>8 and a["token"]+b["token"]>10:
                return [a,b]
        # An all-native two-real-input transfer is also an ordinary MNG1 payment.
        pair=[r for r in rows if r["asset"]==ZERO and r["value"]>5][:2]
        need(len(pair)==2,"no two compatible mined ordinary inputs")
        return pair
    return [next(r for r in rows if (r["asset"]==asset and r["token"]>=20 if kind=="alice" else r["asset"]==ZERO and r["value"]>=11))]


def tail_statement(inner,suite):
    size=int.from_bytes(inner[5:9],"little")
    n=31 if suite=="MNG1" else 34
    need(inner[:5]==suite.encode()+b"\1" and len(inner)==9+size+2*CT,"released proof frame")
    end=9+size
    # Plonky2 ProofWithPublicInputs encodes its final public vector with usize/u64 length.
    need(int.from_bytes(inner[end-8*n-8:end-8*n],"little")==n,"released public vector width")
    return inner[end-8*n:end]


def metered(cmd, payload=None):
    before=time.monotonic()
    with tempfile.TemporaryFile(mode="w+") as metrics:
        command=["/usr/bin/time","-o",f"/proc/self/fd/{metrics.fileno()}","-f","%U %S %M",*cmd]
        subprocess.run(command,input=payload,check=True,stdout=subprocess.DEVNULL,pass_fds=(metrics.fileno(),))
        metrics.seek(0)
        user,system,rss=metrics.read().strip().split()
    return dict(wall_s=round(time.monotonic()-before,4),user_s=float(user),system_s=float(system),max_rss_KiB=int(rss))


def candidate(role,matrix,suite,statement,receipts,packet,assignment):
    import frontend
    command=[str(role),"prove",suite,str(matrix),str(statement),str(receipts),str(packet)]
    proving=metered(command,frontend.words_as_bytes(assignment))
    verifying=metered([str(role),"verify",suite,str(matrix),str(packet)])
    raw=packet.read_bytes()
    proof_n=int.from_bytes(raw[5:9],"little")
    pi=statement.read_bytes()
    need(raw[:5]==(b"FWT1\1" if suite=="MNG1" else b"FWL1\1") and raw[9:9+len(pi)]==pi
         and len(raw)==9+len(pi)+proof_n+2*CT and raw[-2*CT:]==receipts.read_bytes(),"candidate packet statement/receipts")
    return raw,dict(prove=proving,verify=verifying)


def prove_source(name,suite,worker,request,fifo,rows,out,constants,validate,matrix):
    import frontend
    before=time.monotonic()
    from wallet_sync import role_sample
    pre_cpu=role_sample(worker)
    packet=worker.call(request)
    post_cpu=role_sample(worker)
    released_wall=time.monotonic()-before
    pi=tail_statement(packet,suite)
    before_verify=time.monotonic()
    validated=validate(packet)
    released_verify_wall=time.monotonic()-before_verify
    effect=validated
    prefix=(effect.anchor+struct.pack("<Q",effect.height)+b"".join(effect.nfs)+
            b"".join(effect.cms)+struct.pack("<Q",effect.fee))
    policy=(effect.issue_id+struct.pack("<Q",effect.supply) if suite=="MNG1" else
            struct.pack("<8Q",*struct.unpack("<8I",effect.public)))
    need(pi[:22*8]==prefix and pi[26*8:]==policy and b"".join(effect.cts)==packet[-2*CT:],
         "released verifier projection differs from proof statement")
    w=private_capture(os.read(fifo,8192),suite)
    need(pi==struct.pack(f"<{len(w['public'])}Q",*w["public"]),"witness public vector differs from released proof")
    need(all(not w["inputs"][i]["dummy"] for i in range(len(rows))) and all(
        r["nf"]==pi[(5+4*i)*8:(9+4*i)*8] for i,r in enumerate(rows)),"real mined source nullifier mismatch")
    before_frontend=time.monotonic()
    assigned=frontend.assign(suite,constants,w)
    frontend_wall=time.monotonic()-before_frontend
    released_and_frontend=time.monotonic()-before
    control={}
    if name != "leg-b":
        import importlib.util
        spec=importlib.util.spec_from_file_location("funded_wallet_controls",HERE.parent/"relation/controls.py")
        checks=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checks)
        control=checks.check_funded(suite,constants,matrix,w)
    print(f"{name}: released proof and funded constraint checks passed",file=sys.stderr,flush=True)
    (out/(name+".released")).write_bytes(packet)
    (out/(name+".statement")).write_bytes(pi)
    (out/(name+".receipts")).write_bytes(packet[-2*CT:])
    return packet,assigned,validated,dict(real_inputs=len(rows),private_assignment_words=len(assigned),public_words=len(w["public"]),
        released_prove=dict(wall_s=round(released_wall,4),cpu_s=round(post_cpu[0]-pre_cpu[0],4),max_rss_KiB=post_cpu[1]),released_warm_verify_wall_s=round(released_verify_wall,4),released_packet_B=len(packet),released_packet_sha256=sha256(packet).hexdigest(),capture_and_frontend_wall_s=round(released_and_frontend,3),frontend_wall_s=round(frontend_wall,4),private_matrix_control=control)


def start_owner(name,env,a,params,output,workspace):
    """Give the process one seed, registered code, shared read-only public exchange and its own output."""
    seed=(a.home/"wallets/miner-a/seed" if name=="ordinary" else
          a.home/"owner-backups"/("alice" if name in ("leg-a","restore-a") else "bob")/"seed")
    suite="MNG1" if name in ("ordinary","restore-a") else "SLG1"
    owner_output=workspace/name
    owner_output.mkdir(mode=0o700)
    sources = {Path("/usr"):"/usr", Path("/bin"):"/bin",Path("/lib"):"/lib", Path("/lib64"):"/lib64",
               Path("/etc/ld.so.cache"):"/etc/ld.so.cache", HERE:"/src/experiments/funded-whir/wallet",
               HERE.parent/"relation":"/src/experiments/funded-whir/relation",
               HERE.parent/"packet.py":"/src/experiments/funded-whir/packet.py",
               HERE.parents[1]/"spend-proof-decision/whir_port.py":"/src/experiments/spend-proof-decision/whir_port.py",
               HERE.parents[1]/"atomic-swap/swap_wire.py":"/src/experiments/atomic-swap/swap_wire.py",
               a.home/"deployment":"/deploy",a.home/"public/blocks":"/origin/public/blocks",seed:"/owner/seed",params:"/peers",output:"/exchange",
               a.role:"/candidate",a.matrix/"MNG1.r1cs":"/matrix/MNG1.r1cs",a.matrix/"SLG1.r1cs":"/matrix/SLG1.r1cs",
               a.capture/("ordinary" if suite=="MNG1" else "leg")/"native":"/capture/native",
               a.constants:"/constants.rs"}
    cmd=["bwrap","--unshare-all","--die-with-parent","--new-session","--cap-drop","ALL","--clearenv",
         "--setenv","PATH","/usr/bin:/bin","--setenv","LANG","C","--setenv","RAYON_NUM_THREADS","2",
         "--proc","/proc","--dev","/dev","--tmpfs","/tmp"]
    for path,dest in sources.items():
        cmd+=["--ro-bind",str(path.resolve(strict=True)),dest]
    cmd+=["--bind",str(owner_output),"/own","--remount-ro","/","--chdir","/","--",
          "/usr/bin/python3","-IB","/src/experiments/funded-whir/wallet/owner.py",name,suite]
    proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    if env is not None:
        proc.stdin.write(env.hex()+"\n")
        proc.stdin.flush()
    return proc


def exchange(proc, command, expected):
    if command:
        proc.stdin.write(command+"\n")
        proc.stdin.flush()
    need(proc.stdout.readline().strip()==expected,"owner did not confirm "+expected)


def run(a):
    import shutil
    for k in vars(a):
        setattr(a,k,getattr(a,k).resolve(strict=True) if k!="output" else getattr(a,k).resolve())
    out=a.output
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    deploy=a.home/"deployment"
    sys.path.insert(0,str(deploy/"devnet"))
    import chain,history,managed_ops,runtime,swap_wallet,swap_wire
    from run import Resources
    sys.path.insert(0,str(HERE.parent))
    import packet
    run=json.loads((a.home/"public/RUN.json").read_text())
    common=run["tips"]["common"]
    expiry=common["height"]+4
    salt=secrets.token_bytes(32)
    network=chain.NETWORK
    asset=bytes.fromhex(run["asset_ids"]["managed"])
    roster={name:(a.home/"wallets"/name/"address").read_bytes() for name in ("miner-a","alice","bob")}
    need(len(set(roster.values()))==3,"funded roles must have distinct spending keys")
    terms=commitment(network,asset,expiry,salt,roster)
    names=("ordinary","leg-a","leg-b")
    with tempfile.TemporaryDirectory(prefix="funded-workers-") as temp,ExitStack() as stack:
        temp=Path(temp)
        params=temp/"peers"
        params.mkdir(mode=0o700)
        for name,address in roster.items():
            (params/name).write_bytes(address)
        roles=stack.enter_context(closing(Resources(runtime.config(deploy/"runtime"))))
        ledger=stack.enter_context(closing(chain.Chain(temp/"public.sqlite",roles.backend)))
        pages=selected_blocks(ledger,a.home,common)
        for i,page in enumerate(pages):
            (out/f"funded-{i:04}.history").write_bytes(page)
        stable=dict(network=network.hex(),common=common,terms=terms.hex(),expiry=expiry,payer=1,
                    source_blocks=common["height"],profiles={},ordinary_and_swap_parallel_alternatives=True,
                    disposable_fixture_agreement=dict(token_asset=asset.hex(),token_paid_by="a",token_quantity=20,
                    native_paid_by="b",native_quantity=8,fee_paid_by="b",fee=3))
        def save():
            (out/"SOURCE.json").write_text(json.dumps(stable,sort_keys=True,indent=2)+"\n")
        save()
        workers={}
        def stop(proc):
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdin.close()
            proc.stdout.close()
        for name in names:
            workers[name]=p=start_owner(name,salt,a,params,out,temp)
            stack.callback(stop,p)
            exchange(p,None,"prepared")
            for ext in ("candidate","released","statement","receipts"):
                shutil.copyfile(temp/name/(name+"."+ext),out/(name+"."+ext))
            stable["profiles"][name]=json.loads((temp/name/"metrics.json").read_text())
            save()
        ordinary=(out/"ordinary.released").read_bytes()
        normal=managed_ops.wrap(ordinary,"transfer",network)
        miner=bytes.fromhex(run["miner_keys"]["miner-a"])
        ledger.template(miner,packets=[normal])
        checked=stack.enter_context(swap_wallet.actor("verify"))
        parent_digest=None
        previous=[]
        for name in names[1:]:
            exchange(workers[name],"authorize","signed")
        for family in ("released","candidate"):
            legs=[(out/(name+"."+family)).read_bytes() for name in names[1:]]
            sigs=[(temp/name/(family+".signature")).read_bytes() for name in names[1:]]
            digest=swap_wire.digest(network,terms,expiry,1,legs)
            if family=="released":
                bundle=swap_wire.assemble(network,terms,expiry,1,legs,sigs)
                previous=sigs
                parent_digest=digest
            else:
                need(parent_digest!=digest,"released and candidate joint digest collision")
                bundle=packet.assemble(network,terms,expiry,1,legs,sigs)
                aa,bb=packet.validate(bundle,network,common["height"]+1,a.role,a.matrix/"SLG1.r1cs",checked)
                for leg,sig in zip((aa.leg,bb.leg),previous,strict=True):
                    key=struct.pack("<8I",*packet.fields(leg)[26:34])
                    need(checked.call(b"V"+key+digest+sig)==b"0","released signature admitted on candidate")
            (out/(family+".swap")).write_bytes(bundle)
        raw=chain.mine(ledger.template(miner,packets=swap_wire.split((out/"released.swap").read_bytes())))
        need(ledger.accept(raw)["selected"],"freshly mined released swap not selected")
        (out/"released-swap.block").write_bytes(raw)
        mined=ledger.status()
        _,page=ledger.history_range(mined["tip"],common["height"]+1,common["tip"],1)
        (out/"onward.history").write_bytes(page)
        for proc in workers.values():
            need(proc.wait(timeout=30)==0,"funding or negotiation worker did not exit")
        fresh=start_owner("restore-a",None,a,params,out,temp)
        stack.callback(stop,fresh)
        exchange(fresh,None,"restored")
        need(fresh.wait(timeout=30)==0,"restore-only worker failed")
        restored=temp/"restore-a"
        for ext in ("candidate","released","statement","receipts"):
            shutil.copyfile(restored/("onward."+ext),out/("onward."+ext))
        stable["profiles"]["onward"]=json.loads((restored/"metrics.json").read_text())
        save()
        onward=(restored/"restored-onward.transfer").read_bytes()
        need(ledger.offer(onward)["id"]==sha256(onward).hexdigest(),"restored onward spend admission")
        (out/"restored-onward.transfer").write_bytes(onward)
        (out/"COMPLETE.json").write_text(json.dumps(dict(one_seed_per_mounted_namespace=True,
            all_public_equal=True,each_wallet_verified_both_candidates_and_received_output=True,
            released_candidate_same_spent_identity=True,restored_onward_spend_admitted=True,
            fresh_backup_only_process_replayed_from_genesis=True,onward_candidate_fresh_proof_verified=True,
            fresh_candidate_joint_signatures=True,old_signatures_refused=True,swap_mined_at=mined["tip"],
            released_swap_fee=mined["fees"]-common["fees"],ordinary_selected_funded_template=True),indent=2)+"\n")


def commitment(network,asset,expiry,salt,addresses):
    need(len(salt)==32 and len(asset)==32 and asset!=ZERO,"private agreement dimensions")
    return sha256(b"FWIR/disposable-private-terms/v1\0"+salt+network+asset+struct.pack("<QQIB",20,8,expiry,1)
                  +addresses["alice"]+addresses["bob"]).digest()


if __name__=="__main__":
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("home","capture","constants","matrix","role","output"):
        parser.add_argument(key,type=Path)
    run(parser.parse_args())
