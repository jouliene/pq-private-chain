"""Construct an ordinary payment from fresh signed funding. Retain only the public artifacts."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from payment_codec import EXPERIMENTS, Ordinary, anchor
from relation import FundedTree, Input, Statement, Witness, evaluate, h, new_note, occurrence

HERE = Path(__file__).resolve().parent


def main(directory,native):
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    public = directory/"prefix"
    helper = EXPERIMENTS/"hidden-membership"/"paths"/"funding_fixture.py"
    node = os.environ["FS_RECEIPT_NODE"]
    env = dict(PATH="/usr/bin:/bin",LANG="C",OPENBLAS_NUM_THREADS="1",SW_FIELD="gf256",
               PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=str(native),FS_RECEIPT_NODE=node)
    def clip(cmd,data=None):
        return subprocess.check_output(cmd, input=data,env=env)
    def fund(*args):
        return clip([sys.executable,"-IB",str(helper),*args])
    def kem(mode,data):
        return clip([node, str(EXPERIMENTS/"fresh-spend"/"binding"/"receipt.mjs"),mode],data)
    source = json.loads(fund("new",public))
    pin = hashlib.sha256((public/"genesis.bin").read_bytes()).hexdigest()
    prefix = fund("ledger",public,pin)
    chain,count = prefix[4:68],int.from_bytes(prefix[68:72],"little")
    rows = [(prefix[k:k+64],prefix[k+64:k+128]) for k in range(72,len(prefix),128)]
    tree = FundedTree(rows)
    inputs = []
    for record in source:
        def raw(k):
            return bytes.fromhex(record[k])
        def amount(k):
            return int.from_bytes(raw(k),"little")
        idx = record["index"]
        x = Input(raw("ask"),amount("native"),raw("asset"),amount("qty"),raw("salt"),raw("occ"),
                  idx,tuple(tree.path(idx)))
        if (x.occ,x.note().cm(chain))!=rows[idx]:
            raise ValueError("funded input mismatch")
        inputs.append(x)
    available = sum(x.native for x in inputs)
    issue, = [x for x in inputs if x.qty]
    nfs = tuple(h("nf",x.ask,x.occ) for x in inputs)
    secrets_out = [secrets.token_bytes(64) for _ in range(2)]
    descriptors = [kem("descriptor",chain+seed) for seed in secrets_out]
    outputs = (new_note(descriptors[0][:64],0,issue.asset,7),
               new_note(descriptors[1][:64],available-1,issue.asset,issue.qty-7))
    receipts,contexts = [],[]
    for i,(desc,note) in enumerate(zip(descriptors,outputs)):
        ctx = chain+occurrence(chain,0,nfs,i)+bytes([i])+note.cm(chain)
        receipts.append(kem("seal",ctx+desc+note.encode()))
        contexts.append(ctx)
    cms = tuple(note.cm(chain) for note in outputs)
    body = Ordinary(1,0,anchor(pin,chain,tree.root,count),1,nfs,cms,tuple(receipts))
    intent = body.intent(chain,tree.root,count)
    auth = h("auth",inputs[0].ask,intent)
    s = Statement(chain,tree.root,count,1,nfs,cms,intent,auth)
    w = Witness(tuple(inputs),outputs,1,issue.asset)
    schedule = evaluate(s,w)
    header,packet = directory/"header.bin",directory/"payment.bin"
    head = body.prefix()+auth+body.tails()
    header.write_bytes(head)

    def role(action,private=None,reject=False,sample=""):
        timing = directory/(action+sample+".time")
        cmd = ["/usr/bin/time","-f","%e %U %S %M","-o",str(timing),sys.executable,"-B",
               str(HERE/"payment_role.py"),action,str(public),pin,str(packet),str(header)]
        args = dict(input=private) if private is not None else dict(stdin=subprocess.DEVNULL)
        p = subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=directory,env=env,**args)
        if reject:
            if p.returncode!=1 or b"rejected" not in p.stderr.lower():
                raise RuntimeError("expected rejection")
        elif p.returncode:
            raise RuntimeError(f"payment {action} failed: {p.stderr[-300:].decode()}")
        wall,user,system,rss=timing.read_text().splitlines()[-1].split()
        return dict(wall_s=float(wall),user_s=float(user),sys_s=float(system),peak_KiB=int(rss)),p.stdout

    prover,_ = role("prove",w.encode())
    verifier,public_result = role("verify")
    _,warm = role("warm")
    wire = packet.read_bytes()
    for i,(ctx,seed,note) in enumerate(zip(contexts,secrets_out,outputs)):
        off = 398+i*1792
        if kem("open",ctx+seed+wire[off:off+1792])!=note.encode():
            raise ValueError("sealed receipt failed to open from recipient backup")
    # Preserve framing in every test. Changed receipts and fee feed the recomputed intent.
    for off in (70,398,2190,len(wire)-16):
        changed = bytearray(wire)
        changed[off] ^= 1
        packet.write_bytes(changed)
        role("verify",reject=True,sample="-mutation-"+str(off))
    packet.write_bytes(wire)
    result = dict(ordinary_B=len(wire),proof_B=len(wire)-3990,public_rows=count,
                  private_inputs=2,output_receipts_opened=2,changed_fee_receipts_and_proof_rejected=True,
                  signed_leg_B_if_same_proof=len(wire)-3990+33918,
                  two_owner_bundle_B_if_same_proof=2*(len(wire)-3990)+67856,
                  geometry=json.loads(public_result)["geometry"],prover=prover,cold_verifier=verifier,
                  repeated_public_checks=json.loads(warm)["passes"],
                  genesis_sha256=pin,public_packet_sha256=hashlib.sha256(wire).hexdigest(),
                  reference_keccak_permutations=sum(n*(size//136+1) for (_,size),n in schedule.items()))
    (directory/"metrics.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: payment_run.py NEW_DIRECTORY NATIVE_BUILD_DIRECTORY")
    main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
