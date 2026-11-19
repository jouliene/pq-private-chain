"""Build or replay D8C1 certificates over an ordered public DLF1 packet directory."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from certrole import CertificateBuilder,CertificateVerifier,ROOT,sha,wire


def save(path,data):
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    tmp.replace(path)


def require(ok,why):
    if not ok:
        raise ValueError(why)


def rejected(fn):
    try:
        fn()
    except ValueError:
        return True
    raise ValueError("invalid certificate/source passed")


def direct_effects(deploy,items):
    # Use the actual verifier-only DLF1 executable inside its own isolated role.
    sys.path.insert(0,str(deploy/"devnet"))
    import runtime
    cfg=runtime.config(deploy/"runtime")
    role=wire.Role(cfg.binary,cfg.binary_sha,["verify","/keys"],cfg.keys)
    try:
        out=[]
        for packet in items:
            r=role.call(packet)
            require(r[:1]==b"1" and len(r)==3757,"source DLF1 verification failed")
            out.append(r[1:])
        return out,role.close()
    finally:
        role.abort()


def run(a):
    indices=sorted({i for group in a.groups for i in group})
    packets={i:(a.packets/f"{i}.bin").read_bytes() for i in indices}
    require(len({sha256(p).digest() for p in packets.values()})==len(indices),"distinct public sources required")
    observed,source_meters=direct_effects(a.deploy,packets.values())
    truth=dict(zip(indices,observed,strict=True))
    sample=packets[indices[0]]
    binary=a.runtime/"native"
    binary_sha=json.loads((a.runtime/"BUILD.json").read_bytes())["binary_sha256"]
    require(sha(binary)==binary_sha,"builder binary receipt")
    result=dict(profile="D8C1",source_packet_sha256={i:sha256(p).hexdigest() for i,p in packets.items()},direct_verification=source_meters,
                source_bytes={i:len(p) for i,p in packets.items()},certificate={},negative={})
    if not a.replay:
        a.out.mkdir(parents=True,exist_ok=False)
        start=time.monotonic()
        with CertificateBuilder(binary,binary_sha,a.keys) as b:
            result["builder_ready_wall_s"]=time.monotonic()-start
            for group in a.groups:
                k=len(group)
                begin=time.monotonic()
                cert=b.prove([packets[i] for i in group])
                end=time.monotonic()
                # Publish the complete file only: downstream replayers may already be waiting.
                tmp=a.out/f"occupancy-{k}.part"
                tmp.write_bytes(cert)
                tmp.replace(a.out/f"occupancy-{k}.bin")
                result["certificate"][str(k)]=dict(proving_call_wall_s=end-begin)
            result["negative"]["duplicate_funded_source"]=rejected(lambda:b.prove([sample,sample]))
            bad=bytearray(sample);bad[-1]^=1
            result["negative"]["source_receipt_swap"]=rejected(lambda:b.prove([bytes(bad)]))
        result["builder_meters"]=b.meters
        result["builder_pipe_in_out_B"]=b.role.sizes
    start=time.monotonic()
    with CertificateVerifier(binary,binary_sha,a.keys) as v:
        result["verifier_ready_wall_s"]=time.monotonic()-start
        for group in a.groups:
            k=len(group)
            data=(a.out/f"occupancy-{k}.bin").read_bytes()
            begin=time.monotonic()
            observed=v.verify(data)
            end=time.monotonic()
            require(observed==[truth[i] for i in group],"archive and direct authorization differ")
            proof_len=int.from_bytes(data[5:9],"little")
            require(len(data)==9+proof_len+k*3584,"certificate length")
            result["certificate"].setdefault(str(k),{}).update(certificate_B=len(data),proof_B=proof_len,
                source_indices=group,framing_B=9,ciphertexts_B=k*3584,active_count=k,certificate_sha256=sha256(data).hexdigest(),
                equal_all_direct_effects_and_ciphertexts=True,verify_pipe_wall_s=end-begin,
                anchors=[int.from_bytes(row[32:36],"little") for row in observed])
            tests={}
            for name,i in (("opening",35),("last_public_input",9+proof_len-8),("last_receipt",len(data)-1)):
                bad=bytearray(data);bad[i]^=1
                tests[name]=rejected(lambda:v.verify(bytes(bad)))
            if k>1:
                wrong=data[:4]+bytes([k-1])+data[5:-3584]
                tests["truncated_declared_active_count"]=rejected(lambda:v.verify(wrong))
                changed=data[:9+proof_len]+data[9+proof_len+3584:]+data[9+proof_len:9+proof_len+3584]
                tests["rotated_real_receipts"]=rejected(lambda:v.verify(changed))
            result["negative"]["certificate_"+str(k)]=tests
    result["verifier_meters"]=v.meters
    result["verifier_pipe_in_out_B"]=v.role.sizes
    if a.replay:
        print(json.dumps(result,indent=2,sort_keys=True))
    else:
        save(a.out/"CERTIFICATES.json",result)
        print(json.dumps(result["certificate"],sort_keys=True))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("runtime","keys","deploy","packets","out"):
        p.add_argument(name,type=lambda v:Path(v).resolve())
    p.add_argument("--groups",nargs="+",type=lambda s:[int(i) for i in s.split(",")],
                   default=[list(range(8)),[7,8]],help="ordered comma-separated source indices for each certificate")
    p.add_argument("--replay",action="store_true")
    a=p.parse_args()
    require(a.groups and all(1<=len(g)<=8 and len(set(g))==len(g) and min(g)>=0 for g in a.groups) and
            len(a.groups)==len({len(g) for g in a.groups}),"choose distinct widths 1..8 and nonrepeated sources")
    run(a)
