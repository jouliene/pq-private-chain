"""Pass private openings to the prover over stdin. The public verifier reads ledger rows."""
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess


def digest(tag,*xs):
    return hashlib.shake_256(bytes((0xf1,tag))+b"".join(xs)).digest(64)


def public_state(directory, genesis_pin, reverse):
    cmd = [sys.executable,"-IB",str(Path(__file__).with_name("funding_fixture.py")),
           "ledger",directory,genesis_pin]
    if reverse:
        cmd.append("reverse")
    b = subprocess.check_output(cmd)
    if len(b)<72 or b[:4]!=b"HMF1":
        raise ValueError("reference funding log")
    chain, count = b[4:68], int.from_bytes(b[68:72],"little")
    if not 2 <= count <= 1024 or len(b)!=72+128*count:
        raise ValueError("invalid bounded fixture")
    rows = [(b[k:k+64],b[k+64:k+128]) for k in range(72,len(b),128)]
    if len(set(occ for occ,_ in rows))!=count:
        raise ValueError("duplicate creation identity")
    nodes = [digest(5,occ,cm) for occ,cm in rows]
    empty = digest(6)
    for j in range(40):
        if len(nodes)%2:
            nodes.append(empty)
        level = bytes([j])
        nodes = [digest(7,level,nodes[k],nodes[k+1]) for k in range(0,len(nodes),2)]
        empty = digest(7,level,empty,empty)
    return chain,nodes[0],count


def main():
    if len(sys.argv) not in (6,7) or (len(sys.argv)==7 and sys.argv[6]!="reverse"):
        raise ValueError("expected registered profile, role, public funding directory, genesis SHA and nullifiers")
    profile, action, directory, genesis_pin, nf_path = sys.argv[1:6]
    if profile not in ("gf16","mixed"):
        raise ValueError("unknown registered profile")
    os.environ["SW_FIELD"] = "gf256" if profile=="mixed" else "gf16"
    from funded import Funded, execute
    chain,root,count = public_state(directory,genesis_pin,len(sys.argv)==7)
    nf_data = Path(nf_path).read_bytes()
    if len(nf_data)!=128:
        raise ValueError("nullifier framing")
    nfs = (nf_data[:64],nf_data[64:])
    if action in ("prove","check-edges"):
        witnesses = json.load(sys.stdin)
        if len(witnesses)!=2:
            raise ValueError("two openings required")
        for w in witnesses:
            for field in ("ask","native","asset","qty","salt","occ","cm"):
                w[field] = bytes.fromhex(w[field])
            w["path"] = [bytes.fromhex(v) for v in w["path"]]
        if action=="check-edges":
            Funded(chain,root,count,nfs,witnesses).check_detached_paths()
        else:
            sys.stdout.buffer.write(execute(chain,root,count,nfs,genesis_pin=bytes.fromhex(genesis_pin),profile=profile,
                                           secrets=witnesses))
    elif action in ("verify","reject"):
        packet_size = 3730382 if profile=="gf16" else 5966544
        proof = sys.stdin.buffer.read(packet_size+1)
        if len(proof) != packet_size:
            raise ValueError("incorrect funded proof length")
        try:
            shape = execute(chain,root,count,nfs,genesis_pin=bytes.fromhex(genesis_pin),profile=profile,packet=proof)
        except ValueError:
            if action=="verify":
                raise
        else:
            if action=="reject":
                raise ValueError("changed statement accepted")
            print(json.dumps(dict(width=shape[0],rows=shape[1],ell=shape[2])))
    else:
        raise ValueError("unknown role")


if __name__=="__main__":
    main()
