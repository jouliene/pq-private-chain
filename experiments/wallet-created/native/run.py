"""Run distinct wallet processes, a public builder and a fresh validating node with framed public pipes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import resource
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"wallet"))
from bridge import libraries

LIMIT=1048576
CT=1792


class Role:
    def __init__(self, binary, name):
        argv=["bwrap","--unshare-all","--new-session","--die-with-parent","--cap-drop","ALL",
              "--clearenv","--setenv","LANG","C","--setenv","RAYON_NUM_THREADS","2","--proc","/proc",
              "--dev","/dev","--ro-bind",str(binary),"/app"]
        for lib in libraries(binary):
            argv.extend(["--ro-bind",str(lib.resolve()),str(lib)])
        argv+=["--remount-ro","/","--chdir","/","--","/app",name]
        self.name=name
        self.from_role=[]
        self.to_role=[]
        self.p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    def send(self,data):
        assert len(data)<=LIMIT
        self.p.stdin.write(struct.pack("<I",len(data))+data)
        self.p.stdin.flush()
        self.to_role.append(len(data))

    def get(self):
        header=self.p.stdout.read(4)
        if len(header)!=4: raise ValueError("failed "+self.name+" response")
        n,=struct.unpack("<I",header)
        assert n<=LIMIT
        data=self.p.stdout.read(n)
        assert len(data)==n
        self.from_role.append(n)
        return data

    def finish(self):
        self.p.stdin.close()
        self.p.wait(timeout=120)
        if self.p.returncode: raise ValueError("failed "+self.name)
        out=[]
        for line in self.p.stderr.read().splitlines():
            m=re.fullmatch(rb"METER ([a-z_]+) ([\d.]+) ([\d.]+) (\d+)",line)
            if not m: raise ValueError("unexpected "+self.name+" diagnostic")
            out.append(dict(operation=m[1].decode(),elapsed_s=float(m[2]),cpu_s=float(m[3]),peak_rss_kib=int(m[4])))
        return out


def node_check(node, raw):
    node.send(raw)
    reply=node.get()
    assert len(reply)>=97 and reply[0] in (0,1)
    return reply[0]==1, struct.unpack_from("<4Q",reply,1), reply[33:97], reply[97:]


def mutate(buf,offset):
    data=bytearray(buf);data[offset]^=1
    return bytes(data)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary",type=Path)
    ap.add_argument("binary_sha256")
    ap.add_argument("output",type=Path)
    ap.add_argument("--replay",help="Approve SHA256 of public genesis and replay only committed pair and successor")
    a=ap.parse_args()
    binary=a.binary.resolve(strict=True)
    sha=lambda b:hashlib.sha256(b).hexdigest()
    assert sha(binary.read_bytes())==a.binary_sha256
    if not a.replay:a.output.mkdir(exist_ok=False,parents=True)
    out=a.output
    def put(name,data):
        with (out/name).open("xb") as f:f.write(data)
    def read(name):return (out/name).read_bytes()
    actors=[]
    def start(name):
        role=Role(binary,name);actors.append(role);return role
    report={"binary_sha256":a.binary_sha256,"roles":{}}
    def deadline(_signum,_frame):
        raise TimeoutError("native experiment deadline")
    signal.signal(signal.SIGALRM,deadline)
    signal.alarm(360)
    try:
        if not a.replay:
            wallet_a=start("wallet");hello_a=wallet_a.get()
            wallet_b=start("wallet");hello_b=wallet_b.get()
            assert len(hello_a)==len(hello_b)==1665 and hello_a[:1601]!=hello_b[:1601]
            genesis=hello_a[-64:]+hello_b[-64:];put("genesis.bin",genesis)
            wallet_a.send(genesis);wallet_a.send(hello_b[:1601]);first=wallet_a.get();put("a.body",first)
            wallet_b.send(genesis);wallet_b.send(hello_a[:1601]);second=wallet_b.get();put("b.body",second)
            builder=start("builder");inner_key=builder.get();outer_key=builder.get()
            builder.send(genesis);builder.send(first);builder.send(second)
            pair=builder.get();put("pair.block",pair)
            report["roles"]["builder"]=builder.finish()
        else:
            genesis=read("genesis.bin");assert sha(genesis)==a.replay
            pair=read("pair.block")
        node=start("node")
        registered=[node.get(),node.get()]
        if not a.replay:assert registered==[inner_key,outer_key]
        report["verifiers"]=[dict(bytes=len(v),sha256=sha(v)) for v in registered]
        node.send(genesis)
        # One well-formed outer Merkle digest and one ciphertext byte are changed separately.
        ok,initial,identity,_=node_check(node,mutate(pair,8))
        assert not ok and initial==(1,4,0,0)
        controls=["changed-proof"]
        proof_len,=struct.unpack_from("<I",pair,4)
        public_start=8+proof_len-53*8
        assert struct.unpack_from("<Q",pair,public_start-8)[0]==53
        # Canonical field encodings on both sides; only the first leg's public fee changes.
        first_fee=public_start+(1+21)*8
        assert struct.unpack_from("<Q",pair,first_fee)[0]==3
        for label,raw in [("changed-public-fee",mutate(pair,first_fee)),
                          ("changed-ciphertext",mutate(pair,len(pair)-10)),("short",pair[:-1]),("trailing",pair+b"x")]:
            ok,state,new_id,hist=node_check(node,raw)
            assert not ok and state==initial and new_id==identity and not hist
            controls.append(label)
        ok,state,pair_id,history=node_check(node,pair)
        assert ok and state==(2,8,4,6) and len(history)==4*(32+CT)
        ok,state2,current_id,hist=node_check(node,pair)
        assert not ok and state2==state and current_id==pair_id and not hist
        controls.append("replay")
        if not a.replay:
            for owner in (wallet_b,wallet_a):
                owner.send(history)
                assert owner.get()==bytes([2])
            wallet_b.send(b"");report["roles"]["wallet_b"]=wallet_b.finish()
            wallet_a.send(b"spend");follow=wallet_a.get();put("recipient.body",follow)
            report["roles"]["wallet_a"]=wallet_a.finish()
        else:follow=read("recipient.body")
        ok,final,final_id,hist=node_check(node,follow)
        assert ok and final==(3,10,6,9) and len(hist)==2*(32+CT)
        node.send(b"");report["roles"]["node"]=node.finish()
        report.update(genesis_sha256=sha(genesis),negative_controls=controls,final_state=final,final_state_blake2b512=final_id.hex(),
                      pair_body_bytes=len(pair),pair_proof_bytes=len(pair)-8-4*CT,followup_body_bytes=len(follow),
                      pair_history_bytes=len(history),published_ciphertexts=4)
        report["public_pipe_frames"]=[dict(role=role.name,from_role_payload_lengths=role.from_role,
            to_role_payload_lengths=role.to_role,frame_length_prefix_bytes=4) for role in actors]
        if not a.replay:
            report.update(wallet_submissions=[len(first),len(second)],wallet_proofs=[len(first)-8-2*CT,len(second)-8-2*CT],
                          opened_notes_per_wallet=[2,2],handshake_bytes_per_origin=len(hello_a),pair_archive_saving_bytes=len(first)+len(second)-len(pair))
            put("RESULT.json",(json.dumps(report,indent=2)+"\n").encode())
        print(json.dumps(report,indent=2))
    finally:
        signal.alarm(0)
        for role in actors:
            if role.p.poll() is None:
                role.p.kill();role.p.wait()


if __name__=="__main__":
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    main()
