"""Prove and verify the Keccak accelerator used by the selected aggregate design."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9"

def first_main_leaf():
    source = ROOT / "fixtures/cp03-reference/payer2x2.body"
    body = source.read_bytes()
    assert hashlib.sha256(body).hexdigest() == "8907fff56f7b6418c0752c8160cdbae13e10a0ddb19de884d89e99f924a5abe9"
    random_batch = 4876 + 206 + 60364
    count_at = random_batch + 160 * (80 + 64)
    frontier, = struct.unpack_from("<I", body, count_at)
    start = count_at + 4 + 64 * frontier
    row = body[start:start + 584*8]
    salts = start + 160*584*8
    payload = row + body[salts:salts+64]
    return b"PQPC/CP-FRI/01/LEAF\0" + payload + struct.pack("<Q", len(payload))

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("risc0_checkout", type=Path)
    ap.add_argument("target", type=Path, help="dedicated external dependency build directory")
    ap.add_argument("output", type=Path, help="new directory for this proof and measurements")
    args = ap.parse_args()
    upstream, target, output = [x.resolve() for x in (args.risc0_checkout,args.target,args.output)]
    assert subprocess.check_output(["git","rev-parse","HEAD"], cwd=upstream,text=True).strip()==PIN
    subprocess.run(["git","diff","--quiet","HEAD"],cwd=upstream,check=True)
    assert not subprocess.check_output(["git","ls-files","--others","--exclude-standard"],cwd=upstream)
    env = os.environ.copy()
    # The repo's pinned lockfile remains in force. Match the release build in the evidence.
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", RUSTFLAGS="", RAYON_NUM_THREADS="2")
    subprocess.run(["cargo","+1.99.1","build","--locked","--release","-p","risc0-circuit-keccak","--lib"],
                   cwd=upstream,env=env,check=True)
    output.mkdir(parents=True, exist_ok=False)
    deps=target/"release/deps"
    binary=output/"accelerator"
    build=["rustc","+1.99.1","--edition","2024","-O","-Dwarnings",str(HERE/"accelerator.rs"),
           "-L",f"dependency={deps}","-o",str(binary)]
    for name in ("risc0_circuit_keccak","risc0_core","keccak","bytemuck"):
        path, = deps.glob(f"lib{name}-*.rlib")
        build.extend(["--extern", f"{name}={path}"])
    subprocess.run(build, check=True,env=env)
    message=first_main_leaf()
    leaf=output/"public.leaf"
    leaf.write_bytes(message)
    expected=output/"leaf.sha3"
    expected.write_bytes(hashlib.sha3_512(message).digest())
    seal=output/"public.seal"
    results={}
    for mode in ("prove","verify"):
        meter=output/(mode+".time")
        check=subprocess.run(["/usr/bin/time","-f","%e %U %S %M","-o",str(meter),str(binary),mode,
                              str(leaf),str(expected),str(seal)],check=True,text=True,capture_output=True,env=env)
        kind,count,size,digest,wall=check.stdout.split()
        assert kind==mode and int(count)==67 and int(size)==seal.stat().st_size
        elapsed,user,kernel,rss=meter.read_text().split()
        results[mode]={"seal_bytes":int(size),"permutations":int(count),"circuit_claim_digest":digest,
                       "inner_elapsed_s":float(wall),"elapsed_s":float(elapsed),"user_s":float(user),
                       "system_s":float(kernel),"max_rss_kib":int(rss)}
    altered=output/"changed.seal"
    raw=bytearray(seal.read_bytes())
    raw[-24]^=1
    altered.write_bytes(raw)
    bad=subprocess.run([str(binary),"verify",str(leaf),str(expected),str(altered)],env=env,capture_output=True)
    assert bad.returncode!=0 and b"transparent cryptographic seal verification" in bad.stderr
    # Genuine proof presented with a different, internally consistent public input.
    alternate = message[:-9]+bytes([message[-9]^1])+message[-8:]
    other=output/"other.leaf"
    other.write_bytes(alternate)
    other_digest=output/"other.sha3"
    other_digest.write_bytes(hashlib.sha3_512(alternate).digest())
    wrong=subprocess.run([str(binary),"verify",str(other),str(other_digest),str(seal)],env=env,capture_output=True)
    assert wrong.returncode!=0 and b"expected public input/output transcript" in wrong.stderr
    result={"upstream":PIN,"po2":14,"backend":"CPU, 2 Rayon workers","leaf_sha3_512":expected.read_bytes().hex(),
            "framed_leaf_bytes":len(message),"input_material":"first salted main opening, public payer2x2.body",
            "seal_sha256":hashlib.sha256(seal.read_bytes()).hexdigest(),"mismatched_claim_rejected":True,
            "corrupt_seal_crypto_rejected":True,"results":results}
    (output/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
