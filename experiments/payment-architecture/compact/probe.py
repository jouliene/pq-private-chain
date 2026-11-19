"""Build the fixed MatRiCT+ core, encode and publicly verify three fresh authorizations."""
import argparse
import hashlib
import io
import json
import platform
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
COMMIT = "b24f3176d2db15ca55d91c8c9cbe1cef201c5d2d"
ARCHIVE_SHA = "88c96feae3dafc513e2d2f15978730ee7000741840db0e7f83a09e302384587c"
URL = f"https://gitlab.com/raykzhao/matrict_plus/-/archive/{COMMIT}/matrict_plus-{COMMIT}.tar.gz"
D, Q, QHAT = 256, 167770241, 3489661057
RING = 10
ACCOUNT = 9*D*8
# name, coefficient count, minimum and maximum inclusive. Labels ending in 'bytes' are plain bytes.
FIELDS = [("ring",2*RING*9*D,0,Q-1),("output_accounts",18*D,0,Q-1),
          ("serial_bytes",64,0,255),("c_v",5*D,0,Q-1),("v1_i32",D,-(1<<31),(1<<31)-1),("v2",D,0,Q-1),("b",5*D,0,QHAT-1),
          ("alpha_bytes",32,0,255),("x",D,-1,1),("z_out_z0_z1_z2",49*D,-38346,38346),
          ("f1",11*D,-565,565),("zb",10*D,-38346,38346),("z",8*D,-6212586,6212586)]

SHAKE_HEADER = """#include <openssl/evp.h>
#include <stdlib.h>
static inline void SHAKE256(unsigned char *out,size_t n,const unsigned char *input,size_t len) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx,EVP_shake256(),0)!=1 || EVP_DigestUpdate(ctx,input,len)!=1 ||
        EVP_DigestFinalXOF(ctx,out,n)!=1) abort();
    EVP_MD_CTX_free(ctx);
}
"""


def need(check, why):
    if not check:
        raise ValueError(why)


def packed(native):
    """Fixed LSB-first exact-width fields; no channel encodes the observed coefficient distribution."""
    src = io.BytesIO(native)
    result = {}
    for name,count,lo,hi in FIELDS:
        if name.endswith("_bytes"):
            result[name] = src.read(count)
            need(len(result[name])==count,"short byte field")
            continue
        bits = (hi-lo).bit_length()
        buf = bytearray()
        acc = used = 0
        for val, in struct.iter_unpack("<q",src.read(count*8)):
            need(lo<=val<=hi,"coefficient outside registered bounds: "+name)
            acc |= (val-lo)<<used
            used += bits
            while used>=8:
                buf.append(acc&255)
                acc >>= 8
                used -= 8
        need(not used and len(buf)*8==bits*count,"short or nonaligned packed field")
        result[name] = bytes(buf)
    need(src.read()==b"","trailing native bytes")
    return result


def unpacked(fields):
    dest = bytearray()
    for name,count,lo,hi in FIELDS:
        buf = fields[name]
        if name.endswith("_bytes"):
            need(len(buf)==count,"raw length")
            dest.extend(buf)
            continue
        bits = (hi-lo).bit_length()
        need(len(buf)*8==bits*count,"packed length")
        acc = used = idx = 0
        for _ in range(count):
            while used<bits:
                acc |= buf[idx]<<used
                used += 8
                idx += 1
            val = (acc&((1<<bits)-1))+lo
            need(val<=hi,"noncanonical coefficient")
            dest.extend(struct.pack("<q",val))
            acc >>= bits
            used -= bits
    return bytes(dest)


def build(tarfile_path, tmp):
    src = tmp/"n10"
    src.mkdir()
    data = Path(tarfile_path).read_bytes() if tarfile_path else urllib.request.urlopen(URL,timeout=45).read()
    need(hashlib.sha256(data).hexdigest()==ARCHIVE_SHA,"wrong MatRiCT+ archive")
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as archive:
        for m in archive:
            rel = Path(m.name)
            if m.isfile() and len(rel.parts)==3 and rel.parts[1]=="n10" and rel.suffix in {".c",".h"}:
                (src/rel.name).write_bytes(archive.extractfile(m).read())
    include = tmp/"libXKCP.a.headers"
    include.mkdir()
    (include/"SimpleFIPS202.h").write_text(SHAKE_HEADER)
    flags = ["gcc","-O3","-march=native","-fno-strict-aliasing","-include","openssl/evp.h","-I",str(tmp),"-I",str(src)]
    binary = tmp/"probe"
    native = sorted(str(p) for p in src.glob("*.c") if p.name!="test.c")
    subprocess.run([*flags,str(HERE/"probe.c"),*native,"-lcrypto","-lm","-o",str(binary)],check=True)
    kat = tmp/"kat.c"
    kat.write_text('#include <stdio.h>\n#include "libXKCP.a.headers/SimpleFIPS202.h"\nint main(void){unsigned char o[137]; SHAKE256(o,137,(const unsigned char*)"abc",3);return fwrite(o,1,137,stdout)!=137;}\n')
    subprocess.run([*flags,str(kat),"-lcrypto","-o",str(tmp/"kat")],check=True)
    # NIST SHAKE256 short-message vector is also independently implemented by hashlib on supported hosts.
    got = subprocess.check_output([str(tmp/"kat")])
    need(got==hashlib.shake_256(b"abc").digest(137) and got[:8].hex()=="483366601360a877","SHAKE256 KAT")
    # A small intermediary forks the native binary so Linux wait4 high-water RSS
    # excludes the Python controller memory present across its initial fork/exec.
    timer = tmp/"meter.c"
    timer.write_text(r"""#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
int main(int argc,char **argv) {
  if(argc!=3) return 120;
  pid_t pid=fork(); if(pid<0) return 121;
  if(!pid) { execl(argv[1],argv[1],argv[2],(char*)0); _exit(122); }
  int status; struct rusage r;
  if(wait4(pid,&status,0,&r)<0 || !WIFEXITED(status)) return 123;
  fprintf(stderr,"%ld %ld %ld %ld %ld\n",r.ru_utime.tv_sec,r.ru_utime.tv_usec,
          r.ru_stime.tv_sec,r.ru_stime.tv_usec,r.ru_maxrss);
  return WEXITSTATUS(status);
}
""")
    subprocess.run(["gcc","-O2",str(timer),"-o",str(tmp/"meter")],check=True)
    return binary


def timed(cmd, public_input=None):
    start = time.monotonic()
    p = subprocess.run([cmd[0].parent/"meter",*cmd],input=public_input,capture_output=True,timeout=120)
    elapsed = time.monotonic()-start
    user,us,system,ss,rss = map(int,p.stderr.split())
    return p,dict(wall_s=elapsed,cpu_user_s=user+us*1e-6,cpu_system_s=system+ss*1e-6,peak_rss_KiB=rss)


def run(tarfile_path):
    with tempfile.TemporaryDirectory(prefix="mp10-") as directory:
        binary = build(tarfile_path,Path(directory))
        p,resources = timed([binary,"prove"])
        need(p.returncode==0,"native prover exit")
        expected = sum(n if k.endswith("_bytes") else n*8 for k,n,*_ in FIELDS)
        need(len(p.stdout)==3*expected,"public C ABI size")
        records,all_rows,verified,timings = [],[],[],[]
        for i in range(3):
            native = p.stdout[i*expected:(i+1)*expected]
            encoded = packed(native)
            recovered = unpacked(encoded)
            need(native==recovered,"lossless native transcript round trip")
            r,cost = timed([binary,"verify"],recovered)
            need(r.returncode==0,"fresh public verification")
            verified.append(True)
            timings.append(cost)
            all_rows.append({native[j*2*ACCOUNT:(j+1)*2*ACCOUNT] for j in range(RING)})
            records.append(encoded)
        a,retry,new = records
        same_pair = all_rows[0]&all_rows[1]
        need(len(same_pair)==1 and not (all_rows[0]&all_rows[2]),"expected public row intersections")
        need(a["serial_bytes"]==retry["serial_bytes"]==new["serial_bytes"],"serial must follow the reused keys")
        need(a["output_accounts"][:8*D*28//8]==new["output_accounts"][:8*D*28//8],"receiving keys changed")
        bad = dict(a)
        bad["alpha_bytes"] = bytes([a["alpha_bytes"][0]^1])+a["alpha_bytes"][1:]
        bad_statement = dict(a)
        bad_statement["serial_bytes"] = bytes([a["serial_bytes"][0]^1])+a["serial_bytes"][1:]
        for candidate in (bad,bad_statement):
            need(timed([binary,"verify"],unpacked(candidate))[0].returncode==1,"wrong public data accepted")
        def same_proof(x,y):
            return all(x[k]==y[k] for k in x if k not in ("ring","output_accounts","serial_bytes"))
        need(not same_proof(a,retry),"new proof bytes")
        fields = {k:len(b) for k,b in a.items()}
        proof = sum(x for k,x in fields.items() if k not in ("ring","output_accounts","serial_bytes"))
        # Proposed transport includes two implicit-position notes per public ring row.
        quote = dict(profile_and_magic_B=36,anchor_B=32,fee_u64_B=8,ring_positions_u64_B=2*RING*8,
                     two_serials_B=fields["serial_bytes"],two_public_accounts_B=fields["output_accounts"],
                     two_receipts_B=2*(1568+480+16),proof_B=proof)
        return dict(source_commit=COMMIT,source_archive_sha256=ARCHIVE_SHA,compiler=subprocess.check_output(
                    ["gcc","-dumpfullversion"],text=True).strip(),sha_implementation=subprocess.check_output(
                    ["openssl","version"],text=True).strip(),architecture=platform.machine(),ring_rows=RING,
                    input_columns=2,outputs=2,valid_in_fresh_process=verified,
                    wrong_statement_rejected=True,altered_proof_rejected=True,
                    proof_packing_fields_B=fields,packed_proof_B=proof,full_registered_budget_B=quote,
                    budget_total_B=sum(quote.values()),ring_state_read_B=fields["ring"],
                    distinct_funded_coin_row_intersections=len(all_rows[0]&all_rows[2]),
                    retry_row_intersection=len(same_pair),same_serials_across_distinct_funding=True,
                    same_receiving_public_keys=True,proofs_randomized=True,
                    three_proofs_and_setup=resources,three_public_verify=timings)


if __name__=="__main__":
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--source-archive",type=Path,help="use a locally downloaded identical archive")
    print(json.dumps(run(a.parse_args().source_archive),indent=2,sort_keys=True))
