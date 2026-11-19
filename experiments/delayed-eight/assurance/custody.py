"""Recover full public DLF1 PoW history from any four of six archival custodians."""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import itertools
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

D, N = 4, 6
MAGIC = b"DLFCUS01"
FIXED = struct.Struct("<8s32s32s32s32sIIBB32s")
MANIFEST = FIXED.size + N*32
MAX_BLOCK = 214 + 4*(4+256*1024) + 8
GEN = [list(row) for row in ((1,0,0,0),(0,1,0,0),(0,0,1,0),(0,0,0,1),(1,1,1,1),(1,2,4,8))]


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).digest()


def tables():
    exp = [1]
    for _ in range(254):
        a = exp[-1]<<1
        exp.append(a ^ (0x11d if a&256 else 0))
    need(len(set(exp))==255,"GF generator")
    log = {a:i for i,a in enumerate(exp)}
    mul = [bytes(0 if not a or not b else exp[(log[a]+log[b])%255] for b in range(256)) for a in range(256)]
    return mul, [0]+[exp[-log[v]%255] for v in range(1,256)]


MUL,INV = tables()


def inverse(rows):
    a = [list(row)+GEN[i] for i,row in enumerate(rows)]
    for i in range(D):
        j = next(j for j in range(i,D) if a[j][i])
        a[i],a[j] = a[j],a[i]
        inv = INV[a[i][i]]
        a[i] = [MUL[inv][x] for x in a[i]]
        for j in range(D):
            if j!=i:
                factor = a[j][i]
                a[j] = [b ^ MUL[factor][c] for b,c in zip(a[j],a[i])]
    return [row[D:] for row in a]


def linear(coeff,data):
    acc = 0
    for c,s in zip(coeff,data,strict=True):
        if c:
            acc ^= int.from_bytes(s if c==1 else s.translate(MUL[c]),"little")
    return acc.to_bytes(len(data[0]),"little")


def encode(raw):
    size = (len(raw)+D-1)//D
    padded = raw.ljust(size*D,b"\0")
    data = [padded[i*size:(i+1)*size] for i in range(D)]
    return data+[linear(GEN[i],data) for i in range(D,N)]


def decode(parts,size):
    ids = sorted(parts)[:D]
    need(len(ids)==D,"insufficient authenticated shards")
    corrected = [linear(row,[parts[i] for i in ids]) for row in inverse([GEN[i] for i in ids])]
    padded = b"".join(corrected)
    need(not any(padded[size:]),"nonzero padding")
    return padded[:size]


def make_manifest(network,profile,ident,parent,height,raw,shards):
    head = FIXED.pack(MAGIC,network,profile,ident,parent,height,len(raw),D,N,sha(raw))
    return head+b"".join(sha(s) for s in shards)


def parse(manifest,network,profile,ident):
    need(len(manifest)==MANIFEST,"manifest length")
    tag,net,pr,bid,parent,h,size,k,n,digest = FIXED.unpack_from(manifest)
    need((tag,net,pr,bid,k,n)==(MAGIC,network,profile,ident,D,N),"manifest identity")
    need(0<h<2**32 and 222<=size<=MAX_BLOCK,"manifest dimensions")
    return parent,h,size,digest,[manifest[FIXED.size+32*i:FIXED.size+32*(i+1)] for i in range(N)]


def exact(stream,size):
    data = stream.read(size)
    need(len(data)==size,"incomplete custody frame")
    return data


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        query = exact(self.rfile,33)
        suffix = {0:".manifest",1:".shard"}.get(query[0])
        if suffix is None:
            return
        path = self.server.holder/(query[1:].hex()+suffix)
        bound = MANIFEST if query[0]==0 else (MAX_BLOCK+D-1)//D
        try:
            with path.open("rb") as file:
                body = file.read(bound+1)
        except FileNotFoundError:
            body = None
        reply = struct.pack("<I",0xffffffff if body is None else len(body))+(body or b"")
        self.wfile.write(reply)
        self.server.sent += len(reply)
        self.server.received += len(query)


@contextmanager
def holder(path):
    with socketserver.TCPServer(("127.0.0.1",0),Handler) as server:
        server.holder = path
        server.sent = server.received = 0
        worker = threading.Thread(target=server.serve_forever,kwargs={"poll_interval":0.05},daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()


def read_frame(port,kind,ident,meter):
    query = bytes([kind])+ident
    with socket.create_connection(("127.0.0.1",port),timeout=10) as conn:
        conn.sendall(query)
        with conn.makefile("rb") as stream:
            size, = struct.unpack("<I",exact(stream,4))
            meter["requests"] += 1
            meter["request_B"] += len(query)
            meter["reply_B"] += 4
            if size==0xffffffff:
                return None
            need(size<=(MANIFEST if kind==0 else (MAX_BLOCK+D-1)//D)+1,"oversize custody frame")
            data = exact(stream,size)
            meter["reply_B"] += size
            meter["manifest_B" if kind==0 else "shard_B"] += size
            return data



def fetch(port,kind,ident,meter):
    try:
        return read_frame(port,kind,ident,meter)
    except (OSError,ValueError):
        meter["failed_endpoints"] += 1
        return None


def read_block(peers,network,profile,ident,block_id,deblock,meter):
    previous = set()
    bodies = {}
    for peer in peers.values():
        manifest = fetch(peer,0,ident,meter)
        if manifest is None or manifest in previous:
            continue
        previous.add(manifest)
        try:
            parent,height,size,digest,expected = parse(manifest,network,profile,ident)
        except ValueError:
            continue
        parts = {}
        for i,port in peers.items():
            if i not in bodies:
                bodies[i] = fetch(port,1,ident,meter)
            part = bodies[i]
            if part is None:
                continue
            if len(part)!=(size+D-1)//D or sha(part)!=expected[i]:
                meter["bad_fragment_checks"] += 1
                continue
            parts[i] = part
            if len(parts)==D:
                break
        if len(parts)<D:
            continue
        try:
            raw = decode(parts,size)
            need(sha(raw)==digest and block_id(raw)==ident,"reconstructed PoW block identity")
            block = deblock(raw)
            need(block.height==height and block.parent==parent,"untrusted manifest ancestry")
            return raw,block
        except ValueError:
            continue
    raise ValueError("insufficient authenticated shards")


def open_roles(deploy):
    sys.path.insert(0,str(deploy/"devnet"))
    from chain import Chain,GENESIS,NETWORK,PROFILE,block_id,decode_block
    from runtime import config
    from run import Resources
    return Chain,GENESIS,NETWORK,PROFILE,block_id,decode_block,Resources,config


def recover(deploy,tip,peers):
    Chain,gen,network,profile,block_id,deblock,Resources,config = open_roles(deploy)
    ids = list(peers)
    need(all(0<=i<N for i in ids),"invalid holder set")
    need(len(ids)>=D,"insufficient authenticated shards")
    got = tip
    meter = dict(requests=0,request_B=0,reply_B=0,manifest_B=0,shard_B=0,bad_fragment_checks=0,failed_endpoints=0)
    fetched = []
    size_raw = txs = 0
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        expected_height = None
        while got!=gen:
            raw,b = read_block(peers,network,profile,got,block_id,deblock,meter)
            h = b.height
            need((expected_height is None or expected_height==h) and h<=10000,"linked block height")
            f = scratch/(str(h)+".block")
            with f.open("xb") as out:
                out.write(raw)
            size_raw += len(raw)
            txs += len(b.packets)
            fetched.append(f)
            expected_height = h-1
            got = b.parent
        need(expected_height==0,"missing genesis successor")
        resources = Resources(config(deploy/"runtime"))
        try:
            t = time.monotonic()
            ledger = Chain(scratch/"fresh.sqlite",resources.backend)
            try:
                for f in reversed(fetched):
                    ledger.accept(f.read_bytes())
                state = ledger.status()
                need(state["tip"]==tip.hex() and state["height"]==len(fetched),"fresh selected ledger")
            finally:
                ledger.close()
            native_s = time.monotonic()-t
        finally:
            resources.close()
    return dict(state=state,blocks=len(fetched),payments=txs,reconstructed_B=size_raw,
                custody_wire=meter,available=ids,native_replay_wall_s=native_s)


def annual(mix,empty):
    # Real DLF1 submissions are fixed size. Block layout and census are frozen independently.
    payments = 100_000_000
    mean = sum((i+1)*w for i,w in enumerate(mix))
    paid = payments/mean
    widths = [(0,paid*empty)]+[(i+1,paid*w) for i,w in enumerate(mix)]
    raw = sum((222+n*(4+143187))*count for n,count in widths)
    chunks = sum(((222+n*(4+143187)+D-1)//D)*count for n,count in widths)
    meta = sum(count*MANIFEST for _,count in widths)
    return dict(blocks=sum(v for _,v in widths),original_full_archive_TB=raw/1e12,
                one_partial_custodian_TB=(chunks+meta)/1e12,all_six_TB=N*(chunks+meta)/1e12,
                fresh_full_recovery_payload_TB=(D*chunks+meta)/1e12,
                fresh_full_recovery_wire_TB=(D*chunks+meta+sum(v for _,v in widths)*(D+1)*37)/1e12,
                repair_one_lost_holder_from_scratch_read_TB=(D*chunks+meta)/1e12,
                repair_one_lost_holder_from_scratch_write_TB=(chunks+meta)/1e12,
                all_compulsory_wallet_uploads_TB=143187*payments/1e12)


def experiment(deploy,capture):
    _,gen,net,profile,bid,decode_block,_,_ = open_roles(deploy)
    report = json.loads((capture/"BUSY.json").read_bytes())
    selected = report["selected"]
    results = {}
    with tempfile.TemporaryDirectory(prefix="dlf-custody-") as tmp, ExitStack() as stack:
        store = Path(tmp)/"holders"
        for i in range(N):
            (store/str(i)).mkdir(parents=True)
        total_raw=total_shards=packets=0
        parent = gen
        start = time.process_time()
        for h,ident in enumerate(selected,1):
            raw = (capture/"blocks"/(ident+".bin")).read_bytes()
            b = decode_block(raw)
            need(bid(raw).hex()==ident and b.height==h and b.parent==parent,"selected capture")
            packets += len(b.packets)
            shards = encode(raw)
            manifest = make_manifest(net,profile,bytes.fromhex(ident),parent,h,raw,shards)
            for i,content in enumerate(shards):
                (store/str(i)/(ident+".manifest")).write_bytes(manifest)
                (store/str(i)/(ident+".shard")).write_bytes(content)
            total_raw += len(raw)
            total_shards += sum(map(len,shards))
            parent = bytes.fromhex(ident)
        own_cpu = time.process_time()-start
        need(packets==4 and len(selected)==10,"requires released busy shape: 4 real proofs in 10 blocks")
        # Test the MDS threshold on every stored block under all two-erasure patterns.
        for ident in selected:
            manifest = (store/"0"/(ident+".manifest")).read_bytes()
            _,_,size,digest,_ = parse(manifest,net,profile,bytes.fromhex(ident))
            all_parts = {i:(store/str(i)/(ident+".shard")).read_bytes() for i in range(N)}
            for chosen in itertools.combinations(range(N),D):
                need(sha(decode({i:all_parts[i] for i in chosen},size))==digest,"MDS case")
        # Fresh process sees no source-history path. Put two unavailable original data shares off its lookup path.
        for i in (0,2):
            (store/str(i)).rename(Path(tmp)/("unavailable-"+str(i)))
        servers = {i:stack.enter_context(holder(store/str(i))) for i in range(N)}
        args = [sys.executable,"-IB",str(Path(__file__).resolve()),"recover",str(deploy),selected[-1]]
        def child(ids):
            endpoints = [f"{i}={servers[i].server_address[1]}" for i in ids]
            return subprocess.run([*args,*endpoints],capture_output=True,timeout=180)
        successful = child([1,3,4,5])
        if successful.returncode:
            raise RuntimeError(successful.stderr.decode()[-800:])
        recovered = json.loads(successful.stdout)
        need(recovered["payments"]==packets and recovered["reconstructed_B"]==total_raw
             and recovered["state"]["fees"]==12 and recovered["state"]["spent"]==8,"public accounting")
        wire = recovered["custody_wire"]
        need(sum(s.sent for s in servers.values())==wire["reply_B"]
             and sum(s.received for s in servers.values())==wire["request_B"],"independent relay accounting")
        # Include an actually unreachable loopback endpoint in discovery, then fetch four usable shares.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1",0))  # Reserved endpoint with no listener.
            options = [f"0={unavailable.getsockname()[1]}"]+[f"{i}={servers[i].server_address[1]}" for i in (1,3,4,5)]
            absent = subprocess.run([*args,*options],capture_output=True,timeout=180)
            need(absent.returncode==0 and json.loads(absent.stdout)["custody_wire"]["failed_endpoints"]>0,
                 "offline endpoint fallback")
        too_few = child([1,3,4])
        need(too_few.returncode and b"insufficient authenticated shards" in too_few.stderr,"missing quorum")
        # Restore one of the six while a different custodian supplies a corrupted fragment.
        (Path(tmp)/"unavailable-2").rename(store/"2")
        path = store/"1"/(selected[-1]+".shard")
        corrupted = bytearray(path.read_bytes())
        corrupted[0]^=1
        path.write_bytes(corrupted)
        alternate = child([1,2,3,4,5])
        need(alternate.returncode==0 and json.loads(alternate.stdout)["custody_wire"]["bad_fragment_checks"]==1,
             "corruption detection and reconstruction from four others")
        still_short = child([1,3,4,5])
        need(still_short.returncode and b"insufficient authenticated shards" in still_short.stderr,
             "four offered but only three authenticated")
        path.write_bytes(bytes([corrupted[0]^1])+corrupted[1:])
        # A wrong, well-sized first manifest must not prevent another holder supplying the right one.
        mf = store/"1"/(selected[-1]+".manifest")
        original = mf.read_bytes()
        altered = bytearray(original)
        altered[FIXED.size-1]^=1
        mf.write_bytes(altered)
        fallback = child([1,2,3,4,5])
        need(fallback.returncode==0 and json.loads(fallback.stdout)["state"]==recovered["state"],
             "recovered from alternative manifest")
        mf.write_bytes(original)
        files_one = len(selected)*2
        holder_B = total_shards//N+MANIFEST*len(selected)
        need(sum(f.stat().st_size for f in (store/"1").iterdir())==holder_B,"actual custody bytes")
        results = dict(format="DLF-CUSTODY-MDS-1",source_tip=selected[-1],source_public_sha256=sha(
                    (capture/"BUSY.json").read_bytes()).hex(),points=list(range(N)),data_pieces=D,
                    full_source_B=total_raw,manifest_per_block_B=MANIFEST,per_holder_B=holder_B,
                    files_per_holder=files_one,all_holders_B=holder_B*N,all_shard_bytes=total_shards,
                    encoding_and_write_controller_cpu_s=own_cpu,all_15_four_holder_choices_per_block=True,
                    unreachable_endpoint_skipped=True,three_insufficient=True,corrupt_manifest_alternative_recovered=True,actual_loopback_frames_matched_both_ends=True,one_bad_among_five_recovered=True,one_bad_among_four_rejected=True,
                    fresh_public_recovery=recovered,annual_100M_inclusions={
                        "sparse":annual((.85,.10,.04,.01),1),
                        "busy":annual((.05,.10,.15,.70),1/9)})
    return results


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_subparsers(dest="op",required=True)
    init=modes.add_parser("run")
    init.add_argument("deploy",type=Path)
    init.add_argument("public_busy_capture",type=Path)
    read=modes.add_parser("recover")
    read.add_argument("deploy",type=Path)
    read.add_argument("tip")
    read.add_argument("available",nargs="+",help="local holder index=TCP-port pairs")
    a=p.parse_args()
    if a.op=="recover":
        entries = [tuple(map(int,v.split("="))) for v in a.available]
        peers = dict(entries)
        need(len(peers)==len(entries),"duplicate custodian")
        result=recover(a.deploy.resolve(),bytes.fromhex(a.tip),peers)
    else:
        result=experiment(a.deploy.resolve(),a.public_busy_capture.resolve())
    print(json.dumps(result,indent=2,sort_keys=True))
