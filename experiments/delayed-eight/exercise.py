"""Compact genuine multi-block history, interrupt compaction, and reconstruct a wallet-capable forked node."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from archive import Checks, Store
from block_format import core


def save(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")


def same(a,b):
    keys=("height","tip","anchor","header","issued","fees","notes","spent","spent_set_sha256","work")
    if {k:a[k] for k in keys}!={k:b[k] for k in keys}:
        raise ValueError("monetary state or validated history mismatch")


def initialize(net,live,path,crypto):
    import chain
    report=json.loads((live/"CAPTURE.json").read_bytes())
    branch=json.loads((live/"BRANCH.json").read_bytes())
    orders=[report["original_selected"], branch["winner"]]
    ref_head=[]
    sequence=list(dict.fromkeys(orders[0]+orders[1]))
    store=Store(path)
    checks=Checks(net,crypto)
    reference=chain.Chain(path.with_suffix(".reference-test"),checks.direct.backend)
    try:
        checked_known=False
        for seq,bid in enumerate(sequence,1):
            body=(live/"blocks"/(bid+".bin")).read_bytes()
            if chain.block_id(body).hex()!=bid:
                raise ValueError("wrong source block")
            reference.accept(body)
            packets=chain.decode_block(body).packets
            if packets and not checked_known:
                previous=reference.status()
                altered=bytearray(body);altered[218+24]^=1
                assert chain.block_id(body)==chain.block_id(altered)
                try:reference.accept(bytes(altered))
                except ValueError as err:
                    assert str(err)=="cryptographic payment rejection"
                else:raise ValueError("bad replacement attachment accepted")
                same(previous,reference.status())
                checked_known=True
            for p in packets:
                store.add(p,checks)
            store.put_core(bytes.fromhex(bid),core(chain.NETWORK,body))
            if seq in (len(orders[0]),len(sequence)):
                ref_head.append(reference.status())
        same(ref_head[0],report["original"])
        same(ref_head[1],branch["winning_state"])
        assert checked_known
        return dict(known_invalid_attachment_rejected=True,full=store.counts(),reference=ref_head,distinct_blocks=len(sequence),
                    full_bodies_B=sum((live/"blocks"/(x+".bin")).stat().st_size for x in sequence))
    finally:
        reference.close()
        store.db.close()
        checks.close()


def compact(net,path,crypto,file,kill=False):
    s=Store(path)
    check=Checks(net,crypto)
    try:
        raw=file.read_bytes()
        if raw[:4]!=b"D8C1":
            raise ValueError("replacement requires a recursive certificate")
        cid=s.add(raw,check,compact=True,interrupt=kill)
        s.db.execute("VACUUM")
        return dict(id=cid.hex(),store=s.counts())
    finally:
        check.close()
        s.db.close()


@contextmanager
def server(net,db,work,name):
    path=work/(name+".port")
    child=subprocess.Popen([sys.executable,"-IB",str(HERE/"peer.py"),str(net),"serve",str(db),str(path)])
    try:
        for _ in range(200):
            if path.exists():
                break
            if child.poll() is not None:
                raise RuntimeError("archive service stopped")
            time.sleep(.05)
        yield int(path.read_text())
    finally:
        child.terminate()
        child.wait(timeout=10)


def cold_command(net,crypto,data,ledger,port,limit=None,fallback=None):
    # The fresh verifier can reach loopback. Only approved public code, immutable keys,
    # its own empty/partially synchronized databases and system libraries are mounted.
    args=["bwrap","--die-with-parent","--unshare-pid","--unshare-ipc","--unshare-uts","--new-session",
          "--cap-drop","ALL","--proc","/proc","--dev","/dev","--tmpfs","/tmp"]
    for name in ("/usr","/bin","/lib","/lib64","/etc/ld.so.cache"):
        if Path(name).exists():
            args+=["--ro-bind",name,name]
    public_code=[HERE/name for name in ("peer.py","archive.py","block_format.py","crypto/certrole.py","crypto/registry.json")]
    if {e.name for e in crypto.iterdir()}!={"native","keys","approval.sha256"}:
        raise ValueError("unexpected files in public certificate runtime")
    for dest in (*public_code,HERE.parent/"advancing-payments"/"wire.py",HERE.parent/"wallet-created/wallet/bridge.py",net,crypto):
        args+=["--ro-bind",str(dest),str(dest)]
    for dest in (data.parent,ledger.parent):
        args+=["--bind",str(dest),str(dest)]
    args+=["--chdir","/tmp","--",sys.executable,"-IB",str(HERE/"peer.py"),str(net),"sync",str(data),str(ledger),str(crypto),str(port)]
    if fallback is not None:
        args+=["--fallback",str(fallback)]
    if limit is not None:
        args+=["--limit",str(limit)]
    return json.loads(subprocess.check_output(args,timeout=400))


def exercise(net,home,live,crypto,certificates,work):
    import chain
    from cli import Lab,wait
    if work.exists():
        raise ValueError("fresh exercise directory required")
    work.mkdir(parents=True)
    full=work/"original.sqlite"
    initial=initialize(net,live,full,crypto)
    retained=work/"alternate.sqlite"
    shutil.copyfile(full,retained)
    cert=certificates/"occupancy-8.bin"
    partial=certificates/"occupancy-2.bin"
    before=Store(retained)
    before.export(work/"before.d8")
    before.db.close()
    def subprocess_compact(file,interrupt=False):
        cmd=[sys.executable,"-IB",str(HERE/"exercise.py"),str(net),"compact",str(retained),str(crypto),str(file)]
        if interrupt:
            cmd+=["--interrupt"]
        return subprocess.run(cmd,stdout=subprocess.PIPE)
    with server(net,full,work,"original-source") as original_port:
        from transport import rpc
        assert len(rpc(original_port,"inventory",start=0,limit=64)[0])==min(64,initial["distinct_blocks"])
        assert subprocess_compact(cert,True).returncode==73
        s=Store(retained)
        after_crash=s.counts()
        assert after_crash==initial["full"] and s.db.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
        s.export(work/"after-crash.d8")
        assert (work/"before.d8").read_bytes()==(work/"after-crash.d8").read_bytes()
        s.db.close()
        repaired=subprocess_compact(cert);repaired.check_returncode()
        compacted=json.loads(repaired.stdout)
    try:
        rpc(original_port,"inventory",start=0,limit=1)
    except OSError:
        pass
    else:
        raise RuntimeError("original service still online")
    s=Store(retained)
    assert compacted["store"]["by_source"]["DLF1"][0]==1
    s.export(work/"retained.d8")
    cid=bytes.fromhex(compacted["id"])
    assert s.body("proofs",cid)==cert.read_bytes()
    # All online serving sources lack this evidence until the withdrawn certificate returns.
    with s.transaction():
        s.db.execute("DELETE FROM links WHERE id=?",(cid,))
        s.db.execute("DELETE FROM proofs WHERE id=?",(cid,))
    s.db.execute("VACUUM")
    s.db.close()
    missing_replica=work/"unavailable.sqlite"
    shutil.copyfile(retained,missing_replica)
    reader=Lab(work/"new-node",net/"runtime")
    reader.initialize()
    (reader.home/"nodes/c/peers.json").write_text("[]")
    ledger=reader.home/"nodes/c/chain.sqlite"
    local=work/"received"/"evidence.sqlite"
    local.parent.mkdir()
    assert not local.exists() and not ledger.exists()
    with server(net,retained,work,"withheld") as port:
        paused=cold_command(net,crypto,local,ledger,port)
        repeated=cold_command(net,crypto,local,ledger,port)
        assert paused["pending_evidence"]==repeated["pending_evidence"] and paused["pending_evidence"] is not None
        assert paused["state"]["height"]+1==paused["pending_evidence"]["height"]
        same(paused["state"],repeated["state"])
    check=Checks(net,crypto);s=Store(retained)
    try:
        s.add(cert.read_bytes(),check)
    finally:
        s.db.close();check.close()
    with server(net,retained,work,"returned") as port:
        old=cold_command(net,crypto,local,ledger,port,initial["reference"][0]["height"])
        switched=cold_command(net,crypto,local,ledger,port)
        assert old["pending_evidence"] is switched["pending_evidence"] is None
        same(old["state"],initial["reference"][0]);same(switched["state"],initial["reference"][1])
        assert switched["reorgs"] and old["traffic"].get("source_D8C1")==1 and switched["traffic"].get("source_DLF1")==1
        assert old["traffic"].get("source_DLF1",0)==0 and switched["traffic"].get("source_D8C1",0)==0
    # Independently reproduce underfilled-certificate compaction and count shared/duplicated slots.
    partial_store=work/"partial.sqlite"
    shutil.copyfile(retained,partial_store)
    subset=compact(net,partial_store,crypto,partial)
    s=Store(partial_store)
    s.export(work/"partial.d8")
    s.db.close()
    more=work/"additional"
    more.mkdir()
    with server(net,missing_replica,work,"first-choice") as first, server(net,partial_store,work,"partial-service") as second:
        partial_replay=cold_command(net,crypto,more/"received.sqlite",more/"ledger.sqlite",first,fallback=second)
        same(partial_replay["state"],initial["reference"][1])
        assert partial_replay["pending_evidence"] is None and partial_replay["fallback_traffic"]["source_D8C1"]>=1
        only=work/"only-certificates"
        only.mkdir()
        pure=cold_command(net,crypto,only/"evidence.sqlite",only/"ledger.sqlite",second)
        same(pure["state"],initial["reference"][1])
        assert pure["traffic"].get("source_D8C1")==2 and pure["traffic"].get("source_DLF1",0)==0
    cold_disk=dict(ledger_B=ledger.stat().st_size,source_index_B=local.stat().st_size)
    restore={}
    child=subprocess.Popen([sys.executable,"-IB",str(HERE/"peer.py"),str(net),"wallet-node",str(reader.home),str(local),str(crypto)])
    def wallet(*args):
        cmd=[sys.executable,"-IB",str(net/"devnet/cli.py"),"--home",str(reader.home),"--runtime",str(net/"runtime"),*map(str,args)]
        return json.loads(subprocess.check_output(cmd,timeout=200))
    try:
        wait(lambda:reader.status("c"),lambda s:s["tip"]==switched["state"]["tip"],"peer-restored wallet node",50)
        incoming=wallet("restore","recovered",home/"recipient.seed","--node","c")
        if incoming["balance"]!=1201 or incoming["incoming_notes"]!=8:
            raise ValueError("unexpected restored incoming funds")
        reader.mining("c",-1,"miner-a")
        paid=wallet("send","recovered","miner-b",250,"--intent","after-compaction","--node","c","--wait",100)
        reader.mining("c",0)
        remaining=wallet("balance","recovered","--node","c")
        assert paid["status"]=="confirmed" and paid["real_inputs"]==2 and paid["fee"]==3 and remaining["balance"]==948
        sid=paid["tx"]
        proof=reader.request("c","tx",id=sid)[1]
        assert chain.txid_of(proof).hex()==sid and len(proof)==143187
        tip=reader.status("c"); assert tip["fees"]==27 and tip["spent"]==18
        suffix=work/"successor"
        suffix.mkdir()
        public_ids=reader.request("c","selected",start=switched["state"]["height"]+1,limit=128)[0]
        assert public_ids and public_ids[-1]==tip["tip"]
        for bid in public_ids:
            b=reader.request("c","block",id=bid)[1]
            assert chain.block_id(b).hex()==bid
            (suffix/(bid+".bin")).write_bytes(b)
        (suffix/"payment.bin").write_bytes(proof)
        save(suffix/"SUMMARY.json",dict(parent=switched["state"]["tip"],selected=public_ids,
             state={k:tip[k] for k in ("tip","height","work","header","fees","issued","spent","spent_set_sha256")},payment=sid))
        restore=dict(balance=incoming["balance"],incoming_notes=incoming["incoming_notes"],cold_sync=incoming["sync"],
                     spent=250,fee=3,change=paid["change"],remaining=remaining["balance"],attempts=len(paid["attempts"]),
                     new_sid=sid,packet_B=len(proof),height=tip["height"],spent_set_sha256=tip["spent_set_sha256"])
    finally:
        try:reader.admin("c","stop")
        except OSError:child.terminate()
        child.wait(timeout=40)
    results=dict(format="D8-ACCEPT-1",initial=initial,cold_disk_before_spend=cold_disk,interrupted_exit=73,crash_rollback=after_crash,
                 compacted=compacted,partial_compacted=subset,fallback_replay=partial_replay,only_certificates_replay=pure,missing=paused,retry=repeated,original_branch=old,
                 replacement_branch=switched,original_peer_offline=True,restore=restore)
    save(work/"ACCEPT.json",results)
    print(json.dumps(dict(archive_B=compacted["store"]["interchange_B"],cold_restored=restore["balance"],
                          remaining=restore["remaining"],reorg=bool(switched["reorgs"]))))
    return results


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("network",type=Path)
    sub=p.add_subparsers(dest="mode",required=True)
    cp=sub.add_parser("compact")
    for k in ("store","crypto","cert"):cp.add_argument(k,type=Path)
    cp.add_argument("--interrupt",action="store_true")
    full=sub.add_parser("accept")
    for k in ("home","live","crypto","certificates","work"):full.add_argument(k,type=Path)
    a=p.parse_args();net=a.network.resolve();sys.path.insert(0,str(net/"devnet"))
    import chain
    if a.mode=="compact":
        print(json.dumps(compact(net,a.store,a.crypto,a.cert,a.interrupt)))
    else:exercise(net,a.home.resolve(),a.live.resolve(),a.crypto.resolve(),a.certificates.resolve(),a.work.resolve())
