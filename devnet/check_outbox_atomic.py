"""Exercise first-packet reservation rollback on an isolated genuine wallet-walkthrough copy."""
import argparse
from contextlib import ExitStack, closing
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE/"wallet-review")]
from cli import Lab
import chain
from intents import Outbox
from run import Resources
import runtime
from wire_meter import Meter


def configure(home,port):
    home.mkdir(mode=0o700)
    (home/"network.json").write_text(json.dumps(dict(ports={"c":port},version=1)))


def readonly(path):
    return sqlite3.connect(path.resolve(strict=True).as_uri()+"?mode=ro",uri=True)


def normal_send(home,runtime_dir,temp):
    server=temp/"server"
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1",0))
        configure(server,sock.getsockname()[1])
    node_dir=server/"nodes/c"
    node_dir.mkdir(parents=True)
    source=home/"nodes/c"
    shutil.copy2(source/"miner.pk",node_dir/"miner.pk")
    (node_dir/"peers.json").write_text("[]")
    with closing(readonly(source/"chain.sqlite")) as src,closing(sqlite3.connect(node_dir/"chain.sqlite")) as dest:
        src.backup(dest)
    lab=Lab(server,runtime_dir)
    with ExitStack() as group:
        lab.launch("c",continuous=False)
        group.callback(lab.stop)
        initial=lab.status("c")
        assert initial["remaining"]==0 and not initial["peers"]
        relay=group.enter_context(Meter(lab.cfg["ports"]["c"]))
        client=temp/"client"
        configure(client,relay.port)
        private=client/"wallets"/"funded"
        private.mkdir(parents=True,mode=0o700)
        original=home/"client/wallets/live"
        shutil.copy2(original/"seed",private/"seed")
        address=(original/"address").read_bytes()
        assert len(address)==1601
        bad=address[:1]+bytes([255])*32+address[33:]
        framed=b"PQDADDR1"+chain.NETWORK+bad
        destination=temp/"invalid-address"
        destination.write_bytes(framed+sha256(framed).digest())
        def invoke(*args):
            return subprocess.run([str(HERE.parent/"pqd"),"--home",str(client),"--runtime",str(runtime_dir),*args],
                                  capture_output=True,timeout=60)
        balance=invoke("balance","funded")
        assert balance.returncode==0 and json.loads(balance.stdout)["balance"]>=4,"expected funded disposable wallet"
        ident="invalid-address-atomic-control"
        for args in (("send","funded","@"+str(destination),"1","--intent",ident),("resume","funded",ident)):
            refusal=invoke(*args)
            assert refusal.returncode and not refusal.stdout and refusal.stderr.strip()==b"invalid compact payment", "unexpected CLI failure"
            with Outbox(private) as out:
                saved=out.get(ident)
                assert saved["pinned"] is None and saved["amount"]==1 and saved["address"]==bad
                assert saved["disposition"]=="new" and not out.attempts(ident)
                assert not out.db.execute("SELECT 1 FROM reservations").fetchone()
        assert not any(row["op"]=="submit" for row in relay.rows)
        assert lab.status("c")["tip"]==initial["tip"]
        return dict(native_invalid_address_rejections=2,matching_tuple_on_reopen=True,recorded_attempts=0,
                    real_input_reservations=0,observed_submit_frames=0,selected_height=initial["height"])


def atomic_writes(home,native,temp):
    # Use two authorizations of the same actual fixture intent. Their source transcript
    # and private accounting only exist within this disposable local test.
    with closing(readonly(home/"client/wallets/live/intents.sqlite")) as source:
        source.row_factory=sqlite3.Row
        key,=source.execute("SELECT intent FROM attempts GROUP BY intent HAVING count(*)>=2 LIMIT 1").fetchone()
        intent=source.execute("SELECT * FROM intents WHERE id=?",(key,)).fetchone()
        rows=source.execute("SELECT * FROM attempts WHERE intent=? ORDER BY rowid LIMIT 2",(key,)).fetchall()
    pins=json.loads(intent["pinned"])
    with closing(readonly(home/"client/wallets/live/wallet-state.sqlite")) as owned:
        real_nfs={owned.execute("SELECT nf FROM owned WHERE cm=?",(bytes.fromhex(cm),)).fetchone()[0] for cm in pins}
    assert len(real_nfs)==len(pins) and len(real_nfs) in (1,2)
    attempts=[]
    nfs=[]
    public=Resources(native)
    try:
        for row in rows:
            raw=(home/"evidence/attempts"/(row["tx"]+".bin")).read_bytes()
            assert sha256(raw).hexdigest()==row["tx"]
            effect,=public.backend.verify(raw)
            assert effect.height==row["height"]
            nfs.append(set(effect.nfs))
            accounting=json.loads(row["accounting"])
            accounting["input_commitments"]=pins
            state=SimpleNamespace(height=row["height"],tip=bytes.fromhex(row["anchor"]))
            attempts.append((raw,state,accounting,row["prove_s"],pins))
        assert real_nfs<=nfs[0]&nfs[1]
    finally:
        public.close()
    private=temp/"atomic"
    private.mkdir(mode=0o700)
    def snapshot(db):
        return tuple([tuple(row) for row in db.execute("SELECT * FROM "+table+" ORDER BY rowid")]
                     for table in ("intents","reservations","attempts"))
    with Outbox(private) as out:
        out.register(key,intent["address"],intent["amount"])
        out.db.execute("CREATE TABLE fault_at_commit (id TEXT REFERENCES intents(id) DEFERRABLE INITIALLY DEFERRED)")
        checks={}
        for step,values in zip(("first","replacement"),attempts,strict=True):
            for failure in ("trigger","commit","serialization"):
                prior=snapshot(out.db)
                args=list(values)
                if failure=="serialization":
                    # Decimal supports integer arithmetic and comparisons, but json.dumps
                    # fails while constructing the INSERT, after earlier statements ran.
                    args[2]=dict(values[2],fee=Decimal(values[2]["fee"]))
                else:
                    action=("SELECT RAISE(ABORT,'injected late statement')" if failure=="trigger"
                            else "INSERT INTO fault_at_commit VALUES ('fixture-missing-parent')")
                    out.db.execute("CREATE TRIGGER inject AFTER UPDATE OF disposition ON intents "
                                   "WHEN NEW.disposition='prepared' BEGIN "+action+"; END")
                try:
                    out.prepare(key,*args)
                except TypeError as e:
                    assert failure=="serialization" and "JSON serializable" in str(e)
                except sqlite3.IntegrityError as e:
                    assert ((failure=="trigger" and str(e)=="injected late statement") or
                            (failure=="commit" and str(e)=="FOREIGN KEY constraint failed"))
                else:
                    raise AssertionError("injected failure escaped")
                assert not out.db.in_transaction and snapshot(out.db)==prior
                with closing(readonly(private/"intents.sqlite")) as after:
                    assert snapshot(after)==prior and not after.execute("SELECT 1 FROM fault_at_commit").fetchone()
                if failure!="serialization":
                    out.db.execute("DROP TRIGGER inject")
                checks[step+"_"+failure]=True
            out.prepare(key,*values)
            assert len(out.attempts(key))==(1 if step=="first" else 2)
            assert out.db.execute("SELECT count(*) FROM reservations").fetchone()[0]==len(pins)
            retained=out.db.execute("SELECT packet FROM attempts WHERE packet IS NOT NULL").fetchall()
            assert len(retained)==1 and retained[0][0]==values[0]
    return dict(publicly_verified_genuine_packets=2,common_real_inputs_verified=True,atomic_rollback=checks,
                valid_replacement_retains_one_packet=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home",type=lambda v:Path(v).resolve(strict=True),required=True)
    p.add_argument("--runtime",type=lambda v:Path(v).resolve(strict=True),required=True)
    a=p.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(dir="/dev/shm") as folder:
        temp=Path(folder)
        result=dict(invalid_address=normal_send(a.home,a.runtime,temp),
                    prepare=atomic_writes(a.home,runtime.config(a.runtime),temp))
    print(json.dumps(result,indent=2,sort_keys=True))
