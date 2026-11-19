"""Interrupt a real archival fork replay after a replacement block has entered its SQLite transaction."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import chain
import runtime
from run import Resources
from wire import need


def fingerprint(ledger):
    h = hashlib.sha256()
    tables = (("config","id"), ("metrics","id"), ("blocks","id"), ("sel","h"),
              ("outs","pos"), ("spent","nf"), ("pool","seq"), ("txloc","tx,bid"))
    for name, order in tables:
        h.update(name.encode()+b"\0")
        for row in ledger.db.execute(f"SELECT * FROM {name} ORDER BY {order}"):
            for field in row:
                if isinstance(field, bytes):
                    data = b"b"+field
                elif isinstance(field, int):
                    data = b"i"+struct.pack("<q",field)
                else:
                    need(field is None, "unexpected database column type")
                    data = b"n"
                h.update(struct.pack("<Q",len(data))+data)
    return h.hexdigest()


def paths(result):
    winning = result["winning"]
    reorg = result["reorg"]
    common = 0 if reorg["common"] == chain.GENESIS.hex() else winning.index(reorg["common"])+1
    old = winning[:common]+reorg["detached"]
    side = winning[common:]
    need(side == reorg["attached"] and len(old)-common > chain.UNDO, "expected an archived deep fork")
    for ident in (*winning,*old):
        need(isinstance(ident,str) and len(ident) == 64 and bytes.fromhex(ident).hex() == ident,
             "noncanonical public block identifier")
    for i, bid in enumerate(side):
        h = common+i+1
        if h > len(old) or (h == len(old) and bid < old[-1]):
            need(i > 0, "a genuine stored replacement prefix is required")
            return old, side[:i], bid, common
    raise ValueError("capture has no winning fork")


def read_block(evidence, ident):
    data = (evidence/"blocks"/(ident+".bin")).read_bytes()
    need(chain.block_id(data).hex() == ident, "incorrect archived body")
    return data


def phase(args):
    result = json.loads((args.evidence/"RESULT.json").read_bytes())
    need(result["genesis"] == chain.GENESIS.hex(), "wrong captured network")
    old, staged, winner, common = paths(result)
    resources = Resources(runtime.config(args.runtime))
    try:
        ledger = chain.Chain(args.db,resources.backend)
        try:
            if args.phase == "prepare":
                for ident in (*old,*staged):
                    ledger.accept(read_block(args.evidence,ident))
                old_state = ledger.status()
                need(old_state["tip"] == old[-1] and old_state["deep_replays"] == 0, "unexpected initial tip")
                return dict(logical_sha256=fingerprint(ledger),tip=old[-1],height=old_state["height"])
            if args.phase == "interrupt":
                ledger.db.execute("PRAGMA cache_size=8")
                attach = ledger._attach

                def after_attachment(raw, block, bid, existing=False):
                    computed = attach(raw,block,bid,existing)
                    if bid.hex() == staged[0]:
                        need(ledger.db.in_transaction and ledger._head()["id"] == bid and existing,
                             "missing tentative deep-replay checkpoint")
                        journal = Path(str(args.db)+"-journal")
                        with journal.open("rb") as file:
                            magic = file.read(8).hex()
                        need(magic == "d9d505f920a163d7", "expected a disk-backed hot journal")
                        marker = dict(logical_sha256=fingerprint(ledger),height=block.height,
                                      prefix_blocks_from_genesis=common+1,tip=bid.hex(),
                                      journal_B=journal.stat().st_size,journal_magic=magic)
                        print(json.dumps(marker),flush=True)
                        signal.pause()
                        raise RuntimeError("resumed an interrupted replay")
                    return computed

                # The observer runs only after the original attachment and all its normal proof/state checks.
                ledger._attach = after_attachment
                ledger.accept(read_block(args.evidence,winner))
                raise RuntimeError("expected the parent to terminate the writer")
            recovered = fingerprint(ledger)
            state = ledger.status()
            need(state["tip"] == old[-1] and state["deep_replays"] == 0, "selected state not recovered")
            need(ledger.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                 and not ledger.db.execute("PRAGMA foreign_key_check").fetchall(), "recovered database integrity")
            accepted = ledger.accept(read_block(args.evidence,winner))
            end = ledger.status()
            need(accepted["deep_replay"] and end["tip"] == winner and end["deep_replays"] == 1,
                 "failed automatic deep selection on retry")
            return dict(recovered_logical_sha256=recovered,old_tip=state["tip"],winner=winner,
                        retry_height=end["height"],deep_replays=end["deep_replays"],sqlite_integrity="ok")
        finally:
            ledger.close()
    finally:
        resources.close()


def run(args):
    identity = runtime.config(args.runtime)
    with tempfile.TemporaryDirectory(prefix="pqdev1-crash-") as tmp:
        db = Path(tmp)/"chain.sqlite"

        def command(name):
            return [sys.executable,"-I","-B",str(Path(__file__).resolve()),"--runtime",str(args.runtime),
                    "--evidence",str(args.evidence),"--phase",name,"--db",str(db)]

        old = json.loads(subprocess.check_output(command("prepare"),timeout=120))
        with subprocess.Popen(command("interrupt"),stdout=subprocess.PIPE,text=True) as writer:
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(writer.stdout,selectors.EVENT_READ)
                    need(ready.select(90), "writer failed to reach the crash point")
                partial = json.loads(writer.stdout.readline())
                need(partial["logical_sha256"] != old["logical_sha256"], "tentative database did not change")
                os.kill(writer.pid,signal.SIGKILL)
                need(writer.wait(timeout=10) == -signal.SIGKILL, "wrong writer exit status")
            finally:
                if writer.poll() is None:
                    writer.kill()
        after = json.loads(subprocess.check_output(command("recover"),timeout=120))
        need(old["logical_sha256"] == after["recovered_logical_sha256"], "partial effects survived SIGKILL")
        return dict(evidence_sha256=hashlib.sha256((args.evidence/"RESULT.json").read_bytes()).hexdigest(),
                    profile_sha256=identity.profile_sha,binary_sha256=identity.binary_sha,signal="SIGKILL",
                    before=old,interrupted=partial,after=after)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime",type=Path,required=True)
    parser.add_argument("--evidence",type=Path,required=True)
    parser.add_argument("--phase",choices=("prepare","interrupt","recover"),help=argparse.SUPPRESS)
    parser.add_argument("--db",type=Path,help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (args.phase is None) != (args.db is None):
        parser.error("worker phase requires private test database path")
    print(json.dumps(phase(args) if args.phase else run(args),sort_keys=True,indent=2))
