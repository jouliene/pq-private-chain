"""Replay public captured branches and validate fixed-prefix range serving and the v1 index upgrade."""

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import chain
import history
import runtime
from node import Node
from run import Resources


def need(value,message):
    if not value:
        raise AssertionError(message)


def rejected(function,reason):
    try:
        function()
    except ValueError as error:
        need(str(error) == reason, (reason,str(error)))
    else:
        raise AssertionError("unexpected acceptance: "+reason)


def trace_read(db,function):
    queries = []
    steps = 0

    def tick():
        nonlocal steps
        steps += 1
        return 0

    db.set_trace_callback(queries.append)
    db.set_progress_handler(tick,1)
    try:
        result = function()
    finally:
        db.set_trace_callback(None)
        db.set_progress_handler(None,0)
    selects = [q for q in queries if q.lstrip().upper().startswith("SELECT")]
    need(all("OFFSET" not in q.upper() and " RAW" not in q.upper() and " SPENT " not in q.upper()
             for q in selects), "history used an archive or global scan")
    return result,len(selects),steps


def check(args, res):
    evidence = args.evidence
    report = json.loads((evidence/"RESULT.json").read_bytes())
    winning = report["winning"]
    split = winning.index(report["reorg"]["common"])+1
    losing = winning[:split]+report["reorg"]["detached"]
    gen = chain.GENESIS.hex()
    need(report["genesis"] == gen and len(losing)-split > chain.UNDO, "expected a deep fork")

    def block(ident):
        raw = (evidence/"blocks"/(ident+".bin")).read_bytes()
        need(chain.block_id(raw).hex() == ident, "public block identity")
        return raw

    def assert_rows(rows, ids):
        need([row["id"].hex() for row in rows] == ids,"history order")
        for row,ident in zip(rows,ids,strict=True):
            data = block(ident)
            b = chain.decode_block(data)
            need(row["height"] == b.height and row["parent"] == b.parent and row["header"][100:] == b.root,
                 "history header")
            ctx = chain.reward_context(b.parent,b.height,b.pk,chain.packet_vector(b.packets))
            need(row["reward"] == ctx+b.pk+chain.u64(b.amount)+b.reward_cm, "reward data")
            for slot,packet in zip(row["slots"],b.packets,strict=True):
                expected, = res.backend.verify(packet)
                need(slot["txid"] == hashlib.sha256(packet).digest() and list(expected.nfs) == slot["nfs"]
                     and list(expected.cms) == slot["cms"] and list(expected.cts) == slot["cts"], "authorized slot bytes")

    with tempfile.TemporaryDirectory(prefix="pqdev-history-") as temp:
        path = Path(temp)/"chain.sqlite"
        node = chain.Chain(path,res.backend)
        try:
            node.accept(block(winning[0]))
            genesis = [[0,gen]]
            small = node.history_head([[1,winning[0]],*genesis])
            need(small["common_height"] == 1 and small["reads"]["payload_queries"] == 0,"small unchanged head")
            for bid in winning[1:split]:
                node.accept(block(bid))
            fixed = node.history_head(genesis)
            target = fixed["tip"]
            first,raw = node.history_range(target,1,gen,2)
            assert_rows(history.decode_range(raw),winning[:2])
            # Append a genuine child before fetching the remainder of the fixed prefix.
            high,low = sorted((winning[split],losing[split]),reverse=True)
            node.accept(block(high))
            rest,raw2 = node.history_range(target,first["next"],winning[1],16)
            assert_rows(history.decode_range(raw2),winning[2:split])
            need(rest["next"] is None and node.history_check(target)["height"] == split,"fixed prefix after append")
            # Opposite arrival order for equal-work siblings forces a real shallow change by tip-ID tie-break.
            shallow = node.accept(block(low))
            need(shallow["changed"] and len(shallow["detached"]) == 1,"expected shallow fork")
            loc_old = [[split+1,high],[split,target],*genesis]
            found = node.history_head(loc_old)
            need(found["common"] == target and found["reads"]["payload_B"] == 0,"shallow discovery")
            rejected(lambda:node.history_check(high),"history branch changed")
            rejected(lambda:node.history_range(high,1,gen,1),"history branch changed")
            rejected(lambda:node.history_range(low,split+1,high,1),"history branch changed")
            rejected(lambda:node.history_range(low,1,gen,17),"history range bounds")
            for bid in losing[split:]:
                node.accept(block(bid))
            need(node.status()["tip"] == losing[-1], "old fully selected")
            for bid in winning[split:]:
                node.accept(block(bid))
            head = node.status()
            need(head["tip"] == winning[-1] and head["deep_replays"] >= 1, "actual consensus deep switch")
            deep = node.history_head([[len(losing),losing[-1]],[split,target],*genesis])
            need(deep["common"] == target and not deep["reads"]["payload_B"],"deep discovery")
            rejected(lambda:node.history_check(losing[-1]),"history branch changed")
            target = head["tip"]
            (warm,queries,vm) = trace_read(node.db,lambda:node.history_head([[len(winning),target],*genesis]))
            need(warm["reads"] == small["reads"] and queries == 2,"constant unchanged head")
            (empty,body) = node.history_range(target,len(winning)+1,target,1)
            need(body == b"" and history.decode_range(body) == [] and empty["reads"]["payload_queries"] == 0,
                 "empty suffix did a payload read")
            (pair,q,steps) = trace_read(node.db,lambda:node.history_range(target,len(winning),winning[-2],1))
            meta,suffix = pair
            assert_rows(history.decode_range(suffix),winning[-1:])
            need(q == meta["reads"]["sql_queries"] == 3 and meta["reads"]["payload_rows"] == 1
                 and meta["reads"]["payload_B"]+9 == len(suffix),"range meter vs SQL trace")
            plans = [r[3] for r in node.db.execute("EXPLAIN QUERY PLAN "+history.PublicHistory.RANGE_SQL,(1,3))]
            head_plan = node.db.execute("EXPLAIN QUERY PLAN "+history.PublicHistory.HEAD_SQL,(bytes.fromhex(target),)).fetchone()[3]
            need("USING COVERING INDEX wallet_header_lookup" in head_plan, "head metadata lookup must avoid proof-bearing pages")
            need(all("SEARCH" in plan and "SCAN" not in plan for plan in plans),"range must seek both indexes")
            complete = []
            start,base = 1,gen
            while start is not None:
                meta,raw = node.history_range(target,start,base,3)
                rows = history.decode_range(raw)
                complete.extend(rows)
                base = rows[-1]["id"].hex()
                start = meta["next"]
            assert_rows(complete,winning)
            rejected(lambda:history.decode_range(suffix+b"x"),"trailing history bytes")
            rejected(lambda:history.decode_range(suffix[:-1]),"truncated history header" if not complete[-1]["slots"]
                     else "truncated history slot")
            # Exercise the real Node dispatch whitelist without opening any participant/private service.
            receiver = Node.__new__(Node)
            receiver.db = node
            rejected(lambda:receiver.dispatch({"op":"history_head","locator":[],"address":"unused"},b"",False),
                     "unexpected history request fields")
            info = receiver.dispatch({"op":"history_info"},b"",False)[0]
            need(info["startup"]["archive_blocks"] == 0,"unexpected new-archive migration")

            # Remove only the derived table from this temporary test archive to reproduce its exact v1 storage schema.
            node.db.execute("DROP TABLE wallet_history_v2")
            node.db.execute("DROP INDEX wallet_header_lookup")
        finally:
            node.close()
        old = chain.Chain(path,res.backend)
        try:
            migrated = dict(old.history.startup)
            archived = old.db.execute("SELECT count(*),sum(length(raw)) FROM blocks WHERE h>0").fetchone()
            need(migrated["index_created"] and migrated["archive_blocks"] == archived[0]
                 and migrated["archive_bytes"] == archived[1],"explicit archive migration")
            actual = []
            for h in range(1,len(winning)+1):
                base = winning[h-2] if h>1 else gen
                m,raw = old.history_range(target,h,base,1)
                actual.extend(history.decode_range(raw))
            need(actual == complete and old.status() == head,"migration changed history or selected ledger")
        finally:
            old.close()
        # Also exercise a database created by the first, WITHOUT ROWID projection revision.
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE wallet_history_v1 (bid BLOB PRIMARY KEY REFERENCES blocks(id), record BLOB NOT NULL) WITHOUT ROWID")
            db.execute("INSERT INTO wallet_history_v1 SELECT * FROM wallet_history_v2")
            db.execute("DROP TABLE wallet_history_v2")
            db.execute("DROP INDEX wallet_header_lookup")
        upgraded = chain.Chain(path,res.backend)
        try:
            v1_projection = dict(upgraded.history.startup)
            need(v1_projection["archive_bytes"] == 0 and v1_projection["projection_rows_copied"] == archived[0]
                 and v1_projection["projection_bytes_copied"] == migrated["written_payload_B"], "projection-only migration")
            need(upgraded.history_range(target,len(winning),winning[-2],1)[1] == suffix, "projection migration suffix")
        finally:
            upgraded.close()
        reopened = chain.Chain(path,res.backend)
        try:
            need(not reopened.history.startup["index_created"] and reopened.history.startup["archive_bytes"] == 0,
                 "migration reran on reopen")
        finally:
            reopened.close()
    return dict(public_capture_sha256=hashlib.sha256((evidence/"RESULT.json").read_bytes()).hexdigest(),
                selected_blocks=len(winning),verified_ordinary_slots=sum(len(b["slots"]) for b in complete),
                unchanged_at_heights=[1,len(winning)],unchanged_reads=warm["reads"],unchanged_sqlite_vm_steps=vm,
                fixed_target_height=split,extension_served_before_remaining_page=True,
                shallow_common_height=found["common_height"],deep_common_height=deep["common_height"],
                empty_suffix_reads=empty["reads"],single_suffix_reads=pair[0]["reads"],single_suffix_body_B=len(suffix),
                single_suffix_sqlite_vm_steps=steps,query_plan=plans,head_query_plan=head_plan,v1_projection_migration=v1_projection,v1_compatible_migration=migrated,
                restored_selected_effects_identical=True,repeat_migration_required=False)


def legacy_copy(source, resources):
    """Make a read-only backup of a genuine existing v1 operator DB, then migrate the backup only."""
    with tempfile.TemporaryDirectory(prefix="pqdev-v1-copy-") as temp:
        path = Path(temp)/"archive.sqlite"
        source_db = sqlite3.connect(source.resolve(strict=True).as_uri()+"?mode=ro",uri=True)
        copy = sqlite3.connect(path)
        try:
            source_db.backup(copy)
            old_tip, = copy.execute("SELECT id FROM sel ORDER BY h DESC LIMIT 1").fetchone()
            need(not copy.execute("SELECT 1 FROM sqlite_schema WHERE name IN ('wallet_history_v1','wallet_history_v2')").fetchone(),"expected v1 archive")
            size_before = copy.execute("PRAGMA page_count").fetchone()[0]*copy.execute("PRAGMA page_size").fetchone()[0]
        finally:
            source_db.close()
            copy.close()
        start = time.monotonic()
        node = chain.Chain(path,resources.backend)
        try:
            elapsed = time.monotonic()-start
            head = node.history_head([])
            need(head["tip"] == old_tip.hex(), "v1 migration changed selected head")
            side_count, = node.db.execute("SELECT count(*) FROM wallet_history_v2").fetchone()
            stats = node.history.startup
            need(side_count == stats["archive_blocks"],"v1 archive coverage")
            size_after = node.db.execute("PRAGMA page_count").fetchone()[0]*node.db.execute("PRAGMA page_size").fetchone()[0]
            return dict(startup=stats,selected_height=head["height"],selected_tip=head["tip"],
                        elapsed_s=elapsed,before_file_B=size_before,after_file_B=size_after)
        finally:
            node.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime",required=True,type=Path)
    p.add_argument("--evidence",type=Path,default=HERE/"evidence/author")
    p.add_argument("--v1-archive",type=Path,help="make and migrate a read-only backup of this legacy public DB")
    args = p.parse_args()
    resources = Resources(runtime.config(args.runtime))
    try:
        result = check(args,resources)
        if args.v1_archive:
            result["operator_v1_copy"] = legacy_copy(args.v1_archive,resources)
        print(json.dumps(result,indent=2,sort_keys=True))
    finally:
        resources.close()
