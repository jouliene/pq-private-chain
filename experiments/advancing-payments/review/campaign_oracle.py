"""Independently check the public branch, packet correspondence and database from an AP campaign."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from public_chain import check, proof_public, reference


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(args):
    manifest = json.loads((args.campaign/"TRACE.json").read_bytes())
    genesis = (args.campaign/"genesis.bin").read_bytes()
    assert manifest["genesis_sha256"] == sha(genesis) == args.genesis_sha
    assert manifest["profile_sha256"] == args.profile_sha
    def packet(name):
        if name is None:
            return b""
        raw = (args.campaign/"packets"/(name+".bin")).read_bytes()
        assert sha(raw) == name
        return raw
    authored = {}
    for label,ref in manifest["submissions"].items():
        records = proof_public(packet(ref))
        assert len(records) == 1
        authored.setdefault(records[0],set()).add(label)
    blocks = {}
    for identifier,record in manifest["blocks"].items():
        raw = bytes.fromhex(record["prefix"])+packet(record["packet"])
        assert sha(raw)==identifier and len(raw)==record["size"]
        blocks[identifier] = raw
    ids = reference(args.reference,["--header-ids"],b"".join(b[8:140] for b in blocks.values()))
    by_id = {}
    forwarded = {}
    for (identifier,raw),line in zip(blocks.items(),ids,strict=True):
        height,bid = line.split()
        assert int(height) == int.from_bytes(raw[40:44],"little")
        by_id[identifier] = bid
        records = proof_public(raw[152:])
        assert all(r in authored for r in records)
        forwarded[identifier] = [sorted(authored[r]) for r in records]
    current = []
    transitions = []
    skip = {}
    event_counts = {}
    for event in manifest["events"]:
        op = event["op"]
        event_counts[op] = event_counts.get(op,0)+1
        if op=="extend":
            current.append(event["block"])
        elif op=="switch":
            tip_ids = [by_id[x] for x in current]
            # The experiment's reorg has a non-genesis base.
            assert event["base"] in tip_ids
            current = current[:tip_ids.index(event["base"])+1]+list(event["blocks"])
        elif op in ("reject","reject_switch"):
            skip[event["reason"]] = skip.get(event["reason"],0)+1
        else:
            raise ValueError(op)
        assert len(current)==event["state"]["height"] and by_id[current[-1]]==event["state"]["id"]
        state = check(genesis,args.genesis_sha,args.profile_sha,[blocks[x] for x in current],args.reference)
        assert state["funded"]==event["state"]["count"] and state["fees"]==event["state"]["fees"]
        assert state["distinct_spent"]==event["state"]["spent"] and state["head_id"]==event["state"]["id"]
        if op=="switch":
            transitions.append(dict(height=len(current),tip=state["head_id"]))
    reports = [check(genesis,args.genesis_sha,args.profile_sha,[blocks[x] for x in current],args.reference,db)
               for db in args.database]
    assert not reports or reports.count(state)==len(reports)
    # De-duplicate a data object referenced through multiple event descriptions.
    widths = {}
    for key,records in forwarded.items():
        width = len(records)
        widths[width] = widths.get(width,0)+1
    return dict(genesis_sha256=args.genesis_sha,profile_sha256=args.profile_sha,events=event_counts,
                table_comparisons=len(reports),recognized_authored_singles=len(authored),
                distinct_block_objects_by_occupancy=widths,forwarded_wallet_rows_compared=sum(k*n for k,n in widths.items()),
                branch_switches=transitions,rejection_state_checks=skip,final=state)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("campaign",type=Path)
    p.add_argument("reference",type=Path)
    p.add_argument("genesis_sha")
    p.add_argument("profile_sha")
    p.add_argument("--database",action="append",type=Path,default=[])
    print(json.dumps(parse(p.parse_args()),indent=2,sort_keys=True))
