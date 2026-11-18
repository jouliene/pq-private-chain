"""Independently verify per-payment durable effects and partial-batch behavior."""

from pathlib import Path
import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile


def snapshot(db_path, genesis, bodies, completed):
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        root, count, fees, frontier = db.execute("SELECT root,n,fees,frontier FROM head WHERE id=0").fetchone()
        rows = db.execute("SELECT height,body FROM bodies ORDER BY height").fetchall()
        spent = {row[0] for row in db.execute("SELECT nf FROM spent")}
        leaves = db.execute("SELECT pos,origin,cm FROM funded ORDER BY pos").fetchall()
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        db.close()
    expected_nf = set()
    expected_cm = [genesis[104:168], genesis[232:296]]
    for raw in bodies[:completed]:
        statement = raw[20:548]
        expected_nf.update((statement[80:144], statement[144:208]))
        expected_cm.extend((statement[208:272], statement[272:336]))
    assert len(root) == 64 and frontier and (count, fees) == (2 + 2*completed, 2_112_248*completed)
    assert [row[0] for row in leaves] == list(range(count))
    assert [row[2] for row in leaves] == expected_cm and all(len(row[1]) == 64 for row in leaves)
    assert [row[1] for row in leaves[:2]] == [genesis[40:104], genesis[168:232]]
    assert spent == expected_nf and len(spent) == 2*completed
    assert rows == list(enumerate(bodies[:completed], start=1))
    if completed < len(bodies):
        assert root == bodies[completed][20+344:20+408]
    return {"committed_payments": completed, "funded": count, "fees": fees, "nullifiers": len(spent),
            "root_hex": root.hex(), "frontier_sha256": hashlib.sha256(frontier).hexdigest(),
            "archive_bytes": sum(len(row[1]) for row in rows), "database_integrity": "ok"}


def test(args):
    src = args.bodies
    genesis = (src / "genesis.bin").read_bytes()
    assert hashlib.sha256(genesis).hexdigest() == args.genesis_sha
    bodies = [(src / f"payment{i}.body").read_bytes() for i in (1, 2, 3)]
    output = {}
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        for mode, completed in (("valid", 3), ("bad_second_receipt", 1), ("replayed_second_as_third", 2)):
            data = temp / mode
            data.mkdir()
            (data / "genesis.bin").write_bytes(genesis)
            submitted = list(bodies)
            if mode == "bad_second_receipt":
                altered = bytearray(bodies[1])
                altered[548+2000] ^= 1
                submitted[1] = bytes(altered)
            elif mode == "replayed_second_as_third":
                submitted[2] = bodies[1]
            for i, raw in enumerate(submitted, start=1):
                (data / f"payment{i}.body").write_bytes(raw)
            dest = temp / (mode + "-db")
            run = subprocess.run([sys.executable, "-IB", str(args.driver),
                "--installation", str(args.installation), "--approve-installation", args.install_sha,
                "--candidate", str(args.binary), "--approve-candidate", args.binary_sha,
                "--public-genesis", args.genesis_sha, "--output", str(data), "--durable-dir", str(dest)],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=90)
            assert (run.returncode == 0) == (mode == "valid")
            result = snapshot(dest / "node.sqlite", genesis, bodies, completed)
            if run.returncode == 0:
                result["measured"] = json.loads(run.stdout)
            output[mode] = result
    return output


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("driver", "installation", "binary", "bodies"):
        p.add_argument(name, type=Path)
    for name in ("install_sha", "binary_sha", "genesis_sha"):
        p.add_argument(name)
    print(json.dumps(test(p.parse_args()), indent=2))
