"""Export numerical proving costs for the one matching already-public B payment."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sqlite3


def write(home, public):
    packet = public / "legacy-b.bin"
    tx = sha256(packet.read_bytes()).hexdigest()
    source = (home / "wallets/comparison-payer/mng1-intents.sqlite").resolve(strict=True)
    db = sqlite3.connect(source.as_uri()+"?mode=ro", uri=True)
    try:
        row = db.execute("SELECT prove_s, json_extract(accounting,'$.prover_cpu_s'),"
                         " json_extract(accounting,'$.prover_role_peak_rss_KiB') FROM attempts"
                         " WHERE intent='source-identity-b' AND tx=?", (tx,)).fetchone()
        if row is None or any(type(x) not in (int, float) or x <= 0 for x in row):
            raise ValueError("missing target B attempt metrics")
    finally:
        db.close()
    result = dict(tx=tx, packet_B=packet.stat().st_size, proving_wall_s=row[0],
                  prover_cpu_s=row[1], prover_role_peak_rss_KiB=row[2])
    (public / "legacy-b-costs.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("comparison_home", type=Path)
    p.add_argument("public", type=Path)
    args = p.parse_args()
    write(args.comparison_home, args.public)
