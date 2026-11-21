"""Create a genuine released B spend of the original two notes in an independent peer home."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("funded", type=Path)
    parser.add_argument("home", type=Path)
    parser.add_argument("public", type=Path)
    args = parser.parse_args()
    funded, home, out = (p.resolve() for p in (args.funded, args.home, args.public))
    os.umask(0o077)
    home.mkdir(mode=0o700)
    shutil.copytree(funded/"deployment-b", home/"deployment")
    sys.path.insert(0, str(home/"deployment/devnet"))
    from chain import GENESIS, block_id, decode_block
    from cli import Lab
    lab = Lab(home, home/"deployment/runtime")
    data = json.loads((funded/"public/SCENARIO.json").read_bytes())
    tip = data["tips"]["initial"]["tip"]
    lineage = []
    while tip != GENESIS.hex():
        raw = (funded/"public/blocks"/(tip+".bin")).read_bytes()
        if block_id(raw).hex() != tip:
            raise ValueError("funding archive identity")
        lineage.append(raw)
        tip = decode_block(raw).parent.hex()
    try:
        lab.initialize()
        lab.launch("a",False)
        lab.links("a",[])
        for raw in reversed(lineage):
            if not lab.request("a","publish",raw)[0]["selected"]:
                raise ValueError("released B prefix replay")
        lab.new_wallet("comparison-payee")
        def command(*arguments):
            cmd = [ROOT/"pqd", "upgrade", "--home", home, "--node","a","--suite","B", *map(str, arguments)]
            return json.loads(subprocess.check_output(cmd, timeout=300))
        restored = command("restore","comparison-payer",funded/"owner-backups/offline")
        if (restored["balance"],restored["notes"]) != (34,2):
            raise ValueError("released B recovery")
        row = command("send","comparison-payer","comparison-payee",28,data["asset_ids"]["managed"],25,
                      "--intent","source-identity-b")
        packet = lab.request("a","tx",id=row["tx"])[1]
        if not packet.startswith(b"MSP2") or row["real_inputs"] != 2 or sha256(packet).hexdigest() != row["tx"]:
            raise ValueError("unsettled B comparison")
        head = lab.mine("a",1)
        raw = lab.request("a","block",id=head["tip"])[1]
        if decode_block(raw).packets != (packet,) or head["height"] != 25:
            raise ValueError("legacy peer did not confirm B at H25")
        event, = lab.request("a","supply-observation",txs=[row["tx"]])[0]["events"]
        (out/"legacy-b.bin").write_bytes(packet)
        (out/"legacy-b-block.bin").write_bytes(raw)
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from scenario_b_metrics import write
        write(home, out)
        print(json.dumps(dict(tx=row["tx"],block=head["tip"],height=25,nfs=event["nfs"],
                              real_inputs=row["real_inputs"],packet_B=len(packet))))
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
