"""List public issuance descriptors at one selected tip. No wallet keys or holdings are used."""
import argparse
import json
from pathlib import Path
import sys


def inventory(lab, node, tip):
    after = bytes(32).hex()
    registry = {}
    while True:
        page, body = lab.request(node,"assets",tip=tip,after=after,limit=32)
        if body or page["tip"] != tip or len(page["entries"])>32:
            raise ValueError("invalid public issuance page")
        for row in page["entries"]:
            if row["id"] <= after:
                raise ValueError("unordered public issuance page")
            after = row["id"]
            registry[after] = row
        if page["next"] is None:
            return registry
        if len(page["entries"])!=32 or page["next"]!=after:
            raise ValueError("invalid issuance continuation")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("home",type=Path)
    p.add_argument("--node",choices=list("abcd"),default="c")
    args = p.parse_args()
    sys.path.insert(0,str(args.home/"deployment/devnet"))
    from cli import Lab
    lab = Lab(args.home,args.home/"deployment/runtime")
    tip = lab.status(args.node)["tip"]
    print(json.dumps({"tip":tip,"assets":inventory(lab,args.node,tip)},indent=2))
