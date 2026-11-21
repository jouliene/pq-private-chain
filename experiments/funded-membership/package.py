"""Package only public consensus bodies, their public projections and disclosed test observations."""
import argparse
import gzip
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import tarfile


def pack(src, out):
    entries = {}
    for group in ("blocks","packets"):
        for f in (src/group).iterdir():
            if f.is_symlink() or not re.fullmatch(r"[a-f0-9]{64}\.bin",f.name):
                raise ValueError("unregistered file in "+group)
            blob = f.read_bytes()
            if group=="blocks":
                if blob[:8] != b"ASTPOW01":
                    raise ValueError("block encoding")
                t = sha256(b"PQDEV1/template\0"+blob[:-8]).digest()
                ident = sha256(b"PQDEV1/work\0"+t+blob[-8:]).hexdigest()
            else:
                if blob[:4] not in (b"MSP1",b"MSP2",b"MSP3",b"SWF1",b"SWF2",b"SWF3",b"AST1"):
                    raise ValueError("packet encoding")
                ident = sha256(blob).hexdigest()
            if ident != f.stem:
                raise ValueError("identity")
            entries[f"{group}/{f.name}"] = blob
    run = json.loads((src/"RUN.json").read_bytes())
    if set(run) != {"tips","operations","registries","balances","asset_ids","controls","recovery","genesis"}:
        raise ValueError("unreviewed fixture projection")
    legacy = run["controls"]["legacy_B"]
    for name,magic in (("SWAP.bin",b"SWB3\1"),("controls/legacy-b.bin",b"MSP2\1"),
                       ("controls/legacy-b-block.bin",b"ASTPOW01")):
        f = src/name
        if f.is_symlink() or not f.read_bytes().startswith(magic):
            raise ValueError("public fixture encoding")
        entries[name] = f.read_bytes()
    if sha256(entries["controls/legacy-b.bin"]).hexdigest()!=legacy["tx"]:
        raise ValueError("legacy payment")
    if sha256(entries["SWAP.bin"]).hexdigest()!=run["operations"]["swap"]["tx"]:
        raise ValueError("swap bundle")
    costs = src/"controls/legacy-b-costs.json"
    if costs.exists():
        record = json.loads(costs.read_bytes())
        fields = ("tx","packet_B","proving_wall_s","prover_cpu_s","prover_role_peak_rss_KiB")
        if record["tx"] != legacy["tx"]:
            raise ValueError("legacy cost identity")
        entries["controls/"+costs.name] = (json.dumps({k:record[k] for k in fields},sort_keys=True)+"\n").encode()
    entries["RUN.json"] = (json.dumps(run,indent=2,sort_keys=True)+"\n").encode()
    with out.open("xb") as file, gzip.GzipFile(fileobj=file,mode="wb",mtime=0,filename="") as gz:
        with tarfile.open(fileobj=gz,mode="w") as tar:
            for name, blob in sorted(entries.items()):
                info = tarfile.TarInfo("public/"+name)
                info.mode,info.size = 0o644,len(blob)
                tar.addfile(info,BytesIO(blob))
    with tarfile.open(out) as tar:
        for name,blob in entries.items():
            if tar.extractfile("public/"+name).read()!=blob:
                raise ValueError("archive roundtrip mismatch")
    print(sha256(out.read_bytes()).hexdigest()+"  "+out.name)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("public",type=Path)
    p.add_argument("new_archive",type=Path)
    args=p.parse_args()
    pack(args.public,args.new_archive)
