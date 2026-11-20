"""Create a compact allowlisted release archive from the synthetic managed-supply walkthrough."""
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import tarfile


def pack(public, target):
    run=json.loads((public/"RUN.json").read_bytes())
    paths=[public/"RUN.json"]
    for group in ("blocks","packets"):
        paths.extend(sorted(p for p in (public/group).iterdir() if re.fullmatch("[0-9a-f]{64}[.]bin",p.name)))
    for name,item in sorted(run["controls"].items()):
        if isinstance(item,dict) and item.get("packet_sha256"):
            if not re.fullmatch("[a-z-]+",name):
                raise ValueError("invalid control label")
            p=public/"controls"/(name+".bin")
            if sha256(p.read_bytes()).hexdigest()!=item["packet_sha256"]:
                raise ValueError("control identity")
            paths.append(p)
    hashes=[]
    with tarfile.open(target,"x:gz") as tar:
        def append(name, data):
            info=tarfile.TarInfo(name)
            info.size=len(data)
            info.mode=0o644
            tar.addfile(info,io.BytesIO(data))
        for p in paths:
            if not p.is_file() or p.is_symlink() or p.resolve().parent not in (public,public/"controls",public/"blocks",public/"packets"):
                raise ValueError("unapproved public artifact")
            name="public/"+p.relative_to(public).as_posix()
            raw=p.read_bytes()
            append(name,raw)
            hashes.append(sha256(raw).hexdigest()+"  "+name)
        append("SHA256SUMS",("\n".join(hashes)+"\n").encode())
    return dict(file=target.name,bytes=target.stat().st_size,sha256=sha256(target.read_bytes()).hexdigest(),
                public_files=len(paths),blocks=len(list((public/"blocks").glob("*.bin"))),
                complete_packets=len(list((public/"packets").glob("*.bin"))))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("public","target"):
        p.add_argument(arg,type=lambda s: Path(s).resolve())
    args=p.parse_args()
    print(json.dumps(pack(args.public,args.target),sort_keys=True,indent=2))
