"""Archive the allowlisted public PoW history, complete swap and published aggregate results."""
from hashlib import sha256
from pathlib import Path
import argparse
import io
import json
import re
import tarfile


def pack(source,target):
    source=source.resolve(strict=True)
    run=json.loads((source/"RUN.json").read_bytes())
    files=[Path("RUN.json"),Path("SWAP.bin")]
    for group in ("blocks","packets"):
        for path in sorted((source/group).glob("*.bin")):
            if not re.fullmatch("[a-f0-9]{64}",path.stem):
                raise ValueError("unexpected public filename")
            files.append(path.relative_to(source))
    for name,c in run["controls"].items():
        if not re.fullmatch("[a-z-]+",name):
            raise ValueError("unexpected control label")
        path=Path("controls")/(name+".bin")
        if sha256((source/path).read_bytes()).hexdigest()!=c["sha256"]:
            raise ValueError("changed control bytes")
        files.append(path)
    for i,item in enumerate(run.get("capacity_fixture",())):
        rel=Path("capacity")/(str(i)+".bin")
        if rel.name!=item["file"] or sha256((source/rel).read_bytes()).hexdigest()!=item["sha256"]:
            raise ValueError("changed capacity fixture")
        files.append(rel)
    hashes=[]
    with tarfile.open(target,"x:gz") as out:
        def add(name,raw):
            info=tarfile.TarInfo(name)
            info.size=len(raw)
            info.mode=0o644
            out.addfile(info,io.BytesIO(raw))
        for rel in files:
            full=source/rel
            if full.is_symlink() or full.resolve().parent!=(source/rel.parent):
                raise ValueError("outside public directory")
            raw=full.read_bytes()
            name="public/"+rel.as_posix()
            add(name,raw)
            hashes.append(sha256(raw).hexdigest()+"  "+name)
        add("SHA256SUMS",("\n".join(hashes)+"\n").encode())
    return dict(bytes=target.stat().st_size,sha256=sha256(target.read_bytes()).hexdigest(),public_files=len(files))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("public",type=Path)
    p.add_argument("archive",type=Path)
    a=p.parse_args()
    print(json.dumps(pack(a.public,a.archive),indent=2))
