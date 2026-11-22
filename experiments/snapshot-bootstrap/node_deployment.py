"""Identify the exact public funded deployment without importing its code or following links."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat


def _files(directory):
    for path in sorted(directory.iterdir()):
        mode=path.lstat().st_mode
        if stat.S_ISDIR(mode):
            if path.name=="__pycache__":
                for entry in path.iterdir():
                    if not stat.S_ISREG(entry.lstat().st_mode) or entry.suffix!=".pyc":
                        raise ValueError("unexpected entry in deployment bytecode cache")
            else:
                yield "directory",path
                yield from _files(path)
        elif stat.S_ISREG(mode):
            if path.suffix==".pyc":
                if not stat.S_ISREG(path.with_suffix(".py").lstat().st_mode):
                    raise ValueError("unexpected standalone bytecode in deployment")
            else:
                yield "file",path
        else:
            raise ValueError("link or special file in public deployment")


def deployment_id(root):
    root=Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("expected public deployment directory")
    entries=[]
    for kind,path in _files(root):
        name=path.relative_to(root).as_posix()
        if kind=="directory":
            entries.append([kind,name])
            continue
        digest=sha256()
        size=0
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,"rb") as src:
            if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                raise ValueError("unexpected deployment file type")
            while part:=src.read(1<<20):
                digest.update(part)
                size+=len(part)
        entries.append([kind,name,size,digest.hexdigest()])
    manifest=json.dumps(sorted(entries,key=lambda entry:entry[1]),separators=(",",":"),ensure_ascii=True).encode("ascii")
    return sha256(b"PQDEV1/snapshot/public-deployment/v1\x00"+manifest).hexdigest()
