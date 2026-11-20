"""Pack the public allowlist and summary measurements into a deterministic readback archive."""
import argparse
import gzip
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import tarfile


def package(public,observations,costs,receipt,destination):
    paths={name:public/name for name in ('RUN.json','SWAP.bin')}
    for folder in ('blocks','packets','controls','capacity'):
        files=list((public/folder).iterdir())
        assert files
        pattern=r'[0-9a-f]{64}\.bin' if folder!='controls' else r'(incomplete|changed-terms|expired|ordinary-conflict)\.bin'
        if folder=='capacity':
            assert {p.name for p in files}=={'0.bin','1.bin','2.bin'}
            pattern=r'[012]\.bin'
        for p in files:
            assert p.is_file() and not p.is_symlink() and re.fullmatch(pattern,p.name)
            paths[folder+'/'+p.name]=p
    sources={'public/'+name:path for name,path in paths.items()}
    sources.update({'review/peers.json':observations,'review/costs.json':costs,'review/receipt.json':receipt})
    content={name:path.read_bytes() for name,path in sources.items()}
    manifest=''.join(sha256(content[n]).hexdigest()+'  '+n+'\n' for n in sorted(content)).encode()
    content['SHA256SUMS']=manifest
    with destination.open('xb') as out:
        with gzip.GzipFile(fileobj=out,mode='wb',mtime=0,filename='') as zipped:
            with tarfile.open(fileobj=zipped,mode='w') as archive:
                for name,data in sorted(content.items()):
                    header=tarfile.TarInfo(name)
                    header.size=len(data)
                    header.mode=0o644
                    archive.addfile(header,BytesIO(data))
    with tarfile.open(destination,'r:gz') as check:
        assert set(check.getnames())==set(content) and len(check.getmembers())==len(content)
        for member in check:
            assert member.isreg() and check.extractfile(member).read()==content[member.name]
    return dict(archive=destination.name,regular_files=len(content),bytes=destination.stat().st_size,
                sha256=sha256(destination.read_bytes()).hexdigest())


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('public','observations','costs','receipt','new_archive'):
        p.add_argument(key,type=Path)
    a=p.parse_args()
    print(json.dumps(package(a.public,a.observations,a.costs,a.receipt,a.new_archive),sort_keys=True))
