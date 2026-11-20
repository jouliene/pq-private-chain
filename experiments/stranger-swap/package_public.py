"""Export only public advertisements, disclosed totals and fully verifiable mined data."""
import argparse
import gzip
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import tarfile


def pack(public,output):
    public=public.resolve(strict=True)
    files=[public/'RUN.json',public/'SWAP.bin']
    run=json.loads(files[0].read_bytes())
    if run['scenario']!='stranger-token-for-native-v1' or sha256(files[1].read_bytes()).hexdigest()!=run['settlement']['bundle_id']:
        raise ValueError('invalid public capture')
    for group in ('blocks','packets'):
        entries=sorted((public/group).iterdir())
        if not entries or any(not re.fullmatch(r'[0-9a-f]{64}\.bin',p.name) for p in entries):
            raise ValueError('unexpected file in public capture')
        files.extend(entries)
    def add(tar,name,raw):
        info=tarfile.TarInfo(name)
        info.mode=0o644
        info.size=len(raw)
        tar.addfile(info,io.BytesIO(raw))
    manifest=[]
    with output.open('xb') as out,gzip.GzipFile(fileobj=out,mode='wb',filename='',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as tar:
        for p in files:
            if p.resolve()!=p or not p.is_file():
                raise ValueError('public capture contains an indirect file')
            raw=p.read_bytes()
            name='public/'+p.relative_to(public).as_posix()
            add(tar,name,raw)
            manifest.append(sha256(raw).hexdigest()+'  '+name)
        add(tar,'SHA256SUMS',('\n'.join(manifest)+'\n').encode())
    return dict(files=len(files)+1,bytes=output.stat().st_size,sha256=sha256(output.read_bytes()).hexdigest())


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('public',type=Path)
    p.add_argument('archive',type=Path)
    a=p.parse_args()
    print(json.dumps(pack(a.public,a.archive),indent=2))
