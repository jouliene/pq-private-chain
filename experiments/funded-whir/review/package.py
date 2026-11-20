"""Create a deterministic evidence archive from explicit public packets, ancestor blocks and aggregate receipts."""
from gzip import GzipFile
from hashlib import sha256
from io import BytesIO
import argparse
from pathlib import Path
import re
import tarfile

EVENTS=('SOURCE.json','COMPLETE.json','ordinary.released','ordinary.candidate','released.swap','candidate.swap',
        'released-swap.block','restored-onward.transfer','onward.candidate')
REVIEWS=('PUBLIC.json','FUNDS.json','CONTROLS.json','MEASURE.json')


def create(events,blocks,receipts,dest):
    items={'public/'+s:events/s for s in EVENTS}
    items.update({'review/'+s:receipts/s for s in REVIEWS})
    for p in sorted(blocks.iterdir()):
        assert re.fullmatch('[a-f0-9]{64}\\.bin',p.name)
        items['public/blocks/'+p.name]=p
    manifest=[]
    def add(tar,name,buf):
        meta=tarfile.TarInfo(name);meta.size=len(buf);meta.mode=0o644
        tar.addfile(meta,BytesIO(buf))
    with dest.open('xb') as sink,GzipFile(filename='',mode='wb',fileobj=sink,mtime=0) as gzip,tarfile.open(fileobj=gzip,mode='w|') as tar:
        for name,source in sorted(items.items()):
            assert source.is_file() and not source.is_symlink()
            data=source.read_bytes()
            manifest.append(f'{sha256(data).hexdigest()}  {name}\n')
            add(tar,name,data)
        add(tar,'SHA256SUMS',''.join(manifest).encode())
    print(sha256(dest.read_bytes()).hexdigest(),dest.stat().st_size,len(items)+1,dest.name)


if __name__=='__main__':
    if not __debug__:raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('events','blocks','receipts','new_archive'):
        p.add_argument(name,type=Path)
    a=p.parse_args();create(a.events,a.blocks,a.receipts,a.new_archive)
