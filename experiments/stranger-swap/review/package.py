"""Package only mined data, signed adverts in RUN and fixed-name aggregate review outputs."""
import argparse
from gzip import GzipFile
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import re
import tarfile

RECEIPTS=('adverts.json','settlement.json','traffic.json','quotes.json','wallet.json')
CONTROLS=('tls-wire.json','transport.json','negotiation-state.txt')


def pack(public,receipt,controls,path):
    source={'public/'+name:public/name for name in ('RUN.json','SWAP.bin')}
    for part in ('blocks','packets'):
        folder=public/part
        for p in sorted(folder.iterdir()):
            assert re.fullmatch(r'[a-f0-9]{64}\.bin',p.name) and not p.is_symlink()
            source[f'public/{part}/{p.name}']=p
    source.update({'review/'+name:receipt/name for name in RECEIPTS})
    source.update({'review/'+name:controls/name for name in CONTROLS})
    sums=[]
    with path.open('xb') as sink,GzipFile(filename='',mode='wb',fileobj=sink,mtime=0) as gz,tarfile.open(fileobj=gz,mode='w|') as tar:
        def add(name,data):
            meta=tarfile.TarInfo(name);meta.size=len(data);meta.mode=0o644
            tar.addfile(meta,BytesIO(data))
        for name,p in sorted(source.items()):
            assert p.is_file() and not p.is_symlink()
            data=p.read_bytes()
            sums.append(f'{sha256(data).hexdigest()}  {name}\n')
            add(name,data)
        add('SHA256SUMS',''.join(sums).encode('ascii'))
    return len(source)+1


if __name__=='__main__':
    if not __debug__:raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('public','receipts','controls','new_archive'):
        p.add_argument(name,type=Path)
    a=p.parse_args();files=pack(a.public,a.receipts,a.controls,a.new_archive)
    print(sha256(a.new_archive.read_bytes()).hexdigest(),a.new_archive.stat().st_size,files,a.new_archive.name)
