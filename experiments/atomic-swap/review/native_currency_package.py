"""Package the two public currencies, graph, controls and explicitly named independent review receipts."""
import argparse
import gzip
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import tarfile


def package(public,receipts,target):
    public=public.resolve(strict=True)
    run=json.loads((public/'RUN.json').read_bytes())
    assert run['scenario']=='native-currency'
    names=['RUN.json','SWAP.bin']
    for folder in ('blocks','packets'):
        members=list((public/folder).iterdir())
        assert members and all(re.fullmatch('[0-9a-f]{64}\\.bin',p.name) for p in members)
        names.extend(folder+'/'+p.name for p in members)
    expected={'incomplete','missing-first','changed-terms','changed-payer','ordinary-conflict','expired'}
    assert set(run['controls'])==expected
    names.extend('controls/'+label+'.bin' for label in sorted(expected))
    included={'public/'+name:public/name for name in names}
    for key in ('clean-public','clean-wallet','prior-check','measure','packet-controls','peers','legacy-check'):
        included['review/'+key+'.json']=receipts/(key+'.json')
    content={}
    for name,path in included.items():
        assert path.is_file() and not path.is_symlink()
        raw=path.read_bytes()
        if name.startswith('public/packets/'):
            assert sha256(raw).hexdigest()+'.bin'==path.name
        if name.startswith('public/controls/'):
            assert sha256(raw).hexdigest()==run['controls'][path.stem]['sha256']
        if name.startswith('review/'):
            assert json.loads(raw)
        content[name]=raw
    content['SHA256SUMS']=''.join(sha256(content[n]).hexdigest()+'  '+n+'\n' for n in sorted(content)).encode()
    with target.open('xb') as out,gzip.GzipFile(fileobj=out,mode='wb',mtime=0,filename='') as z,tarfile.open(fileobj=z,mode='w') as tar:
        for n,b in sorted(content.items()):
            i=tarfile.TarInfo(n);i.size=len(b);i.mode=0o644
            tar.addfile(i,BytesIO(b))
    with tarfile.open(target) as tar:
        assert len(tar.getmembers())==len(content) and set(tar.getnames())==set(content)
        assert all(i.isreg() and tar.extractfile(i).read()==content[i.name] for i in tar)
    return dict(archive=target.name,regular_files=len(content),bytes=target.stat().st_size,sha256=sha256(target.read_bytes()).hexdigest())


if __name__=='__main__':
    if not __debug__:
        raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('public','receipt_directory','new_archive'):
        p.add_argument(name,type=Path)
    a=p.parse_args()
    print(json.dumps(package(a.public,a.receipt_directory,a.new_archive),indent=2,sort_keys=True))
