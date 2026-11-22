"""Publish only validated public originals, compact records, signed-rule identities and test endpoints."""
import argparse
from hashlib import sha256
import gzip
from io import BytesIO
import json
from pathlib import Path
import re
import tarfile

MAX_TOTAL=64*1024*1024
MAX_MEMBER=4*1024*1024
FIXED={'case.json','pin.json','manifest.json','state.bin'}
CASE={'genesis','prefix','funding','funding_block','fork_height','base','base_height','usable',
      'first_main','main','spend','fork','winning_spend'}


def allowed(name):
    return name in FIXED or re.fullmatch(r'(blocks|records)/[0-9a-f]{64}\.bin',name)


def pack(src,dest):
    case=json.loads((src/'case.json').read_bytes())
    if set(case)!=CASE:
        raise ValueError('unexpected fixture fields')
    selected=set(case['main']+case['fork'])
    if not all(re.fullmatch('[a-f0-9]{64}',x) for x in selected):
        raise ValueError('invalid public block path')
    names=sorted(FIXED|{f'{k}/{ident}.bin' for k in ('blocks','records') for ident in selected})
    with dest.open('xb') as f, gzip.GzipFile(fileobj=f,mode='wb',mtime=0,filename='') as gz, tarfile.open(fileobj=gz,mode='w') as tar:
        for name in names:
            file=src/name
            if file.is_symlink():
                raise ValueError('unexpected fixture link')
            raw=file.read_bytes()
            if not 0<len(raw)<=MAX_MEMBER:
                raise ValueError('fixture size')
            info=tarfile.TarInfo(name)
            info.mode,info.size=0o644,len(raw)
            tar.addfile(info,BytesIO(raw))
    return {'file':dest.name,'archive_B':dest.stat().st_size,'archive_sha256':sha256(dest.read_bytes()).hexdigest(),
            'members':len(names),'pin':json.loads((src/'pin.json').read_bytes())}


def unpack(archive,registry,out):
    spec=json.loads(registry.read_bytes())
    if archive.stat().st_size!=spec['archive_B'] or sha256(archive.read_bytes()).hexdigest()!=spec['archive_sha256']:
        raise ValueError('published fixture SHA256 mismatch')
    out.mkdir()
    expected=set()
    total=0
    with tarfile.open(archive,'r:gz') as tar:
        for item in tar:
            if not allowed(item.name) or item.name in expected or not item.isreg() or not 0<item.size<=MAX_MEMBER:
                raise ValueError('unexpected fixture material')
            total+=item.size
            if total>MAX_TOTAL:
                raise ValueError('fixture extraction ceiling')
            expected.add(item.name)
            path=out/item.name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(tar.extractfile(item).read())
    if not FIXED<=expected or len(expected)!=spec['members'] or spec['pin']!=json.loads((out/'manifest.json').read_bytes()):
        raise ValueError('incomplete or misregistered fixture')
    return spec


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    s=p.add_subparsers(dest='op',required=True)
    a=s.add_parser('pack')
    a.add_argument('fixture',type=Path)
    a.add_argument('archive',type=Path)
    b=s.add_parser('unpack')
    for key in ('archive','registry','dest'):
        b.add_argument(key,type=Path)
    args=p.parse_args()
    result=pack(args.fixture,args.archive) if args.op=='pack' else unpack(args.archive,args.registry,args.dest)
    print(json.dumps(result,sort_keys=True,indent=2))
