"""Pack only the public block graph and disclosed synthetic economic observations."""
import argparse
import gzip
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import tarfile


def pack(public, destination):
    entries = {}
    for path in sorted((public/'blocks').iterdir()):
        if path.is_symlink() or not re.fullmatch(r'[0-9a-f]{64}\.bin',path.name):
            raise ValueError('unexpected block file')
        raw = path.read_bytes()
        template = sha256(b'PQDEV1/template\0'+raw[:-8]).digest()
        work = sha256(b'PQDEV1/work\0'+template+raw[-8:]).hexdigest()
        if work != path.stem or raw[:8] != b'ASTPOW01':
            raise ValueError('incorrect public PoW body')
        entries['public/blocks/'+path.name] = raw
    if not entries:
        raise ValueError('missing graph')
    # Expose only these named projections. Never pack a directory recursively.
    keys = {'SCENARIO':('genesis','network','asset_ids','tips','ordinary','balances','registries'),
            'OUTCOME':('initial_spend','final_spend','initial_settled','reorganized','final','balances')}
    for name, fields in keys.items():
        doc = json.loads((public/(name+'.json')).read_bytes())
        value = {k:doc[k] for k in fields}
        entries['public/'+name+'.json'] = (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with destination.open('xb') as fo, gzip.GzipFile(fileobj=fo,mode='wb',mtime=0,filename='') as gz:
        with tarfile.open(fileobj=gz,mode='w') as tar:
            for name, value in sorted(entries.items()):
                info = tarfile.TarInfo(name)
                info.mode,info.size = 0o644,len(value)
                tar.addfile(info, BytesIO(value))
    with tarfile.open(destination) as tar:
        if tar.getnames()!=sorted(entries) or any(tar.extractfile(k).read()!=v for k,v in entries.items()):
            raise ValueError('archive readback mismatch')
    print(sha256(destination.read_bytes()).hexdigest(), ' '+destination.name)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('public',type=Path)
    p.add_argument('new_archive',type=Path)
    args=p.parse_args()
    pack(args.public,args.new_archive)
