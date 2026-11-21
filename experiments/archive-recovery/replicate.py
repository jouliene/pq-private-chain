"""Seed two independent archive stores from the live original nodes over the public peer protocol."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from roles import Role, disk, save


def replicate(network, output):
    config = json.loads((network / 'network.json').read_bytes())
    scenario = json.loads((network / 'public/SCENARIO.json').read_bytes())
    output.mkdir(mode=0o700,parents=True,exist_ok=True)
    result = {}
    for name, source in (('archive1','c'),('archive2','b')):
        path = output/name
        if path.exists():
            raise ValueError('fresh archive stores required')
        role = Role(network/'deployment',path)
        try:
            assert role.rpc('status')['height'] == 0
            data = role.rpc('sync',source=config['ports'][source])
            status = role.rpc('status')
            assert status['tip'] == scenario['tips']['initial']['tip'] and data['blocks'] == status['height']
            result[name] = dict(sync=data, status=status)
        finally:
            role.stop()
        result[name]['disk'] = disk(path,'archive.sqlite')
    save(output/'replication.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('network',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    replicate(a.network.resolve(),a.output.resolve())
