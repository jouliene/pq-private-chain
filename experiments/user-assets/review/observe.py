"""Independently sample the public TCP peers during a new local AST1 walkthrough."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'devnet'))
from transport import rpc

FIELDS = ('tip','height','work','network','genesis','anchor','spent','spent_set_sha256','notes','issued','fees',
          'assets','registry','asset_count','pid','peers')


def observe(home, destination):
    if home.exists() or destination.exists():
        raise ValueError('empty new home and unused observation path required')
    start = time.monotonic()
    samples = {name:[] for name in 'abcd'}
    process = subprocess.Popen([ROOT/'pqd','assets','--home',home,'walkthrough'])
    ports = None
    try:
        while process.poll() is None:
            if ports is None:
                try:
                    ports = json.loads((home/'network.json').read_bytes())['ports']
                except (FileNotFoundError,json.JSONDecodeError):
                    time.sleep(.1)
                    continue
            for name in samples:
                try:
                    status, body = rpc(ports[name],'status')
                except OSError:
                    continue
                assert not body and status['node'] == name
                record = {k:status[k] for k in FIELDS if k in status}
                record['peers'] = sorted(n for n,port in ports.items() if port in record['peers'])
                previous = samples[name][-1]['status'] if samples[name] else {}
                if record['tip'] != previous.get('tip'):
                    try:
                        page, body = rpc(ports[name],'assets',after='00'*32,tip=record['tip'],limit=32)
                    except OSError:
                        continue
                    except ValueError as err:
                        if 'registry tip changed' not in str(err):
                            raise
                        continue
                    assert not body and page['tip'] == record['tip'] and page['next'] is None
                    record['registry'] = page['entries']
                else:
                    record['registry'] = previous['registry']
                if record != previous:
                    samples[name].append(dict(elapsed_s=round(time.monotonic()-start,4),status=record))
            time.sleep(.07)
    finally:
        destination.write_text(json.dumps(dict(returncode=process.poll(),nodes=samples),separators=(',',':'))+'\n')
    return process.returncode


if __name__ == '__main__':
    if not __debug__:
        sys.exit('assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('home','observations'):
        parser.add_argument(name,type=lambda s:Path(s).resolve())
    args = parser.parse_args()
    sys.exit(observe(args.home,args.observations))
