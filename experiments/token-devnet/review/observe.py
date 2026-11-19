"""Run the normal cold CLI and record read-only public loopback observations independently."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT/'devnet'))
from transport import rpc


def observe(home, outfile):
    if home.exists() or outfile.exists():
        raise ValueError('fresh home and unused observation file required')
    before = time.monotonic()
    proc = subprocess.Popen([str(ROOT/'pqd'),'token','--home',str(home),'walkthrough'])
    events = {n:[] for n in 'abcd'}
    ports = None
    try:
        while proc.poll() is None:
            if ports is None:
                try:
                    ports = json.loads((home/'network.json').read_bytes())['ports']
                except FileNotFoundError:
                    time.sleep(.12)
                    continue
            for n in 'abcd':
                try:
                    data,body = rpc(ports[n],'status')
                    assert data['node']==n and not body
                    summary = {k:data[k] for k in ('tip','height','work','issued','token_issued','fees',
                               'spent_set_sha256','notes','anchor','mempool','remaining','found','pid','peers')}
                    # Preserve only peer labels from the local fixture, not transient endpoints.
                    summary['peers'] = sorted(k for k in ports if ports[k] in summary['peers'])
                    prev = events[n][-1][1] if events[n] else None
                    if prev != summary:
                        if data['mempool']:
                            pending,empty = rpc(ports[n],'pending')
                            assert not empty
                        else:
                            pending = []
                        events[n].append([round(time.monotonic()-before,4),summary,pending])
                except (OSError, ConnectionError):
                    pass
            time.sleep(.065)
    finally:
        outfile.write_text(json.dumps(dict(returncode=proc.poll(),nodes=events),separators=(',',':'))+'\n')
    return proc.returncode


if __name__ == '__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('home', type=lambda x:Path(x).resolve())
    ap.add_argument('observations', type=lambda x:Path(x).resolve())
    args=ap.parse_args()
    sys.exit(observe(args.home,args.observations))
