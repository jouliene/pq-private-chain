"""Follow a new SWP1 walkthrough through public TCP interfaces, without wallet access."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'devnet'))
from transport import rpc

FIELDS = ('tip','height','work','anchor','issued','fees','notes','spent','spent_set_sha256')


def observe(home,out):
    if home.exists() or out.exists():
        raise ValueError("provide an unused home and observation file")
    traces={n:[] for n in 'abcd'}
    clock=time.monotonic()
    proc=subprocess.Popen([ROOT/'pqd','swap','--home',home,'walkthrough'])
    try:
        while proc.poll() is None:
            try:
                ports=json.loads((home/'network.json').read_bytes())['ports']
            except (FileNotFoundError,json.JSONDecodeError):
                time.sleep(.1)
                continue
            for name,trace in traces.items():
                try:
                    status,body=rpc(ports[name],'status')
                    assert not body and status['node']==name
                    peers=sorted(k for k,v in ports.items() if v in status['peers'])
                    prior=trace[-1] if trace else {}
                    if all(prior.get(k)==status[k] for k in ('tip','pid','mempool')) and peers==prior.get('peers'):
                        continue
                    page,body=rpc(ports[name],'assets',after='00'*32,limit=32,tip=status['tip'])
                    assert not body and page['tip']==status['tip'] and page['next'] is None
                except OSError:
                    continue
                except ValueError as error:
                    if 'registry tip changed' not in str(error):
                        raise
                    continue
                trace.append(dict(elapsed_s=round(time.monotonic()-clock,4),peers=peers,registry=page['entries'],
                                  **{k:status[k] for k in (*FIELDS,'pid','mempool')}))
            time.sleep(.08)
    finally:
        out.write_text(json.dumps(dict(returncode=proc.poll(),peers=traces),separators=(',',':'))+'\n')
    return proc.returncode


def reconcile(path,states,winner):
    trace=json.loads(path.read_bytes())
    assert trace['returncode']==0 and set(trace['peers'])==set('abcd')
    result={}
    for name,rows in trace['peers'].items():
        assert rows
        matched=0
        for row in rows:
            state=states.get(bytes.fromhex(row['tip']))
            if state:
                summary=state.summary()
                assert all(row[k]==summary[k] for k in FIELDS)
                assert row['registry']==list(state.supply().values())
                matched+=1
        # The full local (read-only) database comparison covers a final tip missed by the sampler.
        result[name]=dict(changes_observed=len(rows),matched_to_captured_graph=matched,
                          observed_final=any(row['tip']==winner.hex() for row in rows),
                          daemon_pids=len({row['pid'] for row in rows}))
        assert matched>0
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('home',type=Path)
    p.add_argument('observations',type=Path)
    args=p.parse_args()
    sys.exit(observe(args.home.resolve(),args.observations.resolve()))
