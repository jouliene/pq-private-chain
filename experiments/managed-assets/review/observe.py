"""Run the ordinary managed-supply CLI and sample public peer/registry snapshots independently."""
import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'devnet'))
from transport import rpc


def durable_counts(home):
    result={}
    for filename,query,keys in (
        ('bank.sqlite','SELECT count(*),coalesce(sum(amount),0) FROM payments',('bank_rows','paid')),
        ('requests.sqlite','SELECT count(*),count(acknowledged),(SELECT count(*) FROM attempts) FROM requests',
         ('requests','acknowledged','attempts'))):
        file=home/'redemptions'/filename
        if not file.is_file():
            return None
        try:
            conn=sqlite3.connect(file.resolve().as_uri()+'?mode=ro',uri=True,timeout=.05)
            try:
                values=conn.execute(query).fetchone()
            finally:
                conn.close()
        except sqlite3.OperationalError as err:
            if 'no such table' in str(err) or 'locked' in str(err):
                return None
            raise
        result.update(zip(keys,values,strict=True))
    return result


def monitor(home,out):
    if home.exists() or out.exists():
        raise ValueError('new empty home and unused observation file required')
    start=time.monotonic()
    samples={n:[] for n in 'abcd'}
    bank=[]
    proc=subprocess.Popen([ROOT/'pqd','managed','--home',home,'walkthrough'])
    try:
        while proc.poll() is None:
            try:
                ports=json.loads((home/'network.json').read_bytes())['ports']
            except (FileNotFoundError,json.JSONDecodeError):
                time.sleep(.1)
                continue
            for n,hist in samples.items():
                try:
                    st,body=rpc(ports[n],'status')
                    assert st['node']==n and not body
                    if hist and hist[-1]['tip']==st['tip']:
                        continue
                    page,body=rpc(ports[n],'assets',after='00'*32,limit=32,tip=st['tip'])
                    assert not body and page['tip']==st['tip'] and page['next'] is None
                except OSError:
                    continue
                except ValueError as err:
                    if 'registry tip changed' not in str(err):
                        raise
                    continue
                hist.append({k:st[k] for k in ('tip','height','work','anchor','notes','spent','spent_set_sha256','issued','fees')}
                            |dict(assets=page['entries'],elapsed_s=round(time.monotonic()-start,4)))
            durable=durable_counts(home)
            if durable and (not bank or durable!=bank[-1]['counts']):
                bank.append(dict(elapsed_s=round(time.monotonic()-start,4),counts=durable))
            time.sleep(.07)
    finally:
        out.write_text(json.dumps(dict(returncode=proc.poll(),nodes=samples,simulated_bank_samples=bank),separators=(',',':'))+'\n')
    return proc.returncode


if __name__=='__main__':
    if not __debug__:
        sys.exit('assertions are required')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('home','output'):
        p.add_argument(name,type=lambda s:Path(s).resolve())
    a=p.parse_args()
    sys.exit(monitor(a.home,a.output))
