"""Observe public peer heads during a freshly launched native-currency walkthrough."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from observe_swap import FIELDS,ROOT,rpc


def observe(home,report,managed,swap,source):
    assert not home.exists() and not report.exists()
    command=[source/'pqd','swap','--home',home]
    if managed is not None:
        command+=['--managed-build',managed,'--managed-sha',json.loads((managed/'BUILD.json').read_bytes())['binary_sha256'],
                  '--swap-build',swap,'--swap-sha',json.loads((swap/'BUILD.json').read_bytes())['binary_sha256']]
    p=subprocess.Popen([*command,'native-walkthrough'])
    rows={k:[] for k in 'abcd'};start=time.monotonic()
    while p.poll() is None:
        config=home/'network.json'
        if config.is_file():
            try:
                ports=json.loads(config.read_bytes())['ports']
            except json.JSONDecodeError:
                continue
            for k,seen in rows.items():
                try:
                    s,body=rpc(ports[k],'status')
                    assert s['node']==k and not body
                    peers=sorted(n for n,port in ports.items() if port in s['peers'])
                    if seen and all(seen[-1][n]==s[n] for n in ('tip','pid','mempool')) and seen[-1]['peers']==peers:
                        continue
                    regs,body=rpc(ports[k],'assets',after='00'*32,limit=32,tip=s['tip'])
                    assert not body and regs['tip']==s['tip'] and regs['next'] is None
                except OSError:
                    continue
                except ValueError as err:
                    if 'registry tip changed' not in str(err):
                        raise
                    continue
                seen.append(dict(elapsed_s=round(time.monotonic()-start,4),peers=peers,registry=regs['entries'],
                                 **{i:s[i] for i in (*FIELDS,'pid','mempool')}))
        time.sleep(.08)
    report.write_text(json.dumps(dict(returncode=p.returncode,peers=rows),separators=(',',':'))+'\n')
    return p.returncode


if __name__=='__main__':
    if not __debug__:
        sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('new_home','new_report','--managed-build','--swap-build'):
        p.add_argument(name,type=lambda a:Path(a).resolve())
    p.add_argument('--source',type=lambda a:Path(a).resolve(),default=ROOT)
    a=p.parse_args()
    if bool(a.managed_build)!=bool(a.swap_build):
        p.error('specify both pinned role build directories')
    sys.exit(observe(a.new_home,a.new_report,a.managed_build,a.swap_build,a.source))
