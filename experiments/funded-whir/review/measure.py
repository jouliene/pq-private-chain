"""Measure complete public packet checks at the shipped interfaces, with process-setup boundaries."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from statistics import median
import subprocess
import sys
import tempfile
import time
from resource import RUSAGE_CHILDREN,getrusage

HERE=Path(__file__).resolve().parent
EX=HERE.parents[1]
sys.path.insert(0,str(EX/'spend-proof-decision/review'))
import measure_public as old
sys.path.insert(0,str(HERE.parent))
import packet


def measure(events,dep,role,matrices):
    source=json.loads((events/'SOURCE.json').read_text())
    net=bytes.fromhex(source['network']);height=source['common']['height']+1
    raw=(events/'candidate.swap').read_bytes()
    result={}
    with tempfile.TemporaryDirectory() as directory:
        tmp=Path(directory)
        for k,fold,keyname,old_raw in (('ordinary','','managed.vk',b'MSP1\1\0'+(events/'ordinary.released').read_bytes()),
                                      ('swap','swap-','swap.vk',(events/'released.swap').read_bytes())):
            prog=dep/(fold+'runtime')/'native'
            pin=(dep/'devnet'/('approved-'+fold+'native.sha256')).read_text().strip()
            key=(dep/(fold+'keys')/keyname).read_bytes();assert sha256(key).hexdigest()==old.BASE_KEYS[int(k=='swap')]
            keydir=tmp/k;keydir.mkdir();(keydir/keyname).write_bytes(key)
            session=old.session(prog,pin,keydir,old_raw,k,old.BASELINE,height,4)
            current=[]
            def children():
                s=getrusage(RUSAGE_CHILDREN)
                return s.ru_utime+s.ru_stime
            for _ in range(3):
                wall=time.monotonic();cpu=time.process_time();child=children()
                if k=='ordinary':
                    subprocess.run([role,'verify','MNG1',matrices/'MNG1.r1cs',events/'ordinary.candidate'],
                                   check=True,stdout=subprocess.DEVNULL)
                else:
                    signer=old.Role(prog,pin,['verify','/keys'],keydir)
                    try:
                        packet.validate(raw,net,height,role,matrices/'SLG1.r1cs',signer)
                        signer.close()
                    finally:
                        signer.abort()
                current.append(dict(wall_s=round(time.monotonic()-wall,6),cpu_s=round(time.process_time()-cpu+children()-child,6)))
            result[k]={'old_fresh_process_to_first_verified_s':session['calls'][0]['elapsed_from_launch_s'],
                       'old_persistent_node_checks':[{n:c[n] for n in ('check_wall_s','host_plus_native_cpu_s','native_peak_KiB')}
                                                     for c in session['calls'][1:]],
                       'old_verifier_setup':session['setup'],
                       'candidate_full_check_fresh_processes':current,
                       'candidate_median_wall_s':median(r['wall_s'] for r in current)}
    return dict(public_verifier=result,prover_and_per_instance_process_measurements=source['profiles'],
                candidate_scope='Three standalone processes with locally cached files; swap launches a fresh historical signature verifier and two fresh CFW verifiers for each full check. No persistent CFW verifier interface in this revision.',
                source='Wallet per-proof measurements come from the fresh owner-run source trace. Full public packet checks above are separate reviewer runs.')


if __name__=='__main__':
    if not __debug__:raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('events','deployment','role','matrices'):
        p.add_argument(name,type=Path)
    a=p.parse_args();print(json.dumps(measure(a.events,a.deployment,a.role,a.matrices),sort_keys=True,indent=2))
