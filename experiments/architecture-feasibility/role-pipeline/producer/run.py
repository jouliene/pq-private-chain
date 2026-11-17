#!/usr/bin/env python3
"""Generate the real32-proof public workload; private streams remain in RAM."""
import argparse,hashlib,importlib.util,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REPOSITORY=HERE.parents[3]
RESULT=dict(format='CP03-DISTINCT-BLOCK-PRODUCER01',credit_proofs=16,ordinary_proofs=16,
    accepted_blocks=2,private_material_or_mapping_persisted=False,resource_profile_pass=False)
STAGES={'preflight','key-generation','genesis','credit-proofs','credit-block','funded-history',
    'ordinary-proofs','ordinary-block','final-history','workload-manifest','cleanup'}
def need(ok,s):
    if not ok:raise ValueError(s)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb')as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def save(p,v):
    with p.open('x')as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')
def exact(a,b):
    if type(a)is not type(b):return False
    if isinstance(b,dict):return a.keys()==b.keys()and all(exact(a[k],v)for k,v in b.items())
    if isinstance(b,list):return len(a)==len(b)and all(exact(x,y)for x,y in zip(a,b))
    return a==b
def decode(raw):
    def pairs(items):
        out={}
        for k,v in items:need(k not in out,'duplicate JSON');out[k]=v
        return out
    def bad(_):raise ValueError('nonfinite JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)
def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True)
    p.add_argument('--installation',type=Path,required=True);p.add_argument('--approve-installation',required=True)
    p.add_argument('--approve-source',required=True);a=p.parse_args()
    need(re.fullmatch('[a-z][a-z0-9_-]{0,31}',a.label)is not None,'exclusive label')
    source_path=HERE/'SOURCE.json';need(sha(source_path)==a.approve_source,'explicit reviewed source approval')
    source=decode(source_path.read_bytes());need(source['format']=='CP03-PUBLIC-DISTINCT-PRODUCER-SOURCE01','source format')
    pins={HERE/n:h for n,h in source['files'].items()};pins[source_path]=a.approve_source
    need(set(source['files'])=={'run.py','driver.mjs','README.md'},'fixed source closure')
    need(all(p.is_file()and not p.is_symlink()and sha(p)==h for p,h in pins.items()),'source pins')
    helper=REPOSITORY/'scripts/common.py'
    s=importlib.util.spec_from_file_location('public_common',helper);common=importlib.util.module_from_spec(s);s.loader.exec_module(common)
    installation_path=a.installation.resolve(strict=True)
    inst=common.load_installation(installation_path,a.approve_installation)
    need(Path(inst['repository'])==REPOSITORY,'this public repository installation')
    need(inst['pins'].get(str(helper))==sha(helper),'approved lifecycle helper')
    need(str(Path(sys.executable).resolve())in inst['pins'],'approved Python')
    parent=HERE/'.work';parent.mkdir(exist_ok=True);work=parent/a.label;work.mkdir()
    save(work/'claim.json',dict(format='CP03-PUBLIC-DISTINCT-PRODUCER-CLAIM01',source_sha256=a.approve_source,
        installation_sha256=a.approve_installation,proof_job_ceiling=32,private_streams_persisted=False))
    r,stdout,stderr=common.run_private([inst['node'],'--disable-sigusr1',str(HERE/'driver.mjs'),a.label,
        str(installation_path),a.approve_installation],cwd=HERE,env=inst['proof_environment'],seconds=480,cap=65536)
    passed=False;failed_stage=None
    try:
        passed=(r.get('process_exit')==r.get('wrapper_exit')==0 and not r.get('timeout')and not stderr and exact(decode(stdout),RESULT))
        for stage in STAGES:
            if stderr==('CP03_WORKLOAD_FAILED '+stage+'\n').encode():failed_stage=stage
    except BaseException:passed=False
    finally:stdout=stderr=None
    stable=False
    try:
        common.load_installation(installation_path,a.approve_installation)
        need(all(sha(p)==h for p,h in pins.items()),'source postcheck');stable=True
    except BaseException:passed=False
    save(work/'receipt.json',dict(format='CP03-PUBLIC-DISTINCT-PRODUCER-RECEIPT01',actual_process=r,
        installation_sha256=a.approve_installation,source_sha256=a.approve_source,passed=passed,
        fixed_source_failure_stage=failed_stage,source_runtime_unchanged=stable,
        raw_private_streams_persisted_or_hashed=False,result=RESULT if passed else None,
        scope='new32-proof synthetic fixture generation, not throughput or privacy/PQ assurance'))
    print(json.dumps(RESULT if passed else {'format':'CP03-DISTINCT-PRODUCER-FAILED01'},sort_keys=True))
    return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
