#!/usr/bin/env python3
"""Build the bounded Network04 validator using an approved installation."""
import argparse,hashlib,importlib.util,json,math,re,shutil,sys,time,tomllib
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REPOSITORY=HERE.parents[2]
NAME='cp04-network-role01'
def need(ok,s):
    if not ok:raise ValueError(s)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb')as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def load(p):return json.loads(Path(p).read_text())
def save(p,v):
    with Path(p).open('x')as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')
def hashes(pins):
    for p,h in pins.items():need(sha(p)==h,'pinned file drift: '+str(p))
def source(approved):
    need(sha(HERE/'SOURCE.json')==approved,'explicit source approval')
    s=load(HERE/'SOURCE.json');need(s['format']=='CP04-TRANSPORT-SOURCE01','source format')
    hashes({HERE/n:h for n,h in s['files'].items()});return s
def installation(a):
    p=REPOSITORY/'scripts/common.py';s=importlib.util.spec_from_file_location('public_common',p)
    c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
    i=c.load_installation(a.installation.resolve(strict=True),a.approve_installation)
    need(Path(i['repository'])==REPOSITORY and i['pins'].get(str(p))==sha(p),'approved public lifecycle/repository')
    return c,i
def build(a,c,i):
    deadline=time.monotonic()+a.seconds
    source_root=Path(i['source_root']);vendor=Path(i['vendor'])
    work=HERE/'.work'/a.label;work.parent.mkdir(exist_ok=True);work.mkdir()
    crate=work/'crate';crate.mkdir();shutil.copytree(HERE/'src',crate/'src')
    text=(HERE/'Cargo.toml').read_text();old='../../../source/crates/ledger-cp03'
    need(text.count(old)==2,'two explicit ledger/history dependencies')
    (crate/'Cargo.toml').write_text(text.replace(old,str(source_root/'crates/ledger-cp03')))
    shutil.copyfile(HERE/'Cargo.lock',crate/'Cargo.lock')
    home=work/'cargo-home';home.mkdir()
    (home/'config.toml').write_text('[source.crates-io]\nreplace-with="approved-vendor"\n[source.approved-vendor]\ndirectory='+json.dumps(str(vendor))+'\n[net]\noffline=true\n')
    tools=i['toolchain']['tools'];hashes({x['path']:x['sha256']for x in tools.values()})
    env=dict(i['toolchain']['environment']);env.update(CARGO_HOME=str(home),CARGO_TARGET_DIR=str(work/'target'),CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',RAYON_NUM_THREADS='1')
    def command(argv,name,limit):
        remaining=math.floor(deadline-time.monotonic());need(remaining>0,'build child budget exhausted')
        r,o,e=c.run(argv,cwd=REPOSITORY,env=env,seconds=min(remaining,limit),cap=16*1024**2,record=work/name)
        need(r['process_exit']==r['wrapper_exit']==0 and not r['timeout'],'actual build command failure: '+name)
        return r,o,e
    r,o,e=command([tools['cargo']['path'],'build','--offline','--locked','--release','-j1','--message-format=json',
        '--manifest-path',str(crate/'Cargo.toml'),'--bin',NAME],'build',a.seconds)
    events=[json.loads(x)for x in o.splitlines()];need(events[-1]=={'reason':'build-finished','success':True},'actual Cargo terminal')
    artifacts=[x for x in events if x.get('reason')=='compiler-artifact'];binary=work/'target/release'/NAME
    roots=[source_root,vendor,crate];executables=[x for x in artifacts if x.get('executable')]
    need(len(executables)==1 and Path(executables[0]['executable']).resolve()==binary,'isolated actual binary')
    forbidden={'archive-crash-controls','crash-controls','admission-cost-trace','storage-cost-controls'}
    for x in artifacts:
        p=Path(x['manifest_path']).resolve(strict=True)
        need(any(p.is_relative_to(q)for q in roots),'compiler manifest outside approved closure')
        need(not(set(x['features'])&forbidden),'diagnostic feature compiled')
        if x['target']['name']=='ledger_cp03':need(set(x['features'])<={'default'},'unchanged ledger default features')
    names=binary.with_suffix('.d').read_text().replace('\\\n','').splitlines()[0].partition(': ')[2].split()
    paths=[Path(x).resolve(strict=True)for x in names]
    need(all(any(p.is_relative_to(q)for q in roots)for p in paths),'compiled source outside closure')
    _,linked,_=command(['/usr/bin/ldd',str(binary)],'ldd',15);native={}
    for line in linked.decode().splitlines():
        for token in line.split():
            if token.startswith('/'):
                p=Path(token).resolve(strict=True);need(str(p)in i['pins'],'unapproved linked runtime');native[str(p)]=sha(p)
    need('/usr/lib/x86_64-linux-gnu/libcrypto.so.3'in native,'actual libcrypto linkage')
    c.load_installation(a.installation.resolve(strict=True),a.approve_installation);source(a.approve_source)
    hashes({x['path']:x['sha256']for x in tools.values()})
    receipt=dict(format='CP04-TRANSPORT-BUILD01',source_sha256=a.approve_source,installation_sha256=a.approve_installation,
        binary=str(binary),binary_sha256=sha(binary),compiled_inputs={str(p):sha(p)for p in paths},runtime=native,
        own_manifest=str(crate/'Cargo.toml'),own_manifest_sha256=sha(crate/'Cargo.toml'),lock_path=str(crate/'Cargo.lock'),lock_sha256=sha(crate/'Cargo.lock'),
        compiler_artifacts=len(artifacts),actual_ledger_features=[x['features']for x in artifacts if x['target']['name']=='ledger_cp03'],actual_process=r)
    save(work/'BUILD.json',receipt);print(json.dumps({'build_receipt':str(work/'BUILD.json'),'sha256':sha(work/'BUILD.json')}))
def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True)
    p.add_argument('--installation',type=Path,required=True);p.add_argument('--approve-installation',required=True);p.add_argument('--approve-source',required=True);p.add_argument('--seconds',type=int,default=180)
    a=p.parse_args();need(re.fullmatch('[a-z0-9-]+',a.label)is not None,'exclusive label');need(0<a.seconds<=180,'bounded proposed build')
    source(a.approve_source);c,i=installation(a);build(a,c,i)
if __name__=='__main__':main()
