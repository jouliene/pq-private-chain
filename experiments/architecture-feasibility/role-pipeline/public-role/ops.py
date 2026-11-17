#!/usr/bin/env python3
"""Build/run the unchanged Source01 Rust role using an approved public installation."""
import argparse,hashlib,importlib.util,json,math,re,shutil,sys,time,tomllib
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REPOSITORY=HERE.parents[3]
NAME='cp03-distinct-public-role01'
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
    s=load(HERE/'SOURCE.json');need(s['format']=='CP03-PUBLIC-ROLE-SOURCE01','source format')
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
    text=(HERE/'Cargo.toml').read_text();old='../../../../source/crates/ledger-cp03'
    need(text.count(old)==1,'one explicit ledger dependency')
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
    receipt=dict(format='CP03-PUBLIC-ROLE-BUILD01',source_sha256=a.approve_source,installation_sha256=a.approve_installation,
        binary=str(binary),binary_sha256=sha(binary),compiled_inputs={str(p):sha(p)for p in paths},runtime=native,
        own_manifest=str(crate/'Cargo.toml'),own_manifest_sha256=sha(crate/'Cargo.toml'),lock_path=str(crate/'Cargo.lock'),lock_sha256=sha(crate/'Cargo.lock'),
        compiler_artifacts=len(artifacts),actual_ledger_features=[x['features']for x in artifacts if x['target']['name']=='ledger_cp03'],actual_process=r)
    save(work/'BUILD.json',receipt);print(json.dumps({'build_receipt':str(work/'BUILD.json'),'sha256':sha(work/'BUILD.json')}))
def run(a,c,i):
    b=load(HERE/'.work'/a.build_label/'BUILD.json')
    need(b['source_sha256']==a.approve_source and b['installation_sha256']==a.approve_installation,'same approved installation/build source')
    def check():
        hashes(b['compiled_inputs']);hashes(b['runtime'])
        hashes({b['binary']:b['binary_sha256'],b['own_manifest']:b['own_manifest_sha256'],b['lock_path']:b['lock_sha256']})
    check();manifest=a.workload.resolve(strict=True);need(sha(manifest)==a.approve_workload,'explicit public workload pin')
    raw=load(manifest);records=[raw['genesis']]+[x for row in raw['blocks']for x in[row['header']]+row['bodies']]
    public={str(manifest):a.approve_workload}
    for row in records:
        p=Path(row['path']);need(not p.is_absolute()and '..'not in p.parts,'public relative entry')
        p=manifest.parent/p;need(p.resolve(strict=True)==p and not p.is_symlink(),'normalized public entry');public[str(p)]=row['sha256']
    hashes(public);work=HERE/'.work'/a.label;work.parent.mkdir(exist_ok=True);work.mkdir()
    env=c.controlled_env();env.update(RAYON_NUM_THREADS='1',RUST_BACKTRACE='0')
    r,o,e=c.run([b['binary'],str(manifest),a.approve_workload,str(work/'operation')],cwd=REPOSITORY,env=env,seconds=a.seconds,cap=8*1024**2,record=work/'role')
    need(r['process_exit']==r['wrapper_exit']==0 and not r['timeout'],'actual public role process failure')
    value=json.loads(o);need(not e and value['succeeded']and value['stage']=='complete','complete role result')
    need(value['details']['new_genuine_bodies']==32 and value['details']['all32_archive_body_bytes_matched'],'actual32-body scope')
    hashes(public);check();source(a.approve_source);c.load_installation(a.installation.resolve(strict=True),a.approve_installation)
    save(work/'RESULT.json',dict(format='CP03-PUBLIC-ROLE-RUN01',actual_process=r,source_sha256=a.approve_source,installation_sha256=a.approve_installation,
        workload_sha256=a.approve_workload,result_sha256=sha(work/'role.stdout'),public_fixture_pins=public,source_runtime_unchanged=True,whole_resource_acceptance=False))
    print(json.dumps({'result_receipt':str(work/'RESULT.json'),'sha256':sha(work/'RESULT.json')}))
def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['build','run']);p.add_argument('--label',required=True)
    p.add_argument('--installation',type=Path,required=True);p.add_argument('--approve-installation',required=True);p.add_argument('--approve-source',required=True)
    p.add_argument('--build-label');p.add_argument('--workload',type=Path);p.add_argument('--approve-workload');p.add_argument('--seconds',type=int)
    a=p.parse_args();need(re.fullmatch('[a-z0-9-]+',a.label)is not None,'exclusive label')
    source(a.approve_source);c,i=installation(a)
    a.seconds=a.seconds or(180 if a.mode=='build'else 120)
    need(0<a.seconds<=(180 if a.mode=='build'else 120),'bounded proposed experiment')
    if a.mode=='run':need(a.build_label and a.workload and a.approve_workload,'run requires actual build/workload approvals')
    (build if a.mode=='build'else run)(a,c,i)
if __name__=='__main__':main()
