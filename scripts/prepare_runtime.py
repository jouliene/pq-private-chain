"""Explicit auditor-owned installation binding. Never alters global files."""
from pathlib import Path
import argparse,difflib,json,re,sys
import importlib.util,sys
_common_path=Path(__file__).resolve().parent/"common.py"
_spec=importlib.util.spec_from_file_location("common",_common_path)
_common=importlib.util.module_from_spec(_spec);sys.modules["common"]=_common;_spec.loader.exec_module(_common)
from common import ROOT,need,sha,read_json,save,run,controlled_env,hashes,package_sources
NODE_SOURCE='560d795353d3a6282da3c71b0af3baf5df75ffb702e7c3793a3c944c7565de2f'
PROBE="""const fs=require('node:fs');const c=require('node:crypto');c.createHash('sha3-512').update('CP03 public installation probe').digest();process.stdout.write(JSON.stringify({node:process.versions.node,openssl:process.versions.openssl,platform:process.platform,arch:process.arch,maps:fs.readFileSync('/proc/self/maps','utf8')}));"""
def checked(command):
 r,o,e=run(command,cwd=ROOT,seconds=15,cap=1024*1024)
 need(r['process_exit']==0 and not e,'installation subprocess failure');return o

def links(binary):
 raw=checked(['/usr/bin/ldd',str(binary)]).decode('utf8')
 need('not found'not in raw,'missing native library')
 paths={str(Path(w).resolve(strict=True))for w in raw.split()if w.startswith('/')}
 return paths,raw

def discover(a):
 package_sources();node=a.node.resolve(strict=True);need(node.is_file(),'explicit Node regular file')
 before=sha(node);info=json.loads(checked([str(node),'--disable-sigusr1','--eval',PROBE]));need(sha(node)==before,'Node changed')
 need({k:info[k]for k in ('node','openssl','platform','arch')}=={'node':'24.22.1','openssl':'3.5.9','platform':'linux','arch':'x64'},'required Node24.22.1/OpenSSL3.5.9/Linuxx64')
 paths,node_links=links(node)
 for line in info['maps'].splitlines():
  fields=line.split(maxsplit=5)
  if len(fields)==6 and fields[5].startswith('/'):
   need(not fields[5].endswith(' (deleted)'),'deleted mapped native file');paths.add(str(Path(fields[5]).resolve(strict=True)))
 crypto=a.libcrypto.resolve(strict=True);need(crypto.name=='libcrypto.so.3','libcrypto ABI')
 _,crypto_links=links(crypto);openssl=Path('/usr/bin/openssl').resolve(strict=True)
 opaths,openssl_links=links(openssl);need(str(crypto)in opaths,'openssl tool must use selected libcrypto')
 version=checked([str(openssl),'version']).decode().strip();need(re.match(r'^OpenSSL 3\.0\.13(?: |$)',version)is not None,'required system OpenSSL3.0.13')
 paths.update(opaths);paths.update({str(node),str(crypto),str(openssl),str(Path('/usr/bin/ldd').resolve(strict=True)),str(Path('/etc/ld.so.cache').resolve(strict=True)),str(Path('/etc/ssl/openssl.cnf').resolve(strict=True))})
 pins={p:sha(p)for p in sorted(paths)};hashes(pins);need(pins[str(node)]==before,'Node association')
 value={'format':'CP03-AUDIT-RUNTIME-CANDIDATE01','node':str(node),'libcrypto':str(crypto),'runtime':pins,'versions':{k:info[k]for k in ('node','openssl','platform','arch')},'system_openssl':version,'live_node_maps':info['maps'],'node_ldd':node_links,'crypto_ldd':crypto_links,'openssl_ldd':openssl_links,'trust':'Explicitly selected auditor installation. Versions do not attest identical historical binaries or upstream builds. No transaction-selected provider.'}
 save(a.output,value);print(json.dumps({'candidate':str(a.output),'approve_runtime_sha256':sha(a.output)}))

def install(a):
 package_sources();need(sha(a.manifest)==a.approve_runtime,'explicit operator digest mismatch');v=read_json(a.manifest)
 need(v['format']=='CP03-AUDIT-RUNTIME-CANDIDATE01','candidate schema');need(v['versions']=={'node':'24.22.1','openssl':'3.5.9','platform':'linux','arch':'x64'},'required tuple');hashes(v['runtime'])
 need(v['node']in v['runtime']and v['libcrypto']in v['runtime'],'native associations')
 provider=ROOT/'source/runtime/cp03/provider';lib=provider/'src/lib.rs';pins=provider/'src/pins.rs';old=lib.read_text()
 literal='const NODE: &str = "/UNINSTALLED/CP03/node";';need(old.count(literal)==1,'exact canonical NODE declaration')
 need(sha(provider/'embedded/source-signature.mjs')==NODE_SOURCE,'unchanged native worker')
 # ASCII local paths make JSON quoting a valid Rust string literal. No sender configuration.
 need(all(p.isascii()and not any(ord(c)<32 for c in p)for p in v['runtime']),'native paths')
 new=old.replace(literal,'const NODE: &str = '+json.dumps(v['node'])+';')
 table='// Auditor-approved installation pins; algorithm/worker unchanged.\n'+"pub(crate) const NATIVE: &[(&str, &str)] = &[\n"+''.join('    ('+json.dumps(p)+', '+json.dumps(h)+'),\n'for p,h in sorted(v['runtime'].items()))+'];\n'
 dest=ROOT/'installation-preimages';dest.mkdir();changes={};post={}
 for p,data in [(lib,new.encode()),(pins,table.encode())]:
  original=p.read_bytes();(dest/p.name).write_bytes(original);name=str(p.relative_to(ROOT));changes[name]={'before':sha(p),'after':__import__('hashlib').sha256(data).hexdigest()};(dest/(p.name+'.diff')).write_text(''.join(difflib.unified_diff(original.decode().splitlines(True),data.decode().splitlines(True),fromfile='canonical/'+name,tofile='audit-installation/'+name)));p.write_bytes(data);post[name]=sha(p)
 save(ROOT/'installation.json',{'format':'CP03-AUDIT-INSTALLATION01','approved_runtime_manifest_sha256':a.approve_runtime,'node':v['node'],'libcrypto':v['libcrypto'],'runtime':v['runtime'],'versions':v['versions'],'source_changes':changes,'source_postimages':post,'canonical_source_preserved_in':'installation-preimages','historical_runtime_replication':False,'algorithm_or_message_or_profile_changed':False})
 hashes(v['runtime']);print('AUDIT INSTALLATION BOUND; NOT HISTORICAL BINARY ATTESTATION')

def main():
 p=argparse.ArgumentParser();s=p.add_subparsers(dest='mode',required=True)
 d=s.add_parser('discover');d.add_argument('--node',type=Path,required=True);d.add_argument('--libcrypto',type=Path,required=True);d.add_argument('--output',type=Path,required=True)
 i=s.add_parser('install');i.add_argument('--manifest',type=Path,required=True);i.add_argument('--approve-runtime',required=True)
 a=p.parse_args();discover(a)if a.mode=='discover'else install(a)
if __name__=='__main__':main()
