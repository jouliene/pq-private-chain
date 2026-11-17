#!/usr/bin/env python3
"""Focused public structural tests in an explicitly approved fresh installation."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--installation',type=Path,required=True)
    parser.add_argument('--approve-installation',required=True)
    parser.add_argument('--label',default='serving-controls01')
    args=parser.parse_args()
    import re
    if not re.fullmatch('[a-z][a-z0-9-]{0,31}',args.label): raise ValueError('exclusive label')
    spec=importlib.util.spec_from_file_location('sync_public_common',ROOT/'scripts/common.py')
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    inst=common.load_installation(args.installation,args.approve_installation)
    common.need(Path(inst['repository'])==ROOT,'current repository installation')
    workspace=Path(inst['workspace'])
    toolchain=common.read_json(workspace/'fresh/toolchain.json')
    out=workspace/args.label;out.mkdir()
    command=[toolchain['tools']['cargo']['path'],'test','--offline','--locked','--release','-j1',
             '--manifest-path',str(workspace/'fresh/Cargo.toml'),'-p','ledger-cp03','--lib',
             'sync_serving_controls','--','--test-threads=1']
    result,stdout,stderr=common.run(command,cwd=workspace,env=toolchain['environment'],seconds=300,
                                  cap=4*1024**2,record=out/'public-test')
    passed=(result['process_exit']==result['wrapper_exit']==0 and not result['timeout'] and
            b'test result: ok. 6 passed; 0 failed;' in stdout)
    common.load_installation(args.installation,args.approve_installation)
    common.save(out/'RESULT.json',{'format':'CP04-SYNC-SERVING-CONTROLS01','passed':passed,
        'installation_sha256':args.approve_installation,'runner_sha256':common.sha(Path(__file__)),
        'actual_process':result,'scope':'Six structural public SQLite/framing/writer/snapshot tests. No genuine proofs or private wallet execution.'})
    print(json.dumps({'passed':passed,'result':str(out/'RESULT.json')}))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
