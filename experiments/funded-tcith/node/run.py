"""Run public acceptance in a fresh namespace with no wallet filesystem."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from stage import stage


def run(a):
    ex = HERE.parents[1]
    with tempfile.TemporaryDirectory(prefix='ftl-public-') as temp:
        dest = Path(temp)/'deploy'
        stage(a.deployment,dest)
        events = Path(temp)/'events'
        events.mkdir()
        for name in ('SOURCE.json','mixed.swap','released.swap'):
            shutil.copyfile(a.public/name,events/name)
        (events/'blocks').mkdir()
        for p in (a.public/'blocks').glob('*.bin'):
            if len(p.stem)!=64 or bytes.fromhex(p.stem).hex()!=p.stem:
                raise ValueError('unexpected public block name')
            shutil.copyfile(p,events/'blocks'/p.name)
        cmd = ['bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--clearenv',
               '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C','--setenv','RAYON_NUM_THREADS','2',
               '--proc','/proc','--dev','/dev','--tmpfs','/tmp']
        mounts = [(Path(s),s) for s in ('/usr','/bin','/lib','/lib64','/etc/ld.so.cache')]
        mounts += [(dest,'/deploy'),(events,'/events'),(a.engine,'/engine'),(a.shape,'/shape'),(a.constants,'/constants.rs')]
        for name in ('funded-tcith/node','funded-tcith/wallet','lattice-spend/pivot','packed-tcith/encoding',
                     'funded-whir/relation','spend-proof-decision/whir_port.py','atomic-swap/wallet','atomic-swap/swap_wire.py'):
            mounts.append((ex/name,'/src/experiments/'+name))
        for path, target in mounts:
            cmd += ['--ro-bind',str(path.resolve(strict=True)),target]
        cmd += ['--remount-ro','/','--chdir','/','--','/usr/bin/python3','-IB','/src/experiments/funded-tcith/node/check.py']
        subprocess.run(cmd,check=True)


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('deployment','public','constants','engine','shape'):
        p.add_argument(key,type=Path)
    run(p.parse_args())
