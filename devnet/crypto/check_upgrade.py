"""Interrupt every activation rename between the previous devnet runtime and the current compiled runtime."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import runtime


def pair(path):
    return tuple(hashlib.sha256((path/n).read_bytes()).hexdigest() for n in ("native","BUILD.json"))


def verify(old,new):
    legacy=json.loads((old/"BUILD.json").read_bytes())
    frozen=json.loads((HERE/"crypto/evidence/BUILD_V1.json").read_bytes())
    assert legacy.keys()==frozen.keys() and all(legacy[k]==frozen[k] for k in legacy if k!="binary_sha256")
    assert pair(old)[0]==legacy["binary_sha256"]
    current=runtime.config(new)
    observations=[]
    for stop in range(1,5):
        with tempfile.TemporaryDirectory() as temp:
            install=Path(temp)
            generation=runtime._installed(install)
            generation.mkdir(parents=True)
            for name in ("native","BUILD.json"):
                shutil.copy2(old/name,install/name)
                shutil.copy2(new/name,generation/name)
            calls=[]
            link=runtime._link
            def interrupt(directory,name,target):
                link(directory,name,target)
                calls.append(name)
                if len(calls)==stop:
                    raise InterruptedError("activation stopped")
            try:
                with patch.object(runtime,"_link",interrupt):
                    runtime.prepare(install)
                raise AssertionError("missed interruption")
            except InterruptedError:
                pass
            exported=pair(install)
            assert exported in (pair(old),pair(new)),"interrupted mixed runtime pair"
            resumed=runtime.prepare(install)
            assert resumed.binary_sha==current.binary_sha and pair(install)==pair(new)
            assert runtime.config(install).binary_sha==current.binary_sha
            observations.append(dict(interrupted_after=stop,entry_point=calls[-1],
                visible_pair="legacy" if exported==pair(old) else "current",recovered_current=True))
    return observations


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--legacy-runtime",type=Path,required=True)
    p.add_argument("--runtime",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(verify(a.legacy_runtime,a.runtime),indent=2))
