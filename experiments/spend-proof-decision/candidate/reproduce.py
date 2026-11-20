"""Build both K384 roles, reproduce their registered keys, and run the fresh public comparison."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
HERE=Path(__file__).resolve().parent


def reproduce(work,upstream,baseline,target=None):
    work.mkdir(mode=0o700,parents=True,exist_ok=False)
    builds=work/"roles"
    subprocess.run([sys.executable,"-IB",HERE/"build.py",builds,upstream,target or work/"target"],check=True)
    for role,key in (("ordinary","managed.vk"),("leg","swap.vk")):
        root=builds/role
        with (root/"REGISTER.json").open("xb") as out:
            subprocess.run([root/"native","register",root/"registered"],
                           check=True,stdout=out,env=dict(os.environ,RAYON_NUM_THREADS="2"))
        if (root/"registered"/key).read_bytes()!=(HERE/"registry"/key).read_bytes():
            raise ValueError("registration differs from independently supplied key")
    subprocess.run([sys.executable,"-IB",HERE/"run.py",builds,baseline,work/"public"],check=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("work","pristine_upstream","baseline_mng1"):p.add_argument(n,type=Path)
    p.add_argument("--target",type=Path)
    a=p.parse_args()
    reproduce(a.work.resolve(),a.pristine_upstream.resolve(),a.baseline_mng1.resolve(),
              a.target.resolve() if a.target else None)
