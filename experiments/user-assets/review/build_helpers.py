"""Build the AST1 public reference helpers from the pinned pristine upstream libraries."""
import argparse
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0,str(ROOT/'experiments/token-profile/review'))
from build import build


def main(upstream, destination):
    build(ROOT,upstream,destination)
    deps = destination/'target/release/deps'
    library, = deps.glob('libqnero_notes-*.rlib')
    subprocess.run(['rustup','run','1.93.0','rustc','--edition=2021','-C','opt-level=2',
                    '-L','dependency='+str(deps),'--extern','qnero_notes='+str(library),
                    HERE/'rewards.rs','-o',destination/'rewards'],check=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('upstream','destination'):
        p.add_argument(name,type=lambda s:Path(s).resolve())
    a = p.parse_args()
    main(a.upstream,a.destination)
