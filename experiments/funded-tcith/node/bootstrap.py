"""Build and stage both frozen native reference roles from public sources."""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parents[2]/'atomic-swap'
sys.path.insert(0,str(HERE))
from stage import build, install

if __name__ == '__main__':
    home = Path(sys.argv[1]).resolve()
    home.mkdir(parents=True,exist_ok=False)
    install(home,*build(home))
