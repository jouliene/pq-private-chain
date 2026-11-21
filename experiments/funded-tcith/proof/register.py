"""Generate the public verifier circuit from the reviewed fixed-parent frontend."""
from hashlib import sha256
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lattice-spend/pivot"))
import pivot

SHAPE = "77533cc1c383bec78358ae8b304a1151aab834c34656d2edcc167dccdaf1c339"


def register(constants, destination):
    blank = pivot.f.blank("SLG1")
    blank["public"].extend([0] * 4)
    _, public = pivot.compile_full("SLG1", pivot.f.constants(constants), blank, register=True)
    if sha256(public).hexdigest() != SHAPE:
        raise ValueError("unexpected SLG1 fixed-parent circuit")
    with destination.open("xb") as out:
        out.write(public)


if __name__ == "__main__":
    register(*map(Path, sys.argv[1:]))
