"""Differentially compare the canonical monetary model and every native public wire address."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/"structured-keccak"/"payment"))
from monetary import build_payment, public_statement


def digest(w):
    h = hashlib.sha256()
    def word(n):
        h.update(struct.pack("<I",int(n)))
    def vec(x):
        x = np.asarray(x,dtype="<u4")
        word(len(x))
        h.update(x.tobytes())
    word(w.width)
    word(len(w.bounds))
    for perm in w.bounds:
        for boundary in perm:
            vec(boundary)
    word(len(w.selectors))
    for child,sib,d,left in w.selectors:
        vec(child)
        vec(sib)
        word(d)
        vec(left)
    for which in range(3):
        vec(np.concatenate([p[which] for p in w.products]))
    word(len(w.linear))
    for terms,target in w.linear:
        word(len(terms))
        for term in terms:
            vec(term)
        vec(target)
    return h.hexdigest()


def main():
    counts = (1,2,3,13,(1<<39)-1,1<<39,(1<<40)-1,1<<40)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        checker = tmp/"check"
        subprocess.run(["c++","-std=c++20","-O2",str(HERE/"wiring_check.cpp"),
                        str(HERE/"wiring.cpp"),"-lcrypto","-o",str(checker)],check=True)
        for count in counts:
            raw = bytearray(hashlib.shake_256(b"public differential fixture"+count.to_bytes(6,"little")).digest(526))
            raw[128:134] = count.to_bytes(6,"little")
            path = tmp/"statement"
            path.write_bytes(raw)
            expected = digest(build_payment(public_statement(bytes(raw)),4))
            native = subprocess.check_output([str(checker),str(path)],text=True).strip()
            if native != expected:
                raise ValueError(f"public topology mismatch at count {count}")
    print("Complete wire addresses and public targets agreed at all eight anchor counts.")


if __name__=="__main__":
    main()
