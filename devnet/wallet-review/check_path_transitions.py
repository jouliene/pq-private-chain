"""Compare the production incremental tree against the full upstream implementation on public synthetic leaves."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent)]
from check_membership import compare
from wallet import _wire
from wallet_sync import Tree,extend_path


def check(executable,binary_sha,oracle):
    h=_wire.Role(executable,binary_sha,["hash"])
    words=[]
    paths=[]
    cases=[]
    try:
        tree=Tree(0,b"",lambda row:h.call(b"N"+b"".join(row)))
        for i in range(257):
            data=hashlib.sha256(b"public-wallet-tree-control"+struct.pack("<I",i)).digest()
            leaf=struct.pack("<4Q",*(x%0xffffffff00000001 for x in struct.unpack("<4Q",data)))
            words.append(leaf)
            groups,root=tree.append(leaf)
            for p,path in enumerate(paths):
                extend_path(path,p,i,groups)
            paths.append([tuple(children[:slot]+children[slot+1:]) for slot,children in groups])
            if len(words) in (1,2,3,4,5,15,16,17,63,64,65,255,256,257):
                cases.append(compare(oracle,words,root,list(enumerate(paths))))
                tree=Tree(tree.n,tree.encode(),tree.hash)
        sample=paths[0]
        first=sample[0]
        assert first[0]!=first[1]
        incorrect=[(0,[(first[1],first[0],first[2]),*sample[1:]])]
        try:
            compare(oracle,words,root,incorrect)
        except AssertionError:
            pass
        else:
            raise AssertionError("positional permutation escaped the checker")
        return dict(dataset="deterministic public commitments, no proofs or mining",cases=cases,
                    positional_permutation_rejected=True)
    finally:
        h.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary",type=lambda v:Path(v).resolve())
    p.add_argument("binary_sha")
    p.add_argument("oracle",type=lambda v:Path(v).resolve())
    a=p.parse_args()
    print(json.dumps(check(a.binary,a.binary_sha,a.oracle),indent=2))
