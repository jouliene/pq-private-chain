"""Compare actual local prover paths to an upstream full public tree. Return counts only."""
import struct
import subprocess


def compare(oracle, leaves, root, positions_and_siblings):
    data=bytearray(b"QPATH1"+struct.pack("<II",len(leaves),len(positions_and_siblings)))
    data.extend(b"".join(leaves))
    data.extend(root)
    seen=set()
    for pos,levels in positions_and_siblings:
        assert pos not in seen
        seen.add(pos)
        data.extend(struct.pack("<IB",pos,len(levels)))
        for siblings in levels:
            assert len(siblings)==3 and all(len(s)==32 for s in siblings)
            data.extend(b"".join(siblings))
    # Audit all values inside the process; preserve only aggregate success counts.
    result=subprocess.run([str(oracle)],input=data,capture_output=True,timeout=90)
    assert result.returncode==0,"upstream root or membership mismatch"
    n,depth,paths,words=map(int,result.stdout.split())
    assert n==len(leaves) and paths==len(positions_and_siblings) and words==3*paths*depth
    return dict(public_leaves=n,depth=depth,owned_paths=paths,positional_siblings_checked=words)
