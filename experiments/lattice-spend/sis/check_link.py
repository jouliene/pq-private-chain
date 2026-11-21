"""Synthetic depth-40 oracle for the proposed common-leaf relation, no ZK prover."""
from hashlib import shake_256

N, Q, H = 4, 256, 40  # deliberately small public functional fixture
CM_BITS, R_BITS = 16, 24
K = (Q-1).bit_length()


def bits(x, n):
    if not 0 <= x < 1 << n:
        raise ValueError("integer does not fit")
    return [(x >> i) & 1 for i in range(n)]


def matrix(label, cols):
    raw=shake_256(label).digest(N*cols)
    return [list(raw[i*cols:(i+1)*cols]) for i in range(N)]


A=matrix(b"LLNW/public/toy/node",2*N*K)
B=matrix(b"LLNW/public/toy/link",CM_BITS+R_BITS)


def dot(row,x):
    return sum(a*b for a,b in zip(row,x,strict=True))


def leaf(cm):
    return tuple([1]+bits(cm,CM_BITS)+[0]*(N*K-CM_BITS-1))


def parent(left,right):
    return tuple(bit for row in A for bit in bits(dot(row,(*left,*right))%Q,K))


def tree(outputs):
    levels=[{i:leaf(cm) for i,cm in outputs.items()}]
    empty=[(0,)*(N*K)]
    for h in range(H):
        row=levels[-1]
        levels.append({idx:parent(row.get(2*idx,empty[h]),row.get(2*idx+1,empty[h]))
                       for idx in {i//2 for i in row}})
        empty.append(parent(empty[h],empty[h]))
    return levels,empty


def root_at(tree_data):
    levels,empty=tree_data
    return levels[-1].get(0,empty[-1])


def path(tree_data,idx):
    levels,empty=tree_data
    return [levels[h].get((idx>>h)^1,empty[h]) for h in range(H)]


def path_ok(root,node,idx,siblings,count):
    if not 0 <= idx < count <= 1 << H or len(siblings)!=H:
        return False
    for h,sib in enumerate(siblings):
        node=parent(sib,node) if (idx>>h)&1 else parent(node,sib)
    return node==root


def link_tag(cm,r):
    x=bits(cm,CM_BITS)+bits(r,R_BITS)
    return tuple(dot(row,x)%Q for row in B)


def bridge(cm,r,tag,carries):
    x=bits(cm,CM_BITS)+bits(r,R_BITS)
    return (len(tag)==len(carries)==N and
            all(0<=c<Q and 0<=t<=len(x) and dot(row,x)==c+Q*t
                for row,c,t in zip(B,tag,carries,strict=True)))


def check():
    first,second=111,223
    main=tree({0:first,1:second})
    fork=tree({0:first,1:347})
    for i,cm in enumerate((first,second)):
        base=root_at(main)
        siblings=path(main,i)
        assert path_ok(base,leaf(cm),i,siblings,2)
        assert not path_ok(root_at(fork),leaf(cm),i,siblings,2)
        assert not path_ok(base,leaf(cm),i^1,siblings,2)
        assert not path_ok(base,leaf(cm),i,siblings,0)
    # Two slots can both be demonstrated under this same branch. One CMS
    # opening per slot must also match its independently reconstructed money note.
    for i,cm in enumerate((first,second)):
        rand=13+i
        tag=link_tag(cm,rand)
        x=bits(cm,CM_BITS)+bits(rand,R_BITS)
        carries=[dot(row,x)//Q for row in B]
        assert bridge(cm,rand,tag,carries)
        assert not bridge(second if i==0 else first,rand,tag,carries)
        assert not bridge(cm,rand,tag,[carries[0]+1,*carries[1:]])
    assert link_tag(first,13)!=link_tag(first,19)
    print("depth-40 sparse root, 2 occurrences, branch/position/count and modular equality controls passed")


if __name__=="__main__":
    check()
