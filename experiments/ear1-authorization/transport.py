"""Exercise the EC01 compiler transport at registered dimensions using only deterministic public test data."""
import argparse
import hashlib
import json
import math
from pathlib import Path
from alternative import H, K, PRIMARY, SALT, branch_nodes, rounds, subset, wire

N, _, COUNT, _ = PRIMARY
SCHEDULE = rounds(PRIMARY)
INSTANCE = b"EC01" + bytes(32+526)  # public framing fixture, no monetary witness
DOMAIN = b"EC01/transport-test/v1/"


def X(data, size):
    return hashlib.shake_256(data).digest(size)


def vc_tag(i):
    return DOMAIN+b"VC"+bytes([i])


def leaf(cell, salt):
    return b"L"+len(cell).to_bytes(2,"little")+cell+salt


def coins(i, indices, roots, taus):
    prefix = INSTANCE+b"".join(bytes([j])+r for j,r in zip(indices,roots,strict=True))+b"".join(taus)
    return X(DOMAIN+b"FS"+bytes([i])+prefix,SCHEDULE[i][1])


def make():
    roots, taus, oracles, draws = [], [], [], []
    for i,(width,_) in enumerate(SCHEDULE):
        size = N if i == 0 else 1
        tag = bytes([i])
        data = X(DOMAIN+b"fixture/cells"+tag,size*width)
        salts = X(DOMAIN+b"fixture/salts"+tag,size*SALT)
        tree = [b""]*(2*size)
        for j in range(size):
            payload = leaf(data[j*width:(j+1)*width],salts[j*SALT:(j+1)*SALT])
            tree[size+j] = X(vc_tag(i)+payload,H)
        for j in reversed(range(1,size)):
            tree[j] = X(vc_tag(i)+b"N"+tree[2*j]+tree[2*j+1],H)
        roots.append(tree[1])
        taus.append(X(DOMAIN+b"fixture/tau"+tag,SALT))
        oracles.append((data,salts,tree))
        draws.append(coins(i,range(i+1),roots,taus))
    wanted = subset(N,COUNT,int.from_bytes(draws[-1],"little")%math.comb(N,COUNT))
    packet = bytearray()
    for i,((data,salts,tree),(width,_)) in enumerate(zip(oracles,SCHEDULE,strict=True)):
        q = wanted if i == 0 else (0,)
        packet += bytes([i])+roots[i]+taus[i]
        packet += b"".join(j.to_bytes(2,"little") for j in q)
        packet += b"".join(data[j*width:(j+1)*width] for j in q)
        packet += b"".join(salts[j*SALT:(j+1)*SALT] for j in q)
        if i == 0:
            packet += b"".join(tree[j] for j in branch_nodes(N,q))
    return packet


def check(packet):
    cursor = 0
    def take(n):
        nonlocal cursor
        if n > len(packet)-cursor:
            raise ValueError("truncated compiler record")
        val = packet[cursor:cursor+n]
        cursor += n
        return val
    if len(packet)>wire(PRIMARY)["structural_max_proof_B"]:
        raise ValueError("oversized compiler record")
    queries, indices, roots, taus = [], [], [], []
    for i,(width,_) in enumerate(SCHEDULE):
        idx = take(1)[0]
        if idx>=K or idx in indices:
            raise ValueError("wrong VC index")
        indices.append(idx)
        root = take(H)
        roots.append(root)
        taus.append(take(SALT))
        q = tuple(int.from_bytes(take(2),"little") for _ in range(COUNT if i==0 else 1))
        if i==0:
            observed = q
            if q != tuple(sorted(set(q))) or q[-1]>=N:
                raise ValueError("noncanonical query")
        elif q!=(0,):
            raise ValueError("wrong singleton query")
        cells = [take(width) for _ in q]
        salts = [take(SALT) for _ in q]
        size = N if i==0 else 1
        nodes = {1:root}
        if i==0:
            nodes.update({j:take(H) for j in branch_nodes(N,q)})
        for pos,cell,salt in zip(q,cells,salts,strict=True):
            node = size+pos
            queries.append((idx,leaf(cell,salt),nodes[node]))
            while node>1:
                node //= 2
                queries.append((idx,b"N"+nodes[2*node]+nodes[2*node+1],nodes[node]))
    if cursor!=len(packet):
        raise ValueError("incorrect length")
    # Build the entire VC I/O table before making any of its oracle calls.
    if not all(X(vc_tag(i)+inp,H)==expected for i,inp,expected in queries):
        raise ValueError("CheckIO digest mismatch")
    for i in range(K):
        draw = coins(i,indices[:i+1],roots[:i+1],taus[:i+1])
    target = subset(N,COUNT,int.from_bytes(draw,"little")%math.comb(N,COUNT))
    if target!=observed:
        raise ValueError("incorrect query set")
    return len(queries)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("role",choices=("make","check"))
    p.add_argument("file",type=Path)
    a=p.parse_args()
    if a.role=="make":
        with a.file.open("xb") as f:
            f.write(make())
        return
    data=a.file.read_bytes()
    calls=check(data)
    changed=bytearray(data)
    # Mutate a first-round authenticated answer, preserving parse and Q.
    changed[1+H+SALT+2*COUNT] ^= 1
    try:
        check(changed)
    except ValueError as err:
        if str(err)!="CheckIO digest mismatch":
            raise
    else:
        raise AssertionError("changed cell accepted")
    print(json.dumps(dict(fixture="public synthetic EC01 transport only",serialized_B=len(data),
        packet_sha256=hashlib.sha256(data).hexdigest(),VC_checked=calls,FS_calls_per_role=K,
        changed_answer_rejected_by_CheckIO=True),indent=2))


if __name__=="__main__":
    main()
