"""Independently exercise the graph and the exact proof byte decomposition on public values."""
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from model import BASE, CAP, DEGREE, PRIMARY_LOG_N, max_frontier, mul, neighbors, run


def square(x):
    return mul(x,x)


def trace(x):
    value=x ^ square(x) ^ square(square(x))
    assert value in (0,1)
    return value


def small_spectrum():
    n=8**2
    forward=[list(neighbors(r,dimension=2)) for r in range(n)]
    reverse=[[] for _ in range(n)]
    for r,points in enumerate(forward):
        assert len(set(points))==DEGREE
        for point in points:
            reverse[point].append(r)
    assert all(len(rows)==DEGREE for rows in reverse)
    eigenvalues=[]
    for u in range(DEGREE):
        for v in range(DEGREE):
            char=[(-1)**trace(mul(u,i%8)^mul(v,i//8)) for i in range(n)]
            intermediate=[sum(char[r] for r in rev) for rev in reverse]
            applied=[sum(intermediate[point] for point in points) for points in forward]
            roots=sum(u==mul(v,x) for x in range(8))
            eigen=roots*DEGREE
            assert applied==[eigen*t for t in char]
            eigenvalues.append(eigen)
    assert max(e for e in eigenvalues if e!=64)==8
    # For the selected dimension seven, construct an actual nonconstant
    # degree-six frequency polynomial vanishing at six distinct field points.
    coefficients=[1]
    for x in range(6):
        t=[0]*(len(coefficients)+1)
        for j,c in enumerate(coefficients):
            t[j]^=mul(x,c)
            t[j+1]^=c
        coefficients=t
    roots=[]
    for x in range(8):
        y=0
        for c in reversed(coefficients):
            y=mul(y,x)^c
        if y==0:
            roots.append(x)
    assert roots==list(range(6))
    return dict(all_integer_eigenvectors_checked=len(eigenvalues),small_second_squared_normalized="1/8",
                selected_second_squared_normalized="6/8",degree_six_witness_coefficients_low_first=coefficients)


def main():
    j=run()
    assert j==json.loads((HERE/'MODEL.json').read_bytes())
    for h in PRIMARY_LOG_N:
        om=pow(7,(BASE-1)//(1<<h),BASE)
        assert pow(om,1<<h,BASE)==1 and pow(om,1<<(h-1),BASE)!=1
    r=j['primary']
    assert r['maximum_proof_B']==sum(sum(s['bytes'].values()) for s in r['stages'])+r['outer_direct_B']
    assert r['stages'][0]['bytes']['values']>CAP
    assert r['stages'][-1]['bytes']['roots']==128
    assert r['stages'][-1]['bytes']['direct']==40*(r['stages'][-1]['degree']+2)
    for s in r['stages']:
        n=1<<s['log_n']
        assert s['d']*s['queries']+1==s['seed']
        assert s['degree']+1==s['seed']+s['main']+s['aux']+s['spare']<=n
        assert s['hash_proof_nodes_per_tree']==max_frontier(n,s['queries'])
    return dict(graph=small_spectrum(),primary_rows_checked=len(r['stages']),
                full_proof_maximum_B=r['maximum_proof_B'],all_stage_base_subgroup_orders_verified=True)


if __name__=='__main__':
    print(json.dumps(main(),indent=2,sort_keys=True))
