"""Cost the registered CDHZ 11.7/8.2 compiler layout. No alternative spend prover is invoked."""
import argparse
from collections import Counter
from itertools import groupby
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent/"sgm1-security"/"evidence"
PRIMARY = (4096,91,60,75)
K = 215
H = 80
SALT = 64
PACKED = 58876
INDEX_B = 1
QUERY_B = 2
INSTANCE_B = 4+32+526
ORDINARY = 3990
SIGNED = ORDINARY+136+29792


def baseline_rounds():
    # Consecutive prover messages precede one group of consecutive public coins.
    # Widths are (one prover-cell size, total coin bytes). First entry describes the old root.
    regular = [(128,32)]+[(96,32)]*19+[(96,96)]+[(64,32)]*11
    return ([(64,101856),(22650,640)]+regular*5+[(128,32)]+[(96,32)]*19+
            [(96,384)]+[(96,32)]*12+[(96,416)]+[(96,32)]*13+
            [(96,1982112),(256,32),(32,576),(512,8192),(32,8256),(7744,128)])


def check_replay(path):
    events = json.loads(path.read_text())["ordered_events"]
    end = {"mixed open column","mixed salt","mixed Merkle sibling"}
    groups = [(kind,sum(x[2] for x in g)) for kind,g in groupby(
        (x for x in events if x[2] and x[1] not in end),key=lambda x:x[0])]
    assert all((m[0],c[0])==("message","coin") for m,c in zip(groups[::2],groups[1::2],strict=True))
    assert [(m[1],c[1]) for m,c in zip(groups[::2],groups[1::2])]==baseline_rounds()


def octets(bits):
    return (bits+7)//8


def map_bytes(cardinality):
    return octets((cardinality-1).bit_length()+512)


def subset(n,t,rank):
    """Combinadic unranking in colex order, including both extrema, without rejection."""
    if not 0 <= rank < math.comb(n,t):
        raise ValueError("rank outside subset range")
    out = []
    upper = n-1
    for k in range(t,0,-1):
        lo,hi = k-1,upper
        while lo < hi:
            mid = (lo+hi+1)//2
            if math.comb(mid,k)<=rank:
                lo=mid
            else:
                hi=mid-1
        out.append(lo)
        rank -= math.comb(lo,k)
        upper=lo-1
    return tuple(reversed(out))


def rounds(profile):
    n,s,t,eta=profile
    rows=(PACKED+s-1)//s
    out=baseline_rounds()
    out[0]=(2*(rows+32+eta),2*eta*(rows+32))
    out[1]=(2*(s+t)*eta,out[1][1])
    out[-5]=(256,map_bytes((1<<256)-8))
    out[-1]=(32*(2*s+t),map_bytes(math.comb(n,t)))
    return out


def branch_nodes(n,positions):
    """Each occupied parent needs both child labels for a precomputed CheckIO table."""
    found=set()
    for pos in positions:
        node=n+pos
        while node>1:
            found.add(node)
            found.add(node^1)
            node//=2
    return sorted(found)


def path_limits(n,t):
    return tuple(2*sum(op(1<<j,t,n) for j in range(n.bit_length()-1)) for op in (
        lambda p,t,n:(t+n//p-1)//(n//p),lambda p,t,n:min(p,t)))


def wire(profile,h=H):
    n,s,t,eta=profile
    rs=rounds(profile)
    d=n.bit_length()-1
    assert 1<<d==n and n+2*s+t<=65536 and t<=n and len(rs)==K
    opened=t+K-1
    parts=dict(round_indices=K*INDEX_B,queries=opened*QUERY_B,roots=K*h,fs_salts=K*SALT,
               first_answers=t*rs[0][0],broadcast_answers=sum(a for a,c in rs[1:]),leaf_salts=opened*SALT)
    fixed=sum(parts.values())
    low,high=path_limits(n,t)
    literal=fixed+h*((2+2*d)*t+2*(K-1))
    expensive=fixed+h*high
    return dict(components_B=parts,branch_digest_count_min=low,branch_digest_count_max=high,
                literal_proof_B=literal,structural_min_proof_B=fixed+h*low,structural_max_proof_B=expensive,
                ordinary_max_B=ORDINARY+expensive,signed_leg_max_B=SIGNED+expensive,
                two_signed_max_B=20+2*(SIGNED+expensive),literal_ordinary_B=ORDINARY+literal,
                literal_signed_B=SIGNED+literal,literal_bundle_B=20+2*(SIGNED+literal))


def resources(profile):
    n,s,t,eta=profile
    rows=(PACKED+s-1)//s
    d=n.bit_length()-1
    allrows=rows+32+eta
    rs=rounds(profile)
    coin=[b for _,b in rs]
    return dict(funded_permutations=99,depth40_parents=80,bit_coordinates=783808,K_trace_masks=584,
        packed_F_symbols=PACKED,packed_rows=rows,codeword_F_rows=allrows,
        zero_padded_F_coordinates=rows*s-PACKED,
        F_row_blind_slots=rows*t,F_decs_pad_symbols=eta*(s+t),
        F_randomized_split_symbols=16*t,F_zero_sum_mask_free_coefficients=16*(2*s+t-1),
        F_ring_pad_samples=256+16,F_ring_pad_committed_slots=2*(256+16),
        wallet_column_bytes=n*allrows*2,wallet_tree_digest_bytes=(2*n-1+K-1)*H,
        wallet_leaf_salt_bytes=(n+K-1)*SALT,wallet_fs_salt_bytes=K*SALT,
        wallet_column_evaluations_F=n*allrows,
        wallet_dense_column_product_terms_F=n*allrows*(s+t),
        wallet_degree_table_product_terms_F=eta*(rows+32)*(s+t),
        node_degree_open_product_terms_F=t*eta*(rows+32),node_degree_eval_terms_F=t*eta*(s+t),
        node_quotient_eval_terms_K=t*(2*s+t),
        wallet_leaf_and_pair_hashes=2*n-1+K-1,node_MT_CheckIO_queries=t*(d+1)+K-1,
        FS_queries_each=K,node_total_RO_queries=K+t*(d+1)+K-1,qPi=t+K-1,lmax=n,
        ri_min_bits=min(coin)*8,ri_max_bits=max(coin)*8,FS_consumed_B=sum(coin),
        FS_fixed_codomain_full_materialization_B=K*max(coin),
        FS_prefix_tuple_input_B=K*INSTANCE_B+(INDEX_B+H+SALT)*(K*(K+1)//2),
        proof_alphabet_max_payload_B=max(a for a,b in rs))


def geometry_search():
    results=[]
    for n in (512,1024,2048,4096,8192,16384,32768):
        best=None
        # Minimal passing t at each s suffices: for fixed s the cost is nondecreasing over this grid
        # while s+t+1 <= n/2. For small N scan the rest too, ensuring the stated finite minimum.
        for s in range(15,301):
            if 2*s+10>n:
                continue
            for t in range(10,240):
                support=2*s+t-1
                if support>=n or n+2*s+t>65536:
                    break
                if math.comb(support,t)*(1<<256)>math.comb(n,t):
                    continue
                eta=(((math.comb(n,s+t+1)-1).bit_length()+256)+15)//16
                p=(n,s,t,eta)
                if max(a for a,_ in rounds(p)) >= (1<<16):
                    continue
                size=wire(p)["structural_max_proof_B"]
                if best is None or size<best[0]:
                    best=(size,p)
                if s+239+1<=n//2:
                    break
        if best:
            _,p=best
            _,s,t,eta=p
            w=wire(p)
            results.append(dict(N=n,s=s,t=t,eta=eta,proof_B=best[0],signed_leg_B=w["signed_leg_max_B"],
                bundle_B=w["two_signed_max_B"],wallet_column_evaluations_F=n*((PACKED+s-1)//s+32+eta),
                subset_bits=round(math.log2(math.comb(n,t))-math.log2(math.comb(2*s+t-1,t)),4),
                degree_bits=round(16*eta-math.log2(math.comb(n,s+t+1)),4)))
    return results


def opening_codec_check():
    """Tiny deterministic public mechanics probe. SHAKE here tests encoder behavior only."""
    n=8
    hash_pair=lambda left,right:hashlib.shake_256(b"N"+left+right).digest(H)
    hash_leaf=lambda value,salt:hashlib.shake_256(b"L"+len(value).to_bytes(2,"little")+value+salt).digest(H)
    vals=[bytes([i])*9 for i in range(n)]
    salts=[bytes([i+1])*SALT for i in range(n)]
    nodes={n+i:hash_leaf(value,salts[i]) for i,value in enumerate(vals)}
    for pos in reversed(range(1,n)):
        nodes[pos]=hash_pair(nodes[pos*2],nodes[pos*2+1])
    q=(0,1,6)
    needed=branch_nodes(n,q)
    def output_io(hashes):
        table=[]
        for i in q:
            node=n+i
            table.append(("leaf",vals[i],salts[i],hashes[node]))
            while node>1:
                parent=node//2
                table.append(("pair",hashes[2*parent],hashes[2*parent+1],hashes[parent]))
                node=parent
        return table
    # Build all expected query inputs AND outputs before any CheckIO call.
    packed=b"".join(nodes[pos] for pos in needed)
    reconstructed={1:nodes[1],**{pos:packed[j*H:(j+1)*H] for j,pos in enumerate(needed)}}
    assert output_io(nodes)==output_io(reconstructed)
    def check(table):
        return all((hash_leaf if tag=="leaf" else hash_pair)(a,b)==expected for tag,a,b,expected in table)
    assert check(output_io(reconstructed))
    reconstructed[needed[0]]=bytes(H)
    assert not check(output_io(reconstructed))


def selfcheck():
    n,_,t,_=PRIMARY
    assert len(branch_nodes(n,range(t)))==path_limits(n,t)[0]
    spread=[int(f"{i:012b}"[::-1],2) for i in range(t)]
    assert len(branch_nodes(n,spread))==path_limits(n,t)[1]
    assert len({subset(9,4,r) for r in range(math.comb(9,4))})==math.comb(9,4)
    assert subset(n,t,0)==tuple(range(t)) and subset(n,t,math.comb(n,t)-1)==tuple(range(n-t,n))
    counts=Counter(baseline_rounds())
    assert sum(counts.values())==215 and sum(a for a,b in baseline_rounds()[1:])==49626
    trace=json.loads((EVIDENCE/"EAR1_TRACE.json").read_text())
    assert trace["interacting_coin_blocks"]==215 and trace["columns_B"]==rounds(PRIMARY)[0][0]
    assert sum(b for a,b in baseline_rounds())==trace["totals"]["coin_bytes"]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events",type=Path,help="also verify a public EAR1 --early --events transcript")
    args=ap.parse_args()
    if args.events:
        check_replay(args.events)
    selfcheck()
    opening_codec_check()
    rs=rounds(PRIMARY)
    grouped=[dict(repeat=len(list(g)),cell_B=val[0],coin_B=val[1])
             for val,g in groupby(rs)]
    print(json.dumps(dict(registration="CDHZ-11.7/MT8.2 funded EAR1 IOP projection",
        profile=dict(N=4096,s=91,t=60,eta=75,K_bits=256,F_bits=16,sigma_bits=640,nu_bits=512,rs_bits=512),
        compressed_round_schedule=grouped,wire=wire(PRIMARY),resources=resources(PRIMARY),
        hash_width_sensitivities=[dict(sigma_bits=8*h,**wire(PRIMARY,h)) for h in (48,64,80)],
        geometry_sensitivities=geometry_search()),indent=2))


if __name__=="__main__":
    main()
