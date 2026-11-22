"""Recompute the structured payment wire, role costs and inclusion scenarios from public evidence."""
import argparse
import json
from math import ceil, comb, log2
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent
YEAR = 31_557_600
COMPARE = HERE.parent/"funded-membership/evidence/COSTS.json"


def read(path):
    return json.loads(path.read_text())


def envelope(proof):
    return dict(ordinary_B=3990+proof,signed_leg_B=33918+proof,swap_B=67856+2*proof)


def wire(bits,trace,kbits=256,s=91,t=60,eta=75,n=4096):
    r = kbits//16
    if kbits%16 or n&(n-1) or n+2*s+t>65536:
        raise ValueError("invalid extension or evaluation domain")
    rows = ceil((ceil(bits/16)+r*trace+2*(kbits+r))/s)
    parts = dict(opened_data_rows=2*t*rows, mask_rows=2*t*(2*r+eta),
                 salt=t*32, merkle_paths=t*(n.bit_length()-1)*64,
                 degree_completion=2*s*eta, quotient=(2*s+t)*(kbits//8),
                 digests=128, ring=2*kbits+kbits//8, masked_trace=trace*kbits//8)
    return dict(rows=rows,parts=parts,total=sum(parts.values()))


def path_price(parents,paths,k):
    d = 24//k
    ell = 11+(parents*k-1).bit_length()
    t = 1 + d*(3*ell+3) + (d-1)*23 + 3*(5+(parents-1).bit_length())+3 + d+2
    bits = paths*512 + parents*(513+1600*(k+1))
    return wire(bits,t)


def scenario(n,ordinary,swap,ordinary_cpu,swap_cpu):
    annual=(n*9//10)*ordinary+(n//10)*swap
    live=8*annual/YEAR/1e6
    cpu=(0.9*ordinary_cpu+0.1*swap_cpu)*n/YEAR
    return dict(accepted_body_B=annual,canonical_body_TB=annual/1e12,
                original_submitted_B=annual,mean_one_copy_in_Mbps=live,
                four_body_copies_out_Mbps=4*live,full_mempool_and_block_four_peers_out_Mbps=8*live,
                fourteen_day_body_TB=annual*14/365.25/1e12,
                mean_crypto_CPU_cores=cpu,busy_share_of_two_cores=cpu/2)


def report(payment):
    frames = read(HERE/"payment/inventory.json")["shape_by_public_count_and_flattening"]
    k = payment["geometry"]["flatten"]
    b,t = (payment["geometry"][key] for key in ("bit_coordinates","trace_words"))
    exact=wire(b,t)
    if exact["total"]!=payment["proof_B"]:
        raise ValueError("serializer and independent price disagree")
    ext = envelope(exact["total"])
    if payment["ordinary_B"]!=ext["ordinary_B"] or payment["output_receipts_opened"]!=2:
        raise ValueError("incomplete ordinary wire")
    baseline=read(COMPARE)
    groups=[g for g in baseline["groups"] if g["height"]>=25]
    def old_cost(op):
        rows=[g for g in groups if g["operation"]==op]
        return (int(median(g["submission_B"] for g in rows)),
                median(v["verifier_cpu_s"] for g in rows for v in g["warm"]))
    cord,cpu_o=old_cost("transfer")
    cswap,cpu_s=old_cost("swap")
    cw=baseline["wallet_measurements"]["paid"]
    new_cpu=median(v["cpu_s"] for v in payment["repeated_public_checks"][1:])
    # The 2-leg estimate charges two independent proofs. Node signature, networking
    # and durable ledger CPU have no corresponding complete new admission measurement.
    n7_rows=read(HERE.parent/"advancing-note/WIRE.json")["rows"]
    n7_o=int(median(r["packet_B"] for r in n7_rows if r["legs"]==1))
    n7_s,=[r["packet_B"] for r in n7_rows if r["legs"]==2]
    n7_cpu=read(HERE.parent/"advancing-note/COSTS.json")["warm_node"]["full_admission_core_s_per_mixed_operation"]
    roles={}
    for n in (10_000_000,30_000_000,100_000_000):
        roles[str(n)]={"C":scenario(n,cord,cswap,cpu_o,cpu_s),
                       "N7P2":dict(ordinary_B=n7_o,swap_B=n7_s,body_archive_B=(9*n7_o+n7_s)*(n//10),
                                   mixed_measured_core_s_per_operation=n7_cpu,mean_cores=n7_cpu*n/YEAR),
                       "SGM1":scenario(n,ext["ordinary_B"],ext["swap_B"],new_cpu,2*new_cpu),
                       "two_core_cpu_budget_s_per_crypto_leg":2*YEAR/(1.1*n)}
    funding=read(HERE/"evidence/FUNDED.json")
    path_costs = {str(p):path_price(p,2 if p==80 else 1,k)["total"] for p in (1,2,8,40,80)}
    for p,file in ((2,"TWO_PARENTS.json"),(8,"EIGHT_PARENTS.json")):
        if any(r["proof_B"]!=path_costs[str(p)] for r in read(HERE/"evidence"/file)["samples"]):
            raise ValueError("parent serializer and wire geometry disagree")
    if wire(funding["geometry"]["bit_coordinates"],funding["geometry"]["trace_words"])["total"] != funding["proof_B"]:
        raise ValueError("funding geometry")
    # One base cell in each opened row costs exactly 2*t bytes across the proof.
    wide={}
    for width,s,t0,eta,n0 in ((256,91,60,75,4096),(272,91,60,75,4096),(288,91,60,75,4096),
                              (512,101,62,78,4096)):
        g=wire(b,t,width,s,t0,eta,n0)
        wide[str(width)]=dict(encoding_B=g["total"],pack=s,opens=t0,N=n0,eta=eta,
            degree_exponent=16*eta-log2(comb(n0,s+t0+1)),
            subset_exponent=log2(comb(n0,t0))-log2(comb(2*s+t0-1,t0)))
    return dict(mix="90% ordinary, 10% two-owner swaps, 100% included, decimal TB, 365.25 days",
                pricing="body only; separate lost attempts, consensus headers, forks and archival copies",
                measured_ordinary_and_compiled_swap=ext,proof_allowance_B=228226,
                signed_proof_headroom_B=228226-exact["total"],payment=exact,
                constant_except_opened_rows_and_trace_B=sum(v for key,v in exact["parts"].items()
                     if key not in ("opened_data_rows","masked_trace")),
                parent_proofs_B=path_costs,funded_proof_B=funding["proof_B"],
                ordinary_flattentable_at_count_2={key:envelope(x["proof_B"]) for key,x in frames["2"].items()},
                C=dict(ordinary_B=cord,swap_B=cswap,ordinary_native_verify_cpu_s=cpu_o,
                       swap_native_verify_cpu_s=cpu_s,wallet_prover_CPU_s=cw["prover_cpu_s"],
                       wallet_prover_KiB=cw["prover_role_peak_rss_KiB"]),
                SGM1=dict(ordinary_warm_crypto_s=new_cpu,wallet_prover=payment["prover"],
                          cold_verifier=payment["cold_verifier"]), annual=roles,
                extension_sensitivity_fixed_K4=wide)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--payment-metrics",type=Path,default=HERE/"evidence/PAYMENT.json")
    print(json.dumps(report(read(parser.parse_args().payment_metrics)),indent=2))
