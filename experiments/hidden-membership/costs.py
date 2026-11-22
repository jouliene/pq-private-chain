"""Funding proof and network costs. All byte counts are decimal, before block framing."""
from fractions import Fraction
import json
from math import comb, isqrt
from pathlib import Path
from statistics import median
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from alternative.price import geometry, growing_year
from smallwood.mixed.price import size as mixed_wire
sys.path.insert(0, str(HERE.parent / "fresh-spend" / "binding"))
from side import schedule


def single_field_floor(assignment, field_bytes, local_opening_bits, log_leaves):
    """SmallWood+ §4.3 Compiler 1, unpacked binary gates in one large field."""
    # Theorem 4 bounds one term by binom(dQ,k)/binom(N,k). Since dQ>=k,
    # reaching 2^-b with N=2^h requires at least ceil(b/h) openings.
    k = (local_opening_bits + log_leaves - 1) // log_leaves
    # Remark 8 / §4.3: dQ+1-k=2s elements for Q, k*ceil(assignment/s)
    # for witness polynomials. AM-GM, with exact integer rounding.
    radicand = 8*k*assignment
    root = isqrt(radicand)
    return field_bytes * (root + int(root*root < radicand))


def traffic(ordinary, swap, count):
    # One wallet upload to the mining node per final operation, one complete
    # accepted-body reception per validator. Swap negotiation traffic is additional.
    archive = ordinary*(count*9//10) + swap*(count//10)
    mean_mbps = float(Fraction(8*archive, 31_557_600*1_000_000))
    return dict(body_archive_B_year=archive, one_live_copy_Mbps=round(mean_mbps, 5),
                four_full_gossip_copies_out_Mbps=round(4*mean_mbps, 5))


def exact_opening_floor(widths, N, exponent, field_bytes):
    # Minimize only the Q complement and opened witness polynomial values.
    # For fixed s, E(k+1)/E(k)=(2s+k)/(N-k). The first admissible k
    # minimizes transmitted terms for this s. Everything else costs more.
    best = {width: None for width in widths}
    for pack in range(1,N//2):
        def eligible(k):
            return (comb(2*pack+k-1,k) << exponent) <= comb(N,k)
        hi = (N-2*pack+1)//2
        if not eligible(hi):
            continue
        lo = 1
        while lo < hi:
            mid = (lo+hi)//2
            if eligible(mid):
                hi = mid
            else:
                lo = mid+1
        for width in widths:
            fields = 2*pack + lo*((width+pack-1)//pack)
            option = (field_bytes*fields, pack, lo)
            if best[width] is None or option < best[width]:
                best[width] = option
    if any(v is None for v in best.values()):
        raise ValueError("opening target infeasible")
    return best


def direct_wire(width, ell, word, pack, opened, N, eta, hash_bytes, salt_bytes):
    trace = 3*ell + 5
    columns = (width + trace + pack - 1)//pack
    return (word*(trace+2*pack+opened+pack*eta) + 2*hash_bytes +
            opened*((columns+2+eta)*word + salt_bytes + (N.bit_length()-1)*hash_bytes))


def results():
    wire = json.loads((HERE.parent/"advancing-note/WIRE.json").read_text())
    n7_ordinary = int(median(r["packet_B"] for r in wire["rows"] if r["legs"] == 1))
    n7_swap, = [r["packet_B"] for r in wire["rows"] if r["legs"] == 2]
    # A deliberately optimistic width for the generic Fig. 13 monetary template:
    # one committed base-field element per AND and all original private input bits.
    assignment = sum(schedule().values()) + 49_233
    path_width = 80*38_400
    exact = exact_opening_floor([assignment,path_width],2048,256,36)
    payment_proof_floor, pack, opened = exact[assignment]
    path_proof_floor = exact[path_width][0]
    if payment_proof_floor < single_field_floor(assignment,36,256,11):
        raise ValueError("exhaustive result violates the independent analytic bound")
    frames = {
        "funded_C_measured_sample": (182863, 400165),
        "N7P2_sample_median_ordinary_and_measured_swap": (n7_ordinary, n7_swap),
        "C1_unpacked_288bit_partial_proof_floor_plus_FS01_envelope": (
            payment_proof_floor + 3990, 2*payment_proof_floor + 67856),
    }
    # These two identities cross-check the literal serializer on the real calibration.
    probes = {}
    for label,params in {"gf16":(2,32,16,256,16,32,16),
                         "gf256":(32,32,84,1024,4,64,32)}.items():
        probes[label] = dict(link_bytes=direct_wire(81412,17,*params),
                             two_funded_inputs_bytes=direct_wire(3723978,22,*params),
                             modeled_full_proof_floor=direct_wire(assignment+2,22,*params))
    if [probes[x]["link_bytes"] for x in ("gf16","gf256")] != [87760,6926976]:
        raise ValueError("geometry mismatch")
    if probes["gf16"]["two_funded_inputs_bytes"]!=3730382:
        raise ValueError("two funded paths serialization")
    # Mixed-field Compiler 1 splits each masked trace word into 16 base coordinates.
    probes["mixed16x256"] = dict(
        link_bytes=mixed_wire(81412,17)["proof_bytes"],
        two_funded_inputs_bytes=mixed_wire(3723978,22)["proof_bytes"],
        modeled_full_proof_floor=mixed_wire(assignment+2,22)["proof_bytes"])
    if tuple(probes["mixed16x256"].values()) != (241664,5966544,6249904):
        raise ValueError("mixed proof geometry")
    # Unpacked, fixed Compiler 1 parameters and a named optimistic payment compiler.
    for label in probes:
        proof = probes[label]["modeled_full_proof_floor"]
        frames["C1_literal_" + label + "_complete_packet_floor"] = (proof+3990,2*proof+67856)
    rows = {}
    for count in (10_000_000, 30_000_000, 100_000_000):
        # Model one fixed occupancy and also a separate end-of-year snapshot.
        year_end_rows = count*22//10
        lookup = geometry(year_end_rows)["profiles"]["256s"]
        full = geometry(1<<40)["profiles"]["256s"]
        choices = dict(frames, ANF_end_year_snapshot=(lookup["ordinary"], lookup["swap"]),
                       ANF_full_capacity=(full["ordinary"], full["swap"]))
        rows[str(count)] = {name: dict(ordinary_B=a, swap_B=b, **traffic(a,b,count))
                            for name,(a,b) in choices.items()}
        body = growing_year(count,1)
        mbps = body*8/31_557_600/1_000_000
        rows[str(count)]["ANF_growing_first_year"] = dict(body_archive_B_year=body,
            one_live_copy_Mbps=round(mbps,5),four_full_gossip_copies_out_Mbps=round(4*mbps,5),
            raw_funded_digest_growth_B=64*year_end_rows,receipt_ciphertext_B=1792*year_end_rows)
    return dict(mix="90% ordinary and 10% two-leg swaps, all included",
                literal_profiles=probes,
                single_field=dict(field_bits=288, local_opening_bits=256, N=2048,
                                  coarse_minimum_opens=24, assignment_elements=assignment,
                                  monetary_argmin_pack=pack, monetary_argmin_opens=opened,
                                  both_paths_proof_floor_B=path_proof_floor,
                                  full_monetary_proof_floor_B=payment_proof_floor), traffic=rows)


if __name__ == "__main__":
    print(json.dumps(results(), indent=2))
