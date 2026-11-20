"""Public TCitH-MT Π_lppc size and exact finite-field security accounting."""
from math import comb, log2
import json
from pathlib import Path

P = 2**64 - 2**32 + 1
TARGET = 256
CAP = 241_084
CENSUS = json.loads((Path(__file__).resolve().parents[1] / "encoding/CENSUS.json").read_text())
GROUPS = {
    (suite, name): tuple(data["packing_groups"])
    for suite, encodings in CENSUS.items() for name, data in encodings.items()
}


def ceildiv(a, b):
    return -(-a // b)


def min_power(base, target):
    """Return least nonnegative t such that base**t >= target, exactly."""
    t = max(0, int((target.bit_length() - 1) / log2(base)))
    while pow(base, t) < target:
        t += 1
    while t and pow(base, t - 1) >= target:
        t -= 1
    return t


def frontier(height, opened):
    # Maximal occupied nodes at each level, attained by bit-reversed indices.
    return 2 - opened + sum(min(1 << j, opened) for j in range(1, height))


def field_counts(s, ell, d, n, rho, eta):
    deg = s + ell - 1
    hints = ceildiv((d - 1) * deg, s) + ceildiv(2 * s - 1, s)
    return hints, {
        "opened_witness": ell * n, "opened_hints": ell * hints * rho,
        "opened_mask": ell * eta, "degree_tail": s * eta,
        "polynomial_tail": (d - 1) * deg * rho, "linear_tail": (2 * s - 2) * rho,
    }


def cost(suite, encoding, height, s, ell, digest_B=64, target=TARGET):
    N = 1 << height
    d = 2 if encoding == "r1cs" else 7
    D = s + ell - 1
    if min(s,ell,height) < 1 or N+s > P or N <= d * D:
        raise ValueError("inadmissible evaluation domain")
    g = GROUPS[suite, encoding]
    n = sum(ceildiv(w, s) for w in g)
    rho = min_power(P, 1 << target)
    eta = min_power(P, comb(N, D+2) << target)
    good, possible = comb(d*D, ell), comb(N, ell)
    tau = max(1, int(target / (log2(possible) - log2(good))))
    while pow(good, tau) << target > pow(possible, tau):
        tau += 1
    while tau > 1 and (pow(good, tau-1) << target) <= pow(possible, tau-1):
        tau -= 1
    hints, fields = field_counts(s, ell, d, n, rho, eta)
    components = {k: 8*tau*v for k,v in fields.items()}
    paths = frontier(height, ell)
    components.update(fs_digests=3*digest_B, salts=tau*ell*32,
                      frontier=tau*digest_B*paths)
    proof = sum(components.values())
    committed = n + rho*hints + eta
    # Per-party evaluation at dD+1 points suffices for both broadcasts.
    # Each gamma' weight multiplies an inhomogeneous sparse row once, then packed public
    # coefficients at a party multiply the corresponding witness share.
    blocks2 = ceildiv(g[1],s)
    blocks7 = ceildiv(g[-1],s) if d == 7 else 0
    census = CENSUS[suite][encoding]
    pad = n*s - sum(g)
    m = census["linear_wiring_equations"] + pad
    m1 = blocks2 + blocks7
    return dict(profile=dict(stage_target_bits=target,digest_B=digest_B,N=N,s=s,ell=ell,tau=tau,rho=rho,eta=eta,degree=d,
                witness_packs=n,hint_packs_per_mpc=hints,leaf_words=committed,
                max_frontier_hashes_per_tree=paths),components_B=components,
                proof_B=proof,proof_plus_fixed_frame_B=proof+(21060 if suite=="SLG1" else 3841),
                work=dict(padding_zero_rows=pad,committed_leaf_words=tau*N*committed,
                leaf_share_payload_B=tau*N*committed*8,leaf_hash_calls=tau*N,
                internal_hash_calls=tau*(N-1),opened_leaf_words=tau*ell*committed,
                prover_degree_matrix_macs=tau*eta*(n+rho*hints)*(D+1),
                verifier_degree_matrix_macs=tau*eta*(n+rho*hints)*ell,
                verifier_linear_dot_macs=tau*rho*n*ell,
                verifier_public_pack_eval_macs_schoolbook=tau*rho*n*ell*s,
                verifier_quadratic_block_evaluations=tau*rho*ell*blocks2,
                verifier_degree7_block_evaluations=tau*rho*ell*blocks7,
                linear_constraint_rows=m,nonlinear_block_polynomials=m1,
                shared_gamma_random_words=tau*(eta*(n+rho*hints)+rho*(m+m1)),
                public_sparse_row_weight_macs=tau*rho*(census["global_matrix_private_nnz"]+pad),
                public_rhs_projection_terms=census["known_rhs_affine_nnz"],
                public_rhs_batch_macs=tau*rho*census["rows_with_structural_public_or_constant_rhs"],
                prover_broadcast_points_upper_per_tree=d*D+1))
