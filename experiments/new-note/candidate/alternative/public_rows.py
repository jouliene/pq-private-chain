"""Evaluate the proposed public-input row term over the qp-plonky2 quartic field."""
import json
import statistics
import time

P = 2**64 - 2**32 + 1
G32 = 7277203076849721926
ZERO = (0, 0, 0, 0)
ONE = (1, 0, 0, 0)
ROWS = 49

def add(x, y):
    return tuple((a+b) % P for a, b in zip(x, y))

def sub(x, y):
    return tuple((a-b) % P for a, b in zip(x, y))

def scale(x, c):
    return tuple(a*c % P for a in x)

def mul(x, y):
    # The quotient is F_p[u]/(u^4 - 7).
    c = [0]*7
    for i, a in enumerate(x):
        for j, b in enumerate(y):
            c[i+j] += a*b
    for i in range(4, 7):
        c[i-4] += 7*c[i]
    return tuple(v % P for v in c[:4])

def power(x, k):
    y = ONE
    while k:
        if k % 2:
            y = mul(y,x)
        x = mul(x,x)
        k //= 2
    return y

def batch_inverse(values):
    if not values or ZERO in values:
        raise ValueError("empty list or zero denominator")
    prefix = [values[0]]
    for x in values[1:]:
        prefix.append(mul(prefix[-1], x))
    inv = power(prefix[-1], P**4-2)
    result = [ZERO] * len(values)
    for i in range(len(values)-1, 0, -1):
        result[i] = mul(inv, prefix[i-1])
        inv = mul(inv, values[i])
    result[0] = inv
    return result

def roots(log_n):
    n = 1 << log_n
    omega = pow(G32, 1 << (32-log_n), P)
    assert pow(omega,n,P)==1 and pow(omega,n//2,P)!=1
    return [pow(omega,i,P) for i in range(ROWS)]

def barycentric(log_n, h, s, z, wire, z_to_n=None):
    n = 1 << log_n
    zn = power(z, n) if z_to_n is None else z_to_n
    if zn == ONE:
        raise ValueError("opening point on trace subgroup")
    inverse = batch_inverse([sub(z,(x,0,0,0)) for x in h])
    qsum = psum = ZERO
    n_inv = pow(n,-1,P)
    for hi, val, inv in zip(h,s,inverse):
        qi = scale(inv, (hi*n_inv) % P)
        qsum = add(qsum, qi)
        psum = add(psum, scale(qi,val))
    # Reuse z^n-1 from the ordinary PLONK verifier.
    return mul(sub(zn,ONE), sub(mul(qsum,wire),psum))

def inverse_dft(log_n, h, values):
    # Independent coefficient route for trace evaluations, zeros off the chosen rows.
    n = 1 << log_n
    coeffs = [0] * n
    for hi, val in zip(h,values):
        step = pow(hi,-1,P)
        term = val*pow(n,-1,P) % P
        for i in range(n):
            coeffs[i] += term
            term = term*step % P
    return [c % P for c in coeffs]

def horner(cs, z):
    acc = ZERO
    for c in reversed(cs):
        acc = add(mul(acc,z),(c,0,0,0))
    return acc

def main():
    s = [(i+1)**7 % P for i in range(ROWS)]
    z = (19,7,41,8)
    wire = (8,4,17,3)
    checks = {}
    for log_n in (6,14):
        h = roots(log_n)
        coeff_q = inverse_dft(log_n,h,[1]*ROWS)
        coeff_p = inverse_dft(log_n,h,s)
        pts = [z, (31,0,0,0), (3,8,11,29)] if log_n==6 else [z]
        for point in pts:
            direct = sub(mul(horner(coeff_q,point),wire), horner(coeff_p,point))
            assert barycentric(log_n,h,s,point,wire) == direct
        if log_n==6:
            omega = h[1]
            for i in range(64):
                point = (pow(omega,i,P),0,0,0)
                assert horner(coeff_q,point)==(int(i<ROWS),0,0,0)
                assert horner(coeff_p,point)==((s[i] if i<ROWS else 0),0,0,0)
        try:
            barycentric(log_n,h,s,(h[0],0,0,0),wire)
        except ValueError:
            pass
        else:
            raise AssertionError("subgroup opening must be rejected")
        checks[str(1<<log_n)] = {"off_domain_checks":len(pts),
                                "on_domain_oracle_checks":64 if log_n==6 else 0}
    h = roots(14)
    zn = power(z,1<<14)
    base = barycentric(14,h,s,z,wire,zn)
    for i in range(ROWS):
        changed = s.copy()
        changed[i] = (changed[i]+1) % P
        assert barycentric(14,h,changed,z,wire,zn) != base
    times = []
    for _ in range(11):
        start = time.perf_counter_ns()
        assert barycentric(14,h,s,z,wire,zn)==base
        times.append((time.perf_counter_ns()-start)/1e6)
    print(json.dumps({"log_n":14,"public_rows":ROWS, "quartic_modulus":"u^4-7",
                      "trace_omega":h[1],"full_domain_point":z,"full_domain_term":base,
                      "checks":checks,"changed_single_words":49,
                      "python_component_samples_ms":times,
                      "median_python_component_ms":statistics.median(times)}, indent=2))

if __name__ == "__main__":
    main()
