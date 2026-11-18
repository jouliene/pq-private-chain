#!/usr/bin/env python3
"""CFW 12.3, 6.4 (one inner fold), 9.9 and 7.2 on an actual masked EF5 relation."""

import argparse
from itertools import product
from math import prod
from pathlib import Path
import json
import secrets

from field import K, P, dot, eqweight, interpolate, poly, uniform
from transcript import Tape, open_tree, tree

Q = 3
SEEDS = Q + 1
N = 64
ROW = 16
BASE_CHECKS = 4
# Last Boolean coordinate selects the private half. Row indices similarly use little endian bits.
CUBE = [(K(i % 2), K(i // 2)) for i in range(4)]
# Three equalities on z = [1, public_sum, x, y], followed by one zero padding row.
A = [[0,0,1,0], [0,0,0,1], [0,0,1,1], [0,0,0,0]]
B = [[0,0,1,0], [0,0,0,1], [1,0,0,0], [0,0,0,0]]
C = [[0,0,1,0], [0,0,0,1], [0,1,0,0], [0,0,0,0]]
MATRICES = (A, B, C)
# A separate circuit checks x+y=b and (x+y)^2=b, admitting nonbase x at b=1.
Z = [0,0,0,0]
LINE = [0,0,1,1]
PUBLIC = [0,1,0,0]
GUARD_MATRICES = ([LINE, LINE, Z, Z], [[1,0,0,0], LINE, Z, Z], [PUBLIC, PUBLIC, Z, Z])


def powers(x, size):
    out = [K(1)]
    for _ in range(1, size):
        out.append(out[-1]*x)
    return out


def randoms(count):
    return [uniform() for _ in range(count)]


def mask_weights(xs, d):
    pw = [K(1)] + [sum((x**e for x in xs), K()) for e in range(1, d-1)]
    return [prod(xs[i:], start=K(1))*v for i in range(len(xs)+1) for v in pw]


def matrix_row(matrix, point):
    return [dot([eqweight(point, b) for b in CUBE], [row[i] for row in matrix])
            for i in range(4)]


def fold(rows, x):
    return [l+(r-l)*x for l, r in zip(*rows, strict=True)]


def send_poly(tape, label, d, evaluate, target):
    # Source 12.3 sends all d coefficients (no linear-coefficient omission here).
    coeffs = tape.elements(label, d, interpolate([evaluate(K(i)) for i in range(d)])
                           if tape.proving else None)
    if coeffs[0]+sum(coeffs, K()) != target:
        raise ValueError('inconsistent sumcheck: '+label)
    return coeffs


def oracle(label, coefficient_rows):
    columns = [[poly(row, K(j+1)) for row in coefficient_rows] for j in range(N)]
    return tree(label, columns)


def root_message(tape, label, instance):
    return tape.message('root/'+label, 64, instance[1][-1][0] if instance else None)


def execute(tape, public_sum, witness=None, guarded=False):
    matrices = GUARD_MATRICES if guarded else MATRICES
    h = BASE_CHECKS if guarded else 0
    if tape.proving:
        z = [K(1), K(public_sum), *map(K, witness)]
        inner_masks, outer_masks = randoms(3), randoms(15)
        blinds = [K(secrets.randbelow(P)) for _ in range(h)]
        msg = [*z[2:], *inner_masks, *outer_masks, *blinds] + [K()]*(12-h)
        rows = [msg[:ROW], msg[ROW:]]
        sigma = randoms(4)
        masks = [[sigma[0]*b+sigma[2], sigma[1]*b+sigma[3]] for b in (0, 1)]
        seeds = [randoms(SEEDS), randoms(SEEDS)]
        src = oracle('src', [s+m+row for s,m,row in zip(seeds, masks, rows)])
        mask_sum = sum((dot(mask_weights(b, 6), outer_masks) for b in CUBE), K())
    else:
        src = None
    root0 = root_message(tape, 'src', src)
    target = tape.elements('outer/mask-sum', 1, [mask_sum] if src else None)[0]
    # The blinded base traces are sampled after commitment, before outer and combining coins.
    base_forms, masked_base = [], []
    # One verifier challenge vector, with no prover message between its components.
    # The product bound is a single round transition over the complete vector.
    base_challenges = [K(tape.sample('subfield/challenge'+str(j), P)) for j in range(h)]
    for j,b in enumerate(base_challenges):
        weights = powers(b, 3)[1:]
        value = (dot(weights, z[2:]) + blinds[j]) if src else K()
        if src and any(value[1:]):
            raise ValueError('nonbase masked contraction')
        raw = tape.message('subfield/y'+str(j), 8, value[0].to_bytes(8, 'little') if src else None)
        y = int.from_bytes(raw, 'little')
        if y >= P:
            raise ValueError('noncanonical masked base field')
        masked_base.append(K(y))
        base_forms.append(weights)
    eps = tape.challenge('outer/epsilon')
    beta = [tape.challenge('outer/beta'+str(i)) for i in range(2)]

    def terminal_values(pt):
        vanishing = pt[-1]**2-pt[-1]
        return [dot(matrix_row(m, pt), z) + mask*vanishing for m, mask in zip(matrices, inner_masks)]

    def H(pt):
        a, b, c = terminal_values(pt)
        return dot(mask_weights(pt, 6), outer_masks) + eps*(a*b-c)*eqweight(beta, pt)

    alpha = []
    for j in range(2):
        def partial(x):
            return sum((H(alpha+[x]+list(s)) for s in product((K(), K(1)), repeat=1-j)), K())
        coeffs = send_poly(tape, 'outer/h'+str(j), 6, partial, target)
        x = tape.challenge('outer/alpha'+str(j), (K(), K(1)) if j == 1 else ())
        alpha.append(x)
        target = poly(coeffs, x)
    v = tape.elements('outer/terminals', 3, terminal_values(alpha) if src else None)
    nu = powers(tape.challenge('outer/rho'), 4+h)
    mr = [matrix_row(m, alpha) for m in matrices]
    public = [dot(r[:2], [K(1), K(public_sum)]) for r in mr]
    form = [sum((n*r[j] for n, r in zip(nu[:3], mr)), K()) for j in (2,3)]
    form += [n*(alpha[-1]**2-alpha[-1]) for n in nu[:3]]
    form += [nu[3]*u for u in mask_weights(alpha, 6)] + [K()]*12
    target = dot(nu[:3], [a-b for a,b in zip(v, public)]) + nu[3]*(
        target-eps*(v[0]*v[1]-v[2])*eqweight(beta, alpha))
    for j, (weights, y) in enumerate(zip(base_forms, masked_base)):
        for i, weight in enumerate(weights):
            form[i] += nu[4+j]*weight
        form[20+j] = nu[4+j]
        target += nu[4+j]*y
    # 6.4 binds this dense, generally non-point-evaluation form to the first oracle.
    form_rows = [form[:ROW], form[ROW:]]
    inner_sum = masks[0][0]+masks[1][0]+masks[1][1] if src else None
    mu_tilde = tape.elements('fold/mask-sum', 1, [inner_sum] if src else None)[0]
    e = tape.challenge('fold/epsilon')

    def fold_poly(x):
        m = fold(masks, x)
        return m[0]+x*m[1]+e*dot(fold(form_rows, x), fold(rows, x))

    c = send_poly(tape, 'fold/h', 3, fold_poly, mu_tilde+target*e)
    g = tape.challenge('fold/gamma')
    target = poly(c, g)
    folded_form = [e*x for x in fold(form_rows, g)] + [K(1), g] + [K()]*(SEEDS+1)
    if src:
        next_msg = fold(rows, g) + fold(masks, g) + fold(seeds, g) + randoms(1)
        seed1 = randoms(SEEDS)
        nxt = oracle('next', [seed1+next_msg])
    else:
        nxt = None
    root1 = root_message(tape, 'next', nxt)
    # Lemma 9.4 over a field: the single pad coefficient must have full row rank.
    ood = powers(tape.challenge('switch/ood'), len(folded_form)-1)
    ood += [tape.challenge('switch/pad-weight', (K(),))]
    answer = tape.elements('switch/answer', 1, [dot(ood, next_msg)] if src else None)[0]
    indices = [tape.sample('switch/index'+str(i), N) for i in range(Q)]
    batch = powers(tape.challenge('switch/batch'), Q+2)
    opened = open_tree(tape, 'src', N, 2, root0, indices, src)
    form = [l+r*batch[1] for l,r in zip(folded_form, ood, strict=True)]
    target += answer*batch[1]
    for i, (idx, pair) in enumerate(zip(indices, opened)):
        column = powers(K(idx+1), SEEDS+2+ROW)
        # next_msg is ordered [main, fold-masks, fold-seed, one new OOD pad].
        gen = column[SEEDS+2:]+column[SEEDS:SEEDS+2]+column[:SEEDS]+[K()]
        form = [x+batch[i+2]*y for x,y in zip(form, gen, strict=True)]
        target += batch[i+2]*(pair[0]+g*(pair[1]-pair[0]))
    if nxt:
        blind, blind_seed = randoms(len(form)), randoms(SEEDS)
        fresh = oracle('fresh', [blind_seed+blind])
    else:
        fresh = None
    root2 = root_message(tape, 'fresh', fresh)
    blind_target = tape.elements('base/mask-target', 1, [dot(form, blind)] if nxt else None)[0]
    delta = tape.challenge('base/gamma')
    total = len(form)+SEEDS
    combined = tape.elements('base/blinded', total,
                             [a+delta*b for a,b in zip(blind_seed+blind, seed1+next_msg)]
                             if nxt else None)
    if dot(form, combined[SEEDS:]) != blind_target+delta*target:
        raise ValueError('base linear form')
    indices = [tape.sample('base/index'+str(i), N) for i in range(Q)]
    left = open_tree(tape, 'next', N, 1, root1, indices, nxt)
    right = open_tree(tape, 'fresh', N, 1, root2, indices, fresh)
    for i, l, r in zip(indices, left, right):
        if poly(combined, K(i+1)) != r[0]+delta*l[0]:
            raise ValueError('base spot check')
    if tape.at != len(tape.proof):
        raise ValueError('trailing proof')


def instance(value, guarded=False):
    if value not in ((0, 1) if guarded else (0, 1, 2)):
        raise ValueError('public sum')
    return json.dumps(['CFW01', GUARD_MATRICES if guarded else MATRICES, guarded, value, Q, SEEDS, ROW, N, 6, 3, P, 3],
                      separators=(',', ':')).encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prove','verify'))
    parser.add_argument('path', type=Path)
    parser.add_argument('--sum', type=int, default=1)
    parser.add_argument('--controls', action='store_true')
    parser.add_argument('--guarded', action='store_true')
    args = parser.parse_args()
    try:
        public = instance(args.sum, args.guarded)
        if args.mode == 'prove':
            bit = secrets.randbelow(2)
            witness = (bit, 1-bit) if args.sum == 1 else (int(args.sum==2),)*2
            tape = Tape(public)
            execute(tape, args.sum, witness, args.guarded)
            with args.path.open('xb') as file:
                file.write(tape.proof)
        else:
            tape = Tape(public, args.path.read_bytes())
            execute(tape, args.sum, guarded=args.guarded)
        output = {'mode':args.mode, 'accept':True, 'proof_bytes':tape.at}
        if args.controls:
            if args.mode != 'verify':
                raise ValueError('controls require public verification')
            controls = []
            for name, (start, length) in tape.sections.items():
                if length == 0:
                    continue
                edited = bytearray(tape.proof)
                edited[start] ^= 1
                try:
                    execute(Tape(public, edited), args.sum, guarded=args.guarded)
                except ValueError:
                    controls.append(name)
                else:
                    raise RuntimeError('accepted corruption: '+name)
            for name, body, statement in [('trailing', tape.proof+b'!', args.sum),
                                          ('truncated', tape.proof[:-1], args.sum),
                                          ('wrong-public', tape.proof, (args.sum+1)%(2 if args.guarded else 3))]:
                try:
                    execute(Tape(instance(statement, args.guarded), body), statement, guarded=args.guarded)
                except ValueError:
                    controls.append(name)
                else:
                    raise RuntimeError('accepted: '+name)
            output.update(rejected=controls, sections=tape.sections)
        print(json.dumps(output, sort_keys=True))
    except ValueError as e:
        print(json.dumps({'accept':False,'reason':str(e)}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
