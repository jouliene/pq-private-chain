#!/usr/bin/env python3
"""Paper 10.2 complete wire-size projection for a finite family of verifier-owned profiles."""

import argparse
from hashlib import sha3_512
import json
import math

P = 2**64-2**32+1
FIELD = P**5
F = 40
H = 64
SALT = 64
INSTANCE = 528
RECEIPTS = 4328
FRAME = 20
ETA = 0.0125


def ceildiv(a, b):
    return -(-a//b)


def power2(n):
    return 1 << (n-1).bit_length()


def auth_shape(length, width, q):
    def occupied(n):
        return 1. if n == 1 else -n*math.expm1(q*math.log1p(-1/n))
    rows = occupied(length)
    frontier = 0
    n = length
    while n > 1:
        frontier += 2*occupied(n//2)-occupied(n)
        n //= 2
    return rows, frontier


def geometry(main, aux, fold, ratio, limit, mode):
    p = 2 if fold else 0
    for q in range(1, 2049):
        d = main + aux + p + q + 1
        n = power2(d)*ratio
        if n > 2**32:
            return None
        r = (d-1)/n
        if mode == 'third-distance':
            D = (n-d)//3
            delta = D/n
            list_size = 1
            mca = D+1
        else:
            delta = math.nextafter(1-math.sqrt((d+1)/n)-ETA, 0.)
            if delta <= 0:
                continue
            m = max(3, math.ceil(1.000000000001*math.sqrt(r)/(1-math.sqrt(r)-delta)))+0.5
            mca = 1.000000000001*((2*m**5+3*m*delta*r)*n/(3*r**1.5)+m/math.sqrt(r))
            list_size = math.ceil(1.000000000001*(1-r)/((1-delta)**2-r))
        miss = (1-delta)**q
        if miss <= limit:
            return dict(main=main, aux=aux, k=fold, width=2**fold, p=p, seeds=q+1, q=q,
                        d=d, n=n, delta=delta, miss=miss, list=list_size, mca=mca)
    return None


def schedule(ell, k, term_log, ratio, bits, mode, guard_words=0, h=0):
    l = ell.bit_length()-1
    folds = [k]*((l-term_log)//k)
    if (l-term_log)%k:
        folds += [(l-term_log)%k]
    if not folds:
        return None
    folds += [0]
    row_rounds = l+1
    # Rearrange [w, inner masks, outer masks, zeros] into main/aux row blocks.
    aux = ceildiv(3 + 5*(row_rounds+1) + h, 2**folds[0])
    main = ell//2**folds[0]
    stages = []
    for j, fold in enumerate(folds):
        stage_ratio = ratio[j] if isinstance(ratio, (list,tuple)) else ratio
        stage = geometry(main, aux, fold, stage_ratio, 2.**(-bits-1)/len(folds), mode)
        if stage is None:
            return None
        stages.append(stage)
        if fold:
            next_width = 2**folds[j+1]
            next_aux = ceildiv(aux + stage['p'] + stage['seeds'] + 1, next_width)
            stage['ood_pad'] = next_aux*next_width - aux - stage['p'] - stage['seeds']
            main, aux = main//next_width, next_aux
    outer_fields = 6*row_rounds+4
    # PIL bounds use degree per variable = 1 at zerocheck, <=5 each round.
    algebraic = stages[0]['list'] * ((row_rounds+1)/FIELD
                + 5*(row_rounds-1)/FIELD + 5/(FIELD-2) + (3+h)/FIELD)
    guard_error = stages[0]["list"]*(guard_words/P)**h if h else 0
    algebraic += guard_error
    query = 0
    total = FRAME + INSTANCE + RECEIPTS + outer_fields*F + 8*h
    work_bytes = 0
    for j, s in enumerate(stages):
        k, width, n, q, mca, L = (s[a] for a in ('k','width','n','q','mca','list'))
        query += s['miss']
        if k:
            next_L = stages[j+1]['list']
            # 6.4, 9.9; interleaving amplification safe also for Appendix A.
            algebraic += (L + sum(2**i*mca+2*L for i in range(k))
                          + next_L**2/2*max(s['d']-1, FIELD/(FIELD-1))
                          + next_L*(1+q))/FIELD
            fields = 3*k+2  # mask sum, three coefficients/fold, one private OOD answer
            trees = 1
        else:
            algebraic += (mca+L)/FIELD
            fields = 1+s['d']  # blind target, blinded folded main+aux+seed
            trees = 2
        rows, frontier = auth_shape(n, width, q)
        breakdown = dict(roots=trees*H, messages=fields*F, values=trees*rows*width*F,
                         salts=trees*rows*SALT, frontier=trees*frontier*H)
        s['expected_bytes'] = breakdown
        s['trees'] = trees
        s['raw_rs_bytes'] = trees*n*width*F
        s['outer_merkle_tree_nodes_bytes'] = trees*(2*n-1)*H
        total += sum(breakdown.values())
        work_bytes += s['raw_rs_bytes']
    if query + algebraic >= 2**-bits:
        return None
    return dict(expected_body_bytes=round(total, 3), raw_rs_bytes_all_oracles=work_bytes,
                expected_auth_bytes=round(sum(s['expected_bytes']['frontier'] for s in stages),3),
                expected_message_value_bytes=round(sum(s['expected_bytes']['values'] for s in stages),3),
                interactive_error_bits=-math.log2(query+algebraic), algebraic_bits=-math.log2(algebraic),
                query_bits=-math.log2(query), query_target_bits=bits, proximity=mode,
                outer_rounds=row_rounds, outer_direct_bytes=outer_fields*F + 8*h,
                subfield_check_rows=h, subfield_guard_error_bits=(-math.log2(guard_error) if h else None), initial_main=ell,
                direct_wire={'frame':FRAME, 'statement':INSTANCE, 'encrypted_receipts':RECEIPTS},
                ratio=ratio, terminal_main_log2=term_log, stages=stages)


def sample(schedule):
    """Fixed representative query tape, no field elements sampled or payment proven."""
    measured = FRAME+INSTANCE+RECEIPTS+schedule['outer_direct_bytes']
    for j,s in enumerate(schedule['stages']):
        n = s['n']
        selected = {int.from_bytes(sha3_512(f'cfw-schedule01/{j}/{i}'.encode()).digest(),'little') % n
                    for i in range(s['q'])}
        rows = len(selected)
        frontier = 0
        while n > 1:
            frontier += sum((i^1) not in selected for i in selected)
            selected = {i//2 for i in selected}
            n //= 2
        direct = s['expected_bytes']['roots']+s['expected_bytes']['messages']
        value = s['trees']*(rows*(s['width']*F+SALT)+frontier*H)+direct
        s['sample'] = dict(distinct=rows, frontier_per_tree=frontier, stage_bytes=value)
        measured += value
    schedule['sample_complete_body_bytes'] = measured


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rows', type=int, required=True)
    parser.add_argument('--private', type=int, required=True)
    parser.add_argument('--public', type=int, required=True, help='excludes one constant wire')
    parser.add_argument('--base-inputs', type=int, default=0)
    parser.add_argument('--guard-words', type=int, default=0)
    parser.add_argument('--guard-checks', type=int, default=0)
    parser.add_argument('--bits', type=int, default=128, choices=(128,192,256))
    parser.add_argument('--fold', type=int, default=4)
    parser.add_argument('--terminal-log', type=int, default=8)
    parser.add_argument('--ratios', help='print a single Johnson profile at the specified comma-separated ratios')
    args = parser.parse_args()
    if min(args.rows, args.private) < 1 or min(args.base_inputs, args.public) < 0 or args.base_inputs > args.private:
        parser.error('invalid dimensions')
    if (args.guard_words < 0 or args.guard_words > args.private or args.guard_checks < 0
            or bool(args.guard_words) != bool(args.guard_checks)
            or (args.base_inputs and args.guard_words)):
        parser.error('choose explicit guards or positive batched word/check counts')
    rows, private = args.rows+args.base_inputs*64, args.private+args.base_inputs*63
    ell = power2(max(2, private, args.public+1, ceildiv(rows, 2)))
    if args.ratios:
        try:
            ratios = tuple(map(int,args.ratios.split(',')))
        except ValueError:
            parser.error('ratios must be integers')
        l = ell.bit_length()-1
        if (args.fold < 1 or not 0 <= args.terminal_log < l
                or len(ratios) != ceildiv(l-args.terminal_log, args.fold)+1
                or any(r<2 or r & (r-1) for r in ratios)):
            parser.error('ratios must match all folds and be powers of two >= 2')
        candidate = schedule(ell, args.fold, args.terminal_log, ratios, args.bits, 'johnson',
                             args.guard_words, args.guard_checks)
        if candidate is None:
            parser.error('this schedule fails the requested field/domain/interactive budget')
        sample(candidate)
        print(json.dumps(candidate,indent=2,sort_keys=True))
        return
    inputs = {k:v for k,v in vars(args).items() if k not in ('fold','terminal_log','ratios')}
    out = dict(inputs=inputs, effective_rows=rows, effective_private=private, padded_witness=ell,
               paper_square_rows=2*ell, field_order=str(FIELD), johnson_slack=ETA,
               field_and_hash_bytes=[F,H], field_order_log2=math.log2(FIELD), zero_grinding=True,
               hypotheses={}, screen_bytes=175126)
    for mode in ('third-distance','johnson'):
        best, limited, tried, admitted = None, None, 0, 0
        for k in range(1,6):
            for term in range(3, min(13,ell.bit_length()-2)+1,2):
                for ratio in (2,4,8,16,32,64):
                    tried += 1
                    cand = schedule(ell, k, term, ratio, args.bits, mode, args.guard_words, args.guard_checks)
                    if cand is None:
                        continue
                    admitted += 1
                    if best is None or cand['expected_body_bytes'] < best['expected_body_bytes']:
                        best = cand
                    if cand['raw_rs_bytes_all_oracles'] <= 16*2**30 and (limited is None or
                        cand['expected_body_bytes'] < limited['expected_body_bytes']):
                        limited = cand
        for order in (best, limited):
            if order:
                sample(order)
        out['hypotheses'][mode] = dict(profiles_considered=tried, numerically_admitted=admitted,
                                      minimum_expected_body=best, rs_oracles_capped_16_GiB=limited)
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
