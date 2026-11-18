"""Dynamic program over independent RS domain sizes, minimizing expected wire cost under a stage cap."""
from functools import lru_cache
import json, math
from budget import geometry, auth_shape, schedule, ceildiv, sample, F, H, SALT


@lru_cache(maxsize=None)
def choices(main, aux, fold, nstages, bits):
    result = []
    for exponent in range(1,23):
        stage = geometry(main,aux,fold,2**exponent,2.**(-bits-1)/nstages,'johnson')
        if stage is None:
            break
        n,k,q = stage['n'], stage['k'], stage['q']
        width,trees = 2**k, (1 if k else 2)
        peak = trees*(n*width*F+(2*n-1)*H+SALT*n)
        rows,frontier = auth_shape(n,width,q)
        direct = (3*k+2 if k else 1+stage['d'])*F
        size = trees*(H+rows*(SALT+width*F)+frontier*H)+direct
        result.append((peak,size,2**exponent,q))
    return result


def optimal(l, k, term, bits,h, cap):
    folds = [k]*((l-term)//k)
    if (l-term)%k:
        folds.append((l-term)%k)
    folds.append(0)
    main = 2**(l-folds[0])
    # first auxiliary holds outer terminal, degree-six masks and independent base masks
    first_aux = ceildiv(3+5*(l+2)+h,2**folds[0])
    states = {first_aux: (0, [])}
    for j,fold in enumerate(folds):
        states_next = {}
        last = j==len(folds)-1
        width = 1 if last else 2**folds[j+1]
        for aux,(prior,ratios) in states.items():
            for storage, size, ratio, q in choices(main,aux,fold,len(folds),bits):
                if storage>cap:
                    continue
                key = 0 if last else ceildiv(aux+2+q+1+1,width)
                if key not in states_next or prior+size<states_next[key][0]:
                    states_next[key] = (prior+size, ratios+[ratio])
        if not states_next:
            return None
        main //= width
        states = states_next
    return schedule(2**l,k,term,states[0][1],bits,'johnson',296448,h)


def resident(s):
    return s['raw_rs_bytes']+s['outer_merkle_tree_nodes_bytes']+s['trees']*s['n']*SALT


def main():
    out = []
    for bits,h in ((128,4),(192,5),(256,7)):
        for cap_in_mib in (512,768,1024,1536,2048,3072,4096,8192,16384):
            best = None
            for k in (2,3,4,5,6):
                for term in range(3,12):
                    c = optimal(20,k,term,bits,h,cap_in_mib*2**20)
                    if c and (not best or c['expected_body_bytes']<best['expected_body_bytes']):
                        best = c
            if not best:
                continue
            stages = best['stages']
            sample(best)
            out.append(dict(bits=bits, guard_checks=h, cap_mib=cap_in_mib,
                            body=best['expected_body_bytes'], sample=best['sample_complete_body_bytes'],
                            k=[s['k'] for s in stages], n=[s['n'] for s in stages], ratio=best['ratio'],
                            q=[s['q'] for s in stages], conservative_resident_stages=[resident(s) for s in stages],
                            all_stages_in_memory=sum(resident(s) for s in stages),
                            all_rs_bytes=best['raw_rs_bytes_all_oracles'],
                            all_nlogn_butterflies=sum(s['trees']*s['width']*s['n']//2*int(math.log2(s['n'])) for s in stages),
                            row_fft_bytes=40*stages[0]['n'], interactive_bits=best['interactive_error_bits']))
    print(json.dumps(out, indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
