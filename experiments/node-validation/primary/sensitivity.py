"""Stress two search restrictions over the guarded native-dimension scenario."""
import json
import math
from budget import schedule, sample


def summary(candidate):
    if not candidate:
        return None
    sample(candidate)
    return {k:candidate[k] for k in ('expected_body_bytes', 'sample_complete_body_bytes',
            'interactive_error_bits','subfield_guard_error_bits','raw_rs_bytes_all_oracles',
            'ratio','terminal_main_log2','stages')}


def main():
    rows = []
    sec = 365*86400
    avg = 100_000_000/sec
    burst = 10*avg
    remaining = (100_000_000-600*burst)/(sec-600)
    required_service = (burst*600+remaining*3600)/4200
    blocks = math.ceil(100_000_000/96)
    per_body_overhead = 68 + blocks/100_000_000*(228+6*72+72+12)
    body_threshold = 16_000_000/(8*required_service)-per_body_overhead
    for bits,h in ((128,4),(192,5),(256,7)):
        minimal = None
        bounded = None
        count = 0
        net_pass = 0
        assembled_pass = 0
        best_net = None
        best_peak = math.inf
        for k in range(1,7):
            for term in range(2,13):
                for exponent in range(1,19):
                    c = schedule(2**20,k,term,2**exponent,bits,'johnson',296448,h)
                    if c is None:
                        continue
                    count += 1
                    stages = c['stages']
                    first = stages[0]
                    symbols_peak = max(s['raw_rs_bytes']//s['trees'] for s in stages)
                    # Retain each stage in isolation, including its salts and all Merkle nodes.
                    modeled_peak = max(s['raw_rs_bytes'] + s['outer_merkle_tree_nodes_bytes']
                                       + s['trees']*64*s['n'] for s in stages)
                    if c['expected_body_bytes'] <= body_threshold:
                        net_pass += 1
                        if modeled_peak <= 4*2**30:
                            assembled_pass += 1
                        if modeled_peak < best_peak or (modeled_peak == best_peak and
                                c['expected_body_bytes'] < best_net['body']):
                            best_peak = modeled_peak
                            best_net = dict(body=c['expected_body_bytes'], k=first['k'], width=first['width'],
                                n=first['n'], dimension=first['d'], q=first['q'],
                                largest_single_oracle_symbols_bytes=symbols_peak,
                                largest_assembled_stage_bytes=modeled_peak,
                                first_stage_row_fft_bytes=40*first['n'],
                                twiddle_free_one_row_fft_butterflies=first['n']//2*(first['n'].bit_length()-1),
                                raw_rs_bytes_all=c['raw_rs_bytes_all_oracles'], schedule=c)
                    if minimal is None or c['expected_body_bytes'] < minimal['expected_body_bytes']:
                        minimal = c
                    if c['raw_rs_bytes_all_oracles'] <= 16*2**30 and (bounded is None or
                            c['expected_body_bytes'] < bounded['expected_body_bytes']):
                        bounded = c
        if best_net:
            sample(best_net['schedule'])
        rows.append(dict(bits=bits, admissible=count, limited=summary(bounded), minimum=summary(minimal),
            expected_body_limit=body_threshold, profile_satisfying_block_link=net_pass,
            profile_satisfying_link_and_4GiB_stage=assembled_pass, least_assembled_for_link=best_net))
    print(json.dumps(rows, indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
