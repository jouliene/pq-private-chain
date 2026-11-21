"""Cross-check archive-side observations and exact framing against the public block capture."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys


FIELDS = {'status': {'op'}, 'selected': {'op','start','limit'}, 'block': {'op','id'}}
PHASES = ('gap', 'resume', 'extend', 'deep', 'final_extend')


def audit(public, metrics, archive1, archive2):
    intervals = json.loads(metrics.read_bytes())['traces']
    public_sizes = {p.stem:p.stat().st_size for p in (public / 'blocks').glob('*.bin')}
    scenario = json.loads((public / 'SCENARIO.json').read_bytes())
    outcome = json.loads((public / 'OUTCOME.json').read_bytes())
    genesis = scenario['genesis']
    public_sizes[genesis] = 0
    def branch(tip):
        ids = []
        while tip != genesis:
            raw = (public / 'blocks' / (tip + '.bin')).read_bytes()
            ids.append(tip)
            tip = raw[41:73].hex()
        return ids[::-1]

    initial = branch(scenario['tips']['initial']['tip'])
    old = branch(outcome['initial_settled'])
    alternate = branch(outcome['reorganized'])
    final = branch(outcome['final'])
    gap = initial[11]
    expected = dict(gap=initial[:11], resume=initial[11:], extend=old[len(initial):],
                    deep=alternate, final_extend=final[len(alternate):])
    served = {phase:set() for phase in PHASES}
    totals = {}
    outcomes = {}
    for peer, file in (('archive1',archive1), ('archive2',archive2)):
        rows = [json.loads(line) for line in file.read_bytes().splitlines()]
        for row in rows:
            query = row['request']
            op = query['op']
            assert FIELDS[op] == set(query) == set(row['field_names'])
            assert row['source_ip'] == '127.0.0.1'
            # Every byte in the request is accounted for by common public metadata.
            metadata = json.dumps(query, separators=(',', ':')).encode()
            assert row['request_B'] == len(metadata) + 8
            if op == 'block':
                assert query['id'] in public_sizes
                if row['success']:
                    assert row['body_B'] == public_sizes[query['id']]
                    success_metadata = b'{"ok":true,"result":{}}'
                    assert row['reply_B'] == 8 + len(success_metadata) + row['body_B']
                else:
                    assert row['body_B'] == 0
            else:
                assert row['body_B'] == 0
                if op == 'selected':
                    assert type(query['start']) is int and query['start'] >= 0
                    assert type(query['limit']) is int and 1 <= query['limit'] <= 128
            assert row['reply_B'] > row['body_B']
        last = 0
        totals[peer] = {}
        for phase in PHASES:
            start,end = intervals[phase][peer]
            assert last <= start <= end <= len(rows)
            last = end
            selected = rows[start:end]
            served[phase].update(r['request']['id'] for r in selected
                                 if r['success'] and r['request']['op'] == 'block')
            result = {k:sum(r[k] for r in selected) for k in ('request_B','reply_B','body_B')}
            result.update(operations=dict(Counter(row['request']['op'] for row in selected)),
                          failures=sum(not r['success'] for r in selected))
            totals[peer][phase] = result
            outcomes[peer,phase] = [r['success'] for r in selected if r['request'].get('id') == gap]
        assert False in outcomes[peer,'gap'] and not any(outcomes[peer,'gap'])
    assert True in outcomes['archive2','resume'] and not any(outcomes['archive1','resume'])
    assert all(served[phase] == set(expected[phase]) for phase in PHASES), 'unexpected public body coverage'
    return dict(phase_framed_observations=totals, withheld_height=12, refused_by_distinct_archives=2,
                second_archive_served_exact_block_bytes=True,
                unique_successful_bodies={p:len(v) for p,v in served.items()}, request_body_B=0, source_address_scope='loopback',
                observed_request_fields={op:sorted(fields) for op,fields in FIELDS.items()})


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Python assertions must be enabled')
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('public','metrics','archive1','archive2'):
        p.add_argument(arg,type=Path)
    print(json.dumps(audit(**vars(p.parse_args())), indent=2, sort_keys=True))
