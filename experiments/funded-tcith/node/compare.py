"""Compare deterministic public results independently of machine timings."""
import json
from pathlib import Path
import sys


def consensus_fields(data):
    for label,order in data['orders'].items():
        meter = order.pop('meter')
        order.update(bundle_B=meter['bundle_B'])
        if label=='mixed_first':
            registered = meter['registered']
            order['funded_anchor'] = {k:v for k,v in registered.items() if k!='engine'}
    return data


if __name__ == '__main__':
    expected, actual = (consensus_fields(json.loads(Path(p).read_text())) for p in sys.argv[1:])
    if actual != expected:
        raise ValueError('public funding, proof, mining or admission results diverged')
    print('Verified both registration orders, common nullifiers, moving anchor, reorg and archived projections.')
