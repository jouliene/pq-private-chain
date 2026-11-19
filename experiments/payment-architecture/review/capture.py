"""Check public DLF1 selection, conflict, archive boundaries, proof shape and ordered receipts."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from direct_wire import declared_size, dimensions, parse_packet


def check(registry, capture, receipt_program):
    vk = registry.read_bytes()
    prof = dimensions(vk)
    network = sha256(b'PQDEV1/network\x00' + sha256(vk).digest() + struct.pack('<BBBIQ', 22, 8, 4, 8, 100)).digest()
    genesis = sha256(b'PQDEV1/genesis\x00' + network).digest()
    busy = (capture / 'BUSY.json').is_file()
    result = json.loads((capture / ('BUSY.json' if busy else 'RUN.json')).read_bytes())
    bank = {}
    seen = {}
    assertions = {}
    with tempfile.TemporaryDirectory(prefix='dlf-public-check-') as tmp:
        for filename in sorted((capture / 'blocks').glob('*.bin')):
            packet_ledger = []
            raw = filename.read_bytes()
            prefix = sha256(b'PQDEV1/template\x00' + raw[:-8]).digest()
            bid = sha256(b'PQDEV1/work\x00' + prefix + raw[-8:]).digest()
            assert bid.hex() == filename.stem and int.from_bytes(bid, 'big') < (1 << 234)
            assert raw[:41] == b'PQDEVBL1' + network + bytes([22])
            height = int.from_bytes(raw[73:77], 'little')
            count = raw[213]
            assert count <= 4 and int.from_bytes(raw[109:117], 'little') == 100 + 3 * count
            index = 214
            for _ in range(count):
                length = int.from_bytes(raw[index:index + 4], 'little')
                packet = raw[index + 4:index + 4 + length]
                observation = parse_packet(packet, prof)
                assert observation['proof_B'] == declared_size(prof)
                tx = observation['packet_sha256']
                end = 9 + observation['proof_B']
                pi = struct.unpack('<26Q', packet[end - 208:end])
                nullifiers = [pi[i:i + 4] for i in (5, 9)]
                commitments = [pi[i:i + 4] for i in (13, 17)]
                assert len(set(nullifiers)) == len(set(commitments)) == 2
                assert 1 <= height - pi[4] <= 8
                seen[tx] = (nullifiers, commitments)
                assertions[tx] = observation
                (Path(tmp) / tx).write_bytes(packet)
                packet_ledger.append(tx)
                index += 4 + length
            assert index + 8 == len(raw)
            bank[bid.hex()] = dict(parent=raw[41:73].hex(), height=height, count=count,
                                  size=len(raw), payments=packet_ledger)
        hashes = sorted(seen)
        output = subprocess.check_output([receipt_program, *[Path(tmp) / tx for tx in hashes]], text=True)
        assert len(output.splitlines()) == len(hashes)
    branches = {}
    for branch in (('selected',) if busy else ('selected', 'orphan')):
        ids = result[branch]
        parent = genesis.hex()
        payments = []
        for height, bid in enumerate(ids, 1):
            entry = bank[bid]
            assert entry['height'] == height and entry['parent'] == parent
            parent = bid
            payments.extend(entry['payments'])
        nfs = [nf for tx in payments for nf in seen[tx][0]]
        cms = [cm for tx in payments for cm in seen[tx][1]]
        assert len(set(nfs)) == len(nfs) and len(set(cms)) == len(cms)
        branches[branch] = dict(tip=parent, height=len(ids), payments=payments,
                                occupancy=dict(sorted(Counter(bank[i]['count'] for i in ids).items())),
                                raw_B=sum(bank[i]['size'] for i in ids), fees=3 * len(payments),
                                spent=len(nfs), issued=100 * len(ids))
    if busy:
        assert branches['selected']['occupancy'] == {0: 9, 4: 1}
        assert len(seen) == 4 and set(seen) == set(result['wallet_txs'])
        assert all(row['anchor_height'] == 8 for row in assertions.values())
        assert all(not bank[bid]['count'] for bid in result['selected'][:-1])
        assert set(bank) == set(result['selected'])
        overlap = []
        for payment in result['payments']:
            entered, returned = payment['K_enter_s'], payment['K_return_s']
            native = {m['operation']: m['elapsed_s'] for m in payment['wallet_metrics']}
            interval = (returned - native['compact_prove'], entered + native['wallet_prover_setup'] + native['compact_prove'])
            actual = payment['proof_certain_interval_s']
            assert list(interval) == actual and interval[0] <= interval[1]
            overlap.append(interval)
        concurrent = max(0, min(b for _, b in overlap) - max(a for a, _ in overlap))
        assert concurrent == result['all_four_minimum_simultaneous_native_proof_s']
        assert result['full_selected_archive_B'] == branches['selected']['raw_B']
        control = dict(common_native_proof_interval_s=concurrent)
    else:
        correct = sorted(item['tx'] for item in (result['lone'], *result['concurrent'], result['recipient_spend']))
        assert sorted(branches['selected']['payments']) == correct
        competitor = result['orphan_payment']['tx']
        assert competitor in branches['orphan']['payments'] and competitor not in correct
        assert set(seen[competitor][0]) == set(seen[result['concurrent'][0]['tx']][0])
        assert set(bank) == set(result['selected']) | set(result['orphan'])
        assert result['selected'][-1] == result['final_tip']
        control = dict(competing_nullifiers_in_common=2)
    return dict(profile=prof, statements=assertions, **control,
                branch_history=branches, public_packet_receipt_order_checks=len(seen),
                distinct_block_files=len(bank), all_block_files_B=sum(v['size'] for v in bank.values()))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('registry', 'capture', 'receipt_program'):
        p.add_argument(arg, type=Path)
    args = p.parse_args()
    print(json.dumps(check(args.registry, args.capture, args.receipt_program.resolve()), sort_keys=True, indent=2))
