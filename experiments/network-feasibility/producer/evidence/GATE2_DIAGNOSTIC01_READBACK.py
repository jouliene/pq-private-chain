"""One fixed public metadata readback. No native verifier, CP hashes or private access."""
from pathlib import Path
import hashlib
import json
import sqlite3
import struct
import sys
sys.dont_write_bytecode = True
REPOSITORY = Path(__file__).resolve().parents[4]
BASE = REPOSITORY / 'experiments/network-feasibility/producer'
PUBLIC = BASE / '.work/gate2-diagnostic01.public'
WORK = BASE / '.work/gate2-diagnostic01'


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def main():
    receipt = read(WORK / 'receipt.json')
    init = read(PUBLIC / 'retention-init.json')
    costs = read(PUBLIC / 'proof-costs.json')
    workload = read(PUBLIC / 'workload.json')
    assert sha(PUBLIC / 'workload.json') == '617f01cc6378f2f2b587bb4b899512d0abdfa6df093cc45d4dfc5b416caaeb6a'
    assert receipt['passed'] and receipt['source_runtime_unchanged']
    assert not receipt['raw_private_streams_persisted_or_hashed']
    assert receipt['actual_process']['process_exit'] == receipt['actual_process']['wrapper_exit'] == 0
    assert not receipt['actual_process']['timeout']
    assert init['passed'] and init['binary_prechecked'] and init['binary_postchecked']
    assert init['head_reopened_and_matched'] and init['hard_bytes'] == '2147483648'
    assert workload['format'] == 'CP04-NETWORK-PIPELINE-WORKLOAD01'
    assert (workload['batch_size'], workload['ordinary_batch_count'], workload['ordinary_count']) == (2, 3, 6)
    assert len(workload['blocks']) == len(costs['batches']) == 4 and len(costs['rows']) == 8
    installation = read(REPOSITORY / '.work/network01/fresh/installation.json')
    source = Path(installation['source_root'])
    parents, anchors, all_nfs, total_body_bytes = [], [], set(), 0
    for batch, block in enumerate(workload['blocks']):
        assert len(block['bodies']) == 2
        for item in block['bodies']:
            file = PUBLIC / item['path']
            total_body_bytes += file.stat().st_size
            with file.open('rb') as stream:
                prefix = stream.read(20)
                assert prefix[:8] == b'CPBODY03'
                version, statement_bytes, proof_bytes, authorization_bytes, reserved = struct.unpack('<HHIHH', prefix[8:])
                statement = stream.read(statement_bytes)
            assert version == 3 and reserved == 0 and authorization_bytes == (4627 if batch == 0 else 0)
            assert statement[10] == (0 if batch == 0 else 2)
            arity = statement[10]
            offset = 80 + 64 * arity + 128
            fee = struct.unpack_from('<Q', statement, offset)[0]
            root = statement[offset + 8:offset + 72].hex()
            count = struct.unpack_from('<Q', statement, offset + 72)[0]
            expected = init['head'] if batch == 0 else costs['batches'][batch - 1]['endpoint']
            assert root == expected['root_le'] and count == int(expected['leaf_count'])
            assert fee == (2116775 if batch == 0 else 2112248)
            for index in range(arity):
                nullifier = statement[80 + 64 * index:144 + 64 * index]
                assert nullifier not in all_nfs
                all_nfs.add(nullifier)
            anchors.append(dict(body=item['path'], batch=batch, arity=arity, anchor_count=count, anchor_root_le=root))
            cost = next(row for row in costs['rows'] if row['body'] == item['path'])
            assert cost['batch'] == batch and cost['arity'] == arity
            assert cost['proof_bytes'] == proof_bytes and cost['body_bytes'] == file.stat().st_size
            parent_file = source / cost['parent_receipt']
            raw = parent_file.read_bytes()
            parent = json.loads(raw)
            assert hashlib.sha256(raw).hexdigest() == cost['parent_receipt_sha256']
            assert parent_file.name == parent['label'] + '.json' and parent['public_label'] == parent['label']
            assert parent['format'] == 'CP-ALL-PRIVATE-PARENT07' and parent['mode'] == 'prove-private'
            assert parent['arity'] == arity and parent['process_exit'] == parent['wrapper_exit'] == 0
            assert not parent['timeout'] and parent['source_pins_unchanged'] and parent['runtime_pins_unchanged']
            assert not parent['private_input_written_or_hashed'] and not parent['unchecked_child_output_persisted']
            assert parent['child_wall_seconds'] == cost['worker_wall_seconds']
            assert parent['wait4_user_seconds'] == cost['worker_user_seconds']
            assert parent['wait4_system_seconds'] == cost['worker_system_seconds']
            assert parent['wait4_maxrss_kib'] == cost['worker_peak_rss_kib']
            parents.append(dict(label=parent['label'], sha256=cost['parent_receipt_sha256'], arity=arity,
                process_exit=parent['process_exit'], wrapper_exit=parent['wrapper_exit'],
                source_runtime_pins_unchanged=True, private_input_written_or_hashed=False,
                unchecked_child_output_persisted=False))
        if batch:
            assert costs['batches'][batch]['anchor'] == costs['batches'][batch - 1]['endpoint']
        endpoint = costs['batches'][batch]['endpoint']
        assert int(endpoint['height']) == batch + 1 and int(endpoint['leaf_count']) == 4 * (batch + 1)
        assert int(endpoint['fee_escrow']) == 2 * (2116775 + batch * 2112248)
        assert endpoint['unconsumed_liabilities'] == '0'
    assert len(all_nfs) == 12 and costs['batches'][-1]['endpoint'] == workload['endpoint']
    roots = [init['head']['root_le']] + [batch['endpoint']['root_le'] for batch in costs['batches']]
    assert len(set(roots)) == 5
    connection = sqlite3.connect((PUBLIC / 'producer.sqlite').as_uri() + '?mode=ro')
    tables = ['meta', 'sources', 'nullifiers', 'cores', 'leaves', 'nodes', 'anchors', 'blocks',
              'body_cache', 'archive_segments', 'archive_objects', 'bodies', 'archive_pending', 'node_undo']
    assert set(tables) == {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    counts = {table: connection.execute('SELECT count(*) FROM ' + table).fetchone()[0] for table in tables}
    meta = connection.execute('SELECT total,height,head,leaf_count,root,fees,liabilities,genesis FROM meta').fetchone()
    assert meta[:2] == (200000000, 4) and meta[3] == 16 and meta[5:7] == (16907038, 0)
    assert meta[2].hex() == workload['endpoint']['block_id'] and meta[4].hex() == workload['endpoint']['root_le']
    assert meta[7] == (PUBLIC / 'genesis.bin').read_bytes()
    assert counts['blocks'] == 4 and counts['bodies'] == counts['cores'] == 8
    assert counts['leaves'] == 16 and counts['nullifiers'] == 12 and counts['sources'] == 2
    assert counts['archive_pending'] == 0
    assert connection.execute('SELECT count(*) FROM sources WHERE consumed_height=1').fetchone()[0] == 2
    assert connection.execute('SELECT count(*) FROM bodies WHERE full IS NOT NULL').fetchone()[0] == 8
    cache = connection.execute('SELECT hard_bytes,cached_bytes,unexported_bytes,archive_committed_bytes,next_segment,retention FROM body_cache').fetchone()
    assert cache == (2147483648, total_body_bytes, 0, 0, 0, 1)
    for row, block in zip(connection.execute('SELECT height,id,header,leaf_count,root,fees,liabilities FROM blocks ORDER BY height'), workload['blocks']):
        endpoint = costs['batches'][row[0] - 1]['endpoint']
        assert row[2] == (PUBLIC / block['header']['path']).read_bytes()
        assert row[1].hex() == endpoint['block_id'] and row[3] == int(endpoint['leaf_count'])
        assert row[4].hex() == endpoint['root_le'] and row[5] == int(endpoint['fee_escrow']) and row[6] == 0
    connection.close()
    out = BASE / 'evidence'
    save(out / 'GATE2_DIAGNOSTIC01_RECEIPT.json', receipt)
    result = dict(format='CP04-PRODUCER-GATE2-DIAGNOSTIC-READBACK01', passed=True,
        workload_sha256=sha(PUBLIC / 'workload.json'), source_sha256=receipt['source_sha256'],
        installation_sha256=receipt['installation_sha256'], profile_sha256=receipt['profile_sha256'],
        scope='Public-only metadata, statement-prefix, original Parent receipts and readonly SQL; no native/proof/CP field-hash rerun, no private access. Diagnostic only, not Gate2 service or Gate3.',
        actual_generation=receipt['actual_process'], retention_init=init, public_table_counts=counts,
        public_accounting=dict(total=meta[0], height=meta[1], leaf_count=meta[3], fees=meta[5], liabilities=meta[6],
            remaining_note_supply_implied_by_conservation=meta[0] - meta[5] - meta[6]),
        retention=dict(hard_bytes=cache[0], cached_bytes=cache[1], unexported_bytes=cache[2],
            archive_committed_bytes=cache[3], next_segment=cache[4], retain=cache[5] == 1, full_bodies=8),
        body_statement_anchors=anchors, original_parent_receipts=parents, proof_costs=costs,
        checks=dict(all_original_parent_status_and_source_runtime_flags_pass=True,
            all_eight_cost_rows_match_original_parent_resource_receipts=True,
            all_statement_anchors_match_immediately_previous_batch=True,
            all_five_genesis_and_postblock_roots_distinct=True,
            all_four_headers_equal_accepted_SQL_bytes=True,
            all_batch_counts_fees_endpoints_match_actual_SQL=True, all_14_public_tables_read=True),
        gate2_service_acceptance=False, gate3_acceptance=False)
    save(out / 'GATE2_DIAGNOSTIC01_READBACK.json', result)
    print(json.dumps(dict(passed=True, receipt_sha256=sha(out / 'GATE2_DIAGNOSTIC01_RECEIPT.json'),
        readback_sha256=sha(out / 'GATE2_DIAGNOSTIC01_READBACK.json'), body_bytes=total_body_bytes,
        sql_counts=counts, worker_wall_sum_seconds=sum(row['worker_wall_seconds'] for row in costs['rows']),
        worker_cpu_sum_seconds=sum(row['worker_user_seconds'] + row['worker_system_seconds'] for row in costs['rows'])), sort_keys=True))


if __name__ == '__main__':
    main()
