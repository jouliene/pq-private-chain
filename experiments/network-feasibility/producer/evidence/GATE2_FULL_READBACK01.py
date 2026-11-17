"""Fixed full-producer public readback; no proof payload, native helper or private input."""
from pathlib import Path
import hashlib
import json
import sqlite3
import struct
import sys
sys.dont_write_bytecode = True
REPOSITORY = Path(__file__).resolve().parents[4]
BASE = REPOSITORY / 'experiments/network-feasibility/producer'
PUBLIC = BASE / '.work/gate2-96x8-01.public'
WORK = BASE / '.work/gate2-96x8-01'
N, B = 96, 8


def read(path):
    return json.loads(path.read_bytes())


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def resource_summary(rows):
    return dict(count=len(rows), proof_bytes=sum(r['proof_bytes'] for r in rows),
        body_bytes=sum(r['body_bytes'] for r in rows),
        proof_bytes_min=min(r['proof_bytes'] for r in rows), proof_bytes_max=max(r['proof_bytes'] for r in rows),
        inclusive_proving_call_wall_seconds_sum=sum(r['private_proving_call_wall_seconds'] for r in rows),
        worker_wall_seconds_sum=sum(r['worker_wall_seconds'] for r in rows),
        worker_user_seconds_sum=sum(r['worker_user_seconds'] for r in rows),
        worker_system_seconds_sum=sum(r['worker_system_seconds'] for r in rows),
        maximum_individual_worker_peak_rss_kib=max(r['worker_peak_rss_kib'] for r in rows))


def main():
    receipt = read(WORK / 'receipt.json')
    workload = read(PUBLIC / 'workload.json')
    costs = read(PUBLIC / 'proof-costs.json')
    init = read(PUBLIC / 'retention-init.json')
    source_manifest = read(BASE / 'SOURCE.json')
    assert receipt['passed'] and receipt['source_runtime_unchanged']
    assert sha(BASE / 'SOURCE.json') == receipt['source_sha256'] == '380d4c4305eeb326604b28f77bba75c9107fea5010dabe0f407ccfbe6c0a82c2'
    assert all(sha(BASE / name) == digest for name, digest in source_manifest['files'].items())
    assert sha(REPOSITORY / source_manifest['profile']['path']) == source_manifest['profile']['sha256'] == receipt['profile_sha256']
    assert not receipt['raw_private_streams_persisted_or_hashed'] and receipt['fixed_source_failure_stage'] is None
    assert receipt['actual_process']['process_exit'] == receipt['actual_process']['wrapper_exit'] == 0
    assert not receipt['actual_process']['timeout']
    assert receipt['result'] == dict(accepted_blocks=9, credit_proofs=96, ordinary_proofs=768,
        format='CP04-NETWORK-PIPELINE-PRODUCER01', private_material_or_mapping_persisted=False, resource_profile_pass=False)
    assert workload['format'] == 'CP04-NETWORK-PIPELINE-WORKLOAD01' and workload['block_version'] == 4
    assert (workload['batch_size'], workload['ordinary_batch_count'], workload['ordinary_count']) == (N, B, N * B)
    assert len(workload['blocks']) == len(costs['batches']) == B + 1 and len(costs['rows']) == N * (B + 1)
    assert costs['credit_proofs'] == N and costs['ordinary_proofs'] == N * B
    assert init['passed'] and init['binary_prechecked'] and init['binary_postchecked']
    assert init['head_reopened_and_matched'] and init['hard_bytes'] == '2147483648'
    assert init['head']['unconsumed_liabilities'] == str(N * 100000000)
    installation_path = REPOSITORY / '.work/network01/fresh/installation.json'
    assert sha(installation_path) == receipt['installation_sha256']
    installation = read(installation_path)
    source = Path(installation['source_root'])
    network = read(source / 'docs/architecture/CP_NETWORK_04.json')
    row_by_body = {r['body']: r for r in costs['rows']}
    assert len(row_by_body) == N * (B + 1)
    all_nfs, body_names, parent_labels = set(), set(), set()
    parent_receipt_bytes = 0
    identities = {name: set() for name in ['binary_sha256', 'manifest_sha256', 'approved_runtime_digest', 'approved_runtime_receipt_sha256']}
    batch_summaries = []
    total_body_bytes = 0
    for batch, block in enumerate(workload['blocks']):
        assert len(block['bodies']) == N
        selected_rows = []
        expected = init['head'] if batch == 0 else costs['batches'][batch - 1]['endpoint']
        for item in block['bodies']:
            assert item['path'] not in body_names
            body_names.add(item['path'])
            file = PUBLIC / item['path']
            total_body_bytes += file.stat().st_size
            with file.open('rb') as stream:
                prefix = stream.read(20)
                assert prefix[:8] == b'CPBODY03'
                version, statement_bytes, proof_bytes, authorization_bytes, reserved = struct.unpack('<HHIHH', prefix[8:])
                statement = stream.read(statement_bytes)
            arity = 0 if batch == 0 else 2
            assert version == 3 and reserved == 0 and authorization_bytes == (4627 if batch == 0 else 0)
            assert statement[:8] == b'CP-P2-03' and statement[10] == arity and statement_bytes == (448 if batch == 0 else 528)
            assert statement[16:48].hex() == workload['chain']
            offset = 80 + 64 * arity + 128
            fee = struct.unpack_from('<Q', statement, offset)[0]
            root = statement[offset + 8:offset + 72].hex()
            count = struct.unpack_from('<Q', statement, offset + 72)[0]
            assert root == expected['root_le'] and count == int(expected['leaf_count'])
            assert fee == (2116775 if batch == 0 else 2112248)
            for index in range(arity):
                nf = statement[80 + 64 * index:144 + 64 * index]
                assert nf not in all_nfs
                all_nfs.add(nf)
            row = row_by_body[item['path']]
            assert row['batch'] == batch and row['arity'] == arity
            assert row['proof_bytes'] == proof_bytes and row['body_bytes'] == file.stat().st_size
            assert file.stat().st_size == 20 + statement_bytes + 4328 + authorization_bytes + proof_bytes
            # Each original Parent JSON is read/hash/decoded once in this bounded pass.
            parent_file = source / row['parent_receipt']
            raw = parent_file.read_bytes()
            parent_receipt_bytes += len(raw)
            assert sha_bytes(raw) == row['parent_receipt_sha256']
            parent = json.loads(raw)
            assert parent_file.name == parent['label'] + '.json' and parent['public_label'] == parent['label']
            assert parent['label'] not in parent_labels
            parent_labels.add(parent['label'])
            assert parent['format'] == 'CP-ALL-PRIVATE-PARENT07' and parent['mode'] == 'prove-private' and parent['arity'] == arity
            assert parent['process_exit'] == parent['wrapper_exit'] == 0 and not parent['timeout']
            assert parent['source_pins_unchanged'] and parent['runtime_pins_unchanged']
            assert not parent['private_input_written_or_hashed'] and not parent['unchecked_child_output_persisted']
            assert parent['approved_runtime_digest'] == parent['observed_runtime_digest'] == parent['runtime_after_digest']
            assert parent['child_wall_seconds'] == row['worker_wall_seconds']
            assert parent['wait4_user_seconds'] == row['worker_user_seconds']
            assert parent['wait4_system_seconds'] == row['worker_system_seconds']
            assert parent['wait4_maxrss_kib'] == row['worker_peak_rss_kib']
            for name in identities:
                identities[name].add(parent[name])
            directory = source / 'experiments/compact-all-payments-v3/public' / parent['label']
            manifest = read(directory / 'manifest.json')
            assert manifest['genuine_proof_created'] and manifest['mode'] == 'prove-private' and manifest['arity'] == arity
            assert manifest['private_input_boundary'] and not manifest['private_packet_persisted']
            assert not manifest['private_input_debug_digest_created'] and not manifest['whole_protocol_security_claim']
            assert manifest['prepared']['profile'] == network['proof']['profile_id']
            assert manifest['prepared']['program'] == network['proof']['program_ids'][arity]
            assert manifest['envelope_bytes'] == proof_bytes and manifest['statement_bytes'] == statement_bytes
            assert manifest['statement_sha256'] == sha_bytes(statement)
            assert (directory / 'statement.bin').read_bytes() == statement
            assert (directory / 'proof.bin').stat().st_size == proof_bytes  # Proof bytes are not reread/hashed.
            assert read(PUBLIC / (item['path'] + '.proof-cost.json')) == row
            selected_rows.append(row)
        if batch:
            assert costs['batches'][batch]['anchor'] == costs['batches'][batch - 1]['endpoint']
            assert read(PUBLIC / ('batch' + str(batch).zfill(2) + '-receipt.json')) == costs['batches'][batch]
        endpoint = costs['batches'][batch]['endpoint']
        assert int(endpoint['height']) == batch + 1 and int(endpoint['leaf_count']) == 2 * N * (batch + 1)
        assert int(endpoint['fee_escrow']) == N * (2116775 + batch * 2112248) and endpoint['unconsumed_liabilities'] == '0'
        batch_summaries.append({**costs['batches'][batch], 'proof_resources': resource_summary(selected_rows)})
    assert len(all_nfs) == 2 * N * B and costs['batches'][-1]['endpoint'] == workload['endpoint']
    assert all(len(values) == 1 for values in identities.values())
    roots = [init['head']['root_le']] + [b['endpoint']['root_le'] for b in costs['batches']]
    assert len(set(roots)) == B + 2
    connection = sqlite3.connect((PUBLIC / 'producer.sqlite').as_uri() + '?mode=ro')
    tables = ['meta', 'sources', 'nullifiers', 'cores', 'leaves', 'nodes', 'anchors', 'blocks',
              'body_cache', 'archive_segments', 'archive_objects', 'bodies', 'archive_pending', 'node_undo']
    assert set(tables) == {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    counts = {table: connection.execute('SELECT count(*) FROM ' + table).fetchone()[0] for table in tables}
    meta = connection.execute('SELECT total,height,head,leaf_count,root,fees,liabilities,genesis FROM meta').fetchone()
    expected_fee = N * (2116775 + B * 2112248)
    assert meta[:2] == (N * 100000000, B + 1) and meta[3] == 2 * N * (B + 1) and meta[5:7] == (expected_fee, 0)
    assert meta[2].hex() == workload['endpoint']['block_id'] and meta[4].hex() == workload['endpoint']['root_le']
    assert meta[7] == (PUBLIC / 'genesis.bin').read_bytes()
    assert counts['blocks'] == B + 1 and counts['bodies'] == counts['cores'] == N * (B + 1)
    assert counts['leaves'] == 2 * N * (B + 1) and counts['nullifiers'] == 2 * N * B and counts['sources'] == N
    assert counts['archive_pending'] == 0
    assert connection.execute('SELECT count(*) FROM sources WHERE consumed_height=1').fetchone()[0] == N
    assert connection.execute('SELECT count(*) FROM bodies WHERE full IS NOT NULL').fetchone()[0] == N * (B + 1)
    cache = connection.execute('SELECT hard_bytes,cached_bytes,unexported_bytes,archive_committed_bytes,next_segment,retention FROM body_cache').fetchone()
    assert cache == (2147483648, total_body_bytes, 0, 0, 0, 1)
    for row, block in zip(connection.execute('SELECT height,id,header,leaf_count,root,fees,liabilities FROM blocks ORDER BY height'), workload['blocks']):
        endpoint = costs['batches'][row[0] - 1]['endpoint']
        assert row[2] == (PUBLIC / block['header']['path']).read_bytes()
        assert row[1].hex() == endpoint['block_id'] and row[3] == int(endpoint['leaf_count'])
        assert row[4].hex() == endpoint['root_le'] and row[5] == int(endpoint['fee_escrow']) and row[6] == 0
    connection.close()
    out = BASE / 'evidence'
    save(out / 'GATE2_FULL_GENERATION01_RECEIPT.json', receipt)
    result = dict(format='CP04-PRODUCER-GATE2-FULL-READBACK01', passed=True,
        source_sha256=receipt['source_sha256'], profile_sha256=receipt['profile_sha256'], installation_sha256=receipt['installation_sha256'],
        workload_sha256=sha(PUBLIC / 'workload.json'), proof_costs_sha256=sha(PUBLIC / 'proof-costs.json'),
        scope='Author public-only readback: statement prefixes, original Parent/proof manifests, resource rows, batch receipts and readonly SQL. No native/proof/CP field-hash rerun, no proof-payload read/hash and no private input. Generation PASS is not network service or participation acceptance.',
        actual_generation=receipt['actual_process'], retention_init=init, public_table_counts=counts,
        accounting=dict(total=meta[0], height=meta[1], leaf_count=meta[3], fees=meta[5], liabilities=meta[6],
            remaining_note_supply_implied_by_conservation=meta[0] - meta[5] - meta[6], per_lane_balance=100000000 - 2116775 - B * 2112248),
        retention=dict(hard_bytes=cache[0], cached_bytes=cache[1], unexported_bytes=cache[2], archive_committed_bytes=cache[3],
            next_segment=cache[4], retain=cache[5] == 1, full_bodies=N * (B + 1)),
        original_parent_metadata=dict(count=len(parent_labels), bytes_read=parent_receipt_bytes,
            all_receipt_hashes_status_flags_resources_matched=True, distinct_identities={k:list(v)[0] for k,v in identities.items()},
            all_private_input_and_unchecked_output_flags_false=True, all_genuine_public_manifests_profile_program_statement_size_match=True),
        proof_resources=dict(funding=resource_summary(costs['rows'][:N]), ordinary=resource_summary(costs['rows'][N:]), all=resource_summary(costs['rows'])),
        resource_interpretation='Outer first-wait4 is whole generation including waited descendants; Parent workers and private call/batch intervals are nested subsets, not additive costs. Max worker RSS is an individual maximum, not concurrent process-tree RSS. Proving/preparation/admission are not receiving-node service.',
        batches=batch_summaries,
        checks=dict(source_profile_pins_unchanged=True, all864_cost_rows_match_original_parent_metadata=True,
            all_statement_anchors_match_preceding_batch=True, all10_genesis_postblock_roots_distinct=True,
            all9_headers_endpoints_match_SQL=True, all14_public_tables_read=True,
            no_private_material_or_mapping_persisted_per_actual_receipts=True),
        known_readback_failures=[], generation_acceptance=True, gate2_network_service_acceptance=False, gate3_acceptance=False)
    save(out / 'GATE2_FULL_GENERATION01_READBACK.json', result)
    print(json.dumps(dict(passed=True, workload_sha256=result['workload_sha256'],
        readback_sha256=sha(out / 'GATE2_FULL_GENERATION01_READBACK.json'), receipt_sha256=sha(out / 'GATE2_FULL_GENERATION01_RECEIPT.json'),
        parent_count=len(parent_labels), parent_receipt_bytes=parent_receipt_bytes, body_bytes=total_body_bytes,
        accounting=result['accounting'], proof_resources=result['proof_resources']), sort_keys=True))


if __name__ == '__main__':
    main()
