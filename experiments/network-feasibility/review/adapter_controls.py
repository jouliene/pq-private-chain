#!/usr/bin/env python3
"""Public Network04 compatibility controls; retained proofs are NOT new throughput."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys

sys.dont_write_bytecode = True
REPOSITORY = Path(__file__).resolve().parents[3]
TABLES = {'meta', 'sources', 'nullifiers', 'cores', 'leaves', 'nodes', 'anchors',
          'blocks', 'body_cache', 'archive_segments', 'archive_objects', 'bodies',
          'archive_pending', 'node_undo'}
CAP = 268435456


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def h64(role, raw, suffix=b''):
    tag = b'PQPC/CP3/' + role
    return hashlib.sha3_512(len(tag).to_bytes(2, 'little') + tag +
                          len(raw).to_bytes(4, 'little') + raw + suffix).digest()


def integer(value, width=8):
    return value.to_bytes(width, 'little')


def snapshot(path):
    """Logical all-table oracle outside every measured native process."""
    result = {}
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        need(names == TABLES, 'unexpected schema tables')
        for name in sorted(names):
            columns = [row[1] for row in db.execute(f'PRAGMA table_info("{name}")')]
            order = ','.join('"' + col + '"' for col in columns)
            digest = hashlib.sha256()
            count = 0
            for row in db.execute(f'SELECT * FROM "{name}" ORDER BY {order}'):
                encoded = json.dumps([{'blob': value.hex()} if isinstance(value, bytes) else value
                                      for value in row], separators=(',', ':')).encode()
                digest.update(integer(len(encoded)))
                digest.update(encoded)
                count += 1
            result[name] = {'rows': count, 'sha256': digest.hexdigest()}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--approve-installation', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    installation = args.installation.resolve(strict=True)
    need(sha(installation) == args.approve_installation, 'installation approval')
    raw_installation = json.loads(installation.read_text())
    helper = REPOSITORY / 'scripts/common.py'
    need(raw_installation['pins'].get(str(helper)) == sha(helper), 'approved runner source')
    spec = importlib.util.spec_from_file_location('network_review_common', helper)
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    inst = common.load_installation(installation, args.approve_installation)
    need(Path(inst['repository']).resolve() == REPOSITORY, 'this checkout installation')
    source = Path(inst['source_root'])
    operator = json.loads(Path(inst['operator_path']).read_text())
    binary = (source / operator['ledger_binary']['path']).resolve()
    need(inst['pins'].get(str(binary)) == sha(binary) == operator['ledger_binary']['sha256'],
         'new compiled ledger identity')
    output = args.output.resolve()
    need(not output.exists(), 'exclusive output')
    output.parent.mkdir(parents=True, exist_ok=True)
    parent = output.parent / '.work'
    parent.mkdir(exist_ok=True)
    work = parent / output.stem
    work.mkdir(mode=0o700)
    script_hash = sha(Path(__file__))
    input_pins = {}
    calls, checks = [], []
    manifest = common.read_json(REPOSITORY / 'CORE_MANIFEST.json')

    def published(relative):
        path = REPOSITORY / relative
        expected = manifest['files'][relative]['sha256']
        need(path.is_file() and not path.is_symlink() and sha(path) == expected, 'public input pin')
        input_pins[str(path)] = expected
        return path.read_bytes()

    def installed(relative):
        path = source / relative
        need(path.is_file() and inst['pins'].get(str(path)) == sha(path), 'installed source pin')
        input_pins[str(path)] = sha(path)
        return path.read_bytes()

    def write(name, raw):
        path = work / name
        with path.open('xb') as handle:
            handle.write(raw)
        return path

    expected = json.loads(published('fixtures/cp03-reference/expected.json'))
    chain = expected['chain']
    genesis3 = published('fixtures/cp03-reference/genesis.bin')
    credit = published('fixtures/cp03-reference/credit0.body')
    payer = published('fixtures/cp03-reference/payer2x2.body')
    credit_header3 = published('fixtures/cp03-reference/block01.header')
    network = installed('docs/architecture/CP_NETWORK_04.json')
    need(json.loads(network)['format'] == 'PQPC-CP04-NETWORK-RESEARCH-PROTOCOL-01', 'Network04 identity')
    genesis4 = bytearray(genesis3)
    genesis4[:10] = b'CPGEN004\x04\0'
    genesis4[56:120] = h64(b'PROTOCOL', network)
    need(len(genesis4) == 3024 and int.from_bytes(genesis4[52:54], 'little') == 1,
         'fixed one-source fixture')
    g3, g4 = write('legacy.genesis', genesis3), write('network.genesis', genesis4)
    cfile, pfile = write('credit.body', credit), write('payer.body', payer)
    database = work / 'network.sqlite'

    def call(name, arguments, error=None):
        need(name not in [row['name'] for row in calls], 'unique process label')
        receipt, stdout, stderr = common.run([str(binary), *map(str, arguments)],
            cwd=REPOSITORY, env=inst['proof_environment'], seconds=30, cap=65536,
            record=work / name)
        calls.append({'name': name, 'expected_error': error, 'actual_process': receipt})
        need(receipt.get('wrapper_exit') == 0 and not receipt.get('timeout') and
             receipt.get('first_wait4') is True, 'native lifecycle: ' + name)
        if error:
            need(receipt.get('process_exit') == 1 and stdout == b'' and
                 stderr == ('CP03_LEDGER_ERROR ' + error + '\n').encode(), 'exact rejection: ' + name)
            return None
        need(receipt.get('process_exit') == 0 and not stderr, 'native success: ' + name)
        return json.loads(stdout)

    def ledger(name, op, *tail, db=database, error=None):
        return call(name, [op, db, chain, *tail], error)

    def negative(name, op, *tail, error, db=database):
        before = snapshot(db)
        ledger(name, op, *tail, db=db, error=error)
        need(snapshot(db) == before, 'all-table invariance: ' + name)
        checks.append(name + ':all14-unchanged')

    def unchanged_values(before, after):
        need(all(before[k] == after[k] for k in
                 ['root_le', 'leaf_count', 'fee_escrow', 'unconsumed_liabilities']), 'empty state invariance')

    def header(parent_head, bodies, *, version=4, claimed=None, after=None):
        state = after or parent_head
        ids = []
        for body in bodies:
            prefix = 20 + int.from_bytes(body[10:12], 'little') + 4328 + int.from_bytes(body[16:18], 'little')
            ids.append(h64(b'BODY', body[:prefix], h64(b'PROOF', body[prefix:])))
        raw = (b'CPBLOCK4' if version == 4 else b'CPBLOCK3') + integer(version, 2) + b'\0\0'
        raw += bytes.fromhex(chain) + bytes.fromhex(parent_head['block_id']) + integer(int(parent_head['height']) + 1)
        raw += integer(len(bodies), 2) + b'\0\0' + integer(int(state['leaf_count'])) + bytes.fromhex(state['root_le'])
        raw += integer(int(state['fee_escrow'])) + integer(int(state['unconsumed_liabilities']))
        if version == 4:
            raw += integer(claimed if claimed is not None else 228 + 68 * len(bodies) + sum(map(len, bodies)))
        return raw + b''.join(ids)

    common.save(work / 'claim.json', {'format': 'NETWORK04-REVIEW-CONTROLS-CLAIM01',
        'source_sha256': script_hash, 'installation_sha256': args.approve_installation,
        'private_inputs': False, 'retained_proofs_only': True, 'distinct_throughput_claim': False})
    passed, failure = False, None
    try:
        initial = ledger('init-network-retain', 'init-retain', g4, 16 * 1024 * 1024)
        need(initial['block_version'] == '4' and initial['height'] == '0', 'network version')
        # Genesis count limits use public registrations only, never pretend new payments.
        source_record = genesis4[376:]
        for count in [0, 128, 129]:
            raw = bytearray(genesis4[:376])
            raw[44:52] = integer(count * 100000000)
            raw[52:54] = integer(count, 2)
            # For129 keep size below global cap to isolate the count check.
            for index in range(min(count, 128)):
                raw += integer(index, 48) + source_record[48:]
            file = write(f'genesis-{count}.bin', raw)
            ledger(f'genesis-{count}', 'init-retain', file, db=work / f'g{count}.sqlite',
                   error='Codec' if count != 128 else None)
        checks.append('genesis0-and129-rejected-128-accepted-without-payments')
        wrong_genesis = bytearray(genesis4)
        wrong_genesis[:10] = b'CPGEN003\x03\0'
        ledger('mixed-genesis-policy', 'init', write('mixed.genesis', wrong_genesis),
               db=work / 'mixed.sqlite', error='Codec')
        legacy_db = work / 'legacy.sqlite'
        legacy = ledger('init-legacy-for-version-negative', 'init', g3, db=legacy_db)
        ledger('legacy-retain-forbidden', 'init-retain', g3, db=work / 'legacy-retain.sqlite', error='RetentionPolicy')
        empty1 = ledger('empty-prefix', 'admit')
        unchanged_values(initial, empty1)
        need(empty1['height'] == '1', 'empty prefix height')
        scan1 = work / 'empty.scan'
        ledger('scan-empty-only', 'scan', scan1)
        call('check-empty-only', ['check-scan', chain, g4, scan1, '1', empty1['block_id'], work / 'empty.checked'])
        need(scan1.read_bytes() == (work / 'empty.checked').read_bytes(), 'checked empty scan bytes')
        credit_state = {'leaf_count': '2', 'root_le': credit_header3[128:192].hex(),
                        'fee_escrow': '2116775', 'unconsumed_liabilities': '0'}
        negative('legacy-block-in-network-chain', 'replay',
                 write('legacy-on-network.header', header(empty1, [credit], version=3, after=credit_state)),
                 cfile, error='Block')
        negative('network-block-in-legacy-chain', 'replay',
                 write('network-on-legacy.header', header(legacy, [credit], after=credit_state)),
                 cfile, db=legacy_db, error='Block')
        funded = ledger('genuine-credit', 'admit', cfile)
        need(funded['height'] == '2' and all(funded[k] == v for k, v in credit_state.items()), 'actual credit state')
        small_db = work / 'small-retain.sqlite'
        ledger('init-small-retain', 'init-retain', g4, len(credit) - 1, db=small_db)
        negative('retention-capacity-before-mutation', 'admit', cfile, db=small_db, error='ArchiveBacklog')
        bad = bytearray(payer)
        proof_at = 20 + int.from_bytes(bad[10:12], 'little') + 4328 + int.from_bytes(bad[16:18], 'little')
        bad[proof_at + 206 + 4] ^= 1
        negative('genuine-opaque-proof-rejection', 'admit', write('bad-proof.body', bad), error='Proof')
        negative('body-count129', 'admit', *([pfile] * 129), error='Codec')
        negative('claimed-frame-over-cap', 'replay', write('over-cap.header', header(funded, [], claimed=CAP + 1)), error='Codec')
        negative('empty-frame-length-mismatch', 'replay', write('wrong-empty-length.header', header(funded, [], claimed=229)), error='Block')
        ordinary = ledger('genuine-ordinary-followup', 'admit', pfile)
        need(ordinary['height'] == '3' and ordinary['leaf_count'] == '4' and
             ordinary['fee_escrow'] == '4229023' and ordinary['unconsumed_liabilities'] == '0', 'ordinary state')
        ordinary_snapshot = snapshot(database)
        empty4 = ledger('empty-suffix-one', 'admit')
        unchanged_values(ordinary, empty4)
        empty4_snapshot = snapshot(database)
        empty5 = ledger('empty-suffix-two', 'admit')
        unchanged_values(empty4, empty5)
        need(empty5['height'] == '5', 'empty height exceeds leaves/2 without corruption')
        full_scan = work / 'full.scan'
        ledger('scan-five-blocks', 'scan', full_scan)
        call('check-five-blocks', ['check-scan', chain, g4, full_scan, '5', empty5['block_id'], work / 'full.checked'])
        need(full_scan.read_bytes() == (work / 'full.checked').read_bytes(), 'checked scan bytes')
        scan_bytes = full_scan.read_bytes()
        truncated = write('truncated.scan', scan_bytes[:-1])
        call('reject-truncated-scan', ['check-scan', chain, g4, truncated, '5', empty5['block_id'], work / 'bad.checked'], 'Codec')
        need(not (work / 'bad.checked').exists(), 'no published partial scan')
        # A changed aggregate size in reduced history must fail despite no proof bytes.
        changed = bytearray(scan_bytes)
        at = 0
        while at + 4 + int.from_bytes(changed[at:at + 4], 'little') < len(changed):
            at += 4 + int.from_bytes(changed[at:at + 4], 'little')
        changed[at + 4 + 12 + 208:at + 4 + 12 + 216] = integer(229)
        call('reject-reduced-full-length', ['check-scan', chain, g4, write('wrong-size.scan', changed),
             '5', empty5['block_id'], work / 'wrong-size.checked'], 'Codec')
        need(not (work / 'wrong-size.checked').exists(), 'no complete invalid reduced scan')
        ledger('rollback-empty-five', 'rollback', empty5['block_id'])
        need(snapshot(database) == empty4_snapshot, 'empty rollback all-table state')
        ledger('rollback-empty-four', 'rollback', empty4['block_id'])
        need(snapshot(database) == ordinary_snapshot, 'second empty rollback all-table state')
        need(ledger('reopened-head', 'head') == ordinary, 'durable reopen head')
        with sqlite3.connect(database) as db:
            row = db.execute('SELECT retention,cached_bytes,unexported_bytes,archive_committed_bytes,next_segment FROM body_cache').fetchone()
            need(row == (1, len(credit) + len(payer), 0, 0, 0), 'RETAIN exact accounting')
            need(db.execute('SELECT count(*) FROM archive_pending').fetchone() == (0,), 'no retained export obligation')
            need(db.execute('SELECT count(*) FROM bodies WHERE full IS NULL').fetchone() == (0,), 'full bodies retained')
            need(db.execute('SELECT count(*) FROM nullifiers').fetchone() == (2,), 'genuine two-input spentness')
            for sql, error in [('UPDATE bodies SET full=NULL', 'RETAIN_EVICTION_PROHIBITED'),
                               ('UPDATE body_cache SET retention=0', 'RETENTION_POLICY_IMMUTABLE')]:
                db.execute('BEGIN')
                try:
                    db.execute(sql)
                except sqlite3.IntegrityError as exc:
                    need(str(exc) == error, 'exact RETAIN SQL guard')
                else:
                    raise ValueError('retention guard unexpectedly allowed mutation')
                finally:
                    db.rollback()
        need(snapshot(database) == ordinary_snapshot, 'SQL negative controls unchanged')
        checks += ['genuine-credit-and-ordinary-version4', 'empty-prefix-and-two-suffixes',
                   'empty-only-and-mixed-scan', 'empty-rollback-and-reopen',
                   'reduced-size-reconstruction', 'truncated-scan-no-publication',
                   'RETAIN-full-bytes-pending0-no-eviction-policy-immutable']
        passed = True
    except BaseException as exc:
        failure = {'type': type(exc).__name__, 'message': str(exc)}
    finally:
        try:
            common.load_installation(installation, args.approve_installation)
            need(sha(Path(__file__)) == script_hash, 'review source drift')
            common.hashes(input_pins)
        except BaseException as exc:
            passed = False
            failure = {'type': type(exc).__name__, 'message': str(exc)}
        common.save(output, {'format': 'NETWORK04-PUBLIC-ADAPTER-CONTROLS01', 'passed': passed,
            'source_sha256': script_hash, 'installation_sha256': args.approve_installation,
            'binary_sha256': sha(binary), 'public_input_pins': input_pins,
            'actual_calls': calls, 'checks': checks, 'failure': failure,
            'private_material': False, 'new_proofs': 0, 'distinct96_or_gate1_acceptance': False,
            'scope': 'New adapter compatibility using retained genuine public proofs; public-only CLI processes, external SQL oracle/guard controls. No network, WAN, full byte-cap positive, late96 or throughput claim.'})
    print(json.dumps({'passed': passed, 'actual_cli_calls': len(calls), 'new_proofs': 0}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
