// Fixed public initialization using the already-supported native operator quota.
// This does not modify the approved installed wallet wrapper or database policy.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';

const HARD_BYTES = '2147483648';
const OUTPUT_BYTES = 32768;
const ENV = Object.freeze({PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC',
  RUST_BACKTRACE: '0', RUST_LOG: 'off', RAYON_NUM_THREADS: '1'});
function need(ok) { if (!ok) throw new Error('CP04_RETAIN_INIT_CONDITION'); }
function same(a, b) {
  return ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
}
function inspect(fd, binary, expected) {
  const before = fs.fstatSync(fd, {bigint: true});
  need(before.isFile() && before.size > 0n && before.size <= 64n * 1024n * 1024n);
  const hash = crypto.createHash('sha256'), chunk = Buffer.alloc(65536);
  let at = 0;
  while (at < Number(before.size)) {
    const n = fs.readSync(fd, chunk, 0, Math.min(chunk.length, Number(before.size) - at), at);
    need(n > 0);
    if (at === 0) need(n >= 4 && chunk.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])));
    hash.update(chunk.subarray(0, n)); at += n;
  }
  const after = fs.fstatSync(fd, {bigint: true}), named = fs.lstatSync(binary, {bigint: true});
  need(same(before, after) && same(after, named) && hash.digest('hex') === expected);
}
function publicHead(head) {
  return {schema: 'CP03-LEDGER-CLI-01', chain: head.chain.toString('hex'),
    genesis_id: head.genesisId.toString('hex'), height: head.height.toString(),
    block_id: head.blockId.toString('hex'), leaf_count: head.leafCount.toString(),
    root_le: head.root.toString('hex'), fee_escrow: head.feeEscrow.toString(),
    unconsumed_liabilities: head.unconsumedLiabilities.toString(), block_version: '4'};
}
export function initializeRetained({client, binary, expectedSha256, database, chain, genesis, receiptFile}) {
  let fd, child, head;
  const started = performance.now();
  const receipt = {format: 'CP04-PRODUCER-RETAIN-INIT01', hard_bytes: HARD_BYTES,
    process_exit: null, signal: null, transport_error: false, binary_prechecked: false,
    binary_postchecked: false, head_reopened_and_matched: false, passed: false};
  try {
    need(typeof expectedSha256 === 'string' && /^[0-9a-f]{64}$/.test(expectedSha256));
    need(Buffer.isBuffer(chain) && chain.length === 32);
    for (const name of [database, database + '-wal', database + '-shm']) need(!fs.existsSync(name));
    fd = fs.openSync(binary, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    inspect(fd, binary, expectedSha256); receipt.binary_prechecked = true;
    child = spawnSync('/proc/self/fd/3', ['init-retain', database, chain.toString('hex'), genesis, HARD_BYTES], {
      stdio: ['ignore', 'pipe', 'pipe', fd], cwd: '/', env: ENV,
      timeout: 120000, maxBuffer: OUTPUT_BYTES, killSignal: 'SIGKILL',
    });
    receipt.process_exit = child.status; receipt.signal = child.signal;
    receipt.transport_error = !!child.error;
    inspect(fd, binary, expectedSha256); receipt.binary_postchecked = true;
    need(!child.error && child.signal === null && child.status === 0 &&
      Buffer.isBuffer(child.stdout) && child.stdout.length > 1 && child.stdout.length <= OUTPUT_BYTES &&
      Buffer.isBuffer(child.stderr) && child.stderr.length === 0);
    const text = child.stdout.toString('utf8');
    need(Buffer.from(text, 'utf8').equals(child.stdout));
    const result = JSON.parse(text);
    need(JSON.stringify(result) + '\n' === text);
    // Reopen through the unchanged approved wrapper and compare every typed field.
    head = client.head();
    const expected = publicHead(head);
    need(Object.keys(result).sort().join(',') === Object.keys(expected).sort().join(',') &&
      Object.entries(expected).every(([key, value]) => result[key] === value));
    receipt.head_reopened_and_matched = true; receipt.passed = true; receipt.head = expected;
  } finally {
    child?.stdout?.fill(0); child?.stderr?.fill(0);
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch { receipt.passed = false; receipt.close_failed = true; }
    }
    receipt.wall_seconds = (performance.now() - started) / 1000;
    fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  }
  need(receipt.passed);
  return head;
}
