// Portable PUBLIC grammar controls. Proof verification and private recovery are
// deliberately outside this test; inputs are the retained genuine public fixture.
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {encodeHistoryRequest, visitAuthenticatedContinuation, visitAuthenticatedHistory} from '../source/wallet/cp03/recovery.mjs';

const fixture = fileURLToPath(new URL('../fixtures/cp03-reference/', import.meta.url));
const expected = JSON.parse(fs.readFileSync(path.join(fixture, 'expected.json')));
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'cp03-sync-parser-'));
const checks = [];
function h64(label, value, suffix = Buffer.alloc(0)) {
  const tag = Buffer.from('PQPC/CP3/' + label), length = Buffer.alloc(2), size = Buffer.alloc(4);
  length.writeUInt16LE(tag.length); size.writeUInt32LE(value.length);
  return crypto.createHash('sha3-512').update(length).update(tag).update(size).update(value).update(suffix).digest();
}
function blob(value) { const size = Buffer.alloc(4); size.writeUInt32LE(value.length); return Buffer.concat([size, value]); }
function put(name, value) { const file = path.join(work, name); fs.writeFileSync(file, value, {flag: 'wx'}); return file; }
function sameCursor(actual, head) {
  assert.equal(actual.height, head.height); assert(actual.id.equals(head.blockId));
  assert.equal(actual.leafCount, head.leafCount); assert(actual.root.equals(head.root));
  assert.equal(actual.fees, head.feeEscrow); assert.equal(actual.liabilities, head.unconsumedLiabilities);
}
try {
  const heads = [], frames = [];
  for (const entry of expected.blocks) {
    const header = fs.readFileSync(path.join(fixture, entry.header));
    const body = fs.readFileSync(path.join(fixture, entry.body));
    const proofSize = body.readUInt32LE(12), prefix = body.subarray(0, body.length - proofSize);
    const proofDigest = h64('PROOF', body.subarray(body.length - proofSize));
    assert.equal(header.readUInt16LE(116), 1);
    assert(h64('BODY', prefix, proofDigest).equals(header.subarray(208, 272)));
    heads.push({chain: Buffer.from(header.subarray(12, 44)), genesisId: Buffer.from(expected.endpoint.genesisId, 'hex'),
      blockVersion: 3, height: header.readBigUInt64LE(108), blockId: h64('BLOCK', header),
      leafCount: header.readBigUInt64LE(120), root: Buffer.from(header.subarray(128, 192)),
      feeEscrow: header.readBigUInt64LE(192), unconsumedLiabilities: header.readBigUInt64LE(200)});
    const reduced = Buffer.concat([Buffer.from('CPSCAN03'), blob(prefix), proofDigest]);
    frames.push(blob(Buffer.concat([Buffer.from('CPSBLK03'), blob(header), blob(reduced)])));
  }
  const base = heads[0], target = heads.at(-1), tail = frames.slice(1);
  const request = encodeHistoryRequest(base, target);
  assert.equal(request.length, 436); assert.equal(request.subarray(0, 8).toString(), 'CPHREQ01');
  assert.equal(request.readUInt16LE(8), 1); assert.equal(request.readUInt16LE(10), 3);
  assert.equal(request.readBigUInt64LE(108), base.height);
  assert(request.subarray(116, 180).equals(base.blockId));
  assert.equal(request.readBigUInt64LE(180), base.leafCount);
  assert(request.subarray(188, 252).equals(base.root));
  assert.equal(request.readBigUInt64LE(252), base.feeEscrow);
  assert.equal(request.readBigUInt64LE(260), base.unconsumedLiabilities);
  assert.equal(request.readBigUInt64LE(268), target.height); assert.equal(request.readBigUInt64LE(428), 3n);
  checks.push('fixed436-request-layout');
  const header = Buffer.from(request); header.write('CPHCONT1');
  const response = Buffer.concat([header, ...tail]);
  const full = visitAuthenticatedHistory(put('full.scan', Buffer.concat(frames)), target, undefined, () => {});
  let seen = 0;
  const suffix = visitAuthenticatedContinuation(put('suffix.scan', response), base, target, undefined,
    window => { seen += window.length; });
  sameCursor(full.cursor, target); sameCursor(suffix.cursor, target);
  assert.equal(seen, 3); assert.equal(full.authenticatedBlocks, 4n);
  assert.equal(suffix.authenticatedBlocks, 3n); assert.equal(suffix.authenticatedRecords, 3n);
  assert.equal(suffix.readBytes, BigInt(response.length)); checks.push('genuine-public-full-suffix-cursor-equivalence');
  const zero = encodeHistoryRequest(target, target); zero.write('CPHCONT1');
  const noop = visitAuthenticatedContinuation(put('zero.scan', zero), target, target, undefined,
    () => { throw new Error('zero-range callback'); });
  sameCursor(noop.cursor, target); assert.equal(noop.authenticatedBlocks, 0n);
  assert.equal(noop.readBytes, 436n); checks.push('zero-range-header-eof');
  let id = 0;
  function rejects(name, bytes, selected = target, own = base) {
    assert.throws(() => visitAuthenticatedContinuation(put('bad-' + (++id), bytes), own, selected, undefined, () => {}),
      error => error.name === 'WalletInputError');
    checks.push(name);
  }
  for (const [name, offset] of [['magic', 0], ['format', 8], ['block-version', 10], ['chain', 12], ['genesis', 44],
    ['base-height', 108], ['base-id', 116], ['base-count', 180], ['base-root', 188], ['base-fees', 252],
    ['base-liabilities', 260], ['target-height', 268], ['target-id', 276], ['target-count', 340],
    ['target-root', 348], ['target-fees', 412], ['target-liabilities', 420], ['frame-count', 428]]) {
    const bad = Buffer.from(response); bad[offset] ^= 1; rejects('reject-' + name, bad);
  }
  rejects('reject-truncated-header', response.subarray(0, 435));
  rejects('reject-truncated-frame', response.subarray(0, response.length - 1));
  rejects('reject-trailing-byte', Buffer.concat([response, Buffer.from([0])]));
  rejects('reject-missing-block', Buffer.concat([header, ...tail.slice(1)]));
  rejects('reject-duplicate-block', Buffer.concat([header, tail[0], ...tail]));
  rejects('reject-reordered-blocks', Buffer.concat([header, tail[1], tail[0], tail[2]]));
  rejects('reject-wrong-selected-endpoint', response, {...target, blockId: Buffer.alloc(64)});
  rejects('reject-wrong-own-base-accounting', response, target, {...base, feeEscrow: base.feeEscrow + 1n});
  rejects('reject-zero-range-trailing-frame', Buffer.concat([zero, tail[0]]), target, target);
  const link = path.join(work, 'symlink.scan'); fs.symlinkSync(path.join(work, 'suffix.scan'), link);
  assert.throws(() => visitAuthenticatedContinuation(link, base, target, undefined, () => {}), error => error.code === 'ELOOP');
  checks.push('reject-symlink-file');
  console.log(JSON.stringify({format: 'CP04-WALLET-SYNC-PARSER-CONTROLS01', passed: true, checks,
    scope: 'Public grammar/linkage and counters only; no proof verification, wallet secrets, native helper or private spending.'}));
} finally { fs.rmSync(work, {recursive: true, force: true}); }
