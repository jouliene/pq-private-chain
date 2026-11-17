// Local streaming wallet recovery relative to an independently supplied endpoint.
// Reduced history omits proofs: payment validity and canonicality are DELEGATED.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import {withWallet, WalletOperationalError} from './keys.mjs';
import {parseStatement, P, MAX, WalletInputError} from './codec.mjs';
import {wipeOpening} from '../../experiments/compact-receiving-v1/cp03/receipt.mjs';

const recovered = new WeakMap();
function need(condition) { if (!condition) throw new WalletInputError(); }
function bytes(value, size) { need(Buffer.isBuffer(value) && value.length === size); return value; }
function h64(label, value, suffix = Buffer.alloc(0)) {
  const tag = Buffer.from('PQPC/CP3/' + label), size = Buffer.alloc(4), length = Buffer.alloc(2);
  length.writeUInt16LE(tag.length); size.writeUInt32LE(value.length);
  return crypto.createHash('sha3-512').update(length).update(tag).update(size).update(value).update(suffix).digest();
}
function exact(fd, size, allowEof = false) {
  const result = Buffer.alloc(size); let at = 0;
  while (at < size) {
    const n = fs.readSync(fd, result, at, size - at, null);
    if (n === 0) { if (at === 0 && allowEof) return null; throw new WalletInputError(); }
    at += n;
  }
  return result;
}
function cursor(buffer) {
  let at = 0;
  return {
    take(size) { need(Number.isInteger(size) && size >= 0 && at + size <= buffer.length);
      const value = buffer.subarray(at, at + size); at += size; return value; },
    blob(max) { const n = this.take(4).readUInt32LE(); need(n <= max); return this.take(n); },
    end() { need(at === buffer.length); },
  };
}
function reducedRecord(raw, chain) {
  const r = cursor(raw); need(r.take(8).equals(Buffer.from('CPSCAN03')));
  const prefix = r.blob(9423), proofDigest = r.take(64); r.end();
  const p = cursor(prefix); need(p.take(8).equals(Buffer.from('CPBODY03')));
  need(p.take(2).readUInt16LE() === 3);
  const statementSize = p.take(2).readUInt16LE(), proofSize = p.take(4).readUInt32LE();
  const authorizationSize = p.take(2).readUInt16LE(); need(p.take(2).readUInt16LE() === 0);
  need([448, 464, 528].includes(statementSize) && proofSize > 0 && proofSize <= 2097152);
  const statement = p.take(statementSize), parsed = parseStatement(statement);
  need(parsed.chain.equals(chain) && authorizationSize === (parsed.arity === 0 ? 4627 : 0));
  const envelopes = [p.take(2164), p.take(2164)];
  for (const envelope of envelopes) need(envelope.subarray(0, 8).equals(Buffer.from('4350523303010000', 'hex')));
  p.take(authorizationSize); p.end();
  need(prefix.length === [9423, 4812, 4876][parsed.arity] && raw.length === [9499, 4888, 4952][parsed.arity]);
  return {statement, parsed, envelopes, id: h64('BODY', prefix, proofDigest)};
}
function block(raw, endpoint, prior) {
  const r = cursor(raw); need(r.take(8).equals(Buffer.from('CPSBLK03')));
  const header = r.blob(1232), h = cursor(header);
  need(h.take(8).equals(Buffer.from('CPBLOCK3')) && h.take(2).readUInt16LE() === 3 && h.take(2).readUInt16LE() === 0);
  need(h.take(32).equals(endpoint.chain) && h.take(64).equals(prior.id));
  const height = h.take(8).readBigUInt64LE(), count = h.take(2).readUInt16LE();
  need(height === prior.height + 1n && height <= endpoint.height && count >= 1 && count <= 16 &&
    h.take(2).readUInt16LE() === 0);
  const leafCount = h.take(8).readBigUInt64LE();
  need(leafCount === prior.leafCount + 2n * BigInt(count) && leafCount <= (1n << 40n));
  const root = Buffer.from(h.take(64));
  for (let i = 0; i < 8; i++) need(root.readBigUInt64LE(i * 8) < P);
  const fees = h.take(8).readBigUInt64LE(), liabilities = h.take(8).readBigUInt64LE();
  need(fees <= MAX && liabilities <= MAX);
  const ids = Array.from({length: count}, () => h.take(64)); h.end();
  const records = ids.map(id => {
    const record = reducedRecord(r.blob(9499), endpoint.chain); need(record.id.equals(id)); return record;
  });
  r.end(); const id = h64('BLOCK', header);
  if (height === endpoint.height) need(id.equals(endpoint.blockId));
  return {height, leafCount, root, id, records};
}
function disposeCandidate(candidate) { wipeOpening(candidate.opening); candidate.nf.fill(0); }
function disposeAllCandidates(candidates) {
  let clean = true;
  for (const candidate of candidates) { try { disposeCandidate(candidate); } catch { clean = false; } }
  return clean;
}
function stable(a, b) {
  return ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
}

// No old wallet database, witness or spent-state snapshot is accepted.
// The endpoint and inventory basis must come from the operator's documented trust path.
// This function cannot authenticate that external provenance or network consensus.
export function recoverHistory(wallet, scanFile, trustedEndpoint, inventoryBasis = 'unknown') {
  need(['unknown', 'conditional-on-independent-current-inventory'].includes(inventoryBasis));
  const endpoint = {chain: Buffer.from(bytes(trustedEndpoint.chain, 32)),
    genesisId: Buffer.from(bytes(trustedEndpoint.genesisId, 64)),
    blockId: Buffer.from(bytes(trustedEndpoint.blockId, 64)), height: trustedEndpoint.height};
  need(typeof endpoint.height === 'bigint' && endpoint.height >= 0n && endpoint.height < (1n << 64n));
  if (endpoint.height === 0n) need(endpoint.blockId.equals(endpoint.genesisId));
  return withWallet(wallet, value => {
    need(value.chain.equals(endpoint.chain));
    let fd, published = false;
    const recipients = [], unspent = new Map();
    function cleanup(wipeCandidates) {
      let clean = !wipeCandidates || disposeAllCandidates(unspent.values());
      // Each resource gets its own attempt even when a previous cleanup failed.
      while (recipients.length) {
        const recipient = recipients.pop();
        try { value.adapter.disposeRecipient(recipient); } catch { clean = false; }
      }
      if (fd !== undefined) {
        const closing = fd; fd = undefined;
        try { fs.closeSync(closing); } catch { clean = false; }
      }
      return clean;
    }
    try {
      fd = fs.openSync(scanFile, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
      const before = fs.fstatSync(fd, {bigint: true}); need(before.isFile());
      for (const key of value.keys) recipients.push(value.adapter.prepareRecipient(key.descriptor, key.key, value.spending));
      let prior = {height: 0n, id: endpoint.genesisId, leafCount: 0n, root: null};
      // Retain only public cursor fields, never an old block's record buffers.
      function position(next) {
        return {height: next.height, id: next.id, leafCount: next.leafCount, root: next.root};
      }
      let parsedPrior = prior, readBytes = 0n, windowPayments = 0;
      const window = [];
      function applyWindow() {
        if (windowPayments === 0) return;
        need(window.length > 0 && windowPayments <= 256);
        // One complete checked helper response before any effects in this window.
        const contexts = value.adapter.contextsBatch(window.flatMap(next =>
          next.records.map(record => record.statement)));
        need(contexts.length === windowPayments);
        let at = 0;
        for (const next of window) {
          // Public lookahead never changes the order of wallet effects.
          const spentHere = new Set();
          for (const record of next.records) for (const nf of record.parsed.nullifiers) {
            const id = nf.toString('hex'); need(!spentHere.has(id)); spentHere.add(id);
            const old = unspent.get(id);
            if (old) { disposeCandidate(old); unspent.delete(id); }
          }
          const entries = [], occurrences = new Map();
          for (let index = 0; index < next.records.length; index++) for (let ordinal = 0; ordinal < 2; ordinal++) {
            const context = contexts[at + index][ordinal], envelope = next.records[index].envelopes[ordinal];
            need(value.adapter.digest(context, envelope).equals(next.records[index].parsed.receipts[ordinal]));
            const info = value.adapter.contextInfo(context), id = info.origin.toString('hex') + ':' + info.cm.toString('hex');
            need(!occurrences.has(id)); occurrences.set(id, prior.leafCount + BigInt(2 * index + ordinal));
            entries.push({context, envelope});
          }
          const collected = value.adapter.collectLocalCandidates(recipients, entries);
          const pending = collected.candidates;
          try {
            for (const candidate of pending) {
              const id = candidate.nf.toString('hex'), occurrence = candidate.origin.toString('hex') + ':' + candidate.cm.toString('hex');
              need(occurrences.has(occurrence) && !unspent.has(id) && !spentHere.has(id));
              candidate.index = occurrences.get(occurrence);
              candidate.funding_basis = 'included-in-endpoint-linked-history-with-delegated-payment-validity';
              candidate.spentness_basis = 'complete-ordered-nullifier-stream-relative-to-endpoint';
              unspent.set(id, candidate);
            }
          } catch (error) {
            if (!disposeAllCandidates(pending)) throw new WalletOperationalError();
            throw error;
          }
          prior = position(next);
          at += next.records.length;
        }
        need(at === windowPayments);
        window.length = 0; windowPayments = 0;
      }
      for (;;) {
        const prefix = exact(fd, 4, true); if (prefix === null) break;
        const size = prefix.readUInt32LE(); need(size > 0 && size <= 153292 && parsedPrior.height < endpoint.height);
        const raw = exact(fd, size); readBytes += 4n + BigInt(size);
        // Validate this whole block against the separate parsing cursor first.
        const next = block(raw, endpoint, parsedPrior);
        parsedPrior = position(next);
        // Whole blocks are never split: nonfinal windows contain 241..256 payments.
        if (windowPayments + next.records.length > 256) applyWindow();
        window.push(next); windowPayments += next.records.length;
      }
      applyWindow();
      need(prior.height === endpoint.height && prior.id.equals(endpoint.blockId) &&
        readBytes === before.size && stable(before, fs.fstatSync(fd, {bigint: true})));
      let balance = 0n;
      for (const candidate of unspent.values()) balance += candidate.opening.note.readBigUInt64LE(8);
      need(balance <= MAX);
      if (!cleanup(false)) throw new WalletOperationalError();
      const token = Object.freeze({type: 'CP03-recovered-private-wallet-view'});
      recovered.set(token, {unspent, balance, endpoint, leafCount: prior.leafCount, root: prior.root});
      published = true;
      return {state: token, history_linkage_complete: true,
        payment_validity: 'delegated-to-independently-supplied-endpoint',
        canonicality: 'external-consensus-or-explicit-laboratory-checkpoint',
        inventory_completeness_basis: inventoryBasis};
    } catch (error) {
      if (error instanceof WalletInputError) throw error;
      throw new WalletOperationalError();
    } finally {
      if (!cleanup(!published)) throw new WalletOperationalError();
    }
  });
}

// Trusted wallet code only: returned notes are private RAM, never logs/public artifacts.
export function withRecovered(token, operation) {
  const value = recovered.get(token); need(!!value && typeof operation === 'function'); return operation(value);
}
export function disposeRecovered(token) {
  const value = recovered.get(token); need(!!value);
  const clean = disposeAllCandidates(value.unspent.values());
  value.unspent.clear(); value.balance = 0n; recovered.delete(token);
  if (!clean) throw new WalletOperationalError();
}
