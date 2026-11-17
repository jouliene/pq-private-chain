// Private joint receiving/witness coordinator. No DB, remote path or state import API.
import * as crypto from 'node:crypto';
import {WalletInputError, P, MAX, parseStatement} from './codec.mjs';
import {WalletOperationalError, leaseWallet, withWalletLease, releaseWalletLease} from './keys.mjs';
import {preparePayment, publicPayment, disposePayment, paymentLifecycle, retirePayment} from './payments.mjs';
import {prepareHistoryContext, visitAuthenticatedHistory, visitAuthenticatedContinuation, encodeHistoryRequest} from './recovery.mjs';
import {fixedHashCore} from '../../experiments/compact-receiving-v1/cp03/hash-core.mjs';
import {wipeOpening} from '../../experiments/compact-receiving-v1/cp03/receipt.mjs';

const sessions = new WeakMap(), views = new WeakMap();
const STATE_MAX = 173248, ANCHORS = 256, U64 = (1n << 64n) - 1n;
function need(ok) { if (!ok) throw new WalletInputError(); }
function fixed(value, length) { need(Buffer.isBuffer(value) && value.length === length); return value; }
function digest(value) {
  fixed(value, 64);
  for (let at = 0; at < 64; at += 8) need(value.readBigUInt64LE(at) < P);
  return value;
}
function integer(value, max = U64) { need(typeof value === 'bigint' && value >= 0n && value <= max); return value; }
function synchronous(value) { need(!(value && typeof value.then === 'function')); return value; }
function callback(value) { need(typeof value === 'function' && value.constructor?.name !== 'AsyncFunction'); }
function copyCursor(cursor) {
  return {height: cursor.height, id: Buffer.from(cursor.id), leafCount: cursor.leafCount,
    root: Buffer.from(cursor.root), fees: cursor.fees, liabilities: cursor.liabilities};
}
function sameCursor(a, b) {
  return a.height === b.height && a.id.equals(b.id) && a.leafCount === b.leafCount &&
    a.root.equals(b.root) && a.fees === b.fees && a.liabilities === b.liabilities;
}
function recordCursor(next) {
  return {height: next.height, id: next.id, leafCount: next.leafCount, root: next.root,
    fees: next.fees, liabilities: next.liabilities};
}
function head(value, cursor) {
  return {chain: Buffer.from(value.chain), genesisId: Buffer.from(value.genesisId),
    blockVersion: value.blockVersion, height: cursor.height, blockId: Buffer.from(cursor.id),
    leafCount: cursor.leafCount, root: Buffer.from(cursor.root), feeEscrow: cursor.fees,
    unconsumedLiabilities: cursor.liabilities};
}
function target(value, supplied) {
  const {endpoint} = prepareHistoryContext(supplied, value.context);
  need(endpoint.chain.equals(value.chain) && endpoint.genesisId.equals(value.genesisId) &&
    endpoint.blockVersion === value.blockVersion);
  const cursor = {height: endpoint.height, id: Buffer.from(endpoint.blockId),
    leafCount: integer(supplied.leafCount, 1n << 40n), root: Buffer.from(digest(supplied.root)),
    fees: integer(supplied.feeEscrow, MAX), liabilities: integer(supplied.unconsumedLiabilities, MAX)};
  need(cursor.fees + cursor.liabilities <= value.total);
  if (cursor.height === 0n) need(sameCursor(cursor, value.genesisCursor));
  return cursor;
}
function cloneOpening(opening) {
  return {note: Buffer.from(opening.note), cm: Buffer.from(opening.cm), memo: Buffer.from(opening.memo)};
}
function copyOwned(owned) {
  return {token: Buffer.from(owned.token), nf: Buffer.from(owned.nf), origin: Buffer.from(owned.origin),
    cm: Buffer.from(owned.cm), index: owned.index, opening: cloneOpening(owned.opening)};
}
function wipeOwned(owned) {
  wipeOpening(owned.opening);
  for (const name of ['token', 'nf', 'origin', 'cm']) owned[name]?.fill(0);
}
function wipeWitnesses(items) {
  for (const item of items.values()) { item.token.fill(0); for (const sibling of item.siblings) sibling.fill(0); }
  items.clear();
}
function cloneState(state) {
  return {cursor: copyCursor(state.cursor), native: Buffer.from(state.native),
    owned: new Map([...state.owned].map(([id, owned]) => [id, copyOwned(owned)])),
    witnesses: new Map([...state.witnesses].map(([id, item]) => [id, {token: Buffer.from(item.token),
      index: item.index, siblings: item.siblings.map(sibling => Buffer.from(sibling))}])),
    anchors: state.anchors.map(copyCursor)};
}
function wipeState(state) {
  if (!state) return;
  state.native?.fill(0);
  for (const owned of state.owned.values()) wipeOwned(owned);
  state.owned.clear(); wipeWitnesses(state.witnesses); state.anchors.length = 0;
}
function wipeCandidate(candidate) {
  if (!candidate) return;
  wipeState(candidate.state); for (const state of candidate.history) wipeState(state);
  candidate.state = null; candidate.history.length = 0;
}
function invalidateView(value) {
  if (value.view) views.delete(value.view);
  value.view = null;
}
function revoke(value) {
  value.revision++; invalidateView(value);
  if (value.prepared) retirePayment(value.prepared);
  if (value.active) { wipeCandidate(value.active); value.active = null; }
}
function clearCommitted(value) {
  wipeState(value.current); value.current = null;
  for (const state of value.history) wipeState(state);
  value.history.length = 0; value.selectedBase = null;
}
function lease(value) {
  try { return withWalletLease(value.lease, (wallet, inventory) => ({wallet, inventory})); }
  catch {
    revoke(value); clearCommitted(value); value.mode = 'inventory-invalid';
    throw new WalletOperationalError();
  }
}
function session(token) {
  const value = sessions.get(token); need(!!value && !value.disposed); lease(value); return value;
}
function current(view) {
  const held = views.get(view); need(!!held);
  const value = session(held.session);
  need(value.mode === 'ready' && !value.active && value.view === view && held.revision === value.revision && !!value.current);
  return value;
}
function balance(state) {
  let result = 0n;
  for (const owned of state.owned.values()) result += owned.opening.note.readBigUInt64LE(8);
  need(result <= MAX); return result;
}
function stateBufferBytes(state) {
  if (!state) return 0;
  let result = state.native.length + state.cursor.id.length + state.cursor.root.length;
  for (const anchor of state.anchors) result += anchor.id.length + anchor.root.length;
  for (const item of state.owned.values()) for (const buffer of [item.token, item.nf, item.origin, item.cm,
    item.opening.note, item.opening.cm, item.opening.memo]) result += buffer.length;
  for (const item of state.witnesses.values()) {
    result += item.token.length;
    for (const sibling of item.siblings) result += sibling.length;
  }
  return result;
}
function retainedBuffers(value) {
  return {currentBufferBytes: stateBufferBytes(value.current),
    journalBufferBytes: value.history.reduce((sum, state) => sum + stateBufferBytes(state), 0),
    journalCheckpoints: value.history.length,
    scope: 'Committed state/journal Buffer payload bytes only; excludes JS objects, allocator, staging, packet, recipients and process RSS.'};
}
function recoveryBase(value) {
  if (value.selectedTarget) return value.selectedBase;
  return value.mode === 'replay-required' ? null : value.current;
}
function recoveryMode(value) {
  return recoveryBase(value) === null ? 'full-replay' : value.selectedTarget ? 'selected-replay' : 'append';
}
function recoveryResult(value, view, inventoryBasis, mode, walked) {
  return {state: view, history_linkage_complete: true, local_witnesses: true,
    payment_validity: 'delegated-to-independently-supplied-endpoint',
    canonicality: 'external-consensus-or-explicit-laboratory-checkpoint', inventory_completeness_basis: inventoryBasis,
    synchronization: {mode, readBytes: walked.readBytes, authenticatedBlocks: walked.authenticatedBlocks,
      authenticatedRecords: walked.authenticatedRecords, peakWindowBlocks: walked.peakWindowBlocks,
      peakWindowRecords: walked.peakWindowRecords, retained: retainedBuffers(value)}};
}
function wipeNative(result) {
  result?.state?.fill(0);
  if (Array.isArray(result?.witnesses)) for (const item of result.witnesses) {
    item.token?.fill(0); if (Array.isArray(item.siblings)) for (const sibling of item.siblings) sibling.fill(0);
  }
}
function advance(value, state, forget, leaves) {
  let result;
  try {
    result = value.core.treeAdvance(value.chain, {state: state.native, maxOwned: value.maxOwned, forget, leaves});
    lease(value);
    need(Buffer.isBuffer(result.state) && result.state.length > 0 && result.state.length <= STATE_MAX);
    integer(result.count, 1n << 40n); digest(result.root);
    need(Array.isArray(result.witnesses) && result.witnesses.length === state.owned.size);
    const byToken = new Map([...state.owned.values()].map(owned => [owned.token.toString('hex'), owned]));
    const seen = new Set(); let previous = -1n;
    for (const item of result.witnesses) {
      const id = fixed(item.token, 16).toString('hex'), owned = byToken.get(id);
      need(!!owned && !seen.has(id)); seen.add(id);
      integer(item.index, (1n << 40n) - 1n);
      need(item.index === owned.index && item.index < result.count && item.index > previous);
      previous = item.index;
      need(Array.isArray(item.siblings) && item.siblings.length === 40);
      for (const sibling of item.siblings) digest(sibling);
    }
    return result;
  } catch (error) { wipeNative(result); throw error; }
}
function adoptNative(state, result) {
  state.native?.fill(0); wipeWitnesses(state.witnesses);
  state.native = result.state;
  state.witnesses = new Map(result.witnesses.map(item => [item.token.toString('hex'), item]));
}
function checkpoint(value, candidate) {
  candidate.history.push(cloneState(candidate.state));
  while (candidate.history.length > value.rewindBlocks + 1) wipeState(candidate.history.shift());
}
function initial(value) {
  const state = {cursor: copyCursor(value.genesisCursor), native: null, owned: new Map(),
    witnesses: new Map(), anchors: [copyCursor(value.genesisCursor)]};
  let result;
  try {
    result = advance(value, state, [], []);
    need(result.count === 0n && result.root.equals(value.genesisCursor.root));
    adoptNative(state, result); result = null;
    return {state, history: [cloneState(state)]};
  } catch (error) { wipeNative(result); wipeState(state); throw error; }
}
function freshToken(value) {
  need(value.nextToken < U64);
  const token = Buffer.alloc(16); value.tokenPrefix.copy(token); token.writeBigUInt64LE(++value.nextToken, 8);
  return token;
}
function disposePending(pending) {
  let clean = true;
  for (const item of pending) {
    try { wipeOpening(item.opening); item.nf.fill(0); } catch { clean = false; }
  }
  return clean;
}
function applyBlock(value, candidate, next, contexts, adapter, recipients) {
  const state = candidate.state, prior = state.cursor;
  need(next.height === prior.height + 1n && next.leafCount === prior.leafCount + 2n * BigInt(next.records.length));
  const spentHere = new Set(), forget = [], entries = [], occurrences = new Map(), leaves = [];
  let pending = [], result;
  try {
    // All block nullifiers precede every discovery, as in canonical recovery.
    for (const record of next.records) for (const nf of record.parsed.nullifiers) {
      const id = nf.toString('hex'); need(!spentHere.has(id)); spentHere.add(id);
      const owned = state.owned.get(id);
      if (owned) { forget.push(Buffer.from(owned.token)); wipeOwned(owned); state.owned.delete(id); }
    }
    for (let row = 0; row < next.records.length; row++) for (let ordinal = 0; ordinal < 2; ordinal++) {
      const item = contexts[row][ordinal], envelope = next.records[row].envelopes[ordinal];
      need(adapter.digest(item, envelope).equals(next.records[row].parsed.receipts[ordinal]));
      const info = adapter.contextInfo(item), id = info.origin.toString('hex') + ':' + info.cm.toString('hex');
      need(!occurrences.has(id)); occurrences.set(id, leaves.length);
      leaves.push({origin: info.origin, cm: info.cm, token: null}); entries.push({context: item, envelope});
    }
    pending = entries.length === 0 ? [] : adapter.collectLocalCandidates(recipients, entries).candidates;
    for (const item of pending) {
      const id = item.nf.toString('hex'), occurrence = item.origin.toString('hex') + ':' + item.cm.toString('hex');
      need(occurrences.has(occurrence) && !state.owned.has(id) && !spentHere.has(id) && state.owned.size < value.maxOwned);
      const ordinal = occurrences.get(occurrence), token = freshToken(value);
      need(leaves[ordinal].token === null);
      const owned = {token, nf: Buffer.from(item.nf), origin: Buffer.from(item.origin), cm: Buffer.from(item.cm),
        index: prior.leafCount + BigInt(ordinal), opening: cloneOpening(item.opening)};
      state.owned.set(id, owned); leaves[ordinal].token = token;
    }
    if (leaves.length === 0) need(next.root.equals(prior.root) && next.fees === prior.fees && next.liabilities === prior.liabilities);
    // Tokens are attached to their incoming leaves, never an EOF path lookup.
    result = advance(value, state, forget, leaves);
    need(result.count === next.leafCount && result.root.equals(next.root));
    adoptNative(state, result); result = null;
    state.cursor = copyCursor(recordCursor(next)); balance(state);
    state.anchors.push(copyCursor(state.cursor));
    const minimum = state.cursor.height > 255n ? state.cursor.height - 255n : 0n;
    while (state.anchors[0].height < minimum) state.anchors.shift();
    need(state.anchors.length <= ANCHORS);
    checkpoint(value, candidate);
  } finally {
    wipeNative(result);
    for (const token of forget) token.fill(0);
    if (!disposePending(pending)) throw new WalletOperationalError();
  }
}

export class LocalWitnessReplayRequired extends Error {
  constructor() { super('CP03 local witness authenticated replay required'); this.name = 'LocalWitnessReplayRequired'; }
}
export function createLocalWitnessSession(wallet, helperSha256,
  {trustedGenesis, genesis, genesisRoot, maxOwned = 64, rewindBlocks = 8}) {
  need(Number.isInteger(maxOwned) && maxOwned >= 1 && maxOwned <= 64 &&
    Number.isInteger(rewindBlocks) && rewindBlocks >= 0 && rewindBlocks <= 64);
  need(Buffer.isBuffer(genesis));
  const context = {genesis: Buffer.from(genesis), genesisRoot: Buffer.from(digest(genesisRoot))};
  const {endpoint, genesis: parsedGenesis} = prepareHistoryContext({...trustedGenesis,
    height: 0n, blockId: trustedGenesis.genesisId}, context);
  const core = fixedHashCore(helperSha256); need(typeof core.treeAdvance === 'function');
  const held = leaseWallet(wallet, helperSha256);
  try {
    withWalletLease(held, value => need(value.chain.equals(endpoint.chain)));
    const token = Object.freeze({type: 'CP03-private-local-witness-session'});
    sessions.set(token, {wallet, lease: held, context, core, chain: endpoint.chain, genesisId: endpoint.genesisId,
      blockVersion: endpoint.blockVersion, total: parsedGenesis.liabilities, maxOwned, rewindBlocks,
      genesisCursor: {height: 0n, id: endpoint.genesisId, leafCount: 0n, root: context.genesisRoot,
        fees: 0n, liabilities: parsedGenesis.liabilities}, tokenPrefix: crypto.randomBytes(8), nextToken: 0n,
      current: null, history: [], active: null, view: null, borrow: false, revision: 0,
      prepared: null, helperSha256,
      selectedTarget: null, selectedBase: null, mode: 'unrecovered', disposed: false});
    return token;
  } catch (error) { releaseWalletLease(held); throw error; }
}
export function recoverLocalWitnesses(token, scanFile, trustedHead, inventoryBasis = 'unknown') {
  return recoverLocal(token, scanFile, trustedHead, inventoryBasis, false);
}
// Detached PUBLIC request bytes only: no peer/caller cursor becomes a private base.
export function localWitnessSyncRequest(token, trustedHead) {
  const value = session(token); need(!value.active && !value.borrow && value.mode !== 'inventory-invalid');
  const expected = target(value, trustedHead);
  if (value.selectedTarget) need(sameCursor(expected, value.selectedTarget));
  const base = recoveryBase(value), own = base?.cursor ?? value.genesisCursor;
  need(expected.height >= own.height);
  const baseHead = head(value, own), targetHead = head(value, expected);
  const unchanged = value.mode === 'ready' && !!value.current && sameCursor(value.current.cursor, expected);
  return {base: baseHead, target: targetHead, mode: unchanged ? 'unchanged' : recoveryMode(value),
    request: unchanged ? null : encodeHistoryRequest(baseHead, targetHead, value.context)};
}
export function synchronizeLocalWitnesses(token, continuationFile, trustedHead, inventoryBasis = 'unknown') {
  return recoverLocal(token, continuationFile, trustedHead, inventoryBasis, true);
}
function recoverLocal(token, scanFile, trustedHead, inventoryBasis, continuation) {
  const value = session(token);
  need(!value.active && !value.borrow && value.mode !== 'inventory-invalid');
  need(['unknown', 'conditional-on-independent-current-inventory'].includes(inventoryBasis));
  const expected = target(value, trustedHead);
  if (value.selectedTarget) need(sameCursor(expected, value.selectedTarget));
  const from = recoveryBase(value), mode = continuation ? recoveryMode(value) : 'full-prefix-reference';
  if (from) need(expected.height >= from.cursor.height);
  if (continuation && value.mode === 'ready' && value.current && sameCursor(value.current.cursor, expected)) {
    need(scanFile === null || scanFile === undefined);
    need(!!value.view && current(value.view) === value);
    return recoveryResult(value, value.view, inventoryBasis, 'unchanged', {readBytes: 0n,
      authenticatedBlocks: 0n, authenticatedRecords: 0n, peakWindowBlocks: 0, peakWindowRecords: 0});
  }
  const revision = value.revision, priorMode = value.mode;
  let candidate, published = false, cleanupFailed = false;
  const recipients = []; let adapter;
  function cleanupRecipients() {
    while (recipients.length) {
      try { adapter.disposeRecipient(recipients.pop()); } catch { cleanupFailed = true; }
    }
    return !cleanupFailed;
  }
  try {
    candidate = from ? {state: cloneState(from),
      history: value.history.filter(state => state.cursor.height <= from.cursor.height).map(cloneState)} : initial(value);
    value.active = candidate;
    const base = copyCursor(candidate.state.cursor); let baseSeen = continuation || base.height === 0n;
    const held = lease(value); adapter = held.wallet.adapter;
    for (const key of held.wallet.keys) recipients.push(adapter.prepareRecipient(key.descriptor, key.key, held.wallet.spending));
    const onWindow = window => {
      need(value.revision === revision && value.active === candidate); lease(value);
      for (const next of window) if (next.height === base.height) {
        need(sameCursor(recordCursor(next), base)); baseSeen = true;
      }
      const suffix = window.filter(next => next.height > base.height);
      if (suffix.length === 0) return;
      need(baseSeen);
      const statements = suffix.flatMap(next => next.records.map(record => record.statement));
      const contexts = statements.length === 0 ? [] : adapter.contextsBatch(statements);
      need(contexts.length === statements.length);
      let at = 0;
      for (const next of suffix) {
        applyBlock(value, candidate, next, contexts.slice(at, at + next.records.length), adapter, recipients);
        at += next.records.length;
      }
    };
    const walked = continuation ? visitAuthenticatedContinuation(scanFile, head(value, base),
      head(value, expected), value.context, onWindow) :
      visitAuthenticatedHistory(scanFile, head(value, expected), value.context, onWindow);
    need(baseSeen && sameCursor(walked.cursor, expected) && sameCursor(candidate.state.cursor, expected));
    if (!cleanupRecipients()) throw new WalletOperationalError();
    lease(value); need(value.revision === revision && value.active === candidate);
    // Publish one joint capability only after exact EOF, cursor and cleanup passed.
    if (value.prepared) retirePayment(value.prepared);
    clearCommitted(value); invalidateView(value);
    value.current = candidate.state; value.history = candidate.history;
    candidate.state = null; candidate.history = []; value.active = null;
    value.revision++; value.mode = 'ready'; value.selectedTarget = null;
    const view = Object.freeze({type: 'CP03-private-local-witness-view'});
    views.set(view, {session: token, revision: value.revision}); value.view = view; published = true;
    return recoveryResult(value, view, inventoryBasis, mode, walked);
  } catch (error) {
    if (error instanceof WalletInputError || error instanceof LocalWitnessReplayRequired) throw error;
    throw new WalletOperationalError();
  } finally {
    const clean = cleanupRecipients();
    if (!published) {
      wipeCandidate(candidate);
      if (value.active === candidate) value.active = null;
      if (value.revision === revision && value.mode !== 'inventory-invalid') value.mode = priorMode;
    }
    if (!clean) {
      // Cleanup failure publishes nothing; keep the old image private but revoke
      // its capabilities until authenticated full replay repairs the session.
      revoke(value); value.selectedBase = null; value.mode = 'replay-required'; throw new WalletOperationalError();
    }
  }
}
export function selectLocalWitnessBranch(token, {commonPrefix, endpoint}) {
  const value = session(token), prefix = target(value, commonPrefix), selected = target(value, endpoint);
  need(prefix.height <= selected.height);
  // Authenticated caller selection revokes BEFORE any journal lookup, even outside R.
  revoke(value); value.mode = 'replay-required'; value.selectedTarget = selected;
  const found = value.history.find(state => sameCursor(state.cursor, prefix));
  value.selectedBase = found ?? null;
  if (!found) throw new LocalWitnessReplayRequired();
  // Retain the old committed image revoked until the complete replacement
  // authenticates. This pointer refers only to our own immutable joint journal.
  // It is a private replay base, never a spendable view until selected EOF is applied.
  value.mode = 'selected-replay';
}
export function inspectLocalWitnessView(view, operation) {
  const value = current(view); need(!value.borrow); callback(operation);
  value.borrow = true;
  const revision = value.revision, notes = [...value.current.owned.values()].map(owned => ({
    token: Buffer.from(owned.token), index: owned.index, amount: owned.opening.note.readBigUInt64LE(8),
    origin: Buffer.from(owned.origin), cm: Buffer.from(owned.cm)}));
  try {
    const result = synchronous(operation({head: head(value, value.current.cursor), balance: balance(value.current), notes}));
    lease(value); need(value.revision === revision); return result;
  } finally {
    for (const note of notes) { note.token.fill(0); note.origin.fill(0); note.cm.fill(0); }
    value.borrow = false;
  }
}
function equivalentState(a, b) {
  if (!sameCursor(a.cursor, b.cursor) || a.anchors.length !== b.anchors.length ||
      !a.anchors.every((anchor, index) => sameCursor(anchor, b.anchors[index])) ||
      a.owned.size !== b.owned.size || a.witnesses.size !== a.owned.size ||
      b.witnesses.size !== b.owned.size) return false;
  for (const [nf, item] of a.owned) {
    const other = b.owned.get(nf);
    if (!other || item.index !== other.index || !item.nf.equals(other.nf) ||
        !item.origin.equals(other.origin) || !item.cm.equals(other.cm) ||
        !['note', 'cm', 'memo'].every(key => item.opening[key].equals(other.opening[key]))) return false;
    const left = a.witnesses.get(item.token.toString('hex'));
    const right = b.witnesses.get(other.token.toString('hex'));
    if (!left || !right || !left.token.equals(item.token) || !right.token.equals(other.token) ||
        left.index !== item.index || right.index !== other.index ||
        left.siblings.length !== 40 || right.siblings.length !== 40 ||
        !left.siblings.every((sibling, index) => sibling.equals(right.siblings[index]))) return false;
  }
  return true;
}
// Fixed local comparison oracle only. No callback, serialization, hashing or
// private buffers leave this function. It compares semantic owned paths/journal,
// not byte equality of the opaque unowned frontier (which embeds random tokens).
export function equivalentLocalWitnessViews(left, right) {
  const a = current(left), b = current(right);
  need(a !== b && !a.borrow && !b.borrow);
  return a.chain.equals(b.chain) && a.genesisId.equals(b.genesisId) && a.blockVersion === b.blockVersion &&
    a.total === b.total && a.maxOwned === b.maxOwned && a.rewindBlocks === b.rewindBlocks &&
    sameCursor(a.genesisCursor, b.genesisCursor) && equivalentState(a.current, b.current) &&
    a.history.length === b.history.length && a.history.every((state, index) => equivalentState(state, b.history[index]));
}
export function withLocalWitnesses(view, selection, paymentOptions) {
  const value = current(view); need(!value.borrow);
  need(paymentOptions && typeof paymentOptions === 'object' && !Array.isArray(paymentOptions) &&
    Object.keys(paymentOptions).join(',') === 'outputs');
  if (value.prepared) {
    const status = paymentLifecycle(value.prepared);
    need(!status || (status.used && !status.inFlight));
    retirePayment(value.prepared); value.prepared = null;
  }
  if (typeof selection === 'function') callback(selection);
  value.borrow = true;
  const revision = value.revision, state = value.current, inputs = [], metadata = [];
  let refreshed, prepared;
  try {
    for (const owned of state.owned.values()) metadata.push({token: Buffer.from(owned.token), index: owned.index,
      amount: owned.opening.note.readBigUInt64LE(8)});
    metadata.sort((a, b) => a.index < b.index ? -1 : a.index > b.index ? 1 : 0);
    const chosen = typeof selection === 'function' ? synchronous(selection(metadata)) :
      (need(Number.isInteger(selection) && selection >= 1 && selection <= 2), metadata.slice(0, selection).map(item => item.token));
    need(Array.isArray(chosen) && chosen.length >= 1 && chosen.length <= 2);
    if (typeof selection !== 'function') need(chosen.length === selection);
    const byToken = new Map([...state.owned.values()].map(owned => [owned.token.toString('hex'), owned]));
    const used = new Set(), selected = chosen.map(item => {
      const id = fixed(item, 16).toString('hex'); need(!used.has(id) && byToken.has(id)); used.add(id); return byToken.get(id);
    });
    lease(value); need(value.revision === revision);
    // The fixed native helper pads a clone and folds every returned path. It is
    // not a ledger/path oracle and cannot import an arbitrary caller state here.
    refreshed = advance(value, state, [], []);
    need(refreshed.count === state.cursor.leafCount && refreshed.root.equals(state.cursor.root));
    const paths = new Map(refreshed.witnesses.map(item => [item.token.toString('hex'), item]));
    for (const owned of selected) {
      const witness = paths.get(owned.token.toString('hex')); need(!!witness && witness.index === owned.index);
      inputs.push({note: Buffer.from(owned.opening.note), origin: Buffer.from(owned.origin), index: owned.index,
        siblings: witness.siblings.map(sibling => Buffer.from(sibling))});
    }
    // Coordinator owns packet creation; no external callback can allocate a
    // packet then throw/return a Promise before its handle becomes tracked.
    prepared = preparePayment(value.wallet, value.helperSha256,
      {anchor: {root: Buffer.from(state.cursor.root), count: state.cursor.leafCount}, inputs,
        outputs: paymentOptions.outputs});
    const statement = parseStatement(publicPayment(prepared).statement);
    lease(value); need(value.revision === revision && value.mode === 'ready' && !value.active);
    need(statement.chain.equals(value.chain) && statement.root.equals(state.cursor.root) &&
      statement.count === state.cursor.leafCount && statement.arity === selected.length &&
      statement.nullifiers.every((nf, index) => nf.equals(selected[index].nf)));
    const result = prepared; value.prepared = prepared; prepared = null; return result;
  } finally {
    if (prepared) { try { disposePayment(prepared); } catch {} }
    wipeNative(refreshed);
    for (const input of inputs) { input.note.fill(0); input.origin.fill(0); for (const sibling of input.siblings) sibling.fill(0); }
    for (const item of metadata) item.token.fill(0);
    value.borrow = false;
  }
}
export function localDraftEligible(token, statementBytes) {
  const value = session(token); need(value.mode === 'ready' && !value.active && !value.borrow && !!value.current);
  const statement = parseStatement(statementBytes), state = value.current;
  if (!statement.chain.equals(value.chain) || statement.arity < 1 || statement.arity > 2 ||
      !state.anchors.some(anchor => anchor.root.equals(statement.root) && anchor.leafCount === statement.count)) return false;
  return statement.nullifiers.every(nf => {
    const owned = state.owned.get(nf.toString('hex')); return !!owned && owned.index < statement.count;
  });
}
export async function disposeLocalWitnessSession(token) {
  const value = sessions.get(token); need(!!value && !value.disposed);
  // Do not release the inventory lease from inside an active private callback.
  need(!value.borrow);
  value.disposed = true; revoke(value); clearCommitted(value); value.selectedTarget = null;
  value.tokenPrefix.fill(0); value.context.genesis.fill(0); value.context.genesisRoot.fill(0);
  // Logical revocation is immediate; no new session can acquire the wallet
  // lease while an already-consuming revoked packet is still draining.
  try { if (value.prepared) await retirePayment(value.prepared); }
  finally { releaseWalletLease(value.lease); sessions.delete(token); }
}
