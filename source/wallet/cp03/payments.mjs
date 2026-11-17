// Research payment construction. Private packet stays in RAM and is consumed once.
// Current state, source entitlement and genuine proof checks belong to the ledger.
import * as crypto from 'node:crypto';
import {makeNote} from '../../experiments/compact-receiving-v1/cp03/receipt.mjs';
import {fixedHashCore} from '../../experiments/compact-receiving-v1/cp03/hash-core.mjs';
import {withWallet, WalletOperationalError} from './keys.mjs';
import {encodeStatement, encodePrivatePacket, encodeBody, FEES, MAX, WalletInputError} from './codec.mjs';

const payments = new WeakMap();
function need(condition) { if (!condition) throw new WalletInputError(); }
function state(token) { const value = payments.get(token); need(!!value); return value; }
function amount(value) { need(typeof value === 'bigint' && value >= 0n && value <= MAX); return value; }

// inputs: recovered note bytes plus public origin/index/40-sibling membership path.
// outputs: exactly two {descriptor, amount, memo?}. Zero-valued outputs are allowed.
// anchor: independently selected public {root: 64B, count: BigInt}; no DB is read here.
export function preparePayment(wallet, helperSha256, {anchor, inputs, outputs, sourceId = null, credit = 0n}) {
  need(Array.isArray(inputs) && inputs.length <= 2 && Array.isArray(outputs) && outputs.length === 2);
  const n = inputs.length;
  need(n === 0 ? Buffer.isBuffer(sourceId) && sourceId.length === 48 && amount(credit) > 0n :
    sourceId === null && credit === 0n);
  return withWallet(wallet, value => {
    const notes = []; let packet;
    try {
      const core = fixedHashCore(helperSha256), owner = value.adapter.auth(value.spending);
      let available = credit;
      const witnessInputs = inputs.map(input => {
        need(input && Buffer.isBuffer(input.note) && input.note.length === 160 &&
          input.note.readBigUInt64LE(0) === 0n && input.note.subarray(16, 80).equals(owner));
        available += amount(input.note.readBigUInt64LE(8));
        return {note: input.note, key: value.spending, origin: input.origin,
          index: input.index, siblings: input.siblings};
      });
      let outgoing = FEES[n];
      const descriptions = outputs.map(output => {
        need(output && Buffer.isBuffer(output.descriptor));
        const parsed = value.adapter.parseDescriptor(output.descriptor);
        outgoing += amount(output.amount);
        const memo = output.memo === undefined ? Buffer.alloc(0) : output.memo;
        need(Buffer.isBuffer(memo) && memo.length <= 128);
        const note = makeNote(output.amount, parsed.owner); notes.push(note);
        return {descriptor: output.descriptor, memo, note, cm: value.adapter.commitment(note)};
      });
      need(available === outgoing && available <= MAX);
      const nullifiers = witnessInputs.map(input => core.nf(value.chain, value.spending,
        input.origin, value.adapter.commitment(input.note)));
      const fields = {arity: n, chain: value.chain, nonce: crypto.randomBytes(32), nullifiers,
        commitments: descriptions.map(output => output.cm), fee: FEES[n], root: anchor.root,
        count: anchor.count, credit, debit: 0n, receipts: [Buffer.alloc(48), Buffer.alloc(48)], sourceId};
      const draft = encodeStatement(fields);
      const contexts = value.adapter.contextsBatch([draft])[0];
      const envelopes = descriptions.map((output, ordinal) =>
        value.adapter.seal(output.descriptor, contexts[ordinal], output.note, output.memo));
      fields.receipts = envelopes.map((envelope, ordinal) => value.adapter.digest(contexts[ordinal], envelope));
      const statement = encodeStatement(fields);
      // CORE omits receipt digests; reject any accidental context change before proving.
      const finalContexts = value.adapter.contextsBatch([statement])[0];
      for (let ordinal = 0; ordinal < 2; ordinal++) {
        const before = value.adapter.contextInfo(contexts[ordinal]);
        const after = value.adapter.contextInfo(finalContexts[ordinal]);
        need(before.core.equals(after.core) && before.origin.equals(after.origin) && before.cm.equals(after.cm));
      }
      packet = encodePrivatePacket(statement, witnessInputs, notes);
      const token = Object.freeze({type: 'CP03-prepared-private-payment'});
      let settled;
      const settlement = new Promise(resolve => { settled = resolve; });
      payments.set(token, {statement, envelopes, packet, used: false, inFlight: false, retired: false,
        settlement, settled, arity: n});
      packet = undefined; return token;
    } catch (error) {
      if (error instanceof WalletInputError) throw error;
      throw new WalletOperationalError();
    } finally {
      packet?.fill(0);
      for (const note of notes) note.fill(0);
    }
  });
}

export function publicPayment(payment) {
  const value = state(payment); need(!value.retired);
  return {arity: value.arity, statement: Buffer.from(value.statement),
    envelopes: value.envelopes.map(envelope => Buffer.from(envelope))};
}

// Only the installed private-parent bridge may be passed as this trusted callback.
// Do not log/hash/serialize the packet. The callback must wait for child termination.
export async function consumePrivatePacket(payment, operation) {
  const value = state(payment); need(!value.used && !value.retired && typeof operation === 'function');
  value.used = true; value.inFlight = true;
  try {
    const result = await operation(value.packet);
    need(!value.retired); return result;
  } finally {
    value.packet.fill(0); value.packet = null; value.inFlight = false;
    if (value.retired) payments.delete(payment);
    value.settled();
  }
}

export function completeBody(payment, authorization, proof) {
  const value = state(payment); need(!value.retired && value.used && value.packet === null);
  // Assembly makes no statement that proof/authorization is valid or admitted.
  return encodeBody(value.statement, value.envelopes, authorization, proof);
}

export function disposePayment(payment) {
  const value = state(payment); need(!value.inFlight);
  value.packet?.fill(0); value.packet = null; payments.delete(payment); value.settled();
}

// Non-secret lifecycle only; no additional private-packet getter or consumer.
export function paymentLifecycle(payment) {
  const value = payments.get(payment);
  return value ? Object.freeze({used: value.used, inFlight: value.inFlight, retired: value.retired}) : null;
}
export function retirePayment(payment) {
  const value = payments.get(payment);
  if (!value) return Promise.resolve();
  value.retired = true;
  if (!value.inFlight) {
    value.packet?.fill(0); value.packet = null; payments.delete(payment); value.settled();
  }
  // An active consumer retains its packet until its existing awaited operation
  // has ended. The approved Parent callback must wait for actual child exit.
  return value.settlement;
}
