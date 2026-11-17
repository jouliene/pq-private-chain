// CP_INTEGRATION_03 pure ML-DSA-87 source authorization. This is no issuance verdict.
// Self-contained so the ledger can embed these exact reviewed bytes in its worker.
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

export const SOURCE_CONTEXT = 'PQCHAIN-CP3-SOURCE';
export const PUBLIC_KEY_BYTES = 2592;
export const SIGNATURE_BYTES = 4627;
export const MESSAGE_BYTES = 314;
export const REQUEST_BYTES = 8 + PUBLIC_KEY_BYTES + MESSAGE_BYTES + SIGNATURE_BYTES;
const CONTEXT = Buffer.from(SOURCE_CONTEXT, 'ascii');
const SPKI_PREFIX = Buffer.from('30820a32300b060960864801650304031303820a2100', 'hex');
const REQUEST_MAGIC = Buffer.from('CPAUTH03', 'ascii');
const MAX = 1840960000000000n;

export class SignatureInputError extends Error {
  constructor() { super('CP03 signature input rejected'); this.name = 'SignatureInputError'; }
}
export class SignatureOperationalError extends Error {
  constructor() { super('CP03 signature provider failed'); this.name = 'SignatureOperationalError'; }
}
function fixed(value, size) {
  if (!Buffer.isBuffer(value) || value.length !== size) throw new SignatureInputError();
  return value;
}
function tag(label) {
  const text = Buffer.from('PQPC/CP3/' + label, 'ascii');
  const length = Buffer.alloc(2); length.writeUInt16LE(text.length);
  return Buffer.concat([length, text]);
}
function blob(value) {
  if (!Buffer.isBuffer(value) || value.length > 528) throw new SignatureInputError();
  const length = Buffer.alloc(4); length.writeUInt32LE(value.length);
  return Buffer.concat([length, value]);
}
function checkedMessage(message) {
  fixed(message, MESSAGE_BYTES);
  const prefix = tag('CLAIM-AUTH');
  const kind = prefix.length + 32;
  const sequence = kind + 1 + 48;
  const credit = message.readBigUInt64LE(sequence + 8);
  if (!message.subarray(0, prefix.length).equals(prefix) || message[kind] !== 3 ||
      message.readBigUInt64LE(sequence) !== 0n || credit === 0n || credit > MAX ||
      message.readUInt32LE(sequence + 16) !== 0) throw new SignatureInputError();
  return message;
}
export function claimMessage(fields) {
  if (!fields || typeof fields !== 'object') throw new SignatureInputError();
  const {chain, sourceId, registeredCredit, profileId, creditProgramId, statement} = fields;
  if (typeof registeredCredit !== 'bigint' || registeredCredit <= 0n || registeredCredit > MAX ||
      !Buffer.isBuffer(statement) || statement.length !== 448) throw new SignatureInputError();
  const amount = Buffer.alloc(8); amount.writeBigUInt64LE(registeredCredit);
  let statementId;
  try { statementId = crypto.createHash('sha3-512').update(tag('STATEMENT')).update(blob(statement)).digest(); }
  catch { throw new SignatureOperationalError(); }
  return checkedMessage(Buffer.concat([
    tag('CLAIM-AUTH'), fixed(chain, 32), Buffer.from([3]), fixed(sourceId, 48),
    Buffer.alloc(8), amount, Buffer.alloc(4), fixed(profileId, 64),
    fixed(creditProgramId, 64), statementId,
  ]));
}
export function sourcePublicBytes(key) {
  if (!key || key.type !== 'public' || key.asymmetricKeyType !== 'ml-dsa-87') throw new SignatureInputError();
  try {
    const der = key.export({type: 'spki', format: 'der'});
    if (der.length !== SPKI_PREFIX.length + PUBLIC_KEY_BYTES ||
        !der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) throw new SignatureOperationalError();
    return Buffer.from(der.subarray(SPKI_PREFIX.length));
  } catch { throw new SignatureOperationalError(); }
}
function sourcePublicKey(raw) {
  fixed(raw, PUBLIC_KEY_BYTES);
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki',
    });
    if (!sourcePublicBytes(key).equals(raw)) throw new SignatureOperationalError();
    return key;
  } catch { throw new SignatureOperationalError(); }
}
export function signSource(privateKey, message) {
  checkedMessage(message);
  if (!privateKey || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ml-dsa-87') {
    throw new SignatureInputError();
  }
  try {
    const signature = crypto.sign(null, message, {key: privateKey, context: CONTEXT});
    if (signature.length !== SIGNATURE_BYTES) throw new SignatureOperationalError();
    return signature;
  } catch { throw new SignatureOperationalError(); }
}
export function verifySource(publicKey, message, signature) {
  try { fixed(publicKey, PUBLIC_KEY_BYTES); checkedMessage(message); fixed(signature, SIGNATURE_BYTES); }
  catch (error) { if (error instanceof SignatureInputError) return false; throw new SignatureOperationalError(); }
  const key = sourcePublicKey(publicKey);
  try { return crypto.verify(null, message, {key, context: CONTEXT}, signature); }
  catch { throw new SignatureOperationalError(); }
}
export function verificationRequest(publicKey, message, signature) {
  checkedMessage(message);
  return Buffer.concat([REQUEST_MAGIC, fixed(publicKey, PUBLIC_KEY_BYTES), message, fixed(signature, SIGNATURE_BYTES)]);
}
export function verifyRequest(request) {
  if (!Buffer.isBuffer(request) || request.length !== REQUEST_BYTES ||
      !request.subarray(0, 8).equals(REQUEST_MAGIC)) return false;
  const endKey = 8 + PUBLIC_KEY_BYTES;
  const endMessage = endKey + MESSAGE_BYTES;
  return verifySource(request.subarray(8, endKey), request.subarray(endKey, endMessage), request.subarray(endMessage));
}
// Public-only worker: exact bounded stdin, no paths or algorithms selected by input.
// Parent must enforce a deadline, pin this source/runtime and clean the process group.
// This function emits only fixed outcomes. It never prints a provider exception.
export function runPublicWorker() {
  let status = 'OPERATIONAL';
  try {
    const request = Buffer.alloc(REQUEST_BYTES + 1);
    let size = 0;
    while (size < request.length) {
      const count = fs.readSync(0, request, size, request.length - size, null);
      if (count === 0) break;
      size += count;
    }
    status = size === REQUEST_BYTES && verifyRequest(request.subarray(0, size)) ? 'VALID' : 'INVALID';
  } catch { status = 'OPERATIONAL'; }
  try { fs.writeSync(1, 'CPAUTH03 ' + status + '\n'); }
  catch { process.exitCode = 2; return; }
  process.exitCode = status === 'VALID' ? 0 : status === 'INVALID' ? 1 : 2;
}
