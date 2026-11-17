// CP03 wallet bytes. Rust canonical parsers and genuine proof remain mandatory.
// Never format private values in errors; all u64 arithmetic uses BigInt.
export const P = 18446744069414584321n;
export const MAX = 1840960000000000n;
export const FEES = Object.freeze([2116775n, 2112174n, 2112248n]);
const SIZES = [448, 464, 528];
const PROOF_CAP = 2097152;

export class WalletInputError extends Error {
  constructor() { super('CP03 wallet input rejected'); this.name = 'WalletInputError'; }
}
function need(value) { if (!value) throw new WalletInputError(); }
function fixed(value, size) { need(Buffer.isBuffer(value) && value.length === size); return value; }
function unsigned(value, max) { need(typeof value === 'bigint' && value >= 0n && value <= max); return value; }
function u16(value) { const b = Buffer.alloc(2); b.writeUInt16LE(value); return b; }
function u32(value) { const b = Buffer.alloc(4); b.writeUInt32LE(value); return b; }
function u64(value) { const b = Buffer.alloc(8); b.writeBigUInt64LE(unsigned(value, (1n << 64n) - 1n)); return b; }
function fieldBytes(value, words) {
  fixed(value, 8 * words);
  for (let i = 0; i < words; i++) need(value.readBigUInt64LE(i * 8) < P);
  return value;
}
function arityOf(n) { need(Number.isInteger(n) && n >= 0 && n <= 2); return n; }

export function encodeStatement(s) {
  need(s && typeof s === 'object');
  const n = arityOf(s.arity);
  need(Array.isArray(s.nullifiers) && s.nullifiers.length === n &&
    Array.isArray(s.commitments) && s.commitments.length === 2 &&
    Array.isArray(s.receipts) && s.receipts.length === 2);
  unsigned(s.fee, MAX); unsigned(s.count, 1n << 40n); unsigned(s.credit, MAX);
  need(s.debit === 0n);
  if (n === 0) need(s.credit > 0n && Buffer.isBuffer(s.sourceId) && s.sourceId.length === 48);
  else need(s.credit === 0n && s.count > 0n && s.sourceId === null);
  const nullifiers = s.nullifiers.map(x => fieldBytes(x, 8));
  if (n === 2) need(!nullifiers[0].equals(nullifiers[1]));
  const result = Buffer.concat([
    Buffer.from('CP-P2-03'), Buffer.from([3, 0, n, 2, n === 0 ? 3 : 1, 0, 0, 0]),
    fixed(s.chain, 32), fixed(s.nonce, 32), ...nullifiers,
    ...s.commitments.map(x => fieldBytes(x, 8)), u64(s.fee), fieldBytes(s.root, 8),
    u64(s.count), u64(s.credit), u64(s.debit), ...s.receipts.map(x => fixed(x, 48)),
    ...(n === 0 ? [s.sourceId] : []),
  ]);
  need(result.length === SIZES[n]); return result;
}

export function parseStatement(bytes) {
  need(Buffer.isBuffer(bytes) && SIZES.includes(bytes.length));
  need(bytes.subarray(0, 8).equals(Buffer.from('CP-P2-03')) && bytes[8] === 3 &&
    bytes[9] === 0 && bytes[11] === 2 && bytes.subarray(13, 16).every(x => x === 0));
  const n = arityOf(bytes[10]);
  need(bytes.length === SIZES[n] && bytes[12] === (n === 0 ? 3 : 1));
  let at = 16;
  const take = size => { const b = Buffer.from(bytes.subarray(at, at + size)); at += size; return b; };
  const integer = () => { const v = bytes.readBigUInt64LE(at); at += 8; return v; };
  const s = {
    arity: n, chain: take(32), nonce: take(32), nullifiers: Array.from({length: n}, () => take(64)),
    commitments: [take(64), take(64)], fee: integer(), root: take(64),
    count: integer(), credit: integer(), debit: integer(), receipts: [take(48), take(48)],
    sourceId: n === 0 ? take(48) : null,
  };
  need(at === bytes.length && encodeStatement(s).equals(bytes)); return s;
}

export function encodeBody(statement, envelopes, authorization, proof) {
  const s = parseStatement(statement);
  need(Array.isArray(envelopes) && envelopes.length === 2);
  const checkedEnvelopes = envelopes.map(e => {
    fixed(e, 2164); need(e.subarray(0, 8).equals(Buffer.from('4350523303010000', 'hex'))); return e;
  });
  fixed(authorization, s.arity === 0 ? 4627 : 0);
  need(Buffer.isBuffer(proof) && proof.length > 0 && proof.length <= PROOF_CAP);
  return Buffer.concat([
    Buffer.from('CPBODY03'), u16(3), u16(statement.length), u32(proof.length),
    u16(authorization.length), u16(0), statement, ...checkedEnvelopes, authorization, proof,
  ]);
}

export function encodeGenesis({chain, protocolId, proofProfileId, programIds, sources, version = 3}) {
  need(version === 3 || version === 4);
  need(Array.isArray(programIds) && programIds.length === 3 && Array.isArray(sources) &&
    sources.length >= 1 && sources.length <= (version === 4 ? 128 : 16));
  let total = 0n, previous = null;
  const entries = sources.map(source => {
    fixed(source.id, 48); fixed(source.publicKey, 2592); unsigned(source.credit, MAX);
    need(source.credit >= FEES[0] && (previous === null || Buffer.compare(previous, source.id) < 0));
    previous = source.id; total += source.credit; need(total <= MAX);
    return Buffer.concat([source.id, u64(source.credit), source.publicKey]);
  });
  const result = Buffer.concat([
    Buffer.from(version === 4 ? 'CPGEN004' : 'CPGEN003'), u16(version), u16(0), fixed(chain, 32), u64(total), u16(sources.length), u16(1),
    fixed(protocolId, 64), fixed(proofProfileId, 64), ...programIds.map(x => fixed(x, 64)), ...entries,
  ]);
  need(result.length === 376 + 2648 * sources.length); return result;
}

// A returned buffer is PRIVATE. Caller must pipe it without logging/hashing and
// clear it in finally. This function writes no file and does not select a program.
export function encodePrivatePacket(statement, inputs, outputs) {
  const s = parseStatement(statement), n = s.arity;
  need(Array.isArray(inputs) && inputs.length === n && Array.isArray(outputs) && outputs.length === 2);
  for (const input of inputs) {
    need(input && typeof input === 'object');
    fieldBytes(input.note, 20); fieldBytes(input.key, 5); fieldBytes(input.origin, 8);
    unsigned(input.index, (1n << 40n) - 1n);
    need(Array.isArray(input.siblings) && input.siblings.length === 40);
    for (const sibling of input.siblings) fieldBytes(sibling, 8);
  }
  for (const note of outputs) fieldBytes(note, 20);
  const witnessSize = 324 + 2836 * n;
  const packet = Buffer.alloc(20 + statement.length + witnessSize);
  let at = 0;
  const put = bytes => { bytes.copy(packet, at); at += bytes.length; };
  try {
    put(Buffer.from('CPPRV004')); put(u16(4)); put(u16(0)); put(u32(statement.length));
    put(statement); put(u32(witnessSize)); put(Buffer.from([n, 2, 0, 0]));
    for (const input of inputs) {
      put(input.note); put(input.key); put(input.origin); put(u64(input.index)); put(u16(40)); put(u16(0));
      for (const sibling of input.siblings) put(sibling);
    }
    for (const note of outputs) put(note);
    need(at === packet.length && packet.length <= 128 * 1024); return packet;
  } catch {
    packet.fill(0); throw new WalletInputError();
  }
}
