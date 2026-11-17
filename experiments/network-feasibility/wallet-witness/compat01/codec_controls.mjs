// PUBLIC codec controls only. No key generation, proof creation or admission.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import {encodeGenesis, encodeBody, parseStatement, encodeStatement, FEES, WalletInputError}
  from '../../../../source/wallet/cp03/codec.mjs';
const repository = new URL('../../../../', import.meta.url);
const fixture = new URL('fixtures/cp03-reference/genesis.bin', repository);
const raw = fs.readFileSync(fixture), count = raw.readUInt16LE(52);
const sources = Array.from({length: count}, (_, i) => {
  const at = 376 + 2648 * i;
  return {id: raw.subarray(at, at + 48), credit: raw.readBigUInt64LE(at + 48), publicKey: raw.subarray(at + 56, at + 2648)};
});
const base = {chain: raw.subarray(12, 44), protocolId: raw.subarray(56, 120),
  proofProfileId: raw.subarray(120, 184), programIds: [raw.subarray(184, 248), raw.subarray(248, 312), raw.subarray(312, 376)], sources};
function need(value) { if (value !== true) throw new Error('PUBLIC_CODEC_CONTROL_FAILED'); }
function reject(operation) {
  try { operation(); } catch (error) { need(error instanceof WalletInputError); return; }
  throw new Error('PUBLIC_CODEC_NEGATIVE_ACCEPTED');
}
need(encodeGenesis(base).equals(raw));
need(encodeGenesis({...base, version: 3}).equals(raw));
const many = Array.from({length: 128}, (_, i) => {
  const id = Buffer.alloc(48); id.writeUInt32BE(i + 1, 44);
  return {id, credit: FEES[0] + 1n, publicKey: sources[0].publicKey};
});
const network = encodeGenesis({...base, sources: many, version: 4});
need(network.length === 339320 && network.subarray(0, 12).equals(Buffer.from('435047454e30303404000000', 'hex')));
reject(() => encodeGenesis({...base, sources: many}));
reject(() => encodeGenesis({...base, sources: [...many, many[0]], version: 4}));
reject(() => encodeGenesis({...base, sources: [many[1], many[0]], version: 4}));
reject(() => encodeGenesis({...base, sources: [many[0], many[0]], version: 4}));
reject(() => encodeGenesis({...base, version: 5}));
for (const name of ['credit0.body', 'payer2x2.body', 'recipient1x2.body', 'restored1x2.body']) {
  const body = fs.readFileSync(new URL('fixtures/cp03-reference/' + name, repository));
  const n = body.readUInt16LE(10), authorization = body.readUInt16LE(16), statement = body.subarray(20, 20 + n);
  need(encodeStatement(parseStatement(statement)).equals(statement));
  const at = 20 + n;
  const reconstructed = encodeBody(statement, [body.subarray(at, at + 2164), body.subarray(at + 2164, at + 4328)],
    body.subarray(at + 4328, at + 4328 + authorization), body.subarray(at + 4328 + authorization));
  need(reconstructed.equals(body));
}
const output = process.argv[2];
need(typeof output === 'string');
fs.writeFileSync(output, JSON.stringify({format: 'NETWORK04-WALLET-PUBLIC-CODEC-CONTROLS01', passed: true,
  legacy_genesis_exact: true, legacy_statement_and_body_vectors_exact: 4, network_genesis_sources: 128,
  network_genesis_bytes: network.length, negative_controls: 5, private_material: false,
  new_proofs_or_gate_acceptance: false,
  codec_sha256: crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../../source/wallet/cp03/codec.mjs', import.meta.url))).digest('hex')}, null, 2) + '\n', {flag: 'wx'});
process.stdout.write('NETWORK04_PUBLIC_CODEC_CONTROLS_PASSED\n');
