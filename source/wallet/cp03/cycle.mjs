// Root-supervised research cycle. All private fixtures/backups stay in RAM.
// This driver does not substitute for public replay, adverse controls or resource gates.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createWallet, rotateReceivingKey, descriptor, publicInventory, exportBackup,
  restoreBackup, disposeWallet} from './keys.mjs';
import {encodeGenesis, FEES} from './codec.mjs';
import {preparePayment, publicPayment, completeBody, disposePayment} from './payments.mjs';
import {installPrivateProver, provePayment} from './private_prover.mjs';
import {preparePublicLedger} from './public_ledger.mjs';
import {recoverHistory, withRecovered, disposeRecovered} from './recovery.mjs';
import {claimMessage, signSource, sourcePublicBytes} from '../../runtime/cp03/source-signature.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const EVIDENCE = path.join(ROOT, 'experiments/cp03-private-cycle/evidence');
const HELPER = "__CP03_INSTALLED_HELPER_SHA256__";
const ENV = {PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC', RUST_BACKTRACE: '0', RAYON_NUM_THREADS: '1'};
const wallets = new Set(), views = new Set(), payments = new Set(), privateBuffers = [];
let stage = 'startup';
function need(value) { if (value !== true) throw new Error('CP03 cycle condition failed'); }
function heldWallet(value) { wallets.add(value); return value; }
function heldView(value) { views.add(value); return value; }
function heldPayment(value) { payments.add(value); return value; }
function releaseWallet(value) { disposeWallet(value); wallets.delete(value); }
function releaseView(value) { disposeRecovered(value); views.delete(value); }
function privateBuffer(value) { privateBuffers.push(value); return value; }
function sha(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function relative(file) { return path.relative(ROOT, file); }
function resolvePublic(file) {
  need(typeof file === 'string' && !file.includes('\0'));
  const resolved = path.resolve(ROOT, file); need(resolved.startsWith(ROOT)); return resolved;
}
function readPublic(file, cap) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(fd, {bigint: true}); need(before.isFile() && before.size <= BigInt(cap));
    const chunks = []; let total = 0;
    for (;;) {
      const b = Buffer.alloc(Math.min(65536, cap + 1 - total));
      const n = fs.readSync(fd, b, 0, b.length, null); if (n === 0) break;
      total += n; need(total <= cap); chunks.push(b.subarray(0, n));
    }
    const after = fs.fstatSync(fd, {bigint: true});
    need(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(k => before[k] === after[k]));
    return Buffer.concat(chunks, total);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function record(file, cap = 16 * 1024 * 1024) { return {path: relative(file), sha256: sha(readPublic(file, cap))}; }
function writePublic(file, bytes) { fs.writeFileSync(file, bytes, {flag: 'wx', mode: 0o600}); }
function writeJson(file, value) { writePublic(file, Buffer.from(JSON.stringify(value, null, 2) + '\n')); }
function publicJson(file, cap = 65536) { return JSON.parse(readPublic(file, cap).toString('utf8')); }
function h64(label, value) {
  const tag = Buffer.from('PQPC/CP3/' + label), size = Buffer.alloc(4), length = Buffer.alloc(2);
  length.writeUInt16LE(tag.length); size.writeUInt32LE(value.length);
  return crypto.createHash('sha3-512').update(length).update(tag).update(size).update(value).digest();
}
function installation(file, expectedSha) {
  const raw = readPublic(resolvePublic(file), 65536); need(sha(raw) === expectedSha);
  const value = JSON.parse(raw.toString('utf8'));
  need(value.format === 'CP03-CYCLE-OPERATOR01' && value.helper_sha256 === HELPER);
  for (const name of ['ledger_binary', 'ledger_build_receipt', 'private_approval', 'provider_controls_receipt', 'protocol_manifest']) {
    const entry = value[name]; need(entry && /^[0-9a-f]{64}$/.test(entry.sha256));
    need(sha(readPublic(resolvePublic(entry.path), name === 'ledger_binary' ? 64 * 1024 * 1024 : 16 * 1024 * 1024)) === entry.sha256);
  }
  const protocolBytes = readPublic(resolvePublic(value.protocol_manifest.path), 65536);
  const protocol = JSON.parse(protocolBytes.toString('utf8'));
  need(protocol.format === 'PQPC-CP03-RESEARCH-PROTOCOL-01');
  return {value, protocol, protocolId: h64('PROTOCOL', protocolBytes), file, expectedSha};
}
function ledger(inst, chain, database) {
  return preparePublicLedger({binaryPath: resolvePublic(inst.value.ledger_binary.path),
    binarySha256: inst.value.ledger_binary.sha256, chain, dbPath: database});
}
function prover(inst) { return installPrivateProver(inst.value.private_approval.path, inst.value.private_approval.sha256); }
function endpoint(head) { return {chain: head.chain, genesisId: head.genesisId, height: head.height, blockId: head.blockId}; }
function encodedEndpoint(head) {
  return {chain: head.chain.toString('hex'), genesisId: head.genesisId.toString('hex'),
    height: head.height.toString(), blockId: head.blockId.toString('hex')};
}
function decodedEndpoint(value) {
  need(value && /^(0|[1-9][0-9]*)$/.test(value.height));
  return {chain: Buffer.from(value.chain, 'hex'), genesisId: Buffer.from(value.genesisId, 'hex'),
    height: BigInt(value.height), blockId: Buffer.from(value.blockId, 'hex')};
}
function sameHead(a, b) {
  return a.height === b.height && a.leafCount === b.leafCount && a.blockId.equals(b.blockId) &&
    a.root.equals(b.root) && a.feeEscrow === b.feeEscrow && a.unconsumedLiabilities === b.unconsumedLiabilities;
}
function scanWallet(w, client, genesis, expectedHead, directory, name, inventoryBasis = 'unknown') {
  const scan = path.join(directory, name + '.scan'), checked = path.join(directory, name + '.checked.scan');
  const exported = client.scan(scan); need(sameHead(exported, expectedHead));
  // The expected endpoint comes from prior independent laboratory admission, not this export.
  client.checkScan(genesis, scan, endpoint(expectedHead), checked);
  const result = recoverHistory(w, checked, endpoint(expectedHead), inventoryBasis);
  need(result.history_linkage_complete && result.payment_validity === 'delegated-to-independently-supplied-endpoint');
  heldView(result.state); return result.state;
}
function inputsFor(view, client, head, expectedCount) {
  return withRecovered(view, value => {
    const candidates = [...value.unspent.values()].sort((a, b) => a.index < b.index ? -1 : a.index > b.index ? 1 : 0);
    need(candidates.length === expectedCount);
    return candidates.map(candidate => {
      const membership = client.membership(candidate.index, {count: head.leafCount, root: head.root});
      need(membership.origin.equals(candidate.origin) && membership.cm.equals(candidate.cm));
      return {note: candidate.opening.note, origin: candidate.origin, index: candidate.index, siblings: membership.siblings};
    });
  });
}
async function publishPayment(payment, backend, label, authorization, output) {
  const proof = await provePayment(backend, payment, label);
  const body = completeBody(payment, authorization, proof.proof); writePublic(output, body);
  return {body: record(output), parent_receipt: record(proof.parent_receipt),
    statement: record(path.join(proof.public_directory, 'statement.bin')),
    proof: record(path.join(proof.public_directory, 'proof.bin'))};
}
function headersFromScan(scan, directory) {
  // This bounded four-block scenario export is small. General wallet recovery streams.
  const bytes = readPublic(scan, 1024 * 1024), headers = []; let at = 0;
  while (at < bytes.length) {
    need(at + 4 <= bytes.length); const length = bytes.readUInt32LE(at); at += 4;
    need(length > 0 && length <= 153292 && at + length <= bytes.length);
    const block = bytes.subarray(at, at + length); need(block.subarray(0, 8).equals(Buffer.from('CPSBLK03')));
    const size = block.readUInt32LE(8); need(size >= 272 && size <= 1232 && 12 + size <= block.length);
    const file = path.join(directory, 'block' + String(headers.length + 1).padStart(2, '0') + '.header');
    writePublic(file, block.subarray(12, 12 + size)); headers.push(record(file)); at += length;
  }
  need(headers.length === 3); return headers;
}
async function stdinBackup() {
  const chunks = []; let length = 0;
  try {
    for await (const chunk of process.stdin) { chunks.push(chunk); length += chunk.length; need(length <= 16 * 1024 * 1024); }
    return privateBuffer(Buffer.concat(chunks));
  } finally { for (const chunk of chunks) chunk.fill(0); }
}
async function restoreWorker(configPath, configSha) {
  stage = 'restore-worker';
  const configRaw = readPublic(resolvePublic(configPath), 65536); need(sha(configRaw) === configSha);
  const config = JSON.parse(configRaw.toString('utf8')); need(config.format === 'CP03-RESTORE-WORKER01');
  const inst = installation(config.operator.path, config.operator.sha256);
  const expected = decodedEndpoint(config.endpoint), backup = await stdinBackup();
  const inventoryRaw = readPublic(resolvePublic(config.inventory.path), 65536);
  need(sha(inventoryRaw) === config.inventory.sha256);
  const restored = restoreBackup(backup, expected.chain, HELPER, JSON.parse(inventoryRaw.toString('utf8')));
  heldWallet(restored.wallet); need(restored.expected_inventory_matched);
  const client = ledger(inst, expected.chain, resolvePublic(config.database));
  // Public canonical state is queried for membership; no old wallet database exists.
  const head = client.head(); need(head.height === expected.height && head.blockId.equals(expected.blockId));
  const checked = resolvePublic(config.checked_scan);
  client.checkScan(resolvePublic(config.genesis), resolvePublic(config.scan), expected, checked);
  const recovered = recoverHistory(restored.wallet, checked, expected, restored.inventory_completeness_basis);
  const view = heldView(recovered.state); const balance = withRecovered(view, value => value.balance);
  need(balance > FEES[1]); const send = (balance - FEES[1]) / 2n;
  const payment = heldPayment(preparePayment(restored.wallet, HELPER, {
    anchor: {root: head.root, count: head.leafCount}, inputs: inputsFor(view, client, head, 1),
    outputs: [{descriptor: readPublic(resolvePublic(config.destination), 1672), amount: send},
      {descriptor: descriptor(restored.wallet, 0), amount: balance - FEES[1] - send}],
  }));
  await publishPayment(payment, prover(inst), config.proof_label, Buffer.alloc(0), resolvePublic(config.output_body));
  const after = client.admit([resolvePublic(config.output_body)]);
  need(after.height === head.height + 1n && after.leafCount === head.leafCount + 2n &&
    after.feeEscrow === head.feeEscrow + FEES[1] && after.unconsumedLiabilities === head.unconsumedLiabilities);
  // PRIVATE test-oracle output to the original parent RAM only. No extra old
  // state was supplied to this fresh recovery process. Never persist/hash this.
  const assertion = Buffer.alloc(32); Buffer.from('CP3RSLT1').copy(assertion);
  assertion.writeBigUInt64LE(balance, 8); assertion.writeBigUInt64LE(send, 16);
  assertion.writeBigUInt64LE(balance - FEES[1] - send, 24);
  return assertion;
}
async function main(operatorPath, operatorSha, runLabel) {
  need(/^[a-z0-9_-]+$/.test(runLabel));
  const inst = installation(operatorPath, operatorSha), prefix = 'cp03-cycle-' + runLabel;
  fs.mkdirSync(EVIDENCE, {recursive: true}); const out = path.join(EVIDENCE, runLabel + '.public'); fs.mkdirSync(out, {mode: 0o700});
  const chain = crypto.randomBytes(32), sourceId = crypto.randomBytes(48), credit = 100000000n;
  const issuer = crypto.generateKeyPairSync('ml-dsa-87');
  stage = 'wallet-creation';
  const payer = heldWallet(createWallet(chain, HELPER));
  const receiver = heldWallet(createWallet(chain, HELPER)); rotateReceivingKey(receiver);
  const destination = heldWallet(createWallet(chain, HELPER));
  const backup = privateBuffer(exportBackup(receiver)), inventory = publicInventory(receiver);
  const inventoryFile = path.join(out, 'receiver-inventory.json'); writeJson(inventoryFile, inventory);
  const destinationFile = path.join(out, 'destination-descriptor.bin'); writePublic(destinationFile, descriptor(destination, 0));
  const database = path.join(out, 'ledger.sqlite'), client = ledger(inst, chain, database), backend = prover(inst);
  const genesis = path.join(out, 'genesis.bin');
  writePublic(genesis, encodeGenesis({chain, protocolId: inst.protocolId,
    proofProfileId: Buffer.from(inst.protocol.proof.profile_id, 'hex'),
    programIds: inst.protocol.proof.program_ids.map(x => Buffer.from(x, 'hex')),
    sources: [{id: sourceId, credit, publicKey: sourcePublicBytes(issuer.publicKey)}]}));
  stage = 'genesis'; let head = client.init(genesis);
  need(head.height === 0n && head.leafCount === 0n && head.feeEscrow === 0n && head.unconsumedLiabilities === credit);
  const split = BigInt(crypto.randomInt(45000000, 55000001));
  const creditPayment = heldPayment(preparePayment(payer, HELPER, {
    anchor: {root: head.root, count: head.leafCount}, inputs: [], sourceId, credit,
    outputs: [{descriptor: descriptor(payer, 0), amount: split},
      {descriptor: descriptor(payer, 0), amount: credit - FEES[0] - split}],
  }));
  function authorize(payment) {
    return signSource(issuer.privateKey, claimMessage({chain, sourceId, registeredCredit: credit,
      profileId: Buffer.from(inst.protocol.proof.profile_id, 'hex'),
      creditProgramId: Buffer.from(inst.protocol.proof.program_ids[0], 'hex'), statement: publicPayment(payment).statement}));
  }
  stage = 'credit-proof'; const creditFile = path.join(out, 'credit0.body');
  const artifacts = [await publishPayment(creditPayment, backend, prefix + '-credit', authorize(creditPayment), creditFile)];
  stage = 'credit-admission'; head = client.admit([creditFile]);
  need(head.height === 1n && head.leafCount === 2n && head.feeEscrow === FEES[0] && head.unconsumedLiabilities === 0n);
  const payerView = scanWallet(payer, client, genesis, head, out, 'payer-funded');
  const available = withRecovered(payerView, value => value.balance); need(available === credit - FEES[0]);
  const payerInputs = inputsFor(payerView, client, head, 2), received = BigInt(crypto.randomInt(40000000, 50000001));
  const payment = heldPayment(preparePayment(payer, HELPER, {
    anchor: {root: head.root, count: head.leafCount}, inputs: payerInputs,
    outputs: [{descriptor: descriptor(receiver, 1), amount: received},
      {descriptor: descriptor(payer, 0), amount: available - FEES[2] - received}],
  }));
  stage = 'payer-proof'; const payerFile = path.join(out, 'payer2x2.body');
  artifacts.push(await publishPayment(payment, backend, prefix + '-payer', Buffer.alloc(0), payerFile));
  head = client.admit([payerFile]); need(head.height === 2n && head.feeEscrow === FEES[0] + FEES[2]);
  stage = 'offline-receipt'; const receiverView = scanWallet(receiver, client, genesis, head, out, 'receiver-offline');
  need(withRecovered(receiverView, value => value.balance) === received);
  // No wallet database has been written. Original receiver handles are invalidated.
  releaseView(receiverView); releaseWallet(receiver);
  const restoreScan = path.join(out, 'restore.scan'); need(sameHead(client.scan(restoreScan), head));
  const restoreBody = path.join(out, 'restored1x2.body'), restoreConfig = path.join(out, 'restore-public-config.json');
  writeJson(restoreConfig, {format: 'CP03-RESTORE-WORKER01', operator: {path: operatorPath, sha256: operatorSha},
    endpoint: encodedEndpoint(head), inventory: record(inventoryFile), database: relative(database),
    genesis: relative(genesis), scan: relative(restoreScan), checked_scan: relative(path.join(out, 'restore.checked.scan')),
    destination: relative(destinationFile), output_body: relative(restoreBody), proof_label: prefix + '-restored'});
  stage = 'backup-only-new-process';
  const child = spawnSync(process.execPath, ['--disable-sigusr1', SELF, '--restore', relative(restoreConfig), record(restoreConfig).sha256], {
    cwd: ROOT, env: ENV, input: backup, timeout: 180000, maxBuffer: 4096, killSignal: 'SIGKILL',
  });
  try {
    need(!child.error && child.signal === null && child.status === 0 && Buffer.isBuffer(child.stdout) &&
      child.stdout.length === 32 && child.stdout.subarray(0, 8).equals(Buffer.from('CP3RSLT1')) && child.stderr.length === 0);
    const expectedBalance = received;
    const expectedSend = (expectedBalance - FEES[1]) / 2n;
    need(child.stdout.readBigUInt64LE(8) === expectedBalance && child.stdout.readBigUInt64LE(16) === expectedSend &&
      child.stdout.readBigUInt64LE(24) === expectedBalance - FEES[1] - expectedSend);
  }
  finally { child.stdout?.fill(0); child.stderr?.fill(0); backup.fill(0); }
  const after = client.head(); need(after.height === 3n && after.leafCount === 6n &&
    after.feeEscrow === FEES[0] + FEES[2] + FEES[1] && after.unconsumedLiabilities === 0n);
  stage = 'final-history'; const finalScan = path.join(out, 'final.scan'); need(sameHead(client.scan(finalScan), after));
  const finalView = scanWallet(destination, client, genesis, after, out, 'destination-final');
  const restoredBalance = received;
  need(withRecovered(finalView, value => value.balance) === (restoredBalance - FEES[1]) / 2n);
  stage = 'public-artifact-manifest';
  const portableHeaders = headersFromScan(finalScan, out);
  const portableEntry = file => ({path: path.basename(file), sha256: record(file).sha256});
  writeJson(path.join(out, 'workload.json'), {format: 'CP03-DISTINCT-BLOCK-WORKLOAD01',
    chain: chain.toString('hex'), genesis: portableEntry(genesis),
    blocks: [creditFile, payerFile, restoreBody].map((file, i) => ({
      header: {path: path.basename(portableHeaders[i].path), sha256: portableHeaders[i].sha256},
      bodies: [portableEntry(file)]})),
    endpoint: {height: after.height.toString(), block_id: after.blockId.toString('hex'),
      leaf_count: after.leafCount.toString(), root_le: after.root.toString('hex'),
      fee_escrow: after.feeEscrow.toString(), unconsumed_liabilities: after.unconsumedLiabilities.toString()}});

  writeJson(path.join(out, 'cycle-public-artifacts.json'), {format: 'CP03-CYCLE-PUBLIC-ARTIFACTS01', artifacts,
    restored_proof_label: prefix + '-restored',
    endpoint: encodedEndpoint(after), history_validity_trust: 'laboratory endpoint from actual full validating local ledger',
    inventory_trust: 'separate current public inventory retained before offline receipt; no later key rotation',
    backup_or_private_note_files_written: false});
  return JSON.stringify({"format": "CP03-FRESH-PRIVATE-REPRO01", "private_credit_payment_receipt": true, "fresh_backup_only_restore_and_admitted_spend": true, "genuine_proofs_created": 3, "resource_profile_pass": false, "whole_protocol_pq_privacy_theorem": false, "production_ready": false}) + '\n';
}
function clean() {
  let success = true;
  for (const p of payments) { try { disposePayment(p); } catch { success = false; } }
  for (const v of views) { try { disposeRecovered(v); } catch { success = false; } }
  for (const w of wallets) { try { disposeWallet(w); } catch { success = false; } }
  for (const b of privateBuffers) { try { b.fill(0); } catch { success = false; } }
  return success;
}
let result, failed = false;
try {
  if (process.argv.length === 5 && process.argv[2] === '--restore') result = await restoreWorker(process.argv[3], process.argv[4]);
  else { need(process.argv.length === 5); result = await main(process.argv[2], process.argv[3], process.argv[4]); }
} catch {
  failed = true;
} finally {
  if (!clean()) { failed = true; stage = 'cleanup'; }
}
if (failed) {
  if (Buffer.isBuffer(result)) result.fill(0);
  // Static source-selected stage only, never a provider exception or secret fixture.
  fs.writeSync(2, 'CP03_CYCLE_FAILED ' + stage + '\n'); process.exitCode = 1;
} else {
  try { fs.writeSync(1, result); }
  finally { if (Buffer.isBuffer(result)) result.fill(0); }
}
