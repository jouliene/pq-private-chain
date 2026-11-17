// Fixed local workload producer. Private keys, openings and pair selection stay in RAM.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {fileURLToPath, pathToFileURL} from 'node:url';
const HERE = fileURLToPath(new URL('./', import.meta.url));
const REPOSITORY = path.resolve(HERE, '../../../..');
let SOURCE, HELPER, OPERATOR, OPERATOR_SHA;
let createWallet, descriptor, disposeWallet, encodeGenesis, FEES;
let preparePayment, publicPayment, completeBody, disposePayment;
let installPrivateProver, provePayment, preparePublicLedger;
let recoverHistory, withRecovered, disposeRecovered;
let claimMessage, signSource, sourcePublicBytes;
const RESULT = Object.freeze({format: 'CP03-DISTINCT-BLOCK-PRODUCER01',
  credit_proofs: 16, ordinary_proofs: 16, accepted_blocks: 2,
  private_material_or_mapping_persisted: false, resource_profile_pass: false});
const wallets = new Set(), views = new Set(), payments = new Set();
let stage = 'preflight', issuer = null;
function need(value) { if (value !== true) throw new Error('CP03_WORKLOAD_CONDITION'); }
function sha(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function readPublic(file, cap) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(fd, {bigint: true}); need(before.isFile() && before.size <= BigInt(cap));
    const chunks = []; let length = 0;
    for (;;) {
      const bytes = Buffer.alloc(Math.min(65536, cap + 1 - length));
      const n = fs.readSync(fd, bytes, 0, bytes.length, null); if (!n) break;
      length += n; need(length <= cap); chunks.push(bytes.subarray(0, n));
    }
    const after = fs.fstatSync(fd, {bigint: true});
    need(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(k => before[k] === after[k]));
    return Buffer.concat(chunks, length);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function sourcePath(name) {
  need(typeof name === 'string' && !path.isAbsolute(name) && !name.split('/').includes('..'));
  return path.join(SOURCE, name);
}
function writePublic(file, bytes) { fs.writeFileSync(file, bytes, {flag: 'wx', mode: 0o600}); }
function writeJson(file, value) { writePublic(file, Buffer.from(JSON.stringify(value, null, 2) + '\n')); }
function entry(file, directory, cap = 3 * 1024 * 1024) {
  const name = path.relative(directory, file);
  need(name.length > 0 && !path.isAbsolute(name) && !name.split('/').includes('..') && !fs.lstatSync(file).isSymbolicLink());
  return {path: name, sha256: sha(readPublic(file, cap))};
}
function h64(label, bytes) {
  const tag = Buffer.from('PQPC/CP3/' + label), size = Buffer.alloc(4), length = Buffer.alloc(2);
  length.writeUInt16LE(tag.length); size.writeUInt32LE(bytes.length);
  return crypto.createHash('sha3-512').update(length).update(tag).update(size).update(bytes).digest();
}
async function installation(file, approvedSha) {
  need(/^[0-9a-f]{64}$/.test(approvedSha));
  const rawInstallation = readPublic(file, 8 * 1024 * 1024);
  need(sha(rawInstallation) === approvedSha);
  const installed = JSON.parse(rawInstallation.toString('utf8'));
  need(installed.format === 'CP03-PUBLIC-INSTALLATION01' && installed.repository === REPOSITORY);
  SOURCE = installed.source_root;
  need(typeof SOURCE === 'string' && path.isAbsolute(SOURCE) && fs.realpathSync(SOURCE) === SOURCE);
  const relative = path.relative(path.join(REPOSITORY, '.work'), SOURCE);
  need(relative.length > 0 && !path.isAbsolute(relative) && !relative.split(path.sep).includes('..'));
  HELPER = installed.helper_sha256;
  OPERATOR = installed.operator.path;
  OPERATOR_SHA = installed.operator_sha256;
  need(installed.operator.sha256 === OPERATOR_SHA && sourcePath(OPERATOR) === installed.operator_path);
  need(fs.realpathSync(installed.node) === fs.realpathSync(process.execPath));
  const names = ['wallet/cp03/keys.mjs', 'wallet/cp03/codec.mjs', 'wallet/cp03/payments.mjs',
    'wallet/cp03/private_prover.mjs', 'wallet/cp03/public_ledger.mjs', 'wallet/cp03/recovery.mjs',
    'runtime/cp03/source-signature.mjs'];
  for (const name of names) need(installed.pins[sourcePath(name)] === sha(readPublic(sourcePath(name), 1024 * 1024)));
  const modules = [];
  for (const name of names) modules.push(await import(pathToFileURL(sourcePath(name)).href));
  ({createWallet, descriptor, disposeWallet} = modules[0]);
  ({encodeGenesis, FEES} = modules[1]);
  ({preparePayment, publicPayment, completeBody, disposePayment} = modules[2]);
  ({installPrivateProver, provePayment} = modules[3]);
  ({preparePublicLedger} = modules[4]);
  ({recoverHistory, withRecovered, disposeRecovered} = modules[5]);
  ({claimMessage, signSource, sourcePublicBytes} = modules[6]);
  const raw = readPublic(sourcePath(OPERATOR), 65536); need(sha(raw) === OPERATOR_SHA);
  const value = JSON.parse(raw.toString('utf8'));
  need(value.format === 'CP03-CYCLE-OPERATOR01' && value.helper_sha256 === HELPER);
  for (const name of ['ledger_binary', 'ledger_build_receipt', 'private_approval', 'provider_controls_receipt', 'protocol_manifest']) {
    const e = value[name]; need(e && /^[0-9a-f]{64}$/.test(e.sha256));
    need(sha(readPublic(sourcePath(e.path), name === 'ledger_binary' ? 64 * 1024 * 1024 : 16 * 1024 * 1024)) === e.sha256);
  }
  const protocolBytes = readPublic(sourcePath(value.protocol_manifest.path), 65536);
  const protocol = JSON.parse(protocolBytes.toString('utf8'));
  need(protocol.format === 'PQPC-CP03-RESEARCH-PROTOCOL-01');
  return {value, protocol, protocolId: h64('PROTOCOL', protocolBytes)};
}
function sameHead(a, b) {
  return a.height === b.height && a.leafCount === b.leafCount && a.blockId.equals(b.blockId) &&
    a.root.equals(b.root) && a.feeEscrow === b.feeEscrow && a.unconsumedLiabilities === b.unconsumedLiabilities;
}
function endpoint(head) {
  return {height: head.height.toString(), block_id: head.blockId.toString('hex'),
    leaf_count: head.leafCount.toString(), root_le: head.root.toString('hex'),
    fee_escrow: head.feeEscrow.toString(), unconsumed_liabilities: head.unconsumedLiabilities.toString()};
}
function scanEndpoint(head) {
  return {chain: head.chain, genesisId: head.genesisId, height: head.height, blockId: head.blockId};
}
function heldWallet(value) { wallets.add(value); return value; }
function heldView(value) { views.add(value); return value; }
function heldPayment(value) { payments.add(value); return value; }
function releaseView(value) { disposeRecovered(value); views.delete(value); }
function releasePayment(value) { disposePayment(value); payments.delete(value); }
function shufflePrivate(values) {
  // The permutation is never exported: public ordinary order must not reveal
  // which credit pair was selected for each payment.
  for (let i = values.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1); [values[i], values[j]] = [values[j], values[i]];
  }
}
async function publish(payment, backend, label, authorization, file, directory) {
  const proof = await provePayment(backend, payment, label);
  writePublic(file, completeBody(payment, authorization, proof.proof));
  // Parent receipt is retained by the unchanged installed parent. Do not copy
  // private packets or log/have a digest of the input selection.
  const receipt = readPublic(proof.parent_receipt, 8 * 1024 * 1024);
  need(JSON.parse(receipt.toString('utf8')).wrapper_exit === 0);
  releasePayment(payment);
  return entry(file, directory);
}
function headers(scan, directory) {
  const bytes = readPublic(scan, 512 * 1024), result = []; let at = 0;
  while (at < bytes.length) {
    need(at + 4 <= bytes.length); const length = bytes.readUInt32LE(at); at += 4;
    need(length > 0 && length <= 153292 && at + length <= bytes.length);
    const block = bytes.subarray(at, at + length);
    need(block.subarray(0, 8).equals(Buffer.from('CPSBLK03')));
    const size = block.readUInt32LE(8);
    need(size >= 272 && size <= 1232 && 12 + size <= block.length);
    const file = path.join(directory, 'block' + String(result.length + 1).padStart(2, '0') + '.header');
    writePublic(file, block.subarray(12, 12 + size)); result.push(entry(file, directory)); at += length;
  }
  need(result.length === 2); return result;
}
async function main(label, installationFile, approvedInstallation) {
  need(/^[a-z][a-z0-9_-]{0,31}$/.test(label));
  const inst = await installation(installationFile, approvedInstallation), prefix = 'role-' + label;
  const out = path.join(HERE, '.work', label + '.public');
  fs.mkdirSync(path.dirname(out), {recursive: true}); fs.mkdirSync(out, {mode: 0o700});
  // Check all immutable labels before any key exists. No partial retry can
  // accidentally consume a historical producer artifact.
  for (const kind of ['credit', 'ordinary']) for (let i = 0; i < 16; i++) {
    const attempt = prefix + '-' + kind + '-' + String(i).padStart(2, '0');
    need(!fs.existsSync(sourcePath('experiments/compact-all-payments-v3/public/' + attempt)));
    for (const suffix of ['.claim', '.json']) need(!fs.existsSync(sourcePath('experiments/compact-all-payments-v3/evidence/' + attempt + suffix)));
  }
  const backend = installPrivateProver(inst.value.private_approval.path, inst.value.private_approval.sha256);
  const chain = crypto.randomBytes(32), credit = 100000000n;
  stage = 'key-generation'; issuer = crypto.generateKeyPairSync('ml-dsa-87');
  const sourceKey = sourcePublicBytes(issuer.publicKey), records = [];
  for (let i = 0; i < 16; i++) records.push({sourceId: crypto.randomBytes(48),
    payer: heldWallet(createWallet(chain, HELPER)), destination: heldWallet(createWallet(chain, HELPER))});
  records.sort((a, b) => Buffer.compare(a.sourceId, b.sourceId));
  for (let i = 1; i < records.length; i++) need(Buffer.compare(records[i - 1].sourceId, records[i].sourceId) < 0);
  const genesis = path.join(out, 'genesis.bin'), database = path.join(out, 'producer.sqlite');
  writePublic(genesis, encodeGenesis({chain, protocolId: inst.protocolId,
    proofProfileId: Buffer.from(inst.protocol.proof.profile_id, 'hex'),
    programIds: inst.protocol.proof.program_ids.map(x => Buffer.from(x, 'hex')),
    sources: records.map(r => ({id: r.sourceId, credit, publicKey: sourceKey}))}));
  const client = preparePublicLedger({binaryPath: sourcePath(inst.value.ledger_binary.path),
    binarySha256: inst.value.ledger_binary.sha256, chain, dbPath: database});
  stage = 'genesis'; let head = client.init(genesis);
  need(head.height === 0n && head.leafCount === 0n && head.feeEscrow === 0n && head.unconsumedLiabilities === 16n * credit);
  const creditFiles = [], creditRows = [];
  stage = 'credit-proofs';
  for (let i = 0; i < 16; i++) {
    const r = records[i], split = BigInt(crypto.randomInt(45000000, 55000001));
    const payment = heldPayment(preparePayment(r.payer, HELPER, {
      anchor: {root: head.root, count: head.leafCount}, inputs: [], sourceId: r.sourceId, credit,
      outputs: [{descriptor: descriptor(r.payer, 0), amount: split},
        {descriptor: descriptor(r.payer, 0), amount: credit - FEES[0] - split}],
    }));
    const authorization = signSource(issuer.privateKey, claimMessage({chain, sourceId: r.sourceId,
      registeredCredit: credit, profileId: Buffer.from(inst.protocol.proof.profile_id, 'hex'),
      creditProgramId: Buffer.from(inst.protocol.proof.program_ids[0], 'hex'), statement: publicPayment(payment).statement}));
    const file = path.join(out, 'credit' + String(i).padStart(2, '0') + '.body'); creditFiles.push(file);
    creditRows.push(await publish(payment, backend, prefix + '-credit-' + String(i).padStart(2, '0'), authorization, file, out));
  }
  stage = 'credit-block'; head = client.admit(creditFiles);
  need(head.height === 1n && head.leafCount === 32n && head.feeEscrow === 16n * FEES[0] && head.unconsumedLiabilities === 0n);
  const funded = head, scan = path.join(out, 'funded.scan'), checked = path.join(out, 'funded.checked.scan');
  stage = 'funded-history'; need(sameHead(client.scan(scan), funded));
  client.checkScan(genesis, scan, scanEndpoint(funded), checked);
  // This local trusted-service workload intentionally uses the installed public
  // membership API. Neither queries nor the private permutation are persisted.
  shufflePrivate(records);
  const usedIndices = new Set(), ordinaryFiles = [], ordinaryRows = [];
  stage = 'ordinary-proofs';
  for (let i = 0; i < 16; i++) {
    const r = records[i], recovered = recoverHistory(r.payer, checked, scanEndpoint(funded), 'unknown');
    need(recovered.history_linkage_complete && recovered.payment_validity === 'delegated-to-independently-supplied-endpoint');
    const view = heldView(recovered.state), send = BigInt(crypto.randomInt(40000000, 50000001));
    const payment = withRecovered(view, value => {
      need(value.balance === credit - FEES[0] && value.unspent.size === 2);
      const pair = [...value.unspent.values()].sort((a, b) => a.index < b.index ? -1 : a.index > b.index ? 1 : 0);
      const inputs = pair.map(candidate => {
        need(!usedIndices.has(candidate.index)); usedIndices.add(candidate.index);
        const membership = client.membership(candidate.index, {count: funded.leafCount, root: funded.root});
        need(membership.origin.equals(candidate.origin) && membership.cm.equals(candidate.cm));
        return {note: candidate.opening.note, origin: candidate.origin, index: candidate.index, siblings: membership.siblings};
      });
      return heldPayment(preparePayment(r.payer, HELPER, {anchor: {root: funded.root, count: funded.leafCount}, inputs,
        outputs: [{descriptor: descriptor(r.destination, 0), amount: send},
          {descriptor: descriptor(r.payer, 0), amount: value.balance - FEES[2] - send}]}));
    });
    releaseView(view);
    const file = path.join(out, 'ordinary' + String(i).padStart(2, '0') + '.body'); ordinaryFiles.push(file);
    ordinaryRows.push(await publish(payment, backend, prefix + '-ordinary-' + String(i).padStart(2, '0'), Buffer.alloc(0), file, out));
  }
  need(usedIndices.size === 32); usedIndices.clear();
  stage = 'ordinary-block'; head = client.admit(ordinaryFiles);
  need(head.height === 2n && head.leafCount === 64n && head.feeEscrow === 16n * (FEES[0] + FEES[2]) && head.unconsumedLiabilities === 0n);
  const finalScan = path.join(out, 'final.scan'), finalChecked = path.join(out, 'final.checked.scan');
  stage = 'final-history'; need(sameHead(client.scan(finalScan), head));
  client.checkScan(genesis, finalScan, scanEndpoint(head), finalChecked);
  const headerRows = headers(finalChecked, out);
  stage = 'workload-manifest';
  writeJson(path.join(out, 'workload.json'), {format: 'CP03-DISTINCT-BLOCK-WORKLOAD01', chain: chain.toString('hex'),
    genesis: entry(genesis, out), blocks: [{header: headerRows[0], bodies: creditRows}, {header: headerRows[1], bodies: ordinaryRows}],
    endpoint: endpoint(head)});
  return RESULT;
}
function cleanup() {
  let ok = true;
  for (const p of payments) try { disposePayment(p); } catch { ok = false; }
  for (const v of views) try { disposeRecovered(v); } catch { ok = false; }
  for (const w of wallets) try { disposeWallet(w); } catch { ok = false; }
  payments.clear(); views.clear(); wallets.clear(); issuer = null;
  return ok;
}
let result, failed = false;
try { need(process.argv.length === 5); result = await main(process.argv[2], process.argv[3], process.argv[4]); }
catch { failed = true; }
finally { if (!cleanup()) { failed = true; stage = 'cleanup'; } }
if (failed) { fs.writeSync(2, 'CP03_WORKLOAD_FAILED ' + stage + '\n'); process.exitCode = 1; }
else fs.writeSync(1, JSON.stringify(result) + '\n');
