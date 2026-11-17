// Fixed local workload producer. Private keys, openings and pair selection stay in RAM.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {initializeRetained} from './retain-init.mjs';
const HERE = fileURLToPath(new URL('./', import.meta.url));
const REPOSITORY = path.resolve(HERE, '../../..');
let SOURCE, HELPER, OPERATOR, OPERATOR_SHA;
let createWallet, descriptor, disposeWallet, withWallet, encodeGenesis, parseStatement, FEES;
let preparePayment, publicPayment, completeBody, disposePayment;
let installPrivateProver, provePayment, preparePublicLedger;
let createReceiptAdapter, wipeOpening;
let claimMessage, signSource, sourcePublicBytes;
const COUNT = Number(process.argv[5]); // Fixed diagnostic2 or Gate2 lanes96, never peer input.
const BATCHES = COUNT === 2 ? 3 : 8;
const proofCosts = [], batchCosts = [];
const RESULT = Object.freeze({format: 'CP04-NETWORK-PIPELINE-PRODUCER01',
  credit_proofs: COUNT, ordinary_proofs: COUNT * BATCHES, accepted_blocks: BATCHES + 1,
  private_material_or_mapping_persisted: false, resource_profile_pass: false});
const wallets = new Set(), payments = new Set();
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
    'runtime/cp03/source-signature.mjs', 'experiments/compact-receiving-v1/cp03/receipt.mjs'];
  for (const name of names) need(installed.pins[sourcePath(name)] === sha(readPublic(sourcePath(name), 1024 * 1024)));
  const modules = [];
  for (const name of names) modules.push(await import(pathToFileURL(sourcePath(name)).href));
  ({createWallet, descriptor, disposeWallet, withWallet} = modules[0]);
  ({encodeGenesis, parseStatement, FEES} = modules[1]);
  ({preparePayment, publicPayment, completeBody, disposePayment} = modules[2]);
  ({installPrivateProver, provePayment} = modules[3]);
  ({preparePublicLedger} = modules[4]);
  ({claimMessage, signSource, sourcePublicBytes} = modules[6]);
  ({createReceiptAdapter, wipeOpening} = modules[7]);
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
  const networkPath = sourcePath('docs/architecture/CP_NETWORK_04.json');
  const networkBytes = readPublic(networkPath, 65536);
  need(installed.pins[networkPath] === sha(networkBytes));
  const network = JSON.parse(networkBytes.toString('utf8'));
  need(network.format === 'PQPC-CP04-NETWORK-RESEARCH-PROTOCOL-01' &&
    network.base_payment_protocol_id === h64('PROTOCOL', protocolBytes).toString('hex') &&
    network.proof.profile_id === protocol.proof.profile_id &&
    JSON.stringify(network.proof.program_ids) === JSON.stringify(protocol.proof.program_ids) &&
    network.state.block_body_count_max === '128' &&
    network.state.complete_encoded_block_bytes_max === '268435456');
  return {value, protocol: network, protocolId: h64('PROTOCOL', networkBytes)};
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
  return {chain: head.chain, genesisId: head.genesisId, height: head.height, blockId: head.blockId, blockVersion: 4};
}
function heldWallet(value) { wallets.add(value); return value; }
function heldPayment(value) { payments.add(value); return value; }
function releaseWallet(value) { disposeWallet(value); wallets.delete(value); }
function releasePayment(value) { disposePayment(value); payments.delete(value); }
function shufflePrivate(values) {
  // The permutation is never exported: public ordinary order must not reveal
  // which credit pair was selected for each payment.
  for (let i = values.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1); [values[i], values[j]] = [values[j], values[i]];
  }
}
async function publish(payment, backend, label, authorization, file, directory, batch) {
  const published = publicPayment(payment); // Only encrypted envelopes and statement, no openings.
  const started = performance.now();
  const proof = await provePayment(backend, payment, label);
  writePublic(file, completeBody(payment, authorization, proof.proof));
  // Parent receipt is retained by the unchanged installed parent. Do not copy
  // private packets or log/have a digest of the input selection.
  const receipt = readPublic(proof.parent_receipt, 8 * 1024 * 1024);
  const actual = JSON.parse(receipt.toString('utf8'));
  need(actual.wrapper_exit === 0 && actual.process_exit === 0 && actual.timeout === false);
  for (const key of ['child_wall_seconds', 'wait4_user_seconds', 'wait4_system_seconds', 'wait4_maxrss_kib'])
    need(typeof actual[key] === 'number' && Number.isFinite(actual[key]) && actual[key] >= 0);
  need(actual.arity === (batch === 0 ? 0 : 2));
  const cost = {body: path.basename(file), batch, arity: actual.arity,
    private_proving_call_wall_seconds: (performance.now() - started) / 1000,
    worker_wall_seconds: actual.child_wall_seconds, worker_user_seconds: actual.wait4_user_seconds,
    worker_system_seconds: actual.wait4_system_seconds, worker_peak_rss_kib: actual.wait4_maxrss_kib,
    parent_receipt: path.relative(SOURCE, proof.parent_receipt), parent_receipt_sha256: sha(receipt),
    proof_bytes: proof.proof.length, body_bytes: fs.statSync(file).size};
  proofCosts.push(cost);
  writeJson(file + '.proof-cost.json', cost); // Preserve completed public costs even on a later failure.
  releasePayment(payment);
  return {body: entry(file, directory), published};
}
function headers(scan, directory) {
  const bytes = readPublic(scan, 12 * 1024 * 1024), result = []; let at = 0;
  while (at < bytes.length) {
    need(at + 4 <= bytes.length); const length = bytes.readUInt32LE(at); at += 4;
    need(length > 0 && length <= 1224804 && at + length <= bytes.length);
    const block = bytes.subarray(at, at + length);
    need(block.subarray(0, 8).equals(Buffer.from('CPSBLK04')));
    const size = block.readUInt32LE(8);
    need(size >= 216 && size <= 8408 && 12 + size <= block.length);
    const file = path.join(directory, 'block' + String(result.length + 1).padStart(3, '0') + '.header');
    writePublic(file, block.subarray(12, 12 + size)); result.push(entry(file, directory)); at += length;
  }
  need(result.length === BATCHES + 1); return result;
}
// One shared public context batch avoids repeating the same CP hashes for every
// fresh lane wallet. This is fixture extraction from the latest admitted block,
// not general history recovery or the Gate3 selective witness algorithm.
function receiptBatch(adapter, published, head) {
  need(published.length === COUNT);
  const contexts = adapter.contextsBatch(published.map(row => row.statement));
  const firstIndex = head.leafCount - 2n * BigInt(COUNT), entries = [], positions = new Map();
  for (let row = 0; row < COUNT; row++) for (let ordinal = 0; ordinal < 2; ordinal++) {
    const context = contexts[row][ordinal], info = adapter.contextInfo(context);
    const envelope = published[row].envelopes[ordinal];
    const statement = parseStatement(published[row].statement);
    // The canonical admission already checked both receipt digests. Recheck the
    // exact statement projection locally before using a decrypted candidate.
    need(adapter.digest(context, envelope).equals(statement.receipts[ordinal]));
    const identity = info.origin.toString('hex') + ':' + info.cm.toString('hex');
    need(!positions.has(identity));
    positions.set(identity, firstIndex + BigInt(2 * row + ordinal));
    entries.push({context, envelope});
  }
  return {entries, positions, firstIndex};
}
function disposeCandidates(candidates) {
  for (const candidate of candidates) { wipeOpening(candidate.opening); candidate.nf.fill(0); }
}
function paymentFromFreshLane(wallet, destination, adapter, batch, client, anchor, usedIndices, expectedBalance) {
  let recipients = [], candidates = [];
  try {
    withWallet(wallet, value => {
      need(value.keys.length === 1);
      recipients = value.keys.map(key => adapter.prepareRecipient(key.descriptor, key.key, value.spending));
    });
    candidates = adapter.collectLocalCandidates(recipients, batch.entries).candidates;
    need(candidates.length === 2);
    let balance = 0n;
    const inputs = candidates.map(candidate => {
      const identity = candidate.origin.toString('hex') + ':' + candidate.cm.toString('hex');
      const index = batch.positions.get(identity);
      need(typeof index === 'bigint' && index >= batch.firstIndex && index < anchor.leafCount && !usedIndices.has(index));
      usedIndices.add(index);
      balance += candidate.opening.note.readBigUInt64LE(8);
      const membership = client.membership(index, {count: anchor.leafCount, root: anchor.root});
      need(membership.index === index && membership.origin.equals(candidate.origin) && membership.cm.equals(candidate.cm));
      return {note: candidate.opening.note, origin: candidate.origin, index, siblings: membership.siblings};
    });
    need(balance === expectedBalance && balance > FEES[2] + 50000000n);
    const send = BigInt(crypto.randomInt(40000000, 50000001));
    return heldPayment(preparePayment(wallet, HELPER, {anchor: {root: anchor.root, count: anchor.leafCount}, inputs,
      outputs: [{descriptor: descriptor(destination, 0), amount: send},
        {descriptor: descriptor(destination, 0), amount: balance - FEES[2] - send}]}));
  } finally {
    disposeCandidates(candidates);
    for (const recipient of recipients) adapter.disposeRecipient(recipient);
  }
}
function attemptName(prefix, batch, index) {
  return prefix + (batch === 0 ? '-credit-' : '-b' + String(batch).padStart(2, '0') + '-ordinary-') +
    String(index).padStart(3, '0');
}
async function main(label, installationFile, approvedInstallation) {
  need(/^[a-z][a-z0-9_-]{0,31}$/.test(label) && [2, 96].includes(COUNT));
  const inst = await installation(installationFile, approvedInstallation), prefix = 'net2-' + label;
  const out = path.join(HERE, '.work', label + '.public');
  fs.mkdirSync(path.dirname(out), {recursive: true}); fs.mkdirSync(out, {mode: 0o700});
  // All labels are checked before any key exists. A failed label is never reused.
  for (let batch = 0; batch <= BATCHES; batch++) for (let i = 0; i < COUNT; i++) {
    const attempt = attemptName(prefix, batch, i);
    need(!fs.existsSync(sourcePath('experiments/compact-all-payments-v3/public/' + attempt)));
    for (const suffix of ['.claim', '.json'])
      need(!fs.existsSync(sourcePath('experiments/compact-all-payments-v3/evidence/' + attempt + suffix)));
  }
  const backend = installPrivateProver(inst.value.private_approval.path, inst.value.private_approval.sha256);
  const chain = crypto.randomBytes(32), credit = 100000000n;
  stage = 'key-generation'; issuer = crypto.generateKeyPairSync('ml-dsa-87');
  const sourceKey = sourcePublicBytes(issuer.publicKey), records = [];
  for (let i = 0; i < COUNT; i++) records.push({sourceId: crypto.randomBytes(48),
    payer: heldWallet(createWallet(chain, HELPER))});
  records.sort((a, b) => Buffer.compare(a.sourceId, b.sourceId));
  for (let i = 1; i < records.length; i++) need(Buffer.compare(records[i - 1].sourceId, records[i].sourceId) < 0);
  const genesis = path.join(out, 'genesis.bin'), database = path.join(out, 'producer.sqlite');
  writePublic(genesis, encodeGenesis({version: 4, chain, protocolId: inst.protocolId,
    proofProfileId: Buffer.from(inst.protocol.proof.profile_id, 'hex'),
    programIds: inst.protocol.proof.program_ids.map(x => Buffer.from(x, 'hex')),
    sources: records.map(record => ({id: record.sourceId, credit, publicKey: sourceKey}))}));
  const binary = sourcePath(inst.value.ledger_binary.path);
  const client = preparePublicLedger({binaryPath: binary, binarySha256: inst.value.ledger_binary.sha256,
    chain, dbPath: database, blockVersion: 4, retention: 'retain'});
  stage = 'genesis';
  let head = initializeRetained({client, binary, expectedSha256: inst.value.ledger_binary.sha256,
    database, chain, genesis, receiptFile: path.join(out, 'retention-init.json')});
  need(head.height === 0n && head.leafCount === 0n && head.feeEscrow === 0n &&
    head.unconsumedLiabilities === BigInt(COUNT) * credit);
  const blockRows = [], creditFiles = [], creditRows = [], creditPublished = [];
  const fundingStarted = performance.now();
  stage = 'credit-proofs';
  for (let i = 0; i < COUNT; i++) {
    const record = records[i], split = BigInt(crypto.randomInt(45000000, 55000001));
    const payment = heldPayment(preparePayment(record.payer, HELPER, {
      anchor: {root: head.root, count: head.leafCount}, inputs: [], sourceId: record.sourceId, credit,
      outputs: [{descriptor: descriptor(record.payer, 0), amount: split},
        {descriptor: descriptor(record.payer, 0), amount: credit - FEES[0] - split}]}));
    const authorization = signSource(issuer.privateKey, claimMessage({chain, sourceId: record.sourceId,
      registeredCredit: credit, profileId: Buffer.from(inst.protocol.proof.profile_id, 'hex'),
      creditProgramId: Buffer.from(inst.protocol.proof.program_ids[0], 'hex'), statement: publicPayment(payment).statement}));
    const file = path.join(out, 'credit' + String(i).padStart(3, '0') + '.body'); creditFiles.push(file);
    const row = await publish(payment, backend, attemptName(prefix, 0, i), authorization, file, out, 0);
    creditRows.push(row.body); creditPublished.push(row.published);
  }
  stage = 'credit-block';
  const fundingAdmission = performance.now(); head = client.admit(creditFiles);
  need(head.height === 1n && head.leafCount === 2n * BigInt(COUNT) &&
    head.feeEscrow === BigInt(COUNT) * FEES[0] && head.unconsumedLiabilities === 0n);
  blockRows.push({bodies: creditRows});
  batchCosts.push({batch: 0, kind: 'funding', body_count: COUNT, endpoint: endpoint(head),
    inclusive_wall_seconds: (performance.now() - fundingStarted) / 1000,
    admission_wall_seconds: (performance.now() - fundingAdmission) / 1000});
  let owners = records.map(record => record.payer), published = creditPublished;
  records.length = 0; issuer = null;
  const adapter = createReceiptAdapter(chain, HELPER);
  for (let batch = 1; batch <= BATCHES; batch++) {
    const started = performance.now(), anchor = head;
    stage = 'ordinary-receipts';
    const receipts = receiptBatch(adapter, published, anchor);
    shufflePrivate(owners); // Intact two-note owners, independently shuffled each batch.
    const nextOwners = [], files = [], rows = [], nextPublished = [], usedIndices = new Set();
    stage = 'ordinary-proofs';
    for (let i = 0; i < COUNT; i++) {
      const destination = heldWallet(createWallet(chain, HELPER)); nextOwners.push(destination);
      const payment = paymentFromFreshLane(owners[i], destination, adapter, receipts, client, anchor,
        usedIndices, credit - FEES[0] - BigInt(batch - 1) * FEES[2]);
      const file = path.join(out, 'batch' + String(batch).padStart(2, '0') + '-' + String(i).padStart(3, '0') + '.body');
      files.push(file);
      const row = await publish(payment, backend, attemptName(prefix, batch, i), Buffer.alloc(0), file, out, batch);
      rows.push(row.body); nextPublished.push(row.published);
    }
    need(usedIndices.size === 2 * COUNT);
    for (let index = receipts.firstIndex; index < anchor.leafCount; index++) need(usedIndices.has(index));
    usedIndices.clear();
    stage = 'ordinary-block';
    const admissionStarted = performance.now(); head = client.admit(files);
    need(head.height === BigInt(batch + 1) && head.leafCount === 2n * BigInt(COUNT * (batch + 1)) &&
      !head.root.equals(anchor.root) && head.feeEscrow === BigInt(COUNT) * (FEES[0] + BigInt(batch) * FEES[2]) &&
      head.unconsumedLiabilities === 0n);
    blockRows.push({bodies: rows});
    batchCosts.push({batch, kind: 'ordinary', body_count: COUNT, anchor: endpoint(anchor), endpoint: endpoint(head),
      inclusive_wall_seconds: (performance.now() - started) / 1000,
      admission_wall_seconds: (performance.now() - admissionStarted) / 1000});
    // No old wallet/key or private recovered state is needed after its pair is spent.
    for (const wallet of owners) releaseWallet(wallet);
    owners = nextOwners; published = nextPublished;
    writeJson(path.join(out, 'batch' + String(batch).padStart(2, '0') + '-receipt.json'), batchCosts.at(-1));
  }
  stage = 'final-history';
  const finalScan = path.join(out, 'final.scan'), finalChecked = path.join(out, 'final.checked.scan');
  need(sameHead(client.scan(finalScan), head));
  client.checkScan(genesis, finalScan, scanEndpoint(head), finalChecked);
  const headerRows = headers(finalChecked, out);
  for (let index = 0; index < blockRows.length; index++) blockRows[index].header = headerRows[index];
  stage = 'workload-manifest';
  writeJson(path.join(out, 'workload.json'), {format: 'CP04-NETWORK-PIPELINE-WORKLOAD01', block_version: 4,
    ordinary_count: COUNT * BATCHES, batch_size: COUNT, ordinary_batch_count: BATCHES,
    chain: chain.toString('hex'), genesis: entry(genesis, out), blocks: blockRows, endpoint: endpoint(head)});
  writeJson(path.join(out, 'proof-costs.json'), {format: 'CP04-PRODUCER-PROOF-COSTS02',
    credit_proofs: COUNT, ordinary_proofs: COUNT * BATCHES, rows: proofCosts, batches: batchCosts,
    scope: 'Fresh complete proof generation and repeated producer admission; fixture-local receipt extraction/membership, not Gate3 discovery, live wallet throughput or receiving-node service. Worker CPU/RSS from actual first wait4; peaks are not summed.'});
  return RESULT;
}
function cleanup() {
  let ok = true;
  for (const p of payments) try { disposePayment(p); } catch { ok = false; }
  for (const w of wallets) try { disposeWallet(w); } catch { ok = false; }
  payments.clear(); wallets.clear(); issuer = null;
  return ok;
}
let result, failed = false;
try { need(process.argv.length === 6); result = await main(process.argv[2], process.argv[3], process.argv[4]); }
catch { failed = true; }
finally { if (!cleanup()) { failed = true; stage = 'cleanup'; } }
if (failed) { fs.writeSync(2, 'CP04_WORKLOAD_FAILED ' + stage + '\n'); process.exitCode = 1; }
else fs.writeSync(1, JSON.stringify(result) + '\n');
