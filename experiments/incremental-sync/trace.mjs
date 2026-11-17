// Isolated zero-owned-note trace. All keys/backups remain RAM-only; no proving.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

let stage = 'configuration';
const wallets = new Set(), sessions = new Set();
let keys, local;
function need(ok) { if (!ok) throw new Error('CP04_TRACE_CONDITION'); }
function read(size) {
  const value = Buffer.alloc(size); let at = 0;
  while (at < size) { const n = fs.readSync(0, value, at, size - at, null); need(n > 0); at += n; }
  return value;
}
function send(kind, value) {
  const raw = Buffer.from(JSON.stringify(value)), prefix = Buffer.alloc(5);
  need(raw.length <= 65536); prefix[0] = kind; prefix.writeUInt32LE(raw.length, 1);
  for (const part of [prefix, raw]) { let at = 0; while (at < part.length) at += fs.writeSync(1, part, at); }
}
function rpc(value) {
  send(1, value); const prefix = read(5);
  need(prefix[0] === 2 && prefix.readUInt32LE(1) <= 65536);
  const raw = read(prefix.readUInt32LE(1));
  try { return JSON.parse(raw); } finally { raw.fill(0); }
}
function sha(raw) { return crypto.createHash('sha256').update(raw).digest('hex'); }
function publicFile(file, cap) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
  try { const info = fs.fstatSync(fd); need(info.isFile() && info.size <= cap);
    const value = fs.readFileSync(fd); need(value.length === info.size); return value;
  } finally { fs.closeSync(fd); }
}
function checked(file, digest, cap) { const raw = publicFile(file, cap); need(sha(raw) === digest); return JSON.parse(raw); }
function fullHead(value) {
  need(value.schema === 'CP03-LEDGER-CLI-01' && value.block_version === '4');
  return {chain: Buffer.from(value.chain, 'hex'), genesisId: Buffer.from(value.genesis_id, 'hex'), blockVersion: 4,
    height: BigInt(value.height), blockId: Buffer.from(value.block_id, 'hex'), leafCount: BigInt(value.leaf_count),
    root: Buffer.from(value.root_le, 'hex'), feeEscrow: BigInt(value.fee_escrow),
    unconsumedLiabilities: BigInt(value.unconsumed_liabilities)};
}
function waited() {
  const raw = fs.readFileSync('/proc/self/stat', 'utf8'), fields = raw.slice(raw.lastIndexOf(')') + 2).split(/\s+/);
  return {user: BigInt(fields[13]), system: BigInt(fields[14])};
}
function measure(operation) {
  const children = waited(), cpu = process.cpuUsage(), start = process.hrtime.bigint();
  const value = operation();
  const wall = process.hrtime.bigint() - start, own = process.cpuUsage(cpu), after = waited();
  return {value, cost: {wall_nanoseconds: wall.toString(), node_self_user_microseconds: own.user,
    node_self_system_microseconds: own.system, waited_user_ticks: (after.user - children.user).toString(),
    waited_system_ticks: (after.system - children.system).toString()}};
}
function metrics(result) {
  const value = result.synchronization;
  return {mode: value.mode, read_bytes: value.readBytes.toString(), blocks: value.authenticatedBlocks.toString(),
    records: value.authenticatedRecords.toString(), peak_window_blocks: value.peakWindowBlocks,
    peak_window_records: value.peakWindowRecords, retained: value.retained};
}
function zeroOwned(view) {
  local.inspectLocalWitnessView(view, value => need(value.notes.length === 0 && value.balance === 0n));
}
async function disposeCase() {
  for (const session of sessions) await local.disposeLocalWitnessSession(session);
  sessions.clear(); for (const wallet of wallets) keys.disposeWallet(wallet); wallets.clear();
}
async function main() {
  const config = checked(process.argv[2], process.argv[3], 65536);
  need(config.format === 'CP04-INCREMENTAL-TRACE-CONFIG01');
  const inst = checked(config.installation, config.installation_sha256, 8 * 1024 * 1024);
  need(fs.realpathSync(process.execPath) === fs.realpathSync(inst.node));
  for (const name of ['wallet/cp03/keys.mjs', 'wallet/cp03/local_witnesses.mjs', 'wallet/cp03/recovery.mjs'])
    need(inst.pins[inst.source_root + '/' + name] === sha(publicFile(inst.source_root + '/' + name, 1024 * 1024)));
  keys = await import(pathToFileURL(inst.source_root + '/wallet/cp03/keys.mjs'));
  local = await import(pathToFileURL(inst.source_root + '/wallet/cp03/local_witnesses.mjs'));
  stage = 'capability-boundary';
  const probe = spawnSync('/usr/bin/python3', ['-I', '-B', config.probe_script, config.probe_config, '--descendant'],
    {env: {PATH: '/usr/bin:/bin', LANG: 'C'}, timeout: 10000, maxBuffer: 8192, stdio: ['ignore', 'pipe', 'pipe']});
  try {
    need(!probe.error && probe.status === 0 && !probe.signal && !probe.stderr.length);
    rpc({op: 'boundary', pid: process.pid,
      namespaces: Object.fromEntries(['pid', 'mnt', 'net'].map(k => [k, fs.readlinkSync('/proc/self/ns/' + k)])),
      descendant: JSON.parse(probe.stdout)});
  } finally { probe.stdout?.fill(0); probe.stderr?.fill(0); }
  const inputs = checked(config.inputs, config.inputs_sha256, 1024 * 1024);
  need(inputs.heads.length === 261 && inputs.prefixes.join(',') === '32,128,260');
  const genesis = publicFile(inputs.genesis, 339320); need(sha(genesis) === inputs.genesis_sha256);
  const genesisHead = fullHead(inputs.heads[0]), helper = inst.helper_sha256;
  const options = {trustedGenesis: genesisHead, genesis, genesisRoot: genesisHead.root, maxOwned: 8, rewindBlocks: 8};
  const summaries = [];
  stage = 'trace';
  for (const prefix of inputs.prefixes) {
    rpc({op: 'case-start', prefix});
    const wallet = keys.createWallet(genesisHead.chain, helper); wallets.add(wallet);
    const backup = keys.exportBackup(wallet); let restored;
    try { restored = keys.restoreBackup(backup, genesisHead.chain, helper, keys.publicInventory(wallet)); }
    finally { backup.fill(0); }
    need(restored.expected_inventory_matched); wallets.add(restored.wallet);
    const session = local.createLocalWitnessSession(wallet, helper, options);
    const reference = local.createLocalWitnessSession(restored.wallet, helper, options);
    sessions.add(session); sessions.add(reference);
    let view = local.recoverLocalWitnesses(session, inputs.empty_scan, genesisHead).state;
    local.recoverLocalWitnesses(reference, inputs.empty_scan, genesisHead);
    for (let height = 1; height <= prefix; height++) {
      const target = fullHead(inputs.heads[height]), plan = local.localWitnessSyncRequest(session, target);
      need(plan.mode === 'append' && Buffer.isBuffer(plan.request) && plan.request.length === 436);
      const reply = rpc({op: 'range', prefix, height, request: plan.request.toString('hex')});
      rpc({op: 'sync-start', prefix, height});
      const actual = measure(() => local.synchronizeLocalWitnesses(session, reply.file, target));
      view = actual.value.state;
      rpc({op: 'sync-row', prefix, height, metrics: metrics(actual.value), cost: actual.cost});
    }
    zeroOwned(view);
    const target = fullHead(inputs.heads[prefix]), plan = local.localWitnessSyncRequest(session, target);
    need(plan.mode === 'unchanged' && plan.request === null);
    const noop = local.synchronizeLocalWitnesses(session, null, target);
    need(noop.state === view && noop.synchronization.readBytes === 0n && noop.synchronization.authenticatedBlocks === 0n);
    rpc({op: 'noop', prefix, same_view: true, request_null: true, metrics: metrics(noop)});
    // The independent same-backup reference remained at genesis throughout this
    // case: this is actual full private reconstruction, outside sync measurements.
    const referenceCost = measure(() => local.recoverLocalWitnesses(reference, inputs.references[String(prefix)], target));
    zeroOwned(referenceCost.value.state);
    need(local.equivalentLocalWitnessViews(view, referenceCost.value.state));
    const summary = {prefix, equivalent: true, zero_owned_notes: true,
      reference_metrics: metrics(referenceCost.value), reference_cost: referenceCost.cost};
    rpc({op: 'case-complete', ...summary}); summaries.push(summary);
    await disposeCase();
  }
  stage = 'cleanup'; await disposeCase();
  rpc({op: 'native-work-complete'});
  send(5, {format: 'CP04-INCREMENTAL-TRACE-DONE01', passed: true, cases: summaries.length,
    node_process_self: process.cpuUsage(), node_process_maxrss_kib: process.resourceUsage().maxRSS,
    resource_scope: 'Whole Node process includes key setup, reference replay and cleanup; not sync-only cost.',
    new_proofs: 0, owned_note_claim: false});
}
try { await main(); }
catch {
  try { await disposeCase(); } catch {}
  fs.writeSync(2, 'CP04_TRACE_FAILED ' + stage + '\n'); process.exitCode = 1;
}
