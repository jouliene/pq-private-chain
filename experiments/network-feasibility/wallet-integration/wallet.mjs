// Fixed isolated Gate3 research actor. No ledger import, DB or membership RPC.
// Backup, amounts, selected tokens, openings and paths stay in private RAM/pipes.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

let stage = 'configuration';
const sessions = new Set(), wallets = new Set();
let backup;
function need(ok) { if (!ok) throw new Error('CP04_WALLET_CONDITION'); }
function exact(size) {
  const b = Buffer.alloc(size); let at = 0;
  while (at < size) { const n = fs.readSync(0, b, at, size - at, null); need(n > 0); at += n; }
  return b;
}
function frame(kind, data) {
  need(Buffer.isBuffer(data) && data.length <= 16 * 1024 * 1024);
  const h = Buffer.alloc(5); h[0] = kind; h.writeUInt32LE(data.length, 1);
  for (const b of [h, data]) { let at = 0; while (at < b.length) at += fs.writeSync(1, b, at, b.length - at); }
}
function readFrame(kind, cap) {
  const h = exact(5); need(h[0] === kind && h.readUInt32LE(1) <= cap); return exact(h.readUInt32LE(1));
}
function rpc(value) {
  const raw = Buffer.from(JSON.stringify(value)); need(raw.length <= 65536); frame(1, raw);
  const response = readFrame(2, 65536);
  try { return JSON.parse(response.toString('utf8')); } finally { response.fill(0); }
}
function publicFile(file, cap) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd); need(st.isFile() && st.size <= cap);
    const b = fs.readFileSync(fd); need(b.length === st.size); return b;
  } finally { fs.closeSync(fd); }
}
function hash(b) { return crypto.createHash('sha256').update(b).digest('hex'); }
function h64(label, bytes) {
  const tag = Buffer.from('PQPC/CP3/' + label), n = Buffer.alloc(2), size = Buffer.alloc(4);
  n.writeUInt16LE(tag.length); size.writeUInt32LE(bytes.length);
  return crypto.createHash('sha3-512').update(n).update(tag).update(size).update(bytes).digest();
}
function writePublic(file, value) { fs.writeFileSync(file, value, {flag: 'wx', mode: 0o600}); }
function fullHead(row) {
  need(row.schema === 'CP03-LEDGER-CLI-01' && row.block_version === '4');
  return {chain: Buffer.from(row.chain, 'hex'), genesisId: Buffer.from(row.genesis_id, 'hex'),
    blockVersion: 4, height: BigInt(row.height), blockId: Buffer.from(row.block_id, 'hex'),
    leafCount: BigInt(row.leaf_count), root: Buffer.from(row.root_le, 'hex'),
    feeEscrow: BigInt(row.fee_escrow), unconsumedLiabilities: BigInt(row.unconsumed_liabilities)};
}
async function main() {
  const configRaw = publicFile(process.argv[2], 65536); need(hash(configRaw) === process.argv[3]);
  const config = JSON.parse(configRaw);
  need(config.format === 'CP04-ISOLATED-WALLET-CONFIG01' && ['small', 'full', 'incremental'].includes(config.profile));
  const instRaw = publicFile(config.installation, 8 * 1024 * 1024); need(hash(instRaw) === config.installation_sha256);
  const inst = JSON.parse(instRaw), source = inst.source_root, helper = inst.helper_sha256;
  need(fs.realpathSync(process.execPath) === fs.realpathSync(inst.node));
  const names = ['wallet/cp03/keys.mjs', 'wallet/cp03/codec.mjs', 'wallet/cp03/payments.mjs',
    'wallet/cp03/private_prover.mjs', 'wallet/cp03/local_witnesses.mjs', 'runtime/cp03/source-signature.mjs'];
  for (const name of names) need(inst.pins[path.join(source, name)] === hash(publicFile(path.join(source, name), 1024 * 1024)));
  const [keys, codec, pay, proof, local, signature] = await Promise.all(names.map(name => import(pathToFileURL(path.join(source, name)))));
  need(hash(publicFile(config.controls_script, 65536)) === config.controls_sha256);
  const controls = await import(pathToFileURL(config.controls_script));
  need(hash(publicFile(config.sync_controls_script,65536)) === config.sync_controls_sha256);
  const syncControls = await import(pathToFileURL(config.sync_controls_script));
  const cleanup = async () => {
    for (const s of sessions) await local.disposeLocalWitnessSession(s); sessions.clear();
    for (const w of wallets) keys.disposeWallet(w); wallets.clear(); backup?.fill(0); backup = undefined;
  };
  try {
    stage = 'capability-boundary';
    const probe = spawnSync('/usr/bin/python3', ['-I', '-B', config.probe_script, config.probe_config, '--descendant'],
      {env: {PATH: '/usr/bin:/bin', LANG: 'C'}, timeout: 10000, maxBuffer: 8192, stdio: ['ignore', 'pipe', 'pipe']});
    need(!probe.error && probe.status === 0 && !probe.signal && probe.stderr.length === 0);
    const checked = JSON.parse(probe.stdout); probe.stdout.fill(0); probe.stderr.fill(0);
    need(checked.seccomp === '2');
    rpc({op: 'boundary', pid: process.pid, namespaces: Object.fromEntries(['pid', 'mnt', 'net'].map(k => [k, fs.readlinkSync('/proc/self/ns/' + k)])), descendant: checked});
    const operatorRaw = publicFile(inst.operator_path, 65536); need(hash(operatorRaw) === inst.operator_sha256);
    const operator = JSON.parse(operatorRaw);
    const backend = proof.installPrivateProver(operator.private_approval.path, operator.private_approval.sha256);
    const netPath = path.join(source, 'docs/architecture/CP_NETWORK_04.json'), netRaw = publicFile(netPath, 65536);
    need(inst.pins[netPath] === hash(netRaw)); const protocol = JSON.parse(netRaw);
    const out = config.public_output;
    const held = w => { wallets.add(w); return w; };
    let genesis, genesisHead, lastHead;
    const incremental = config.profile === 'incremental', references = new Map(), liveViews = new Map(), referenceViews = new Map(), syncRows = [], requestedRanges = new Map();
    let counts = {proofs: 0, history_reads: 0, history_bytes: 0, history_wall_seconds: 0};
    if (incremental) Object.assign(counts, {synchronization: syncRows, reference_equivalence_checks: 0, same_head_noops: 0, ownership_independent_equal_ranges: 0, atomic_failure_controls: 0, staged_window_failure_controls: 0});
    function sessionOptions() {
      return {trustedGenesis: {chain: genesisHead.chain,
        genesisId: genesisHead.genesisId, blockVersion: 4}, genesis, genesisRoot: genesisHead.root,
        maxOwned: 8, rewindBlocks: 8};
    }
    function newSession(wallet) {
      const s = local.createLocalWitnessSession(wallet, helper, sessionOptions()); sessions.add(s);
      if (incremental) {
        // Separate live wallet/lease, private backup only in RAM; never a public oracle.
        const raw = keys.exportBackup(wallet);
        try {
          const r = keys.restoreBackup(raw, genesisHead.chain, helper, keys.publicInventory(wallet));
          need(r.expected_inventory_matched); wallets.add(r.wallet);
          const reference = local.createLocalWitnessSession(r.wallet, helper, sessionOptions());
          sessions.add(reference); references.set(s, reference);
        } finally { raw.fill(0); }
      }
      return s;
    }
    function selectBranch(session, selection) {
      let first;
      try { local.selectLocalWitnessBranch(session, selection); } catch (error) { first = error; }
      if (incremental) {
        let second;
        try { local.selectLocalWitnessBranch(references.get(session), selection); } catch (error) { second = error; }
        need(Boolean(first) === Boolean(second));
        if (first) need(first instanceof local.LocalWitnessReplayRequired && second instanceof local.LocalWitnessReplayRequired);
      }
      if (first) throw first;
    }
    function scan(session, basis = 'unknown', selectedDraft = null) {
      let reply, recovered, request;
      const head = fullHead(rpc({op:'head'}).head); lastHead = head;
      if (incremental) {
        request = local.localWitnessSyncRequest(session,head);
        if (request.mode === 'full-replay' || config.restore) reply = rpc({op:'scan'});
        else if (request.request !== null) {
          // Only common public cursors are sent. Compare equal ranges across
          // live wallets with different note ownership, without exporting notes.
          const key = request.base.height + ':' + request.target.height + ':' + request.target.blockId.toString('hex');
          const prior = requestedRanges.get(key);
          if (prior && prior.session !== session) {
            need(prior.bytes.equals(request.request)); counts.ownership_independent_equal_ranges++;
          } else requestedRanges.set(key,{session,bytes:Buffer.from(request.request)});
          syncControls.checkDetachedPublicRequest({session,head,witnesses:local});
          reply = rpc({op:'scan-range',request:request.request.toString('hex')});
        }
      } else reply = rpc({op:'scan'});
      if (reply) need(JSON.stringify(reply.head) === JSON.stringify(rpc({op:'head'}).head));
      if (incremental && reply && (request.mode === 'append' || request.mode === 'selected-replay')) {
        // Public adversarial fixtures and private bool-only correctness oracle;
        // explicitly outside the successful synchronization measurement span.
        const raw = publicFile(reply.file, 4*1024*1024), chunks = [];
        let at=436;
        while (at<raw.length) { const end=at+4+raw.readUInt32LE(at); need(end<=raw.length); chunks.push(raw.subarray(at,end)); at=end; }
        const variants = [];
        for (const [name,offset] of [['wrong-base',116],['wrong-chain',12],['wrong-endpoint',284]]) {
          const bad=Buffer.from(raw); bad[offset]^=1; variants.push([name,bad]);
        }
        variants.push(['truncated',raw.subarray(0,raw.length-1)]);
        if (chunks.length) {
          variants.push(['missing',Buffer.concat([raw.subarray(0,436),...chunks.slice(1)])]);
          variants.push(['duplicated',Buffer.concat([raw,...chunks.slice(-1)])]);
        }
        if (chunks.length>=2) variants.push(['reordered',Buffer.concat([raw.subarray(0,436),chunks[1],chunks[0],...chunks.slice(2)])]);
        for (const [name,data] of variants) {
          const file=path.join(out,'control-'+String(counts.atomic_failure_controls).padStart(4,'0')+'-'+name+'.public');
          writePublic(file,data);
          if (request.mode === 'append') {
            syncControls.checkAppendFailureAtomic({session,view:liveViews.get(session),referenceView:referenceViews.get(session),file,target:head,witnesses:local});
          } else {
            need(selectedDraft !== null);
            syncControls.checkSelectedFailureStaysRevoked({session,oldView:liveViews.get(session),oldDraftStatement:selectedDraft,file,target:head,witnesses:local});
          }
          counts.atomic_failure_controls++;
          if (name==='truncated' && chunks.length>257) counts.staged_window_failure_controls++;
        }
      }
      const started = performance.now(), cpu = process.cpuUsage();
      recovered = incremental && request.mode !== 'full-replay' && !config.restore
        ? local.synchronizeLocalWitnesses(session,reply?.file ?? null,head,basis)
        : local.recoverLocalWitnesses(session,reply.file,head,basis);
      const used = process.cpuUsage(cpu), elapsed = (performance.now()-started)/1000;
      counts.history_wall_seconds += elapsed;
      if (reply) { counts.history_reads++; counts.history_bytes += fs.statSync(reply.file).size; }
      need(recovered.local_witnesses && recovered.history_linkage_complete &&
        recovered.payment_validity === 'delegated-to-independently-supplied-endpoint');
      if (incremental) {
        const m = recovered.synchronization;
        syncRows.push({mode:m.mode,height:head.height.toString(),read_bytes:m.readBytes.toString(),
          authenticated_blocks:m.authenticatedBlocks.toString(),authenticated_records:m.authenticatedRecords.toString(),
          peak_window_blocks:m.peakWindowBlocks,peak_window_records:m.peakWindowRecords,retained:m.retained,
          elapsed_seconds:elapsed,node_self_user_microseconds:used.user,node_self_system_microseconds:used.system});
        const same = local.localWitnessSyncRequest(session,head); need(same.mode === 'unchanged' && same.request === null);
        const noop = local.synchronizeLocalWitnesses(session,null,head,basis);
        need(noop.state === recovered.state && noop.synchronization.readBytes === 0n && noop.synchronization.authenticatedBlocks === 0n);
        counts.same_head_noops++;
        // Full reference IO/proving-free reconstruction is OUTSIDE measured roles.
        const referenceReply = rpc({op:'scan-reference'});
        const referenceSession=references.get(session);
        // Force true genesis reconstruction; persistent full-prefix authentication
        // alone would share the same incremental transition state.
        try { local.selectLocalWitnessBranch(referenceSession,{commonPrefix:genesisHead,endpoint:head}); }
        catch (error) { need(error instanceof local.LocalWitnessReplayRequired); }
        const reference = local.recoverLocalWitnesses(referenceSession,referenceReply.file,head,basis);
        need(local.equivalentLocalWitnessViews(recovered.state,reference.state));
        counts.reference_equivalence_checks++;
        liveViews.set(session,recovered.state); referenceViews.set(session,reference.state);
      }
      return recovered.state;
    }
    function amounts(view) {
      return local.inspectLocalWitnessView(view, state => state.notes.sort((a,b) => a.index < b.index ? -1 : 1).map(n => n.amount));
    }
    async function publish(payment, label, authorization = Buffer.alloc(0)) {
      const statement = pay.publicPayment(payment).statement;
      const p = await proof.provePayment(backend, payment, config.label + '-' + label);
      const file = path.join(out, label + '.body'); writePublic(file, pay.completeBody(payment, authorization, p.proof));
      counts.proofs++;
      rpc({op: 'proof', label, body: file, receipt: p.parent_receipt});
      return {file, statement};
    }
    function admit(files) { lastHead = fullHead(rpc({op: 'admit', files}).head); return lastHead; }
    function rolled(expected) { lastHead = fullHead(rpc({op: 'rollback', expected_tip: expected.blockId.toString('hex')}).head); return lastHead; }
    function mark(name) { rpc({op: 'mark', name}); }
    function reject(file) { const r = rpc({op: 'reject', file, expected: 'Anchor'}); need(r.rejected === 'Anchor' && r.all14_unchanged); }
    function outgoing(view, selection, a, b, amount = null) {
      const available = amounts(view);
      const selected = typeof selection === 'number' ? available.slice(0, selection) : [available[selection.index]];
      need(selected.length === (typeof selection === 'number' ? selection : 1));
      const value = selected.reduce((sum, n) => sum + n, 0n) - codec.FEES[selected.length]; need(value > 0n);
      const send = amount === null ? value / 2n : amount; need(send >= 0n && send <= value);
      const selector = typeof selection === 'number' ? selection : notes => [notes[selection.index].token];
      return local.withLocalWitnesses(view, selector, {outputs: [{descriptor: a, amount: send}, {descriptor: b, amount: value - send}]});
    }
    if (config.restore) {
      stage = 'backup-restore'; backup = readFrame(3, 16 * 1024 * 1024);
      const inventory = JSON.parse(publicFile(path.join(out, 'receiver-inventory.json'), 65536));
      const context = rpc({op: 'context'}); genesis = publicFile(context.genesis, 339320); genesisHead = fullHead(context.genesis_head);
      const restored = keys.restoreBackup(backup, genesisHead.chain, helper, inventory); backup.fill(0); backup = undefined;
      need(restored.expected_inventory_matched); const wallet = held(restored.wallet), session = newSession(wallet);
      const view = scan(session, restored.inventory_completeness_basis);
      const destination = publicFile(path.join(out, 'destination.bin'), 1672);
      const payment = outgoing(view, 1, destination, keys.descriptor(wallet, 1));
      const p = await publish(payment, 'restored-spend');
      need(local.localDraftEligible(session, p.statement)); admit([p.file]); mark('backup-only-new-process-spend');
      await cleanup();
      mark('native-work-complete');
      frame(5, Buffer.from(JSON.stringify({format: 'CP04-ISOLATED-WALLET-DONE01', restore: true, counts,
        process_self: process.resourceUsage(), private_material_persisted_or_hashed: false})));
      return;
    }
    stage = 'new-wallets';
    const chain = crypto.randomBytes(32), issuer = crypto.generateKeyPairSync('ml-dsa-87');
    const rolling = held(keys.createWallet(chain, helper)), payer = held(keys.createWallet(chain, helper));
    const receiver = held(keys.createWallet(chain, helper)); keys.rotateReceivingKey(receiver);
    backup = keys.exportBackup(receiver); const inventory = keys.publicInventory(receiver);
    writePublic(path.join(out, 'receiver-inventory.json'), Buffer.from(JSON.stringify(inventory) + '\n'));
    writePublic(path.join(out, 'destination.bin'), keys.descriptor(payer, 0));
    const credits = [1000000000n, 100000000n], sources = credits.map(credit => ({id: crypto.randomBytes(48), credit,
      publicKey: signature.sourcePublicBytes(issuer.publicKey)}));
    genesis = codec.encodeGenesis({version: 4, chain, protocolId: h64('PROTOCOL', netRaw),
      proofProfileId: Buffer.from(protocol.proof.profile_id, 'hex'), programIds: protocol.proof.program_ids.map(v => Buffer.from(v, 'hex')),
      sources: [...sources].sort((a,b) => Buffer.compare(a.id,b.id))});
    const genesisFile = path.join(out, 'genesis.bin'); writePublic(genesisFile, genesis);
    genesisHead = lastHead = fullHead(rpc({op: 'init', chain: chain.toString('hex'), genesis: genesisFile}).head);
    const payerSession = newSession(payer), receiverSession = newSession(receiver), rollingSession = newSession(rolling);
    if (incremental) scan(rollingSession); // Authenticated empty genesis state; later suffix spans258blocks.
    stage = 'funding'; const funding = [];
    for (let i = 0; i < 2; i++) {
      const wallet = [rolling, payer][i], credit = credits[i], available = credit - codec.FEES[0];
      const payment = pay.preparePayment(wallet, helper, {anchor: {root: lastHead.root, count: 0n}, inputs: [],
        sourceId: sources[i].id, credit, outputs: [{descriptor: keys.descriptor(wallet,0), amount: available/2n},
          {descriptor: keys.descriptor(wallet,0), amount: available-available/2n}]});
      const auth = signature.signSource(issuer.privateKey, signature.claimMessage({chain, sourceId: sources[i].id,
        registeredCredit: credit, profileId: Buffer.from(protocol.proof.profile_id, 'hex'),
        creditProgramId: Buffer.from(protocol.proof.program_ids[0], 'hex'), statement: pay.publicPayment(payment).statement}));
      try { funding.push((await publish(payment, 'credit-' + i, auth)).file); }
      finally { pay.disposePayment(payment); }
    }
    admit(funding);
    const receiverDescriptor = keys.descriptor(receiver, 1), payerDescriptor = keys.descriptor(payer, 0), rollingDescriptor = keys.descriptor(rolling, 0);
    stage = 'ordinary-receipt';
    if (incremental) scan(receiverSession);
    const send = await publish(outgoing(scan(payerSession), 2, receiverDescriptor, receiverDescriptor), 'ordinary-receipt'); admit([send.file]);
    if (incremental) scan(payerSession);
    let receiverView = scan(receiverSession); need(amounts(receiverView).length === 2);
    const reserveAmount = amounts(receiverView)[0], receiptRoot = Buffer.from(lastHead.root);
    controls.checkInventoryLease({wallet: receiver, helperSha256: helper, sessionOptions: sessionOptions(), keys, witnesses: local});
    controls.checkSyncInspectionOnly({view: receiverView, witnesses: local});
    controls.checkNoOperationCallback({view: receiverView, witnesses: local});
    controls.checkSinglePendingPacket({view: receiverView, witnesses: local, payments: pay,
      outputs: [{descriptor: payerDescriptor, amount: 1n},
        {descriptor: receiverDescriptor, amount: reserveAmount - codec.FEES[1] - 1n}]});
    mark('joint-lease-and-packet-controls');
    mark('genuine-private-receipt-and-local-witnesses');
    let stale;
    if (config.profile !== 'small') {
      stage = 'stale-draft'; stale = await publish(outgoing(receiverView, 1, payerDescriptor, receiverDescriptor), 'old-anchor-draft');
      const h = admit([stale.file]); rolled(h); mark('old-draft-genuine-positive-before-expiry');
    }
    stage = 'recipient-spend';
    const recipient = await publish(outgoing(receiverView, {index: 1}, payerDescriptor, receiverDescriptor, 10000000n), 'recipient-spend');
    admit([recipient.file]); need(!lastHead.root.equals(receiptRoot)); receiverView = scan(receiverSession); mark('recipient-fresh-local-witness-spend');
    if (config.profile !== 'small') {
      need(local.localDraftEligible(receiverSession, stale.statement));
      const h = admit([stale.file]); rolled(h); mark('old-origin-draft-valid-on-common-prefix');
      if (incremental) {
        stage = 'empty-block-expiry-history';
        const changedRoot = Buffer.from(lastHead.root); need(!changedRoot.equals(receiptRoot));
        for (let i = 0; i < 255; i++) {
          lastHead = fullHead(rpc({op:'empty'}).head); need(lastHead.root.equals(changedRoot));
        }
      } else {
        stage = 'changing-root-history'; let priorRoot = lastHead.root;
        for (let i = 0; i < 255; i++) {
          const p = await publish(outgoing(scan(rollingSession), 2, rollingDescriptor, rollingDescriptor), 'rolling-' + String(i).padStart(3,'0'));
          admit([p.file]); need(!lastHead.root.equals(priorRoot)); priorRoot = lastHead.root;
        }
      }
      need(lastHead.height === 258n); scan(rollingSession);
      const prefix = lastHead;
      stage = 'expiry-refresh'; receiverView = scan(receiverSession);
      need(!local.localDraftEligible(receiverSession, stale.statement)); reject(stale.file);
      if (incremental) mark('empty-block-anchor-expiry-atomic-rejection');
      else mark('changing-root-anchor-expiry-atomic-rejection');
      const refreshed = await publish(outgoing(receiverView, 1, payerDescriptor, receiverDescriptor), 'refreshed-old-spend'); admit([refreshed.file]);
      const orphanHead = lastHead; receiverView = scan(receiverSession); mark('old-note-refreshed-and-spent');
      // Last received note exists only on this soon-orphaned branch.
      const orphan = await publish(outgoing(receiverView, {index: 1}, payerDescriptor, receiverDescriptor), 'orphan-child-draft');
      // Later Anchor rejection happens before proof verification. Establish
      // genuine positive public verification now, without another proof.
      const childHead = admit([orphan.file]); rolled(childHead);
      mark('orphan-child-genuine-positive-before-reorg');
      stage = 'selected-branch-change'; rolled(orphanHead);
      const replacement = await publish(outgoing(scan(rollingSession), 2, rollingDescriptor, rollingDescriptor), 'replacement'); admit([replacement.file]);
      need(lastHead.height === 259n && !lastHead.root.equals(orphanHead.root));
      let revokedPacket;
      if (incremental) {
        revokedPacket=outgoing(receiverView,1,payerDescriptor,receiverDescriptor);
        syncControls.checkNoopPreservesViewAndPacket({session:receiverSession,view:receiverView,head:orphanHead,payment:revokedPacket,witnesses:local,payments:pay});
      }
      selectBranch(receiverSession, {commonPrefix: prefix, endpoint: lastHead});
      if (incremental) {
        need(pay.paymentLifecycle(revokedPacket) === null);
        let packetRejected=false; try { pay.publicPayment(revokedPacket); } catch { packetRejected=true; }
        need(packetRejected);
      }
      let staleViewRejected = false;
      try { local.inspectLocalWitnessView(receiverView, () => true); } catch { staleViewRejected = true; }
      need(staleViewRejected); receiverView = scan(receiverSession,'unknown',orphan.statement);
      need(!local.localDraftEligible(receiverSession, orphan.statement)); reject(orphan.file);
      need(amounts(receiverView).length === 2 && amounts(receiverView)[0] === reserveAmount);
      mark('joint-rewind-orphan-discovery-and-spentness-repaired');
      stage = 'deep-selected-replay';
      const selected = lastHead;
      let replayRequired = false;
      try { selectBranch(receiverSession, {commonPrefix: genesisHead, endpoint: selected}); }
      catch (error) { replayRequired = error instanceof local.LocalWitnessReplayRequired; }
      need(replayRequired);
      controls.checkViewRevoked({view: receiverView, witnesses: local});
      controls.checkReplayUnavailable({session: receiverSession, validDraftStatement: stale.statement, witnesses: local});
      receiverView = scan(receiverSession);
      need(amounts(receiverView).length === 2 && amounts(receiverView)[0] === reserveAmount);
      mark('joint-deep-replay-revocation-and-recovery');
    }
    if (incremental) {
      need(counts.ownership_independent_equal_ranges > 0 && counts.reference_equivalence_checks > 0 && counts.same_head_noops > 0 && counts.atomic_failure_controls > 0 && counts.staged_window_failure_controls > 0);
      mark('incremental-reference-equivalence-and-noop');
    }
    stage = 'backup-handoff';
    // Destroy every original wallet/session before the parent starts a fresh process.
    for (const s of sessions) await local.disposeLocalWitnessSession(s); sessions.clear();
    for (const w of wallets) keys.disposeWallet(w); wallets.clear();
    mark('native-work-complete');
    frame(4, backup); backup.fill(0); backup = undefined;
    frame(5, Buffer.from(JSON.stringify({format: 'CP04-ISOLATED-WALLET-DONE01', restore: false, counts,
      process_self: process.resourceUsage(), private_material_persisted_or_hashed: false})));
  } finally { await cleanup(); }
}

try { await main(); }
catch { backup?.fill(0); fs.writeSync(2, 'CP04_WALLET_FAILED ' + stage + '\n'); process.exitCode = 1; }
