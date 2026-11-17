// Fixed controls for Root's genuine installed sessions. No code runs on import;
// no mock helper/verdict, private export, hash or logging sink is provided.
function need(ok) { if (!ok) throw new Error('CP04_SYNC_WALLET_CONTROL_FAILED'); }
function rejected(operation) {
  let caught;
  try { operation(); } catch (error) { caught = error; }
  need(caught?.name === 'WalletInputError');
}
export function checkNoopPreservesViewAndPacket({session, view, head, payment, witnesses, payments}) {
  const prior = payments.paymentLifecycle(payment);
  need(prior && !prior.used && !prior.inFlight && !prior.retired);
  const plan = witnesses.localWitnessSyncRequest(session, head);
  need(plan.mode === 'unchanged' && plan.request === null);
  const result = witnesses.synchronizeLocalWitnesses(session, null, head);
  const after = payments.paymentLifecycle(payment), metrics = result.synchronization;
  need(result.state === view && metrics.mode === 'unchanged' && metrics.readBytes === 0n &&
    metrics.authenticatedBlocks === 0n && metrics.authenticatedRecords === 0n);
  need(after && !after.used && !after.inFlight && !after.retired);
  return {same_view_preserved: true, ready_packet_preserved: true, no_history_request_or_authentication: true};
}
export function checkDetachedPublicRequest({session, head, witnesses}) {
  const first = witnesses.localWitnessSyncRequest(session, head);
  need(Buffer.isBuffer(first.request));
  const expected = Buffer.from(first.request);
  first.request.fill(0); first.base.root.fill(0); first.base.chain.fill(0); first.target.genesisId.fill(0);
  const second = witnesses.localWitnessSyncRequest(session, head);
  need(second.request.equals(expected));
  return {public_request_mutation_cannot_import_or_modify_base: true};
}
export function checkAppendFailureAtomic({session, view, referenceView, file, target, witnesses}) {
  const before = witnesses.localWitnessSyncRequest(session, target);
  need(before.mode === 'append' && Buffer.isBuffer(before.request));
  rejected(() => witnesses.synchronizeLocalWitnesses(session, file, target));
  const after = witnesses.localWitnessSyncRequest(session, target);
  need(after.mode === before.mode && after.request.equals(before.request));
  need(witnesses.equivalentLocalWitnessViews(view, referenceView));
  return {failed_append_does_not_advance_joint_state: true, previous_ready_view_preserved: true};
}
export function checkSelectedFailureStaysRevoked({session, oldView, oldDraftStatement, file, target, witnesses}) {
  const before = witnesses.localWitnessSyncRequest(session, target);
  need(before.mode === 'selected-replay' || before.mode === 'full-replay');
  rejected(() => witnesses.synchronizeLocalWitnesses(session, file, target));
  const after = witnesses.localWitnessSyncRequest(session, target);
  need(after.mode === before.mode && after.request.equals(before.request));
  let reached = false;
  rejected(() => witnesses.inspectLocalWitnessView(oldView, () => { reached = true; }));
  need(!reached); rejected(() => witnesses.localDraftEligible(session, oldDraftStatement));
  return {failed_selected_replay_does_not_advance_base: true, old_view_and_draft_remain_revoked: true};
}
export function checkSameRootNewHeadNeedsSuffix({session, head, witnesses}) {
  const plan = witnesses.localWitnessSyncRequest(session, head);
  need(plan.mode === 'append' && Buffer.isBuffer(plan.request) && plan.target.height > plan.base.height);
  need(plan.base.root.equals(plan.target.root) && plan.base.leafCount === plan.target.leafCount);
  need(plan.request.readBigUInt64LE(428) === plan.target.height - plan.base.height);
  return {unchanged_root_does_not_skip_empty_block_history: true};
}
