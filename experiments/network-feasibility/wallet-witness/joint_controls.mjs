// Focused assertions for a Root-approved real session. No mock/native substitute.
// The acceptance caller supplies its actual installed module namespace objects.
// This module does not generate keys/proofs, log data, or run on import.
function need(ok) { if (!ok) throw new Error('CP03_JOINT_CONTROL_FAILED'); }
function rejected(operation) {
  let error = null;
  try { operation(); } catch (caught) { error = caught; }
  need(error !== null && error.name === 'WalletInputError');
}
export function checkInventoryLease({wallet, helperSha256, sessionOptions, keys, witnesses}) {
  // The caller already created a genuine session leasing this genuine wallet.
  rejected(() => keys.rotateReceivingKey(wallet));
  rejected(() => keys.disposeWallet(wallet));
  rejected(() => witnesses.createLocalWitnessSession(wallet, helperSha256, sessionOptions));
  return {rotation_rejected: true, disposal_rejected: true, second_session_rejected: true};
}
export function checkViewRevoked({view, witnesses}) {
  let reached = false;
  rejected(() => witnesses.inspectLocalWitnessView(view, () => { reached = true; return null; }));
  need(!reached);
  return {old_view_callback_unreachable: true};
}
export function checkReplayUnavailable({session, validDraftStatement, witnesses}) {
  // Use an actually parsed valid public draft, not malformed input that would
  // fail for unrelated grammar reasons even if stale authority were retained.
  rejected(() => witnesses.localDraftEligible(session, validDraftStatement));
  return {old_draft_authority_unavailable: true};
}
export function checkSyncInspectionOnly({view, witnesses}) {
  let reached = false;
  rejected(() => witnesses.inspectLocalWitnessView(view, async () => { reached = true; }));
  need(!reached);
  return {async_inspection_rejected_before_callback: true};
}
export function checkNoOperationCallback({view, witnesses}) {
  let reached = false;
  rejected(() => witnesses.withLocalWitnesses(view, 1, () => { reached = true; }));
  need(!reached);
  return {external_packet_callback_rejected: true};
}
export function checkSinglePendingPacket({view, outputs, witnesses, payments}) {
  const payment = witnesses.withLocalWitnesses(view, 1, {outputs});
  try {
    const status = payments.paymentLifecycle(payment);
    need(status && !status.used && !status.inFlight && !status.retired);
    rejected(() => witnesses.withLocalWitnesses(view, 1, {outputs}));
    need(payments.paymentLifecycle(payment)?.used === false);
  } finally { payments.disposePayment(payment); }
  return {one_pending_packet_enforced: true, original_packet_not_silently_replaced: true};
}
