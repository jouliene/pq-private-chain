# Next investment after the actual full wallet run

**Provisional recommendation: implement one bounded authenticated common-history
suffix mechanism before permissionless PoW/issuance integration.** Preserve CP03
as the finite full-RETAIN validator plus separately provisioned opaque archive
research model. This is a specific history repair, not acceptance of its annual
participation costs. Independent full-result review and the scoped clean-checkout
reproduction have passed. The global blockchain goal remains ACTIVE.

This does **not** add a gate to the current network-feasibility Goal: finish its
independent reproduction, decision and publication, then close that bounded Goal.
The suffix proposal is one separate follow-up. The dominant global architecture
priority remains first-copy payment/history storage and participation, not local
witness arithmetic or consensus ordering speed.

## What changed the decision

The [full wallet result](../wallet-integration/evidence/wallet-full01/RESULT.json)
(SHA256 `2835c26138b20e75716b6ce048e55731b41001b38f2a2dfdf7768a2b55068637`)
reports PASS,264 genuine generated proofs with positive native admissions,
changing-root anchor expiry and refresh, controlled rewind/replacement, orphan
rejection, deep replay and backup-only fresh-process spending. It supports the
feasibility of local selective witnesses; it is not consensus or a joint PQ/privacy
theorem. The exercised wallet bounds are K=8 owned notes and R=8 rewind blocks.
Recovery still requires the relevant key inventory, genesis, common history and
an independently selected validating endpoint.

The actual265 history reads total **187364746B**, while the final scan consumed
by the restored process is **1374318B**. Their ratio is136.3329; this includes
refreshes, branch controls and recovery, and is not a universal amplification
factor. The original process accounts for264 reads/185990428B, recovery for one
read/1374318B. `recoverLocalWitnesses` applies only records beyond its current
cursor to receiving/witness state, but authenticates the supplied history from
genesis again. At repeated one-block refreshes of a growing equal-sized history,
that prefix obligation grows quadratically in block count. Bounded live frontier
and rewind state do not bound cumulative history traffic or authentication work.
This is now an observed integration seam rather than a hypothetical wallet flaw.

The [resource decision](../../../docs/network-feasibility/RESOURCE_DECISION.md)
remains binding context: Gate2 drained eight genuine96-payment batches under the
declared paced-loopback profile, but the ordinary body mean1751265.75B projects
**175.126575TB/year per full-body copy** at100M offered payments/year. Validator
plus one archive is350.25315TB/year before replication and other state. Reduced
common scan projects about502.242GB/year before requests/retries. These are
projections, not year-long measurements; the owner supplied no annual cap or
accepted annual hardware/storage budget. Removing repeated prefixes cannot
remove the first-copy body obligation or fresh-node bootstrap.

## The single discriminating milestone

Add a versioned, bounded common block-range continuation, starting only from the
wallet's own previously authenticated joint cursor/state (chain, genesis, height,
block identity, root/count and value-accounting context). Bind the new stream to
that base and an independently selected endpoint; verify every intervening public
link and exact EOF. Keep payment validity delegated to the same declared
validating source. An arbitrary peer checkpoint or caller-imported tree state is
not a base. This changes history delivery/authentication, not the complete-payment
relation or proof/security parameters.

The acceptance boundary it changes is whether a continuously synchronized wallet
can process newly arriving common history without repeatedly downloading and
authenticating everything since genesis. It does not change the annual full-body
retention boundary. This is an asymptotic usability repair, not a target of
shaving milliseconds from a closed benchmark.

Use global public ranges/chunks, with no owned-note index, subtree, recipient or
note-dependent request. Retain atomic publication of receiving state, spentness,
witnesses and cursor. A selected branch inside R uses an authenticated retained
base; a deeper rewind revokes the old view and performs explicitly priced full
replay. A new-process recovery may still perform one full scan. Neither case may
silently bless an old checkpoint as consensus or erase unavailable history.

Pass the milestone only if:

* Successive ordinary refreshes consume/authenticate the actual suffix plus
  declared bounded framing, rather than resending/rechecking the full prefix.
  An unchanged selected head requires no full-history reread. Report request,
  response, CPU, RSS and retained journal bytes, including cold recovery and deep
  replay; demonstrate linear cumulative append work over a fixed existing trace
  and its longer prefix. This is an algorithmic experiment criterion, not an
  owner latency/bandwidth budget.
* Existing genuine public bodies can drive the changed history path; regenerate
  proofs only if a new correctness question requires it. Compare joint wallet
  state and a fresh actual spend against the existing full-replay path. Preserve
  changing-root expiry, shallow/deep rewind and fresh-process recovery semantics.
* Wrong/missing/reordered/truncated suffixes, wrong base/chain/endpoint and stale
  capabilities fail atomically. Failed or interrupted continuation cannot make a
  spendable view, reuse an orphan state or advance a durable cursor early.

Stop or reject this repair if continuation requires a remote owned-index query,
untrusted imported checkpoint, retained producer verdict, unbounded hidden prefix
cache, or a trust/availability assumption stronger than the explicitly declared
validating source. Preserve the full-replay implementation as the correctness
reference and fallback, charging its full cost.

**Stop after this one evaluated implementation and its reviewed result, PASS or
FAIL.** Do not grow it into codec tuning, remote pruning, checkpoint construction
or another proof-generation campaign. A failure leaves the replay cost explicit
and returns the architecture decision; it does not justify successive optimization
milestones. A pass closes this specific history seam and returns the same decision
with the first-copy storage figures unchanged.

## Why this choice, and its limit

| Candidate next investment | Disposition |
|---|---|
| Incremental common authenticated history | First: exact demonstrated repeated work; bounded change to an already functioning joint wallet mechanism, with a decisive byte/authentication test and no new proof construction. |
| Remote pruning/checkpoint | Not assumed available. Pruning relocates175.126575TB/year per body copy to provisioned archives and needs restart-safe ACK/catalog/eviction/refetch plus availability policy. Checkpoints additionally need an authenticated bootstrap and selected-chain rule; they do not remove initial data availability or private common scanning. |
| Complete-proof-size challenger | The relevant material route if the first-copy body/retention model is rejected or a substantially smaller complete relation can be demonstrated. A compression/container rewrite or smaller Merkle path does not establish that result. No closed challenger benchmark is repeated or invalid construction revived by this recommendation. |
| Limited PoW/permissionless issuance | Deferred as implementation investment. It replaces the laboratory authority and establishes ordering/issuance, but adds puzzle, fork-choice, relay and bootstrap costs while retaining payment/history duties. No mining cost is zero or measured here, and no PoS/hybrid alternative is introduced. |

After the suffix result, publish the corrected wallet cost alongside the unchanged
body/state/bootstrap obligations. A suffix PASS alone does **not** authorize full
consensus integration or turn the finite retention model into decentralized annual
affordability. That decision still needs an explicit participation model covering
retention/pruning, archive replication/availability, initial sync and growing
nullifier/tree/undo state. If that model is adopted for a stated research scope,
limited standalone PoW/issuance becomes a coherent next experiment; if it is
rejected because of first-copy size, the next investment must directly reduce the
complete payment/storage obligation. No owner budget or universal rejection
threshold is invented here.

Until such a participation model is affirmatively adopted, the default next
**global architecture** investment after this one-shot follow-up is a materially
smaller complete-payment proof/storage candidate, not further suffix tuning or a
full consensus engine. The present finite PASS supplies no missing adoption.
