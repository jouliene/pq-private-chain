# Final documentation review — before independent Gate5 completion

Scope: current README, ARCHITECTURE, SECURITY, RESOURCE_DECISION, OBLIGATIONS,
DELIVERY, STATUS, GOAL and POST_GATE3_INVESTMENT_DECISION, compared with retained
Gate2/full01 public results and the adopted Gate5 scope. This is a lightweight
documentation review, not another cryptographic verification or resource run.
No large payload rehash, native command, build or proof was executed.

## Actionable findings

1. **Align the next-investment instructions.**
   `docs/ARCHITECTURE.md:5–10` still says to advance standalone PoW “for the next
   integration stage.” This conflicts with README and
   `docs/network-feasibility/RESOURCE_DECISION.md:123–139`: the next bounded
   follow-up is one evaluated authenticated-suffix implementation; PoW/issuance
   remains deferred behind an explicit participation decision. Preserve PoW as
   the preferred *consensus direction*, but remove its immediate-stage wording.
   Similarly, `OBLIGATIONS.md:146–153` still prescribes a transport/container
   comparison as the smallest first-copy-byte discriminator. Mark that older
   conditional advice as historical/superseded, or defer it explicitly to the
   adopted one-shot suffix decision and subsequent complete-payment/storage
   decision. Otherwise two current normative documents direct different work.

2. **Make independent acceptance match the selected Gate5 scope.**
   `OBLIGATIONS.md:178–182` asks a clean checkout to reproduce the separate-role
   finite queue result and the actual wallet expiry/rewind sequence. Its later
   instruction to reuse evidence does not identify which parts are reused.
   Read literally, it requires more execution than Root adopted in
   `review/GATE5_REPRO_SCOPE.md` and STATUS: fresh clean build, fresh isolated
   small5, full264 public chronology, conditional on independent original full01
   private-evidence acceptance; unchanged Gate2 is reviewed, not obligatorily
   rerun. State that split explicitly and link the scope. Do not describe public
   chronology as an independently repeated full private expiry/rewind campaign.

3. **Update the remaining full-result-review pending phrase.**
   `POST_GATE3_INVESTMENT_DECISION.md:7–8` still groups independent full-result
   review with outstanding clean reproduction. Full01 independent review is now
   PASS (`STATUS.md:27–31`, review SHA256
   `bdb31d729f01ecc3cf9013f28b5ccba4465aa81f42518362c2631a3882a71784`).
   Say that original full-result review passed while clean independent execution
   and publication remain pending. Keep the timestamped earlier GOAL checkpoints
   as history; they are not retroactively false results.

## Checked conclusions and limits

The actual arithmetic is represented consistently: Gate2 has864 generated proofs
and768 ordinary payments; full01 has264 distinct proofs,265 positive proof
admissions,264 successful block admissions,4 rollbacks and2 atomic Anchor
rejections. Final full01 fees551305634 plus remaining notes548694366 equal issued
1100000000 with zero liability. Selected retention261 bodies differs correctly
from all264 generated bodies.

RESOURCE_DECISION and STATUS keep nested proof-worker measurements inside wallet
spans, and separate Node, waited descendants, CLI and controller costs. Sampled
RSS is qualified. The175.126575TB/year figure is one ordinary full-body copy;
502.242GB is a one-pass common-scan projection, explicitly **not** current wallet
annual traffic. Repeated-prefix reads are charged, no owner annual cap/adoption
is invented, and finite success is separated from affordability/security/global
blockchain completion. README, SECURITY and DELIVERY preserve these limits.

The substantive POST_GATE3 decision is coherent: one suffix result, PASS or FAIL,
then stop; cold/deep replay charged; no ownership-selective requests or untrusted
checkpoints; no new gate for closing this milestone; first-copy storage remains;
no automatic permission for full consensus. No implementation was authorized or
performed by this review.
