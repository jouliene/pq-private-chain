# Independent local devnet review

The starting revision is `4693276`. The earlier advancing-chain campaign exercised registered payment proofs, synthetic funding and a supplied branch-selection event sequence. The present review covers mined issuance, independently selected PoW history, private wallet use and actual local network delivery. Finite local service results, privacy assumptions and capacity estimates have different scopes.

## Checks registered before product implementation

- Start from the published empty genesis in a clean work directory. Record source, locked build, operator registry, genesis/network identifiers, selected consensus parameters and actual TCP endpoints. Start independently persisted nodes. Shut down one participant, mine and pay while it is absent, restart it and sync all required data. Synchronize one entirely new node against a chain extended beyond a recent-anchor window. Compare tips, cumulative work, supply, outputs, nullifiers and wallet scan outcomes with the continuously running participants.
- Independently decode complete public blocks, hash exact bytes, recompute declared work for every height, validate ancestry, prescribed difficulty, tie policy, height and payment count/length bounds. Check that economic/security claims follow the work of the actual public candidate branch. Exercise competing branches selected by the protocol rule, including an honest lower-work fork and a winning replacement that removes mined outputs and their descendant effects. A locally remembered prior high-water tip cannot silently determine consensus for late joiners.
- Independently derive the ordinary subsidy schedule, fee total, cumulative issuance and the reward commitment for each accepted height. A miner must not choose the amount hidden in the value funded by the reward. The same fee must be paid once from the spend and awarded once; only subsidy creates additional units. Validate prescribed zero-supply genesis, absence of privileged funding calls, reward uniqueness, configured bounds, any maturity rule, and supply after branch replacement. State precisely which reward data are public. Sum hidden wallet amounts only in owned wallet test processes when explicitly necessary. Avoid logging seeds, private notes, blindings or witnesses.
- Require a miner to spend a reward through the ordinary registered wallet proof. Isolate an external recipient with no prior endowment or incoming change. Check the requested amount, sender change and exact fee with wallet-local observables; then spend the externally received payment, restart/restore from the supported private backup and reconfirm ownership after fresh sync or reorg. Count real users and signed/proved spends, their actual inclusion slots, full framed bytes and proven acceptance. A successful upload, valid proof or a fee counter alone does not establish the other checks.
- At multiple-ordinary-payment occupancy, retain every independent anchor and ordered ciphertext pair, enforce current branch-local nullifiers and output uniqueness within and across blocks, and verify every payment afresh. A complete funded local case should exercise capacity at configured maximum and underfill, eligibility boundary and stale or branch-only authorizations. A single failed validity/commitment/consensus check must leave the persisted selected state and accounting unchanged. Reopening the node should reproduce the same disposition from public genesis and blocks.
- On the candidate revision run the documented one-command walkthrough as written from a separate checkout and new work directories. Record realistic prerequisites, computing resources, actual wallets/peers, verification and state-transfer bytes, confirmations and configured PoW/difficulty assumptions. Compare independently reproduced facts with evidence from the author. Use compact designated public objects and numerical wallet outcomes for the review record. Keep private state and unapproved code outside the public verifier.

The test implementation will use consensus constants and framing from the frozen contract, a standard-library reference for PoW/work/supply and separate upstream Qnero reference computations as required. Its public input consists only of externally approved genesis/profile identities and complete downloaded blocks. The source build and real proof generator/verifier are tested separately from this accounting reference.

## Clean disposition

The implemented local PoW payment milestone passes the independent functional review at `8c4fb94334994ac98253348384050f23904d40a5`. A new detached clone, absent runtime/Cargo target and absent node home ran the documented walkthrough directly. The script fetched the upstream commit over HTTPS. The machine supplied installed Rust 1.93.0 and a warm registry/download cache. The 75-second Cargo release build produced the same native executable SHA-256 as the published source receipt, `0d74f63ee0a201fd49f62f91b269fa959b5388a17b4665a14dbb77200f9b0634`. The total including first prepare was 197.23 seconds. The two additional calculation oracles were relinked from the furnished review sources and independently compiled upstream Qnero libraries at the same pin. The published registry was reused as a trusted public input. [Build receipt](evidence/BUILD.json) · [Review summary](CLEAN.json)

| Observation | Independently reproduced |
| --- | --- |
| Fresh genesis and first funding | Three distinct daemons reported zero supply, zero notes and zero spent entries. Two different miners each received their first 100. The separate recipient started at zero. |
| Ordinary payments | One 100-unit reward funded 37 to the recipient, 60 change and 3 fee. A seed-restored recipient then spent the 37 into 11, 23 change and 3 fee. A different miner combined two rewards worth 203 for a payment of 124, change of 76 and fee of 3. The last two payments shared H4. Each packet occupied 230,206 bytes. |
| Fork choice and monetary effect | The isolated H14 branch had 1,400 issued and 12 fees. Of its 14 blocks, 10 detached following the winning H15 branch. The detached 100-unit miner balance returned to zero, and the recipient lost the detached 13. All four stores ended at 1,500 issued, 9 fees, 1,509 credited to miners over the winning history, 21 funded commitments and six published nullifier slots (some are dummy slots). Both orderings of two equal-work H1 blocks chose the same ID. A genuine H2 on the other H1 then won. |
| Delivery, persistence and proofs | A new D assembled the winner from genesis. After restart, four independent SQLite snapshots agreed, including each branch's saved header/frontier, selected receipt rows, nullifier heights and transaction locations. A–C archived 25 distinct blocks each; D archived the 15 winning blocks. Four different restarted TCP processes each answered 40 independent public requests, including every selected body and every tip-pinned wallet page. Another empty registered verifier received only public blocks, selected H14 then H15 and replayed the deep fork from genesis. The same verifier separately accepted the author's independently generated 25 objects. |
| Input rejection and reannouncement | Each of three fixed invalid economic fixtures passed the full 22-bit PoW requirement, then failed the subsidy, funded denomination or tree check. Every SQL table retained its prior contents. A valid 100-unit control succeeded. A fresh two-node network reannounced an eligible ordinary payment previously known only inside a losing block, then included it once at H5 for 3 fees. The ordinary walkthrough rejected a genuine conflicting proof from the pool and from confirmed state. A malformed 31-byte backup left the restore destination absent. |

The fresh selected capture contains thirteen empty blocks, one singleton and one two-payment block, totaling 693,960 complete block bytes and 62,914,560 units of credited work. Both branches together contain 926,390 unique body bytes. The inspection of the four-payment bound covers framing and admission logic; actual positive block occupancy in this independent network reached two. The H15 branch tip is `00000074e008a2db0d59bad2d4899371b5d3c9dbfaf50cb8a8b546ff7f6f192b`. [Full capture](evidence/main/RESULT.json) · [Public proof replay](evidence/public-replay.json) · [Database and TCP comparisons](evidence/audit/) · [Side-only reannouncement](evidence/side/RESULT.json) · [Other controls](evidence/tie-restore.json)

The finite fork test verifies selection between fully supplied, correctly solved competing histories and recovery after a ten-block divergence. It gives no probability of finality or inclusion under arbitrary hashpower. The walkthrough uses directed block counts; mining times include deliberate pauses and concurrent competitors. Its separate steady-miner test belongs to the wallet/author evidence. No network anonymity or concrete quantum security level follows from these runs. Reward openings and miner spending public keys are visible; the Qnero spent-nullifier computation also requires the nullifier key. Wallet scanning materializes branch history and emits the owned inventory in a single native response; bounded transport pages alone do not establish bounded-memory restoration. The amount, fee, dummy-input and change figures in the public fixture describe synthetic consenting test wallets. The public-only verifier has no access to those wallets.

## Reproduce

Use the published repository with this review directory present. For an exact fresh product run check out the execution revision in a separate directory. All product code used for the clean capture comes from that revision. The review utilities can be run from the release tree on those outputs. Following the Linux prerequisites in the devnet README:

```sh
repo=$(pwd)
lab=$(mktemp -d)
git clone --no-local "$repo" "$lab/product"
git -C "$lab/product" checkout --detach 8c4fb94334994ac98253348384050f23904d40a5
"$lab/product/pqd" --home "$lab/home" --runtime "$lab/runtime" walkthrough
(cd "$repo/devnet/review/evidence" && sha256sum -c SHA256SUMS)
```

Use a separate checkout of the pristine upstream for the two public arithmetic references. This equivalent Cargo build supplies the dev dependencies used by both small commands. The actual reviewed run used an existing independently compiled matching set of upstream libraries and invoked `rustc` directly on these two sources.

```sh
git clone --no-local "$lab/runtime/source" "$lab/reference-source"
git -C "$lab/reference-source" checkout --detach f04c91307837c0231668383bec76ba98d89d2652
examples="$lab/reference-source/crates/qnero-prover/examples"
mkdir -p "$examples"
cp "$repo/experiments/advancing-payments/review/reference_roots.rs" "$examples/devnet_review_roots.rs"
cp "$repo/devnet/review/reward_oracle.rs" "$examples/devnet_review_rewards.rs"
(cd "$lab/reference-source" && CARGO_TARGET_DIR="$lab/ref-target" rustup run 1.93.0 cargo build --release --offline --locked -j2 -p qnero-prover --example devnet_review_roots --example devnet_review_rewards)
roots="$lab/ref-target/release/examples/devnet_review_roots"
rewards="$lab/ref-target/release/examples/devnet_review_rewards"
rev="$repo/devnet/review"
python3 -IB "$rev/replay_capture.py" "$lab/home/evidence" "$lab/runtime" "$roots" "$rewards"
python3 -IB "$rev/replay_capture.py" "$rev/evidence/main" "$lab/runtime" "$roots" "$rewards"
for n in a b c d; do
  python3 -IB "$rev/audit_db.py" "$lab/home/nodes/$n/chain.sqlite" "$roots" "$rewards"
done
binary_sha=$(sha256sum "$lab/runtime/native" | cut -d' ' -f1)
python3 -IB "$rev/issuance_controls.py" --valid-first "$rev/fixtures/first.bin" --bank "$rev/fixtures/economics" --reference "$roots" --reward "$rewards" --binary "$lab/runtime/native" --binary-sha "$binary_sha" --keys "$repo/experiments/advancing-payments/evidence/public-registry" --profile-sha af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1
python3 -IB "$rev/side_reannounce.py" --evidence "$lab/home/evidence" --runtime "$lab/runtime" --reference "$roots" --reward "$rewards"
```
