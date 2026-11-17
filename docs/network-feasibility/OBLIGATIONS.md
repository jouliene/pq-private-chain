# Network feasibility: fixed obligations and review gates

Named question: can a versioned 96-distinct-ordinary-payment block preserve the
complete CP03 payment predicate and wallet privacy boundary while paying the
actual destination and archive costs? This map authorizes no parameter change.
Baseline is public `d8f800037b5efbb76a5a1d6d4d3100e55f676a00`. The network
adapter and declared finite Gate2 workload passed functional/resource review as
recorded in [RESOURCE_DECISION.md](RESOURCE_DECISION.md). The joint local-witness
wallet has passed the full264-proof finite campaign and independent evidence
review. Clean-checkout reproduction and final publication remain pending; see
STATUS.md for actual closure rather than interpreting these tests as a theorem.

The existing evidence permits a labelled research experiment. It has not
demonstrated a currently applicable soundness, authorization or ledger-privacy
attack against this exact retained construction. That is a bounded source/evidence
finding, not exhaustive cryptanalysis or a whole-protocol security theorem. A
demonstrated mandatory-property failure blocks dependent work immediately.

## Exact cryptographic boundary

| Role and source | Fixed mechanism | Remaining assumption; prohibited shortcut |
|---|---|---|
| Receiving, `source/experiments/compact-receiving-v1/cp03/receipt.mjs` | Final ML-KEM-1024, public key/ciphertext 1568 bytes, shared secret 32 bytes; native Node24.22.1/OpenSSL3.5.9 | Standard KEM confidentiality is not recipient anonymity. Honest-key/common-simulator, multi-user/adaptive and QROM composition remain qualified. No new public recipient identifier or remote key-dependent receipt/error oracle. |
| Receipt KDF/DEM/KC, same source and `codec.mjs` | Labelled HKDF-SHA384; AES-256-GCM nonce12/tag16/plaintext512; SHAKE256 48-byte key confirmation; descriptor1672/envelope2164/context174 | Preserve descriptor, chain, suite, core, output ordinal, commitment, KEM ciphertext and nonce binding. Public adaptive salts, one-use DEM/KC and correlated receipt/note/proof simulation remain obligations. Native failure is operational failure, not silent nonreceipt; never emit tentative plaintext. |
| Laboratory source authority, `source/crates/ledger-cp03/src/trusted.rs` and `admission.rs` | Pure ML-DSA-87, fixed context `PQCHAIN-CP3-SOURCE`, message314/signature4627/public key2592 | Signature, registered exact credit, current unconsumed source and atomic consumption are all required. This authorizes laboratory credit only; no permissionless issuance or spend-knowledge claim follows. |
| AUTH/NOTE/NF/LEAF/NODE/CORE/ORIGIN, `source/experiments/compact-payment-v1/src/{hash,permutation}.rs` | Framed Goldilocks Poseidon2, width16, exponent7, RF8/RP24, rate8/capacity8/output8, exact152 constants and initial external layer | Binding, randomized note hiding and secret-derived authority/nullifier unpredictability are distinct experimental assumptions. Domain/chain/length/padding and occurrence identity remain fixed. No numerical system PQ level follows from output size or the Poseidon2 name. |
| Complete proof, `source/experiments/compact-all-payments-v3/src/{registry,frame,engine}.rs` and `data/profile.json` | Hiding uni-STARK/direct FRI, Goldilocks^5 with X^5−3; N512/H1024,579main/114fixed,965/966/966 assertions,33/41/49 public fields; B16/q160,8 quotient chunks,10 binary folds, SHA3-512 roles | Keep the sealed three-program registry, exact preprocessing commitment, canonical statement/full frame, codec and proof envelope. Joint FRI/mask hiding, knowledge or direct authorization, adaptive multiple-proof privacy and Fiat–Shamir/QROM remain qualified. A library label or successful verifier is not their proof. |
| Randomness/challenges, `source/experiments/compact-payment-proof-v1/src/config.rs` and modified P3 sources | Three separate fallible32-byte OS seeds; StdRng/ChaCha internal forks; one-use private opening state; fresh frame/transcript. Fixed(2) first-outside-base-field selection at zeta and PCS alpha, abort if both fail | Preserve salts, five helper columns, quotient randomization and interleaving2. Never reuse consumed private masks or retry an abort with the same private commitment. Public deterministic preparation may be reused; proof verdicts may not. PRG/output-volume and multi-target losses remain assumptions. |

The exact AIR is `source/experiments/compact-arities-v3/src/air.rs`, reached through
the bounded arity adapter, with its fixed schedule in `program.rs`. It connects
the same input opening/key to owner authentication, note commitment, occurrence
nullifier, depth40 membership path, index below authenticated count, and bounded
integer conservation. It constrains both output commitments and zero debit;
ordinary credit is zero. `statement.rs` additionally rejects noncanonical fields,
wrong arity/kind/length, duplicate input nullifiers and invalid amount/count bounds.
The outer full frame binds statement fields not present in the AIR projection,
including receipt digests and source identity. None may be dropped during batching.
The proof does not establish honest encryption or recipient decryptability: a
malicious payer can strand its own value; successful receipt opening still needs
funding/authenticated-history and spentness checks.

Independent proofs in a larger block do not share private witnesses, masks or
challenges. There is no new aggregate proof or coordinator knowledge assumption.
Existing multi-proof composition qualifications remain; 96 executions do not
establish a new formal bound.

## Cross-layer gates for the versioned adapter

1. **Unambiguous version and bounded intake.** Specify accepted old/new versions,
   schema identity and explicit empty-block semantics. Bound count and total
   encoded bytes before allocation, with checked sums and exact end-of-frame/EOF;
   keep the per-body/proof bounds. Test count, byte, length, trailing-data and
   version failures. A hypothetical128/256MiB/30s profile is not current capacity.
2. **Every consumer agrees.** Review block/header/full/reduced history, ledger,
   CLI, SQL body ordinal, archive locator/catalog, scan/recovery and cache bounds.
   Baseline hidden16 limits include ledger `schema.sql`, `store.rs` LIMIT17 and
   append count, `main.rs`, `cache.rs`, and `store_archive.rs`. Note-output
   ordinal0/1 is unrelated and stays fixed. Operational export/eviction batches
   may remain16 if bounded iteration accounts for every row and terminates with
   the required pending count; do not increase every occurrence of16 blindly.
3. **No partial acceptance.** Destination uses fresh `apply_expected_block` or
   equivalent ordinary live admission, including actual proof verification for
   every body. Historical-content verification is not current-state admission.
   Preserve chain/parent/ordered-body IDs/root/count, eligible anchors, existing
   and intra-block core/nullifier/source uniqueness, exact fees/liabilities and
   checked integer arithmetic. A final changed real proof must reach the proof
   rejection gate and leave all consensus tables unchanged; follow with a valid
   block. Trace-only or framing-only rejection is a different control.
4. **Durability and retention are real obligations.** Interrupted intake cannot
   expose accepted partial state. Durable ledger commit and archive publication
   are different events. Acknowledgement must bind the exact durable object and
   its retrieval identity; no locator minted from producer assertions. Exercise
   one interruption between persistence/publication/ACK and retry after restart:
   no silent loss, duplicate application or eviction before acknowledged durable
   retention. Account pending rows/bytes, duplicate physical objects, disk/WAL,
   transfer retries and archive recovery; a nonempty deferred queue is unfinished
   work unless explicitly counted as retained durable responsibility.
5. **Independent measured roles.** Producer, archive and destination are separate
   processes with bounded transport. Receiver cannot read producer fixtures or
   its database; expected-state/body oracles stay outside timed processes.
   Report every actual verification, including archive revalidation, separately
   from reused public preparation. Validate canonical state equality excluding
   only declared installation/local database identities. Measure all transfer,
   parse, proof/state, commit, retention and ACK work; do not add overlapping spans.

Funding is separate: 96 valid ordinary payments need independently funded,
nonconflicting occurrences and real new proofs, not repeated transaction bytes.
Exact source counts, credit/fee totals and genuine generation costs must be
visible. The generation order and public fixture labels must not disclose a
retained private credit-to-spend assignment as an alleged protocol property.

## Wallet gates and concrete hazards

Current remote use of `Ledger::membership(index,...)` would disclose owned indices;
it is therefore prohibited in the new wallet path. The complete local ledger may
be an external test oracle, never the path supplier attributed to streaming
construction. All wallet requests must be common history requests independent of
owned notes; no unique subtree/range, recipient-dependent retry or key-miss report.
The experiment does not hide IP addresses, activity or timing.

The selected new local builder is a fixed depth40 stateless native operation on
an unpadded frontier and bounded target paths. It uses the existing LEAF/NODE
framing, not a new payment relation or hash. Native canonical state decoding is
not authenticated bootstrap: only a private coordinator checkpoint bound to the
full applied cursor, chain/genesis, inventory and selected revision is admissible.
The coordinator jointly journals openings/spentness/frontier/cursor, freezes the
inventory and owns a single prepared packet with deferred retirement until its
actual consumer terminates. Source review and helper controls do not establish
wallet receipt, proof, expiry/rewind or backup acceptance. Actual no-DB/FD/proc/
membership-route isolation of the wallet and descendants remains a run criterion.

Bind history chain/genesis/order and endpoints to the declared independent
validating source. Hash linkage alone accepts a coherent server-selected stale
history and supplies neither validity, consensus, freshness nor availability.
Measure discovery, local path construction, any second pass/spool, key scans and
recovery history. Keys/backups/openings/witnesses remain private bounded RAM/pipes.

The current anchor window permits height h for inclusions h+1 through h+256.
An expiry control must advance with changing roots and reject the old anchor,
then reconstruct a current path for the same old unspent occurrence and actually
spend. Expiry never forgets spent nullifiers or destroys old balances. Rewind
must undo orphan discoveries, nullifiers and witness updates; reject orphan-only
funding or an ineligible orphan anchor, retain common-prefix eligible funds, and
successfully spend on the replacement branch. Branch origin alone is not an
invalidity condition. This is a controlled branch controller, not fork choice.

Backup-only fresh-process recovery requires every retained random receiving key
needed for the history plus spending secret, public inventory and endpoint/history
context. A backup predating an unknown random rotation cannot recreate that key.
Static receiving-key compromise exposes historical receipts; no forward secrecy,
mnemonic recovery or privileged-host protection is claimed.

## Known qualifications and decision triggers

The retained Poseidon2 screen of primary2026/306 and2026/1792 found no demonstrated
mandatory-property attack for this exact framed candidate. Its non-MDS16 finding,
zero budget for one model and ideal-degree arithmetic are neither attacks nor
security lower bounds. Do not rerun closed structure/count controls without new
evidence. The retained native provider review identified unchecked internal XOF
status propagation in a signing path under a provider fault; fault-safe signing
and universal error propagation are not established. No practical exploit was
demonstrated. The current research scope assumes a functioning pinned provider,
retains real signature verification and does not claim fault/side-channel safety.

The complete path now identifies two separate obligations: repeated common-history
prefix work in the wallet and the large first-copy payment bodies. The selected
next bounded development recommendation is authenticated common-history suffix
synchronization, as specified in RESOURCE_DECISION.md. It changes no proof
parameters or annual first-copy size and stops after one reviewed outcome.
A later payment-size route must address the complete relation and retained data;
neither repeated compression surveys nor a cell rewrite is automatically allocated.
Any representation experiment must decode byte-exactly into the unchanged verifier,
charge dictionaries/references/decoder/missing-object costs and show a material
decision benefit. Existing path sharing cannot be counted twice. Modest past
gains do not justify a codec rewrite.

A materially different complete native-lattice backend remains a conditional
initial-data challenger, not an available qualified substitute: its prior run
failed and source/target/sparse/rotation/verifier gaps must first be repaired.
A genuine complete-verifier/state checkpoint is a different bootstrap experiment,
not relief from initial data availability or receipt-history retention. Neither
route may be selected through a gadget-only result, weaker parameters, leaked
coordinator witnesses or free recursive verification. No such pivot is allocated
or claimed executed here.

## Evidence and independent acceptance

Primary component references: [FIPS203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS204](https://csrc.nist.gov/pubs/fips/204/final),
[HKDF](https://www.rfc-editor.org/rfc/rfc5869),
[GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[Poseidon2](https://eprint.iacr.org/2023/323), and
[small-field STARK zero knowledge](https://eprint.iacr.org/2024/1037).
These specify components/discuss constructions, not this protocol's composition.
The existing exact source/errata/hash-screen analyses are retained research
evidence; no private research file is a runtime or public reproduction dependency.
The public [security map](../SECURITY.md) and [architecture](../ARCHITECTURE.md)
remain the compact statement of assurance limits.

Before final acceptance, a reviewer who did not implement the path must execute
the decisive final slice from a Root-allocated clean checkout. The reviewed
[Gate5 scope](../../experiments/network-feasibility/review/GATE5_REPRO_SCOPE.md)
requires a fresh build, new isolated small5 private receive/witness/spend/recovery
cycle and fresh public-only replay of every full01 proof and its branch/expiry
chronology. Independent review of full01's actual private expiry/rewind/deep-replay
evidence supplies the source-to-public-outcome correspondence; public replay alone
cannot establish those private actions. This is explicitly not a second full264
private campaign. Retain independent review of unchanged separate-role transport,
failure controls and finite queue/retention evidence. A new material private-state
finding invalidates the reduced scope and requires the shortest affected genuine
private reproduction. Check
source/manifests/build/runtime correspondence, real terminal statuses, data-access
boundaries and safe public evidence. Publish the exact tested revision, commands
and actual CI result. Keep experiment completion, provisional backend acceptance
for an explicit participation model, and the unfinished global blockchain Goal
as separate conclusions. Owner acceptance of a cost model cannot be inferred.
