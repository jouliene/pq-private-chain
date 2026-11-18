# Independent clean wallet reproduction

I used detached repository commit `1e5956364b2a39117f80d00d41923b6b92422439` with no tracked edits. The external Qnero source came from a separate clean checkout of `f04c91307837c0231668383bec76ba98d89d2652`. Only the two test/example overlays were added to that checkout. All private outputs and keys stayed in the producing processes or their disposable private storage. The [measurement record](CLEAN_CORE.json) contains only public proof identities, outcomes and resource counters.

## Structured full payment

I independently relinked the release Rust driver with the previous clean CP03 installation, installation SHA-256 `f885a09c9768b383cf4004ed92786f25e4b40610089f76b7de489358e06ebb46`. The compiler and release libraries were reused after pin checks. The resulting executable had SHA-256 `5bf939b195efd1188edd2f2435f8923ff3217976c53d7d0d62324ddd88d0303d`. The endowment, three wallets, subsequent notes and all masking randomness were fresh. Each payment spent two funded occurrences and created two encrypted notes for the next wallet. That wallet opened both and used them in the next leg for the first two transfers. An unrelated wallet opened zero on every transfer.

| Payment | Proof B | Complete body B | Wallet backend user + system CPU s | Peak RSS KiB |
|---|---:|---:|---:|---:|
| 1 | 256,672 | 261,548 | 27.25 | 2,339,676 |
| 2 | 261,152 | 266,028 | 27.28 | 2,339,864 |
| 3 | 259,296 | 264,172 | 26.98 | 2,339,656 |

The three-proof public ledger replay reached eight funded occurrences, six distinct spent nullifiers and 6,336,744 fees. Wrong statement, changed receipt, changed proof and replay each failed on all three payments with the existing state preserved. The wallet lifecycle used a shared orchestration process for its three owners. Each cryptographic verifier ran in a fresh restricted namespace with public data only.

Separately, the [independent public runner](structured_public.py) extracted only the public statements and proofs from the three author bodies, then from the reviewer bodies. It checked the approved genesis identity, packet framing, chain, published occurrence counts, exact fee and distinct public nullifiers. A separate namespace with empty stdin ran the compiled three-proof verifier. Each stream passed. In each case a valid proof paired with the other valid statement and an appended byte were independently rejected by the cryptographic process. The six warm cryptographic checks took 0.0768–0.0809 thread CPU s apiece following 1.120–1.123 CPU s of matrix preparation per three-proof process. This scope excludes ledger, receipt hashing, dissemination, retained history growth and durable recovery. Individual timings vary with the host. A single-core Qnero dependency compile initially overlapped the first wallet run before it was suspended.

The outcome demonstrates actual complete masked spending and a working structured evaluation. The four base guard answers share the initially committed message with the outer terminal masks. Proving that the joint adaptive transcript hides the trace and that a noninteractive adversary yields a valid base-field witness remains a separate cryptographic obligation. The sampler extends domain-separated hashes into field/challenge packets; the prover salts authenticated oracles, and Merkle openings are implied by committed roots and queries. Carrying interactive honest-verifier guarantees to this compiled oracle model needs a joint simulator/extractor and a quantified Fiat–Shamir/QROM analysis. Resource or mutation tests do not furnish those reductions.

The preserved CP03 reference also replayed all three author bodies from the public genesis pinned in `wallet/REFERENCE.json` using the separately installed reference verifier. All twelve controls rejected, with six spends, eight funded occurrences and 6,336,744 fees.

## Qnero default wallet

I copied the existing Cargo target as a dependency cache and rebuilt pinned local Qnero crates and the two experiment entry points from the separate upstream checkout. Cargo reported `fresh=false` for the rebuilt local wallet, verifier, circuit, aggregator and wallet test executable. Compilation ran offline with the existing Rust 1.93.0 toolchain, Cargo.lock and registry artifacts. The wallet and verifier executable hashes matched the author artifacts. A four-thread wallet process generated new keys, submitted a fresh one-real-input/one-dummy-input transfer to the test RPC node, and demonstrated one recipient receipt from history and seed-only recovery. A public-only verifier checked the approved private-batch artifact, the new proof, anchor, two output commitments and ciphertext digest. The public-only verifier also passed the retained author's different commitment/transaction. Both runs rejected a corrupted proof and detected a changed ciphertext.

The reviewer transaction was 154,508 B, including a 150,908 B proof, 3,584 B of ciphertext and 16 B of bare SCALE framing. The [separate parser](qnero_wire.py) found one real slot, five padding slots, 131 public field elements inside the proof and a fee of eight steps. The public digest differs from the author's. The four-thread wallet used 18.42 CPU s in `prepare_spend`, 5.069 s wall, and 7.36 additional CPU s for setup. Its complete process used 25.95 CPU s and 1,112,064 KiB peak RSS. The isolated new-proof cryptographic check took 6.69 ms elapsed after artifact load. This run used an authenticated synthetic RPC history, explicit endowment and a selected head. It did not run mining, network propagation or a year of recovery. Source-level service and asset semantics are reviewed [separately](QNERO.md).

## Reproduction entry points

From a clean project checkout with its own approved CP03 installation, use the installation digest and binary digest generated locally. The first command creates the candidate, the second creates new three-wallet data and publicly replays it. The third command needs only the generated public bodies and the independently recorded public genesis digest. In a separate clean Qnero clone at the pin above, the last command performs the ordinary default wallet comparison with the upstream 1.93.0 toolchain.

```sh
d=experiments/wallet-created
python3 -IB "$d/structured/build.py" --installation "$inst" --approve-installation "$install_sha" --output "$candidate"
python3 -IB "$d/wallet/run.py" --installation "$inst" --approve-installation "$install_sha" --candidate "$candidate" --approve-candidate "$candidate_sha" --output "$out/three"
python3 -I "$d/review/structured_public.py" "$candidate" "$candidate_sha" "$out/three" "$genesis_sha"
python3 -IB "$d/qnero/run.py" "$qnero_checkout" "$out/qnero"
python3 -I "$d/review/qnero_wire.py" "$out/qnero/public/payment.scale"
```

## Durable admission and rollback

At detached commit `abbca400862233bba0c9a7f7f9e468c7b19c58c4`, the reviewer submitted the three retained author bodies and trusted genesis to a new durable node directory. The [independent test](durable_check.py) opened each resulting SQLite database read-only, checked integrity and compared all committed bodies, exact fee balance, funded commitments and distinct nullifiers against the original public files. The accepted database contained 789,876 bytes of body payload and occupied 815,104 bytes for this three-payment fixture. The three measured hot proof checks plus ledger transitions took 0.2783 CPU s, including 0.04185 CPU s of ledger operations. The corresponding average was 0.0928 CPU s/payment. The proof process separately consumed 1.41 CPU s including preparation. Large indexes, long-history contention, full-block dispatch, restart/reorganization and physical archive growth were outside the measurement.

Two additional cases used valid proofs throughout. Changing only the second receipt left exactly one payment committed (four funded, two spent, fees 2,112,248). Replaying the second accepted packet as the third left exactly two payments committed (six funded, four spent, fees 4,224,496). For both, the stored commitment root equaled the next genuine public statement's expected root and the retained body prefix was byte-for-byte identical. Per-payment effects were atomic. Earlier accepted payments survived in the same batch. The [raw outcomes](CLEAN_DURABLE.json) include public roots, frontier digests and retained byte counts.

```sh
python3 -I "$d/review/durable_check.py" "$d/wallet/run.py" "$inst" "$candidate" "$d/wallet/evidence" "$install_sha" "$candidate_sha" "$genesis_sha"
```

## Full folded-vector check on fresh proof coins

At clean source revision `6cccc82b7e084bdd1273d2b667b76f82b4f1b0d4`, I relinked the separate `--audit` executable with the approved CP03 installation and replayed all six real author/reviewer statements and proofs in namespaces receiving only public files. For each instance the instrumented verifier first ran its optimized contraction, then compared every one of 50 public coefficients and 65,536 folded EF5 values directly against the registered generic matrix on the actual transcript challenges. All six matched; all three author output digests also matched the published dense-oracle audit. [Audit timing, executable identity and six independent comparison results](CLEAN_AUDIT.json)

## Decision and independent arithmetic

I support keeping CP03 as the executable reference and deferring network integration for both new validation rules. Complete WHIR validation has demonstrated wallet-produced ordinary authorized transfers and a substantial reduction in full body size, together with acceptable post-preparation cryptographic and ledger CPU on the three-record test. It still needs a quantitative joint noninteractive privacy/knowledge analysis, an implemented branch-aware acceptance window for concurrent independent payers, and a practical history-retention policy. The tested two-wallet recursive alternative does reduce retained bytes while keeping private witnesses and unblinded leaf proofs local. At real occupancy two it still requires more than the 5 decimal TB single-archive scenario at the demanded rate, has a different note/authorization model and pays appreciable builder and ordered-state work. These observations apply to the measured constructions. The owner specified 100M offers, with no archive or traffic ceiling.

I checked the archived body lengths and archive arithmetic directly. For WHIR, add 68 B per included body and 228 B per 96-payment transport block. At 95M / 100M included the resulting one-copy totals were 25.019425625152 / 26.336237500076 TB. At the same demand two-payment native packets alone require 7.46795 / 7.861 TB, and direct Qnero extrinsics 14.67826 / 15.4508 TB. On the author measurements, WHIR's 0.098377554 CPU s/payment implies 1.49824 / 1.57710 cores for one historical year in 90 days while following the live workload, excluding verifier setup. The strict current-tip rules under test serialize independently arriving spends on *both* candidates; replay speed does not measure sustainable live originations, and transport batching 96 transfers does not grant concurrent anchor validity. The native implementation rehashes a growing ordered commitment list. The leaf payload alone is 144.40000304 / 160.0000032 PB for that historical year before tree work or header framing. No one-year performance, persistent native state, or full-block rollback run is claimed. A proposed multiasset conservation circuit and a joint mode-bound all-or-nothing swap must be implemented and tested independently before either is counted as supported.

At final executable/evidence freeze `c6c38785316a5a3bdb7cff1425ef241d1fab8c45`, both cross-route and stock-only role calculators reproduced their tracked JSON byte-for-byte from the clean detached checkout. Cross-route output SHA-256 was `77e59249344e638d9167097164bc7ce2bbe6d669bb41486d146e4c4ee723cd2f`. The published stock HTTP measurement matched the independently checked capture at SHA-256 `0aa0a74a8645e58c8b543d16e865e2d778937e84042f3a30246784e949f8290b`.
