# Funded two-owner authorization

Alice transfers 20 units of the lab's registered managed asset to Bob. Bob transfers 8 native units to Alice and pays the 3-unit network fee. These are intentionally disclosed, disposable fixture amounts. Both transfers spend real notes on the selected local PoW branch. Alice produces a released SLG1 leg and an FTL1 proof for the same private opening. Bob produces a fresh released SLG1 leg. Both owners sign the complete released pair, then sign the complete mixed pair. These are conflicting alternatives on the same funding. The coordinator exports public packets and measurements. The node harness owns settlement and fork tests.

Each owner runs in a separate mount, PID and network namespace with a single read-only seed. The test operator provisions the two seeds, the expected addresses, the managed asset and the selected funding block. The ordinary receiver checks its seed-derived address. Each wallet replays the public blocks from genesis with the deployed rules, reconstructs its live funding, checks the selected header and computes the fixed-parent auxiliary root from ordered occurrences. Alice converts her own fresh released opening to the registered 38-public-word, 16,818-private-word circuit assignment. The native prover receives the 32-byte context, public words and private words through an anonymous pipe. The capture FIFO, fixed-parent paths and signing nonces stay within their owner process trees. The prover and every fresh candidate verifier see their respective pipes, approved executable, libraries and registered public shape. The public verifier has no seed mount.

Before releasing either signature, each wallet verifies both released proofs and the candidate proof, constrains the original 34 words and both ordered receipts to match, checks the branch, fee, expiry and spentness, opens its incoming slot zero under its own spending key for the independently agreed currency and amount, and opens its change slot one for the amounts calculated from its own selected input. Both wallets exercise wrong-amount, wrong-currency and wrong-recipient-key refusals. An explicit check binds the signing role's public key to the proof. The joint digest covers network, private agreement commitment, expiry, payer and the ordered SHA-256 hashes of the exact complete proof-bearing legs. The fresh public check verifies both signatures again and rejects substitutions between the released and mixed authorizations.

## Reproduce

Use Linux x86-64 with nested unprivileged bubblewrap, GNU time and Python 3.11+. A new operator can create the disposable PoW home and matching capture roles using the [funded wallet setup](../../funded-whir/wallet/README.md). Supply the pinned `qp-poseidon-core-3.1.0/src/poseidon2.rs` and build the local engine and registered shape from the [proof source](../proof). From the repository root run the following, using a new output path.

```sh
c++ -std=c++17 -O3 experiments/funded-tcith/proof/engine.cpp -lcrypto -o "$work/tcith"
python3 -IB experiments/funded-tcith/proof/register.py "$constants" "$work/shape"
python3 -IB experiments/funded-tcith/wallet/run.py "$lab" "$capture" "$constants" \
  "$work/tcith" "$work/shape" "$work/public-pair"
```

`SOURCE.json` has `complete=true` after all checks succeed. `blocks/` contains exactly the selected prefix through the eligible block. `leg-a.candidate`, `leg-a.released` and `leg-b.released` are the public offers. `mixed.swap` and `released.swap` carry the complete independent authorizations. The operator keeps the two private wallet address-book files, seeds, agreement salt, private change amounts, note openings and witnesses outside this output. The copied blocks retain their public miner keys and commitments. A disposable operator controls both wallet installations on one host. The run does not measure interaction between independent organizations or traffic privacy.

## Matched costs on the first funded run

| Alice's leg | Released SLG1 | Fixed-parent FTL1 |
| --- | ---: | ---: |
| Proof, bytes | 139,658 | 238,120 |
| Complete signed physical frame, bytes | 160,446 | 259,212 |
| Proving role wall time, seconds | 4.790 | 27.45 |
| Proving role CPU time, seconds | 9.28 | 27.44 |
| Proving role peak RSS, KiB | 451,924 | 64,772 |
| Verification wall time, seconds | 0.0068, loaded role | 1.40, fresh process |
| Verification role peak RSS, KiB | 201,004, lifetime high-water | 22,820, fresh process |

The measured mixed submission is 419,671 bytes and the matched released submission is 320,905 bytes. Both include two length-prefixed frames and a five-byte bundle identifier. The candidate signed frame has 2,932 bytes free under the 262,144-byte limit. Bob's signed frame stays at 160,446 bytes. The selected funding history contains 12 blocks and 22 note occurrences. Both wallets computed auxiliary root `178aa295e318a30998b1e3b25d1622063d1309052b3123ccb3ee890fb998c130`.

The capture role uses the existing two-thread released prover, constructs real outputs and ciphertexts, and exports its opening to a bounded FIFO. The SLG1 row times its funded request, including IPC. Alice's fresh release actor initialization, proof request, capture read and closure took 4.869 seconds. The measured candidate prover consumes Alice's in-memory assignment and uses one native thread. GNU time runs inside its namespace and reports CPU, elapsed and peak RSS for the native executable, including the shape read. The extra Python frontend took 0.988 seconds to check the receipt hash, derive the selected input's new path, assign the circuit and serialize the private pipe payload. The shared whole-branch replay and root construction occur before either proof timer. The paired experiment builds the original proof to obtain a checked opening. Neither proving row measures an entire wallet workflow, simultaneous memory consumption, signature exchange or block admission. The released verifier's RSS includes prior role initialization, and CPU sampling rounds to host ticks. The fresh candidate verifier includes registration reads and performed full proof verification independently for both owners. The node harness measures admission separately.

## Whole-wallet time and memory

A second funded run used fresh proofs and authorizations on the same branch. The coordinator sampled each owner's complete process tree from launch through exit. The measurement includes the owner Python process, namespace workers, original ledger replay services, wallet and prover. The process-accounting sampler runs outside the owner tree. The public host counters supply summed resident set size (RSS) and proportional set size (PSS). RSS counts shared pages for each participating process. PSS apportions shared pages among their users. Values below are largest simultaneous sampled totals. Short peaks between observations may be larger. The nominal interval was 50 ms, and the longest observed gap in either complete tree was 53.3 ms. [Resources-only receipt](OWNER_RESOURCES.json)

| Wallet interval | Wall, seconds | Peak summed PSS, KiB | Peak summed RSS, KiB |
| --- | ---: | ---: | ---: |
| Alice, complete dual-format wallet | 43.461 | 728,450 | 768,428 |
| Alice, replay and prepare both leg formats | 35.200 | 728,450 | 768,428 |
| Alice, fixed-parent frontend and prover within preparation | 28.649 | 336,442 | 382,500 |
| Alice, wait for Bob's offer | 6.551 | 277,359 | 312,708 |
| Alice, verify and authorize both registrations | 1.677 | 291,962 | 340,608 |
| Bob, complete companion wallet | 9.999 | 725,740 | 768,712 |
| Bob, replay and prepare released leg | 6.550 | 725,740 | 768,712 |
| Bob, wait for Alice's authorization | 1.711 | 274,852 | 312,848 |
| Bob, verify and authorize both registrations | 1.706 | 294,655 | 340,812 |

The two complete durations overlap. Each includes approximately 0.032 seconds of teardown. The candidate frontend/prover interval is a subset of Alice's preparation and includes baseline services resident during proving. Its native prover alone took 27.64 seconds at 64,904 KiB peak RSS and emitted 238,376 proof bytes. The 238,120-byte public proof in the first run stays the decision artifact. Either interval can be independently measured by running the command above. `SOURCE.json` records per-interval sample counts and actual observation gaps.
