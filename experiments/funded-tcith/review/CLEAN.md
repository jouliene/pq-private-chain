# Independent public reproduction

I cloned the public HTTPS repository into an empty directory using an empty Git home, no credentials, disabled prompts, no system Git configuration, HTTPS as the only transport and no object alternates. The clone advertised `origin/main` at `00918a5eae77bd422cc13750539a823d371ee399`. I detached there and confirmed that `33bc626c66ba6a83e8ee496e8b6f44b7e207333f` is an ancestor. The release tarball matched SHA-256 `49da26ad29c613a3a8d85966e7c1650ca30203337a3e79084cc25f46dc0c19d3`.

I built both released Rust roles from a separate anonymous baseline checkout, a new public Qnero checkout at `f04c91307837c0231668383bec76ba98d89d2652`, a previously empty Cargo home and a new build target. Rust 1.93.0 fetched the pinned registry dependencies and compiled offline. Both newly generated verifier registrations matched the released keys. Together with staging, the two builds took 92.89 s. The source changes from baseline were confined to GOAL.md, STATUS.md, docs/DELIVERY.md and experiments/funded-tcith. This build reused no prior deployed binary, local source tree or project object store.

From the detached tested revision, I ran the following command, providing the newly source-built reference deployment.

~~~sh
bash experiments/funded-tcith/reproduce.sh "$scratch" "$reference/deployment"
~~~

The command completed in 54.91 s. The C++ binary matched SHA-256 `fc8fc51b398c5227c59254ada31c79102e08a564273a2652e90fd81a9832f9a8`. The regenerated circuit matched `77533cc1c383bec78358ae8b304a1151aab834c34656d2edcc167dccdaf1c339`. The two security cost reports and the complete deterministic branch comparison matched the checked-in files. A separate chronological reader based on the earlier reviewed incremental tree reconstructed all 12 public funding blocks, verified the proof-of-work targets and legacy header roots, and derived the auxiliary root `178aa295e318a30998b1e3b25d1622063d1309052b3123ccb3ee890fb998c130` over 22 leaves. The prefix contained ten spent nullifiers.

My independent framing/Merkle reader derived 32 opened party indices, authenticated 387 siblings and checked 9,461 terminal field words. It reproduced the 238,120-byte funded proof and the 259,212-byte candidate frame, with 2,932 bytes remaining. The isolated native verifier rechecked the actual monetary broadcasts using only public inputs. It took 1.42 s and peaked at 22,820 KiB on this run.

The complete mixed/released pair occupied 419,671/320,905 bytes. Comparing their admissions in opposite orders, measured offer wall times were 1.48049/0.02829 s and instrumented CPU was 1.46722/0.02485 s. After the height-14 blocks both branches had 28 notes, 14 spent nullifiers and 18 cumulative fee units. The node recognized identical resubmissions as idempotent and rejected conflicting registrations, orphaned anchors and public proof/receipt/root/signature alterations. The heavier branch restored the ten previously spent nullifiers and 15 cumulative fee units; startup reconstructed all 18 archived wallet records, including the orphan’s, from the public blocks. These checks used public bundles and blocks in a fresh isolated verifier.

## Fresh independent funded proof

I then ran the published wallet entry point using the earlier independently mined disposable funding from the funded-WHIR review. Its height-12 anchor was `000002199e08d8eed9254dc699686679ddf074a1f053e25696db67d652bdc3b5`, distinct from the first archive. Each owner process saw only its own backup. The funded home and released capture executable were from that earlier independent campaign. The FTL1 engine, verifier shape, constants and wallet code came from the newly tested checkout and pinned dependencies. Each owner replayed the chain and received the other side's public offer. The disposable agreement exchanges 20 token units for 8 native units, with 3 native fee units paid by the native payer.

~~~sh
python3 -IB experiments/funded-tcith/wallet/run.py "$prior_funding_home" "$prior_capture" \
    "$scratch/qp-poseidon-core-3.1.0/src/poseidon2.rs" "$scratch/tcith" "$scratch/shape" "$fresh"
python3 -IB experiments/funded-tcith/review/readback.py "$fresh"
~~~

One fresh FTL1 proof occupied 237,800 bytes with 382 Merkle siblings. The signed candidate frame occupied 258,892 bytes. The funded frontend took 1.000 s, and the native prover took 27.37 s wall, 27.34 s user and 0.02 s system CPU with 64,808 KiB peak RSS. The sampled wallet process tree during frontend plus prover reached 458,884 KiB aggregate PSS and 505,532 KiB aggregate RSS over 567 samples. The full owner preparing the candidate and the released reference peaked at 850,893 KiB PSS. The two owners verified the candidate in fresh native processes in 1.41/1.44 s, each with 22,820 KiB peak RSS. Both checked change and the counterparty receipt, rejected incorrect receipt terms and signed both exact registration digests. The coordinator separately verified both registrations and their signatures and compared public effects. The deterministic controls above exercised the first bundle in the public-only node. The second run ended at signed, verified public packets.

The independent public fixture archive measures 1,467,564 bytes. Its SHA-256 is `2ac53dce741c8d116480536be5b3dc8b7d2bee2e7d61f9090ed78b96abded3f4`. I explicitly included SOURCE.json, mixed.swap, released.swap and the 12 mined blocks reached by following the funding tip to genesis. I verified all 15 extracted members against the allowlisted bytes. The source manifest discloses the synthetic asset identifier, quantities, fee payer, public branch information and aggregate measurements. Backup files and private wallet data stayed in the earlier private test environment.

## Public continuous integration

Both automatic workflows succeeded on `00918a5eae77bd422cc13750539a823d371ee399`. They exercise the established payment and PoW/wallet paths. The separate public-clone reproduction above exercised FTL1. [Payment smoke](https://github.com/jouliene/pq-private-chain/actions/runs/44860388115) · [Local PoW devnet](https://github.com/jouliene/pq-private-chain/actions/runs/44860388094) · [API receipt](ACTIONS.json)
