# Independent live-token reproduction

A fresh HTTPS checkout of `c78053fabf7e9944a27921a348cad6c3804284bd` built the registered TKN1 executable, mined on two loopback peers, recovered two offline recipients and settled five payments on the selected H44 chain. A separate public replay verified six distinct full TKN1 authorizations and all 50 captured PoW blocks across the selected and detached histories. The reviewer authored the public oracle and observer, and had no part in the wallet, chain, comparison prover or walkthrough implementation. [Recorded identities, amounts, timings and packet hashes](CLEAN.json)

The first cold HTTPS attempt at `3041fe96fc5b7a732cef82480e37daa7c50d6e82` stopped after 3.05 seconds. The pristine pinned Qnero tree lacks the intermediate `crates/qnero-prover/examples` directory. Creation of `examples/token_pair` therefore failed before any proof or enrollment. The corrected build creates the intermediate directory in its disposable source copy. The second run used another new HTTPS clone, home, build target and upstream fetch. Source remained clean after execution. Cargo registry caching and an already installed rustc 1.93.0 were available on the Linux host.

## What the four peers selected

| Observation | Independent readback |
|---|---|
| Funding | The locally approved 216-byte genesis pinned one 240-token founding note and zero native. Native rewards began at H1. Full upstream note and tree arithmetic matched the founding commitment, every reward commitment and every funded root. |
| Offline payment | The sender used the recipient's exported public address. The seed-restored recipient wallet reported 0 native and 70 token. A different miner funded a native-only payment of 23 from a 100-native reward. The recipient spent both notes for 9 native and 45 token, paying 3 native with 11 native and 25 token change. A second restored recipient paid onward 4 native and 13 token. These amounts and input categories depend on deliberate participant disclosures. |
| Branch switch | Common H31 retained four payments and 12 units of fees. The H37 losing tip included the first invoice attempt, with 15 cumulative fees. Its isolated miner had six distinct reward commitments worth 603 native and zero token. H41 won with 12 fees. Every losing-suffix reward commitment was absent there, the losing miner balance went to zero, and its ordinary outbound command refused for insufficient selected funds. |
| Retry and duplicate | The two verified invoice packets at H32 and H41 shared their first nullifier, had different anchors, different outputs and different receipt digests. At the next winning admission the first anchor was on a detached branch and had age ten, outside the eight-block window. The receiving peer acknowledged a duplicate of the same pending bytes. The reviewer sampled that pending packet ID on all four public TCP peers. Only the replacement appears on the final selected chain. |
| Cold peer and persistence | An independent read-only TCP sampler observed node D at genesis, H37 losing tip, H41 winning tip and H44 final tip in order. It observed two distinct node A process lifetimes. The frozen deployment and authorized genesis were shared locally. Each node had a separate database. After shutdown all four selected height/ID sequences, funded rows including ordered ciphertext bytes and rewards, nullifier heights, payment locations, header, anchor and work matched the independently computed values. |
| H44 accounting | Gross miner credits 4,415, including 15 native transfer fees. Net native issuance 4,400, token issuance 240, 55 funded rows, ten spent nullifiers, five selected payments. The selected funded root was `af766a66ff16307de53528b8c654450ea32260a17bedaafe1a7b2974d82848ec`. All eight final disclosed wallet inventories reconciled. |

The observer uses public status and pending requests. The duplicate ACK and the failed post-reorg wallet command are observations of the walkthrough process. The public proofs, ordered receipts, deadline and ancestry, selected incidence and final economic totals have independent checks. Public nullifier equality establishes a linkage between transcripts. The supplied business-intent and sender labels come from the controlled scenario. The refused orphan-only wallet command produced no payment proof.

## Stronger comparison and costs

The reviewer rebuilt the separate TKQ1 executable after the live trial, reusing the cold run's Cargo dependency target, and regenerated its byte-identical verification key. A wallet-free verifier accepted the published genuine TKQ1 specimen and the baseline verifier accepted its TKN1 positive control. Both mismatched combinations failed when retagged for the receiving parser. The serialized proof shapes also differ, so these observations establish complete-profile incompatibility. The independent reader traversed 640 opaque Keccak authentication paths across 64 queries, observed 192 distinct nonzero salt tuples and recomputed the ordered two-ciphertext digest. The proof was 379,440 bytes, or 383,033 bytes with framing and receipts, exceeding the live ceiling by 120,889 bytes.

The six captured live TKN1 payments were 143,187 bytes each. Their wallet-reported proving-call wall times ranged from 4.982 to 5.074 seconds. GNU time around the cold build plus entire observed walkthrough reported 186.13 seconds wall, 228.07 seconds user, 11.02 seconds system and a 405,096 KiB maximum RSS. This last counter is a process high-water statistic and excludes simultaneous resident memory aggregation. TKQ1 verifier setup took 3.320 CPU seconds, followed by 7.208 ms of warm proof verification, with a 668,436 KiB process high-water mark. The TKQ1 payment was generated in the separate comparison experiment. The non-author replayed that identical public payment and did not run a new TKQ1 private prover.

A six-codeword bound at *at least* one-quarter agreement gives no upper bound of one quarter on every listed word's agreement. The 125.415-bit union exponent additionally assumes at most six fixed bad sets, each having mass at most roughly one quarter, and modeled independent draws. An end-to-end FRI/Fiat–Shamir or quantum knowledge/privacy reduction remains open. These finite local results also leave network throughput, confirmation security under hostile peers, long-term erasure, multi-token issuance, and cross-owner swaps open.

## Reproduction

The operator prerequisites are Linux with working unprivileged bubblewrap isolation, Git, a Rust 1.93.0 toolchain, a C build toolchain and Python. This invocation wraps the same `./pqd token --home ... walkthrough` in the independent read-only observer. Use a new directory. Ordinary unobserved operation can invoke that CLI directly. Start these commands in the checkout containing this report to use its expanded pending/settled observer checks on a newly generated history.

```sh
auditor="$PWD/experiments/token-devnet/review"
work=$(mktemp -d)
git -C "$work" init -q source
git -C "$work/source" fetch --depth=1 https://github.com/jouliene/pq-private-chain.git c78053fabf7e9944a27921a348cad6c3804284bd
git -C "$work/source" checkout -q --detach FETCH_HEAD
cd "$work/source"
export RAYON_NUM_THREADS=2
python3 -IB experiments/token-devnet/review/observe.py "$work/home" "$work/peers.json"

set -- "$work/home"/source-build-*/build
build=$1
python3 -IB experiments/token-profile/review/build.py . "$build/upstream" "$work/helpers"
node="$work/home/deployment"
native_pin=$(cat "$node/devnet/approved-native.sha256")
genesis_pin=$(cat "$node/devnet/approved-genesis.sha256")
python3 -IB "$auditor/network.py" --public "$work/home/public" \
  --genesis-sha "$genesis_pin" --binary "$node/runtime/native" --binary-sha "$native_pin" \
  --keys "$node/keys" --helpers "$work/helpers" --observations "$work/peers.json" \
  --db "$work/home/nodes/a/chain.sqlite" --db "$work/home/nodes/b/chain.sqlite" \
  --db "$work/home/nodes/c/chain.sqlite" --db "$work/home/nodes/d/chain.sqlite"
python3 -IB experiments/token-devnet/money/reconcile.py "$work/home/public" --approve-genesis "$genesis_pin"

cmpdir=experiments/token-devnet/comparison
python3 -IB "$cmpdir/build.py" "$work/tkq" "$build/upstream" "$build/target"
"$work/tkq/native" register "$work/tkq/registered"
cmp "$work/tkq/registered/token.vk" "$cmpdir/evidence/tkq1.vk"
python3 -IB "$cmpdir/probe.py" "$work/tkq" "$build/roles" "$cmpdir/evidence" --replay
python3 -IB experiments/token-devnet/review/stronger.py "$cmpdir/evidence/tkq1.vk" \
  "$cmpdir/evidence/payment.bin" "$work/helpers/roots"
python3 -IB "$cmpdir/bounds.py" | cmp - "$cmpdir/evidence/BOUNDS.json"
git status --porcelain
```

The public release object `TKN1-PoW-clean-public.tar.gz` contains the 50 raw blocks, six raw packets, founding record, intentional scenario disclosures, public peer observations and public check outputs. SHA-256 is `e9c8e3c21d38af756ceb430572bcce829f874f2d07b649d68183d0e48d3debf1`, length 1,727,003 bytes. The reproducibility bundle has 66 regular files and an internal SHA-256 manifest. After verifying the archive digest, extract to an empty directory, run `sha256sum -c SHA256SUMS` there, and pass its `public/` and `cold-peer-observations.json` to the same public replay. Pin the recorded genesis `49c9784951723bb725028193c5c6a43c0f964f497a9403dc824169b720ea24f7` and omit all four optional database arguments. A locally rebuilt verifier with the registered key and its own local executable approval suffices. The reviewer performed this public-only replay with fresh upstream primitive helpers and a wallet-free verifier, then compared the four databases separately. A review-only extension distinguishes pending and settled IDs if an extra renewal occurs after the duplicate probe. In this capture those IDs were identical.
