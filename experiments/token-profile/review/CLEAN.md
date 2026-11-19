# Independent TKN1 reproduction

**The new profile passed conservation, one- and two-real-input spends, receipt recovery and wrong-profile rejection on four fresh transfers.** The reviewer did not implement TKN1, its driver or the parameter checker. The reviewer authored the separate privacy comparison. The clean source came from the public HTTPS repository, detached at `ee0da6c9ade4c4342203e63cb274e19efa6df5e9` on `review/token-spend-profile-2026-11-20`. The full command used an empty work directory, a new native target, Rust 1.93.0, the existing dependency download cache and two Rayon threads. The source stayed clean, and the remote ref matched after the run. [Machine-readable readback and public file hashes](CLEAN.json)

| Height | Sender → recipient | Native / token paid | Native / token change | Real inputs | Complete packet SHA-256 |
|---|---|---:|---:|---:|---|
| 1 | A → C | 0 / 40 | 197 / 80 | 2 | `f32f054795970c5e2412f2f712d24470022969012c2b17141b78ccf6eeda5fa6` |
| 2 | B → C | 70 / 65 | 127 / 55 | 2 | `c11835b8b23d156f41895529fa685f2bff4c514f019421dbe4eb87a3c56c2c3e` |
| 3 | Restored C → D | 41 / 75 | 26 / 30 | 2 | `01373e774a68c46c1bc789cdad2fede5fb29af7956fc0bc2a11ea3f527d0ad97` |
| 4 | Restored D → B | 12 / 14 | 26 / 61 | 1 | `45d70f207658b1849dd3d5f81cf57498685e8e6b8cca856f4d2403fa0b423873` |

C and D were offline at payment and reopened in separate directories with only their individual seed file. C combined a zero-native token note and a funded native/token note. D paid using its only note and a zero-value dummy. The successful independent full run also exercised a local private-opening mismatch. The scanner skipped that receipt and recovered the subsequent valid one at the same public root. An additional inconsistent token output was refused by the prover. Both source-approved public verifiers accepted their own packets and refused the other proof after reframing. Sender, receiver, amount, real input count and change in the table are deliberately disclosed synthetic wallet observations. The public oracle consumes genesis and sealed blocks and independently verifies authorization, state and fees. [Fresh receipt and admission records](CLEAN.json) · [Source for recovery and controls](../candidate/campaign.py)

**Independently checked public history.** The oracle derived the four founding commitments from their public context, spend identifier and both amounts using separately built, unmodified upstream primitives. It revalidated every nonce seal, the previous seal's inclusion in the next state digest, each full tree root and header anchor, each native proof and PI/receipt digest, ordered commitments, spent identifiers and native fees. The independently predicted proof length was 139,594 B. The 9 B frame and two 1,792 B receipts produce 143,187 B. All four sealed blocks were 143,371 B, or 573,972 B including the 488 B genesis. The H4 root was `38ea0eb37967fc91f78d211c5c3bc853c247dbd4c9bd8fb43adca292d84018f1`, with 12 funded commitments, eight spent identifiers and 12 native units in the fee sink. The four wallets' disclosed end balances totaled 388 native and 240 token against the authorized 400 / 240 issuance. The older committed four-block corpus produced its distinct approved H4 root with the same verifier and fee total. The reference DLF1/D8C1 parameter JSON and separate public privacy observations also reproduced. [Public history oracle](audit.py) · [Genesis primitive checker](genesis.rs) · [Source and parameter checks](../parameters.py)

The full driver took 2 min 10.81 s. Four successful proofs averaged 6.973 native CPU-s and 3.549 native wall-s, with a maximum process high-water RSS of 452,304 KiB. Lazy wallet setup averaged a further 2.398 CPU-s. After a 2.440 CPU-s verifier setup, mean native verification was 6.315 ms CPU per successful packet. Verifier lifetime high-water RSS reached 201,084 KiB including setup. This is a finite local experiment with a pinned founding schedule, a linear sealed history, two fixed asset lanes and a native fee sink. It establishes neither general token issuance, offline data availability, multi-peer fork choice nor a quantified privacy or post-quantum security level.

## Reproduce

Use a release checkout containing this review as `review`. The separate source checkout below fixes the independently executed candidate. The first command under Python fetches the pinned dependency source and prepares the locked Cargo download cache. Install rustup toolchain 1.93.0 and the [project prerequisites](../../delayed-eight/README.md) first.

~~~sh
review="$PWD/experiments/token-profile/review"
lab=$(mktemp -d)
git clone --branch review/token-spend-profile-2026-11-20 --depth 1 https://github.com/jouliene/pq-private-chain.git "$lab/source"
git -C "$lab/source" checkout --detach ee0da6c9ade4c4342203e63cb274e19efa6df5e9
cd "$lab/source"
RAYON_NUM_THREADS=2 python3 -IB experiments/token-profile/reproduce.py "$lab/work"
python3 -IB "$review/build.py" "$lab/source" "$lab/work/direct/upstream" "$lab/public-helpers"
~~~

For the published non-author corpus, place the allowlisted release objects under `$lab/released/fresh-payments`. The reviewer's actual public directory was `/tmp/pq-token-public-bsvFigqi/work/fresh-payments`. It contained `genesis.bin`, four numbered block files and `RESULT.json`. The independently confirmed genesis SHA-256 is `6dec606f2aceff5a8dd5c77d548995923f6637be4206ec6639b64ad8e2b64ce2`. The independent oracle opens only the founding record and numbered block files from this evidence directory. The operator provides the approval digest separately.

~~~sh
mkdir -p "$lab/released"
curl -fLsS https://github.com/jouliene/pq-private-chain/releases/download/token-spend-profile-2026-11-20/independent-public.tar.gz -o "$lab/released/public.tar.gz"
(cd "$lab/released" && echo 'c837eb82429efe75fbd951c423c9765a126dee3f3ad3be622d84d5ba3cf362ff  public.tar.gz' | sha256sum -c - && tar xzf public.tar.gz)
python3 -IB "$review/audit.py" "$lab/source" "$lab/work/token" "$lab/public-helpers" \
  "$lab/released/fresh-payments" --genesis 6dec606f2aceff5a8dd5c77d548995923f6637be4206ec6639b64ad8e2b64ce2
~~~

A new run generates different founding keys and PoW seals. For the operator's own freshly authorized inventory, substitute its independently accepted genesis digest and `$lab/work/fresh-payments`. The helper builder checks upstream commit `f04c91307837c0231668383bec76ba98d89d2652`, the Cargo lock digest and the unmodified Git tree. It compiles the two Rust helpers in a distinct offline target. [Helper build command](build.py)
