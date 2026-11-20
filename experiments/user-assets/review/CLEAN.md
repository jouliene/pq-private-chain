# Independent AST1 reproduction

The non-author fetched public candidate `a4939423ea0abe2b22e12339bd80f4134d16a267` by anonymous HTTPS and ran the ordinary walkthrough in a detached clean checkout. The source stayed clean. A new upstream checkout and Cargo target rebuilt the native verifier and its registered key byte-for-byte. A new private home created fresh issuers, miners, wallets and PoW history. Each run used two distinct issuer spend keys. All four public spend keys across the author and independent runs differed. [Machine results](CLEAN.json)

| Independently checked quantity | Fresh run | Author capture replay |
|---|---:|---:|
| Common, losing, heavier and final heights | 43, 56, 59, 104 | 49, 64, 66, 106 |
| Full public blocks / distinct complete packets | 117 / 14 | 121 / 14 |
| Positive native proof verifications across block and packet files | 28 | 28 |
| Selected payments / spent nullifiers / public fees | 12 / 24 / 36 | 12 / 24 / 36 |
| Gross miner credits / net native issuance | 10,436 / 10,400 | 10,636 / 10,600 |
| Native credits removed with losing suffix, including its six fees | 1,306 | 1,506 |
| Final registered A / B supply | 180 / 260 | 180 / 260 |
| Peer databases matching the winning state | 4 | 4 |
| Privately recognized selected outputs / real inputs checked | 24 / 16 | 24 / 16 |

The independent reader recomputed the PoW graph, network, zero-allocation genesis, branch anchor eligibility, fixed fees, registry origins, nullifiers, state commitments, funded-tree roots and every native-only reward opening. A fresh native verifier with its approved executable and a mount containing only the registered public key verified each packet occurrence. Four node databases in each run matched the selected public commitment positions, ordered ciphertexts, rewards, spent heights, transactions, header, fees and registry.

The losing suffix contained B's original issuance and a payment of 60 B. Both disappeared on the heavier branch. A's registration and its original issuance transaction stayed unchanged. The B issuer recovered the unspent native funding and successfully issued the same B identifier on the new branch under a different proof, with the same first nullifier. Each selected history contained at most one B issuance. The live cold peer D reported genesis, the losing tip, the heavier tip and the final tip at sample indices 0, 5, 8 and 54. A separate empty database then replayed only the 104 winning blocks through production `Chain.accept`. Its verifier accepted 12 payments and it reached the same tip, spend set, two registry entries and fees.

The 32-byte backup restored 40 native, 70 A and 60 B after B's winning payment had arrived. The original cold-address wallet had no cursor database. The restored wallet paid 9 native plus 45 A, then 6 native plus 34 B. Its final inventory was 19 native, 25 A and 26 B. Both recipients spent onward. For every selected transaction, a separate local check matched the participants' recognized output commitments and real input nullifiers against the accepted proof effects. It checked the payment/change allocations, exact denominations and input categories in both private homes. Only aggregate counts leave this check. Participant-reported directions and amounts in the published capture are intentional disclosures. Public verification alone cannot identify the owners or amounts of an ordinary transfer.

The clean losing node refused the second submission of its B issuance and left its pool and selected status unchanged. The funded A recipient's ordinary request to spend B failed at wallet selection. The independently rerun constraint controls rejected an A-to-B output relabel, a one-unit inflation, a token-funded issue, a dummy first issuing input, and an out-of-range cap. A normal A transfer and the maximum 62-bit issuance verified. Separately, changing the public issuance ID, cap, proof or receipt on one real issuance and one real ordinary packet gave eight fresh verifier refusals per capture.

## Double change and costs

Both restored payments used two real inputs, one of the selected asset and one separately funded native-only note. Each proof authenticated two outputs. One paid the recipient in both lanes and the other returned both changes. Under a single-asset-per-note design these same positive amounts require four outputs, totalling 7,168 receipt bytes if the receipt size stays at 1,792 bytes per output. This is a structural lower bound. The measured prover and verifier below implement AST1.

| Fresh mixed payment | A | B |
|---|---:|---:|
| Native / token change | 11 / 25 | 8 / 26 |
| Complete packet / proof / receipts / framing, bytes | 143,227 / 139,634 / 3,584 / 9 | 143,227 / 139,634 / 3,584 / 9 |
| Wallet call including setup, wall / CPU seconds | 5.243 / 10.12 | 5.019 / 9.73 |
| Native proving after setup, wall / CPU seconds | 3.864 / 7.556 | 3.726 / 7.314 |
| Wallet native role peak RSS, KiB | 451,740 | 451,680 |
| Fresh verifier setup wall seconds / role peak RSS KiB | 1.282 / 201,236 | 1.282 / 200,976 |
| Warm verification median CPU milliseconds, 3 calls | 6.196 | 6.212 |

Independent native roles ran with two Rayon threads on an Intel Core i7-8700K. GNU time around a new build plus the entire walkthrough and observer reported 283.86 wall seconds, 164.31 user seconds, 11.36 system seconds and 405,688 KiB maximum RSS. That process-tree accounting differs from individual native-role peak measurements and does not give aggregate simultaneous memory. The packet leaves out its four-byte length prefix inside a block. These two samples do not characterize live public network throughput, eclipse resistance, or hostile PoW finality. Full cryptographic privacy and quantum knowledge bounds remain conditional on the registered proof, hash and receipt composition. The honest sender's blinded proof binds the receipt bytes; proof verification alone cannot guarantee a malicious sender supplied recoverable ciphertext.

## Reproduce

Use Linux x86-64 with working unprivileged bubblewrap, a C toolchain, Git, Python 3 and Rust 1.93.0. The clean run used a new release target, a fresh public upstream checkout at `f04c91307837c0231668383bec76ba98d89d2652` and the normal Cargo dependency download cache. If the pinned compiler lives in a separate rustup installation, point `RUSTUP_HOME` at it. Start in the checkout containing this report. The final straight-line reader is a review-only addition and uses the production implementation built from the pinned candidate.

```sh
auditor="$PWD/experiments/user-assets/review"
work=$(mktemp -d)
git init -q "$work/source"
git -C "$work/source" fetch --depth=1 https://github.com/jouliene/pq-private-chain.git a4939423ea0abe2b22e12339bd80f4134d16a267
git -C "$work/source" checkout -q --detach FETCH_HEAD
cd "$work/source"
export RAYON_NUM_THREADS=2
python3 -IB experiments/user-assets/review/observe.py "$work/home" "$work/peers.json"
set -- "$work/home"/source-build-*/build
build=$1
python3 -IB experiments/user-assets/review/build_helpers.py "$build/upstream" "$work/helpers"
node="$work/home/deployment"
native_pin=$(cat "$node/devnet/approved-native.sha256")
vk_pin=99ed868d5bd0f8541bb6467a210bf75140ec696e49e53044f7bca011ed59438a
"$node/runtime/native" check-relation "$node/keys" > "$work/relation.json"
cmp "$work/relation.json" experiments/user-assets/native/CHECK.json
python3 -IB experiments/user-assets/measure.py --public "$work/home/public" --binary "$node/runtime/native" \
  --approve-binary "$native_pin" --keys "$node/keys" > "$work/measure.json"
set --
for n in a b c d; do set -- "$@" --db "$work/home/nodes/$n/chain.sqlite"; done
python3 -IB "$auditor/public_replay.py" --public "$work/home/public" --binary "$node/runtime/native" \
  --approve-binary "$native_pin" --vk "$node/keys/asset.vk" --approve-vk "$vk_pin" \
  --helpers "$work/helpers" --observations "$work/peers.json" "$@" > "$work/clean-replay.json"
python3 -IB "$auditor/private_counts.py" "$work/home" "$work/clean-replay.json"
python3 -IB "$auditor/winning_replay.py" "$node" "$work/home/public" "$work/clean-replay.json" "$work/new-db"
git status --porcelain
```

The allowlisted release asset `AST1-PoW-clean-public.tar.gz` has 139 regular files, 4,041,857 bytes and SHA-256 `2809763f2658f85f988eaf866c624680b9476a14d0a824237248b4ec493fc2bb`. After checking its digest, extract it into a new directory and run `sha256sum -c SHA256SUMS` there. Its `public/` and `review/peers.json` can replace the corresponding replay arguments. Omit the four database options when using only public artifacts. The public proof replay and the straight-line production node replay use no wallet files. The optional private row check requires an actual locally generated home.
