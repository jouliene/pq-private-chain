# Independent managed-supply reproduction

The reviewer fetched public candidate `79b7ff184de560c7112b21d6359c0ce9ada9f7c0` via anonymous HTTPS in a clean detached checkout. The ordinary walkthrough built original AST1 and upgraded MNG1 in separate new Cargo targets against separate fresh copies of upstream `f04c91307837c0231668383bec76ba98d89d2652`. Each build produced the same registered key and executable bytes as the corresponding author build. The two trials used different newly created managed-issuer public keys. The source and both upstream checkouts remained clean. The subsequent operator guard for an already active home is outside this cold candidate run. [Machine results](CLEAN.json)

| Verified result | Independent trial | Replay of author trial |
|---|---:|---:|
| Original funded AST1 prefix height | 5 | 5 |
| Common, losing, heavier, final heights | 47, 57, 64, 70 | 46, 56, 58, 64 |
| Retained PoW blocks / distinct included packets | 80 / 9 | 74 / 9 |
| Selected payments / fees / spent nullifiers | 8 / 24 / 16 | 8 / 24 / 16 |
| Gross selected miner credits / net native issuance | 7,024 / 7,000 | 6,424 / 6,400 |
| Final fixed supply / managed outstanding | 17 / 1,100 | 17 / 1,100 |
| Peer databases / private final wallet inventories checked | 4 / 7 | 4 / 7 |

**Supply and authorization.** The original AST1 CLI created 17 fixed units from a mined reward. A local participant check matched the actual 17-unit funded output commitment to the original packet and its nullifier to a new MSP1 spend paying 5 units after the upgrade. Both versions used the original network and genesis. The managed issuer registered 1,000 units and authorized 300 additional units using a different native funding nullifier. The independent reader rebuilt each branch's event sequence, outstanding balance, issuer key, prior transaction and revision. It verified every PoW seal, eligibility anchor, ordered ciphertext digest, funded-tree root, state commitment and native reward opening. The selected asset-event rows, commitments, ciphertexts, spent sets, fees and headers matched all four databases in both trials.

For each capture, the mounted public roles made 20 MNG1 proof checks and two checks with the separately built original AST1 verifier. These include both block and packet copies and the four recorded state-policy controls. The Rust provider checked seven valid SLH-DSA-SHAKE-128f signatures, including occurrences belonging to rejected ledger candidates. Independently reconstructed 32-byte authorization messages verified under Node 24.22.1 / OpenSSL 3.5.9. For both registration and mint, thirteen single-field changes failed independently. These covered the signature, prior event, sequence, network, authority, operation, inner proof, both output commitments, both encrypted receipts, asset ID and quantity. The original proof remained valid for the stale mint, unregistered authority, fixed-policy mint and duplicate burn. The branch evidence identified the respective state-level reasons for rejection. Thirteen native constraint controls separately covered positive and maximum quantities, private burns, wrong tag, insufficient ownership and supply bounds. [Independent message reader](events.py) · [Alternative signature provider](verify_slh.mjs)

**Private return and payout.** The offline seed restored 12 native and 400 managed units. Its new transaction returned 200 units and 3 native to the treasury. On each of the two tested branches the treasury spent that same incoming note and paid exactly 3 native for its burn. In each disposable lab we privately matched the receiver-recognized output commitment to the returned packet and its nullifier to the first input of both accepted burns. No other token-bearing input contributed. Public proof verification alone cannot identify which private receipt was redeemed. The final wallet aggregates showed 900 managed units at the treasury and 200 at the recovered wallet.

| Independent simulated settlement | Selected burn confirmations | Managed outstanding | Mock cash paid | Currently uncovered |
|---|---:|---:|---:|---:|
| Return enrolled | 0 | 1,300 | 0 | 0 |
| Burn included | 1 | 1,100 | 0 | 0 |
| Bank paid, local coordinator exited before acknowledgment | 3 | 1,100 | 200 | 0 |
| Heavier branch selected | 0 | 1,300 | 200 | 200 |
| Replacement burn confirmed | 3 or more | 1,100 | 200 | 0 |

The independent process sampled the two live SQLite stores. It observed the committed 200-unit bank payment while the coordinator still had no acknowledgment, followed by the recorded acknowledgment. The recovered coordinator and separately persisted bank retained one request, two burn attempts and exactly one payment for 200 after replay. Both attempts referenced actual archived blocks. The stable bank receipt matched the coordinator and business terms. A separate deterministic service check exercised concurrent SQLite writers and a process exit between the two commits. Three inclusive confirmations are the experiment's payout rule. Zero uncovered amount describes selected-chain burn coverage at the read head. The bank simulation exercises no external fiat rail, capital reserve or irreversible consensus finality. [Public monetary and payout checks](payout.py) · [Private aggregate check](check_return.py)

The independently sampled cold peer reported genesis and the H70 final tip. A fifth empty database accepted the 70 winning blocks through production admission, starting with zero native and no registered asset. Its verifier made ten public calls for eight proofs and two signatures. It reached the same final registry and tip as the four peers. The RPC observer and public oracle checked that spending fees enter miner credits once. Issuer authority is economically trusted to create new managed units. Ordinary transfers hide amounts and tags under the inherited circuit/receipt assumptions. Registration, mint and burn expose their tag and quantity. The finite runs establish neither a whole-system quantum knowledge bound nor public-network anonymity.

## Measured costs

Each packet contained a 139,634-byte proof, 3,584 bytes of encrypted receipts and 9 bytes of inner framing. Native-only or ordinary managed transfers and burns add a six-byte outer header. Registration and mint also carry 17,160 bytes of issuer state and signature. Each enclosing block adds a four-byte length. The following are clean-run whole wallet-call wall times and warm median public verification wall times from three measured calls after warm-up. The JSON includes verifier setup, per-role CPU and peak RSS. [Complete measurements](CLEAN.json)

| Actual operation | Complete bytes | Wallet wall seconds | Wallet peak KiB | Public verification ms |
|---|---:|---:|---:|---:|
| Original AST1 fixed issuance | 143,227 | 4.742 | 451,928 | 6.426 |
| Upgraded payment of original asset | 143,233 | 4.889 | 452,192 | 6.664 |
| Managed registration | 160,393 | 5.088 | 451,804 | 11.814 |
| Authorized mint | 160,393 | 5.009 | 451,928 | 11.831 |
| Private delivery | 143,233 | 4.917 | 451,940 | 6.741 |
| Private return | 143,233 | 5.066 | 452,056 | 6.721 |
| Original burn | 143,233 | 4.853 | 451,932 | 6.695 |
| Confirmed replacement burn | 143,233 | 5.038 | 451,736 | 6.871 |

GNU time around both fresh builds plus the whole observed walkthrough recorded 330.18 wall seconds, 294.96 user seconds, 18.95 system seconds and 405,320 KiB maximum RSS on an Intel Core i7-8700K. Rust 1.93.0 and two Rayon threads were used. This observer-process accounting differs from native-role high-water marks and does not measure aggregate simultaneous memory.

## Reproduction and public artifacts

Use Linux x86-64, Git, Python 3, a C toolchain, functioning unprivileged bubblewrap, and a pinned Rust 1.93.0 toolchain. The alternative signature check additionally uses the Node 24.22.1 installation in the repository's [build guide](../../../BUILD.md). Start in the checkout containing this report. Supply the path to that Node executable; the audit checks the Node and OpenSSL versions. No external signature-verification service is used.

~~~sh
audit="$PWD/experiments/managed-assets/review"
node24="$PWD/.tools/node-v24.22.1-linux-x64/bin/node"
work=$(mktemp -d)
git init -q "$work/source"
git -C "$work/source" fetch --depth=1 https://github.com/jouliene/pq-private-chain.git 79b7ff184de560c7112b21d6359c0ce9ada9f7c0
git -C "$work/source" checkout -q --detach FETCH_HEAD
cd "$work/source"
export RAYON_NUM_THREADS=2
python3 -IB experiments/managed-assets/review/observe.py "$work/home" "$work/peers.json"
set -- "$work/home"/source-build-*/build
build=$1
node="$work/home/deployment"
old="$work/home/legacy/deployment"
pin=$(cat "$node/devnet/approved-native.sha256")
old_pin=$(cat "$old/devnet/approved-native.sha256")
vk=1895505caa69ce3cf55adcde8ce2e60c03ac0d7d4d8551888d71a8176e8b946d
python3 -IB experiments/user-assets/review/build_helpers.py "$build/upstream" "$work/helpers"
"$node/runtime/native" check-relation "$node/keys" > "$work/relation.json"
cmp "$work/relation.json" experiments/managed-assets/native/CHECK.json
python3 -IB experiments/managed-assets/native/check_issuer.py "$build/roles" > "$work/issuer.json"
cmp "$work/issuer.json" experiments/managed-assets/native/ISSUER.json
python3 -IB experiments/managed-assets/wallet/check.py
python3 -IB experiments/managed-assets/check_redeem_service.py
python3 -IB experiments/managed-assets/measure.py "$node" "$work/home/public"
set --
for n in a b c d; do set -- "$@" --db "$work/home/nodes/$n/chain.sqlite"; done
python3 -IB "$audit/chain_audit.py" --public "$work/home/public" --binary "$node/runtime/native" --approve-binary "$pin" \
  --vk "$node/keys/managed.vk" --approve-vk "$vk" --legacy-binary "$old/runtime/native" --legacy-vk "$old/keys/asset.vk" \
  --approve-legacy-binary "$old_pin" --helpers "$work/helpers" --node "$node24" --observations "$work/peers.json" "$@" > "$work/clean-replay.json"
python3 -IB "$audit/check_return.py" "$work/home" "$work/clean-replay.json"
python3 -IB "$audit/winner_only.py" "$node" "$work/home/public" "$work/clean-replay.json" "$work/winner-only"
git status --porcelain
~~~

The reviewed `MNG1-redemption-clean-public.tar.gz` contains 103 regular files totalling 3,300,832 compressed bytes. SHA-256 is `58060f2e8cbaf5fb8ac5a3585d26f674d9fb7c0785bcef9186aa0cc6c8fbe3e5`. Verify the archive digest, extract it into an empty directory, then run `sha256sum -c SHA256SUMS` there. The archived `public/` contains complete blocks, packet bodies, rejection controls and intentionally disclosed participant results. `review/peers.json` carries read-only samples. Use these two paths in the public replay and omit the four database options. The optional private check requires a locally generated disposable home. [Versioned release](https://github.com/jouliene/pq-private-chain/releases/tag/managed-supply-redemption-2026-11-20)
