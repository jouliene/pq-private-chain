# Independent SWP1 live reproduction

A reviewer outside the implementation team fetched public candidate `7cb00ba285193213d7c18996d5b6a95bc83822f6` anonymously into an empty checkout. Both native executables and verifier registrations were rebuilt from pinned Qnero `f04c91307837c0231668383bec76ba98d89d2652`, starting with an empty Cargo target. The run used independent seeds, new issuers, newly mined funds and two independent signing wallets. The public reader also checked a separate author capture. Each capture contains 38 PoW blocks over three branches. The independent winning tip was `000000283478d2bb1fc52d54563196f8ffbcf735000a5cc73fb78723a4b67d48`. [Machine results and build hashes](CLEAN.json)

## Authorization and settlement

Both wallets authorized the same 320,905-byte submission. The reviewer independently decoded each SLG1 proof's 34 public inputs, reproduced its ordered ciphertext digest and checked the registered verifier's complete effects in a public-only process. Node 24.22.1 with OpenSSL 3.5.9 validated both final SLH-DSA signatures and both historical issuer signatures. The separate provider rejected 50 alterations of the joint authorization. The historical role rejected each extracted leg and both AST1 and MNG1 retaggings. Changing a receipt or its proof-bound public key also failed. The original wallet interface rejected an otherwise valid proof for a delivery of 29 instead of 30. [Review registration](REGISTER.md)

Private checks matched both stored final authorizations to the exact published signatures and reconstructed the blinded agreement from the two local receiving addresses and the selected asset IDs. The public archive contains neither the private salt nor either full address. The two separate restored wallets spent the exact incoming commitments, each using an additional native-only input for the onward fee. The fixed output positions identify counterparty payment and change on the wire. The synthetic amounts below come from local disclosure and wallet reconciliation.

| Selected state | Height | Alice (native / fixed / managed) | Bob (native / fixed / managed) | Aggregate fees |
| --- | ---: | ---: | ---: | ---: |
| Common funded state | 16 | 29 / 15 / 0 | 27 / 0 / 80 | 27 |
| Swap included | 17 | 26 / 8 / 30 | 27 / 7 / 50 | 30 |
| Heavier ordinary conflict | 23 | 29 / 15 / 0 | 24 / 0 / 75 | 30 |
| Swap branch selected again | 25 | 26 / 8 / 30 | 27 / 7 / 50 | 30 |
| Both onward payments included | 27 | 23 / 8 / 0 | 24 / 0 / 50 | 36 |

Alice's swap leg consumed one funded note and returned 17 native plus 8 fixed units as change. Bob's leg returned 18 native plus 50 managed units. On the conflicting branch Bob's ordinary recipient held 5 managed units. On the winning branch the onward recipient held 7 fixed and 30 managed units. Asset supplies stayed at 70 fixed and 330 managed. Twelve winning logical payments consumed 13 physical slots over the height-27 history. The winning branch issued 2,700 native units and credited miners 2,736, including fees. Four public peers reached the independently reconstructed tip. A separate validator replayed just the winning history from the empty genesis.

The cut-off for inclusion was height 20. With the same unspent funds, a valid pair could form a production candidate at height 20 and failed at height 21. An ordinary spend conflicting with the second leg failed against the queued pair. Submitting the pair behind the queued ordinary spend also failed, preserving the pool and balances. Three distinct valid ordinary proposals behind the common funding history filled the first three physical slots. The scheduler deferred the entire pair. With those ordinary proposals removed it selected both frames. These capacity checks constructed candidates without mining additional invalid blocks.

## Measured costs

| Cold-run operation | Complete bytes | Wall time | CPU time | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| Alice's prepared leg, fee 3 | 143,251 | 4.867 s | 9.44 s | 452,116 KiB |
| Bob's prepared leg, fee 0 | 143,251 | 4.893 s | 9.50 s | 451,680 KiB |
| Warm joint verification, five measured pairs | 320,905 | 26.67 ms median | 26.06 ms median | 201,132 KiB |
| Cold verifier lifecycle | 320,905 | 1.344 s | 2.418 s through last verdict | 201,136 KiB at setup |

The RPC request was 320,928 bytes. Two proofs used 279,316 bytes, four ciphertexts 7,168, two signatures 34,176, and the inner, frame and upload headers another 245. Each physical frame occupied 160,446 bytes. The block grew by 320,900 bytes over an empty block and the captured swap-only block measured 321,122 bytes in full. A one-copy sum of the private terms file, both proposals and both signatures was 324,036 bytes. The combined cold build and observed walkthrough took 341.01 seconds on an Intel Core i7-8700K with two Rayon threads. Wallet figures cover the leg-generation call, verifier figures cover both proofs and both signatures. Cold wall time includes teardown. [Measurement method](../native/README.md)

## Reproduction

The final checkout supplies the review scripts. Retain its path as `audit` while fetching the candidate into a new directory. Use the toolchain and Node/OpenSSL provider from the repository build guide. Public replay requires the registered verifier binaries and keys plus the two independent helper binaries. Only the separate wallet-joins check opens local wallet databases.

~~~sh
audit="$PWD/experiments/atomic-swap/review"
node24="$PWD/.tools/node-v24.22.1-linux-x64/bin/node"
work=$(mktemp -d)
git init -q "$work/source"
git -C "$work/source" fetch --depth=1 https://github.com/jouliene/pq-private-chain.git 7cb00ba285193213d7c18996d5b6a95bc83822f6
git -C "$work/source" checkout -q --detach FETCH_HEAD
cd "$work/source"
export RAYON_NUM_THREADS=2
python3 -IB experiments/atomic-swap/review/observe_swap.py "$work/home" "$work/peers.json"
set -- "$work/home"/source-build-*/build
build=$1
home="$work/home"
python3 -IB experiments/user-assets/review/build_helpers.py "$build/upstream" "$work/helpers"
"$build/swap/native" check-relation "$build/swap/registered" > "$work/relation.json"
cmp "$work/relation.json" experiments/atomic-swap/native/CHECK.json
python3 -IB experiments/atomic-swap/native/check_roles.py "$build/swap" "$build/roles" > "$work/roles.json"
cmp "$work/roles.json" experiments/atomic-swap/native/ROLE.json
set --
for n in a b c d; do set -- "$@" --db "$home/nodes/$n/chain.sqlite"; done
python3 -IB "$audit/audit.py" --public "$home/public" --deployment "$home/deployment" --helpers "$work/helpers" --node "$node24" --observations "$work/peers.json" "$@" > "$work/audit.json"
python3 -IB "$audit/wallet_joins.py" "$home" "$work/audit.json"
python3 -IB "$audit/admission.py" "$home/deployment" "$home/public" "$work/audit.json" "$work/fresh-validation"
python3 -IB experiments/atomic-swap/check_admission.py "$home"
python3 -IB experiments/atomic-swap/measure.py "$home/deployment" "$home/public/SWAP.bin" > "$work/measure.json"
python3 -IB "$audit/costs.py" "$home/public" "$work/audit.json" "$work/measure.json"
~~~

The independent release attachment `SWP1-clean-public.tar.gz` has 65 regular files, 5,991,937 compressed bytes, and SHA-256 `5a95bd5c8281c2c8f3f425055951bd4a12cb94db77b04c6509cc63f8950da9ab`. A new extraction passed every checksum. Running the public reader on the extracted blocks, transfers, capacity proposals, negative cases and public observer samples reproduced all public semantic results. It used no local wallet or database arguments. The signer interactions ran under one local Unix account. The cold candidate's walkthrough kept test backups beside the private message files. The subsequent operator change gives each backup a separate private owner directory. Formal proof composition, adversarial public-network anonymity, a confidential transport service and price fairness remain outside these measurements.
