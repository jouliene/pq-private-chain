# Permissionless private user assets

Two users can issue different fixed supplies on a running PoW network and pay from the ordinary wallet. A single registered AST1 verifier handles all issuers, all asset IDs, and native-only payments. The local genesis starts with no assets and no native money. Miners produce only the native currency. A user needs enough spendable native currency for the fee. Issuance requires no operator registration or service restart.

## Run the network

Use x86-64 Linux with Python 3.10+, Git, a C toolchain, rustup, and bubblewrap with usable unprivileged namespaces. The first run fetches the pinned public Qnero source and locked Cargo dependencies.

```sh
git clone https://github.com/jouliene/pq-private-chain.git
cd pq-private-chain
git checkout --detach live-user-assets-2026-11-20
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
./pqd assets --home "$lab/network" walkthrough
```

The command starts two continuous CPU miners and a third validating process. The walkthrough adds a fourth peer with an empty database, records public branches and packets, reads back the wallets' balances, and stops its own processes. A fresh lab produces new issuers, addresses, asset IDs, proofs and PoW seals. Keep the home private. Share only its `public/` subdirectory. The earlier fixed-token reference remains runnable under `./pqd token`.

For interactive use, start a separate home and create an issuer and a receiving wallet. The fee is three native units for both issuance and ordinary payments. The preconfigured miners demonstrate initial native funding. Any funded user can issue.

```sh
net="$lab/interactive"
asset() { ./pqd assets --home "$net" "$@"; }
asset start
asset create issuer
asset create alice
asset export-address alice "$lab/alice.addr"
asset backup alice "$lab/alice.seed"
asset balance miner-a
# Once miner-a has a confirmed reward, fund the independent issuer.
asset send miner-a issuer 50 native 0 --intent fund-issuer --wait 180
asset issue issuer 180 --intent my-new-asset --wait 180 > "$lab/issuance.json"
id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["asset_id"])' "$lab/issuance.json")
asset list
asset send issuer "@$lab/alice.addr" 0 "$id" 70 --intent first-transfer --wait 180
asset restore alice-restored "$lab/alice.seed"
asset stop
```

The amounts after the payee are native units, asset selector, token units. A zero-token native transfer uses the selector `native`. `issue` pays the new supply to the issuer, with native change retained by its wallet. Use a different intent ID for each planned issuance. `resume` reuses the same authorized inputs for that intent. A 32-byte seed recovers on-chain holdings. Sender retries also need the durable private intent journal. [Wallet behavior](wallet/README.md)

## Consensus, privacy and change

* The fixed network ID commits to the shared verifier and PoW rules. The 22-bit work target, 100-unit block subsidy, accepted anchor ages 1–8, and block limit of four packets apply on every branch. Miners credit exactly one native reward per block including its verified fees. Each ordered proof, its receipts and its public issuance fields are committed by the PoW block. The history projection includes the two receipts and the issuance descriptor for each slot. [Network installation](stage.py) · [Baseline consensus](../../devnet/CONSENSUS.md)
* A positive public supply selects issuance. The first input must be real, prove spend authority and membership, and spend native-only funding. Both token input quantities are zero. The shared verifier permits outputs totalling exactly the published supply in the new asset, with each amount in the unsigned 62-bit range. The canonical ID is SHA-256 of the versioned domain, network ID and first input's nullifier, with the highest bit of each little-endian 64-bit word cleared. The all-zero ID is reserved. A node checks the ID and rejects repeat issuance on the selected history. The issuance registry, spent set and funded tree change atomically on branch selection. [Ledger](asset_ledger.py) · [Exact witness relation](native/PROFILE.md)
* An ordinary payment has five zero issuance words. Its asset ID and both amount lanes occur inside the proved openings. Every positive token input and output agrees on the private asset ID. Both token and native totals are conserved and the fee is paid in native currency. A token with zero quantity uses the zero tag. The proof binds the ordered ciphertext digest. An honest recipient decrypts a receipt with the seed-derived receiving key and checks the resulting note commitment.
* Issuance publicly exposes the ID, cap, authorizing first nullifier, height and block order. It introduces no persistent public issuer account or separate mint key. Relayers can see timing and network origin. Ordinary packets reveal their branch anchor, two nullifiers, two output commitments, fixed fee and ciphertexts. Low activity or voluntary disclosure can permit further inference. An issuance retried with the same real funding exposes the same ID and nullifier on both forks. Availability of the private seed also exposes the recoverable history. Formal whole-transcript zero knowledge, recipient anonymity, quantitative post-quantum knowledge soundness and economic consensus security remain open. [Security boundary](native/PROFILE.md) · [Underlying assurance](../token-profile/ASSURANCE.md)

The wallet chooses tagged native-plus-one-asset notes. For a partial mixed payment from 70 A and 23 native that delivers 45 A and 9 native, a single-asset design needs four outputs: 45 A and 9 native to the recipient, then 25 A and 11 native back to the sender. AST1 stores the two recipient amounts in one note and the two change amounts in another. For a token-only gift with positive change in both lanes, single-asset notes need three outputs and AST1 needs two. These are structural counts. Only AST1 was implemented and measured. A note with a positive A balance cannot be combined with a positive B balance in a single AST1 payment. Hence the recovered test wallet receives two separate native-only notes for its two independent partial payments. [Note comparison and controls](native/README.md)

## Public evidence

The author and independent reviewer retain full PoW blocks and complete payment packets, including the displaced branch. Participant names, transfer amounts, input categories and final holdings in the walkthrough are deliberate disclosures by disposable test wallets. Public-only replay verifies proofs, ancestry, work, registry, tree roots and exact native fees. The disclosed account reconstruction and private wallet cross-check answer a different question about which test participant owned a given amount. No private keys, seeds, openings, private witness paths or wallet databases belong in a published capture.

The first-stage fork intentionally detaches the initial B issuance and its dependent transfer. A remains registered on the heavier branch while B and its balances disappear. The independent issuer can later spend its original, again-unspent native note under a fresh authorization. The same canonical ID reappears with exactly one selected issuance. A wallet that saw only the final valid history receives the final B payment. Fixed supply is defined per selected chain. Numeric labels and ticker uniqueness are outside the protocol. Atomic swaps remain the next separate milestone.

## Decision and measurements

Use tagged two-lane AST1 for the multi-asset research devnet. It supports a private native amount and one private non-native asset in each ordinary payment. Under the same receipt format the single-asset representation needs four separate 1,792-byte receipts for a payment with positive balances in both lanes on both sides, or 7,168 bytes before proof or framing. No equivalent single-asset prover was timed. Fresh wallets can issue another ID with the same binary, verifier and network identity. IDs carry no ticker, public name or price. The public registry lists initial supplies on the selected branch. A concurrent head change invalidates an in-progress public listing and the caller can request it again. Wallet scanning uses common history.

Both measured payments consumed one externally received token-only note and one externally received native-only note. Each paid a 3-unit native fee. Author timings use two prover workers. The wall and CPU times are for the complete wallet role call, including cold setup. Peak memory is a per-process high-water mark. The public verifier ran in a separate process for each packet and performed three complete verifications after its own setup.

| Amount sent | Change retained | Real inputs / outputs | Complete bytes | Wallet wall / CPU | Wallet peak | Median public verification CPU |
|---|---|---:|---:|---:|---:|---:|
| 9 native + 45 A | 11 native + 25 A | 2 / 2 | 143,227 | 5.00 / 9.68 s | 451,936 KiB | 6.39 ms |
| 6 native + 34 B | 8 native + 26 B | 2 / 2 | 143,227 | 5.01 / 9.69 s | 451,940 KiB | 6.31 ms |

Verifier setup cost 2.38–2.41 CPU seconds and 1.28–1.30 wall seconds, with 200,980 KiB peak RSS. The packet includes 139,634 proof bytes, two receipts totaling 3,584 bytes, and 9 bytes of framing. A block adds a four-byte length per packet and a shared 222-byte fixed part. Compared with the complete 143,187-byte TKN1 payment, the extra 40 bytes encode the five public issuance words. At 100 million inclusions this packet alone projects to 14.3227 decimal TB per archive-year, before block framing, empty blocks, forks or replicas. [Raw author timings](evidence/AUTHOR-COST.json)

The author's 121 public blocks and 14 distinct payments span both branches. The common block at height 49 had six payments and only A. On the losing branch at height 64, B existed and a payment delivered 60 B. The alternative at height 66 retained A, removed B and rolled the losing miner's 1,506 native units back to zero. Twelve payments on the final selected history at height 106 paid 36 in fees. The miners received gross rewards of 10,636. The eleven wallets held 10,600 native, 180 A and 260 B in aggregate. The recovered wallet started with 40 native, 70 A and 60 B. After both independent payments it held 19 native, 25 A and 26 B. Both recipients spent onward. The proof controls also rejected an inconsistent A-to-B witness, inflation, token-bearing issuance inputs, dummy first issuance input and cap overflow. [Participant disclosures and public tips](evidence/AUTHOR-RUN.json) · [Relation controls](native/CHECK.json)

The non-author fetched implementation `a4939423ea0abe2b22e12339bd80f4134d16a267` over HTTPS, rebuilt in a new target and obtained the same native binary and verifier key. New issuers and miners produced 117 distinct blocks across two branches. The final height was 104, with 12 selected payments, 36 fees and 10,400 native in the eleven wallets. In a separate initially empty node database, delivering only the winning blocks reached the identical tip with 12 full proof verifications. Two new partial payments again measured 143,227 bytes each. The blinded proof construction itself took 3.86 / 3.73 wall seconds and 7.56 / 7.31 CPU seconds for A / B. With wallet initialization the calls took 5.24 / 5.02 wall seconds, at 451,740 / 451,680 KiB peak RSS. Full verification after setup cost a median 6.20 / 6.21 ms CPU. The clean archive includes raw role meters and peer observations. [Non-author review](review/CLEAN.md) · [Download both public captures](https://github.com/jouliene/pq-private-chain/releases/tag/live-user-assets-2026-11-20)

## Recheck public packets

After a clean walkthrough, run these commands from the repository root. The public verifier needs the registered key and the locally approved executable. The separate replay program uses pristine pinned primitives to derive rewards, roots and anchors, verifies each available complete packet and compares the selected balances with the numerical disclosures. Use either your local `public/` or an extracted capture from the [release](https://github.com/jouliene/pq-private-chain/releases/tag/live-user-assets-2026-11-20). Published captures contain no issuer or recipient seed.

```sh
t=experiments/user-assets
net="$lab/network"
set -- "$net"/source-build-*/build
python3 -IB "$t/review/build_helpers.py" "$1/upstream" "$lab/helpers"
bin="$net/deployment/runtime/native"
approved=$(cat "$net/deployment/devnet/approved-native.sha256")
keys="$net/deployment/keys"
vk_pin=99ed868d5bd0f8541bb6467a210bf75140ec696e49e53044f7bca011ed59438a
python3 -IB "$t/review/public_replay.py" --public "$net/public" --binary "$bin" \
  --approve-binary "$approved" --vk "$keys/asset.vk" --approve-vk "$vk_pin" \
  --helpers "$lab/helpers" > "$lab/replay.json"
python3 -IB "$t/review/winning_replay.py" "$net/deployment" "$net/public" \
  "$lab/replay.json" "$lab/winning-only"
python3 -IB "$t/measure.py" --public "$net/public" --binary "$bin" \
  --approve-binary "$approved" --keys "$keys"
```

To add independent live peer observations, replace the initial walkthrough command with `python3 -IB experiments/user-assets/review/observe.py "$lab/network" "$lab/observations.json"` in a fresh lab. Supply `--observations "$lab/observations.json"` to the public replay for that same run.
