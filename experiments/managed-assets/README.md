# Managed supply and voluntary redemption

An upgraded local PoW node validates both the original AST1 fixed-asset history and versioned MSP1 payments. The same network and genesis identify the chain. A fixed asset keeps its original ID, notes and immutable supply policy. A managed registration publishes the initial issuance and commits permanently to an issuer public key. This research upgrade requires participating validators to install the new rules before accepting the first MSP1 payment. Old software remains runnable with the historical rules.

## Reproduce the mined walkthrough

Use x86-64 Linux, Python 3.10+, Rustup, Git, a C toolchain, bubblewrap with working unprivileged namespaces, and network access for the pinned upstream and Cargo dependencies. A fresh home builds both suites and generates disposable private seeds. The original AST1 software mines and funds a fixed asset first. Upgraded peers check those blocks from genesis. After restoring an original miner's seed, the ordinary upgraded wallet spends its already funded asset. The privately owned fixed-asset outputs and the managed dollars then coexist on one selected chain.

~~~sh
git clone https://github.com/jouliene/pq-private-chain.git
cd pq-private-chain
git checkout --detach managed-supply-redemption-2026-11-20
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
./pqd managed --home "$lab/net" walkthrough
python3 -IB experiments/managed-assets/measure.py "$lab/net/deployment" "$lab/net/public"
~~~

For a separate interactive network start with an unused private directory. Any wallet with sufficient native funds may register a new asset. Existing managed assets check their own recorded issuer on every additional mint. All payments, including supply changes, cost three native units. The amounts in this walkthrough are integer research units. The simulated bank uses one test dollar per redeemed token.

~~~sh
net="$lab/interactive"
m() { ./pqd managed --home "$net" "$@"; }
m start
m create treasury
m create customer
m backup customer "$lab/customer.seed"
m export-address customer "$lab/customer.addr"
# After a mining reward is available, fund the registration fee.
m send miner-a treasury 30 native 0 --intent native-funding --wait 180
m register treasury 1000 --intent register-usd --wait 180 > "$lab/register.json"
usd=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["asset_id"])' "$lab/register.json")
m mint treasury treasury "$usd" 300 --intent mint-300 --wait 180
m send treasury "@$lab/customer.addr" 12 "$usd" 400 --intent private-payment --wait 180
m restore restored "$lab/customer.seed"
m send restored treasury 3 "$usd" 200 --intent voluntary-return --wait 180 > "$lab/return.json"
tx=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tx"])' "$lab/return.json")
m redeem enroll request-1 treasury "$usd" 200 "$tx" test-payee
m burn treasury "$usd" 200 "$tx" --intent redeem-200 --wait 180 > "$lab/burn.json"
burn=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tx"])' "$lab/burn.json")
m redeem settle request-1 "$burn"
# Repeat settle once the burn has three confirmations, counting its own block.
m redeem status request-1
m list
m stop
~~~

The full walkthrough first restores 400 dollars plus 12 native units. Returning 200 plus three native units gives the treasury both the exact returned note and its burn fee. The original holder keeps 200 dollars and six native units. A treasury that receives token-only returns must supply its own compatible native fee input. The issuer cannot confiscate another holder's note. A managed holder can voluntarily destroy owned tokens without claiming fiat. The simulated payout coordinator requires evidence of receipt in its enrolled treasury wallet, the exact return and a selected burn.

## Consensus and issuer authority

| Operation | Authority and local validity | Public supply evidence |
|---|---|---|
| Original AST1 issue or MSP1 fixed registration | Fixed ID derived from the network and first funded nullifier. The original or new registered spend proof establishes a native-only fee input and exact issuance. Registration is unique on the selected branch. | ID and fixed quantity. Later mint and burn of this asset are ineligible. |
| Managed registration | The shared spend proof and issuer signature authorize the initial issuance. The ID is the masked SHA-256 of a versioned domain, network, issuer key and first funding nullifier. | Immutable managed policy, issuer public key, initial quantity and first event. |
| Managed mint | A new native-funded wallet proof and the registered issuer's signature authorize a positive quantity. Current issuer revision and previous event transaction must both match. | Same asset ID, increase, previous event and signature. Mint funding can change. |
| Ordinary transfer | The funded commitments, spend secrets and current nullifier set authorize the transfer. Both private amount lanes balance and the fee is native. | Zero public issuance fields. The asset ID and amounts are private witness values. |
| Managed burn | A complete wallet proof consumes the holder's notes and proves the published positive reduction. The node requires a managed asset and sufficient outstanding supply. | Asset ID, decrease and spent nullifiers. The issuer signature is unnecessary. |

The MSP1 frame starts with the ASCII magic, width one and a one-byte opcode. For registration and mint it appends a 32-byte issuer public key, prior revision as little-endian u64, 32-byte previous event ID, and a 17,088-byte signature. Every frame ends in the complete MNG1 proof packet with its two ordered ciphertexts. The issuer signs SHA-256 over the dedicated supply-authorization domain, network, operation, authority, prior revision, previous event and SHA-256 of that entire inner packet. That digest binds the asset and amount, inputs, two intended output commitments, ordered encrypted receipts, fee, anchor and proof. Replacing any of those bytes requires a new signature. Correct delivery to an intended human still depends on the wallet constructing recoverable ciphertexts for the authenticated address.

The issuer uses stateless hash-based SLH-DSA-SHAKE-128f, specified in FIPS 205. The existing pinned Rust implementation avoids a new cryptographic dependency. The 32-byte issuer public key remains constant across fee inputs and wallet restarts. The wallet derives its signing seed under a dedicated domain from its 32-byte wallet backup. Loss and compromise of that backup affect issuance authority as well as spending. This version has no key rotation, recovery quorum, freeze or seizure mechanism. FIPS standardization supports the choice of signature primitive. Concrete key derivation, implementation, multi-target loss and composition with the payment proof still require review. [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) · [Registered proof and signature implementation](native/PROFILE.md)

Each asset's append-only selected event history determines policy, authority, current outstanding supply and revision. Registration starts at revision one. Subsequent mints and burns increment it. Supply remains in the interval from zero through 2^62−1, including after a complete burn. A zero-supply managed asset keeps its identity and authority. Within a block only one supply change per asset is eligible. Fork selection atomically rewinds event rows alongside funded outputs, spends, rewards and fees. New MSP1 transitions commit the full transaction ID in addition to the monetary effects. The old AST1 state and reward encodings stay byte-compatible. The supported upgrade path uses a new managed database, validates the original public blocks and rebuilds private inventory from the wallet's seed. The walkthrough transfers public history plus private miner backups to demonstrate continuity. It leaves the original databases in their old format. The historical compact wallet projection delegates transaction identity to the selected validating source as in AST1. For MSP1 the transaction ID is also inside the proved-work block's state transition.

The registered issuer signature is a separate security boundary from the payment proof. Its authenticity relies on the FIPS 205 hash-based signature assumptions for the chosen parameters, sufficient entropy of the issuer seed, domain separation and SHA-256 binding of the signed preimage. The ID uses a 252-bit masked label space. Generic ideal-hash collision costs for that space are roughly 126 classical bits or 84 quantum bits. The branch registry rejects a second registration under an existing ID. The spend proof also relies on commitment binding, sound funded-membership and range constraints, nullifier rules and the actual noninteractive transcript. The configured proof parameters alone do not establish a concrete end-to-end quantum bound.

Ordinary transfers disclose the anchor, fee, output commitments, two nullifiers, timings, proof suite and two ciphertexts. Supply operations also disclose operation, ID and quantity. A managed mint identifies the persistent issuer and prior state. Reusing a funded input on a competing branch reveals the same real nullifier. Enrollment at the redemption operator additionally reveals the surrendered transfer and off-chain payout destination to that operator. The participant amounts in the walkthrough are voluntary test disclosures. End-to-end quantum knowledge soundness, complete transcript hiding, recipient/network anonymity, offline key security and production economics remain open. [AST1 assurance](../user-assets/native/PROFILE.md) · [Redemption service](REDEMPTION.md)

## Costs and public evidence

The author run retained 74 full blocks across the two branches and nine distinct confirmed payment packets. Eight payments are selected at height 64. Six of those fees originated after the legacy fixed issue and before the final burn. Total selected fees are 24. Seven wallets hold an aggregate of 6,400 native units, 17 fixed tokens and 1,100 managed dollars. The treasury holds 900 dollars and the restored holder retains 200. The five-unit fixed payment spent the 17-unit note created by the original AST1 wallet, leaving 12 with the original miner. All quantities refer to this disposable test. [Public run](evidence/AUTHOR-RUN.json)

| Author operation | Complete packet | Wallet wall / CPU | Wallet role peak | Full public verification after setup |
|---|---:|---:|---:|---:|
| Register 1,000 | 160,393 B | 5.02 / 9.55 s | 452,060 KiB | 12.01 ms |
| Mint 300 | 160,393 B | 5.00 / 9.51 s | 452,056 KiB | 12.12 ms |
| Private payment | 143,233 B | 4.94 / 9.58 s | 451,932 KiB | 6.88 ms |
| Voluntary return | 143,233 B | 4.91 / 9.50 s | 451,800 KiB | 6.70 ms |
| Final burn | 143,233 B | 4.89 / 9.46 s | 451,932 KiB | 6.72 ms |

Each complete packet includes a 139,634-byte blinded proof, two ciphertexts totaling 3,584 bytes and nine inner framing bytes. An MSP1 ordinary transfer or burn adds six outer bytes. Registration and additional mints add 17,166 outer bytes, including the 17,088-byte signature. Four further length bytes and a shared 222-byte block header/body frame apply on inclusion. Wallet wall time covers the complete local proof/authorization call. Wallet CPU meters sample work in the native role around proving, and the process high-water memory also covers setup. The public verifier times are median wall times of three whole-packet checks after warmup, including issuer verification where applicable. Initializing the public verifier took approximately 1.27 s wall time in the author run. These measurements exclude mining and wallet sync. [Raw native and outer role meters](evidence/AUTHOR-COST.json)

| Observed state | Managed outstanding | Paid in simulated fiat | Still owed for this request | Paid with no selected burn |
|---|---:|---:|---:|---:|
| Return enrolled before burn | 1,300 | 0 | 200 | 0 |
| Burn with one confirmation | 1,100 | 0 | 200 | 0 |
| Burn with three confirmations | 1,100 | 200 | 0 | 0 |
| Deeper fork removes the burn | 1,300 | 200 | 0 | 200 |
| Returned note burned again, at least three confirmations | 1,100 | 200 | 0 | 0 |

On the author's losing height-56 branch the mining reward for the ten-block detached suffix included 1,000 newly mined native units and three fees. That miner's balance fell from 1,003 to zero on the heavier branch. The same fixed 17 and the original issuance at height three survived both histories. [Per-tip wallet balances and roots](evidence/AUTHOR-RUN.json)

The tested fork retained the original customer's return at its common ancestor. The treasury therefore recovered the same note and could burn it again. A fork that also removes the return can leave the operator exposed without that note. Three confirmations are a research policy, with no absolute finality. A real bank would need durable idempotency for the same business key, and its authorization and customer identity checks would be separate operational obligations. No real fiat moved.

The public capture contains complete blocks on both forks, packets, rejected public submissions and participant-disclosed numbers. Only aggregate conclusions leave the private wallet and bank checks. An observer of ordinary network traffic would not normally have the test labels, private balances, or the customer's payout request. The compact author and non-author archives and commit/CI readback are attached to the [tagged release](https://github.com/jouliene/pq-private-chain/releases/tag/managed-supply-redemption-2026-11-20).

The non-author started from an anonymous HTTPS checkout, rebuilt both native suites, generated new issuer and holder seeds, and mined a different history. Its independent public reader reconstructed all 80 captured blocks, reconciled both forks and compared all four node databases. A fifth fresh database received only the 70 winning blocks. This yielded 17 fixed tokens, 1,100 managed dollars, 7,000 newly issued native units, and 24 in fees. Separate checks against the seven controlled private wallets confirmed that the upgraded spend used the old funded fixed output and both burns used the same returned note. The independent bank reader found one request, two burn attempts and one payout. Its second signature implementation (Node/OpenSSL) verified the actual issuer signatures and rejected 26 changes to signed fields. [Independent instructions and results](review/CLEAN.md)
