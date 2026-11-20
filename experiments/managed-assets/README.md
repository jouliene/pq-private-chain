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

Each asset's append-only selected event history determines policy, authority, current outstanding supply and revision. Registration starts at revision one. Subsequent mints and burns increment it. Supply remains in the interval from zero through 2^62−1, including after a complete burn. A zero-supply managed asset keeps its identity and authority. Within a block only one supply change per asset is eligible. Fork selection atomically rewinds event rows alongside funded outputs, spends, rewards and fees. New MSP1 transitions commit the full transaction ID in addition to the monetary effects. The old AST1 state and reward encodings stay byte-compatible. A fresh database validates the original blocks, and locally regenerated wallet state authenticates the appropriate history encoding for each suite.

Ordinary transfers disclose the anchor, fee, output commitments, two nullifiers, timings, proof suite and two ciphertexts. Supply operations also disclose operation, ID and quantity. A managed mint identifies the persistent issuer and prior state. Reusing a funded input on a competing branch reveals the same real nullifier. Enrollment at the redemption operator additionally reveals the surrendered transfer and off-chain payout destination to that operator. The participant amounts in the walkthrough are voluntary test disclosures. End-to-end quantum knowledge soundness, complete transcript hiding, recipient/network anonymity, offline key security and production economics remain open. [AST1 assurance](../user-assets/native/PROFILE.md) · [Redemption service](REDEMPTION.md)
