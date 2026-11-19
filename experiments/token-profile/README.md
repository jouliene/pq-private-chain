# Spend-proof decision for the first native private token

**Use TKN1 for an isolated, fixed-supply research token with fees in the native currency. Keep DLF1 for existing native-only direct payments. Keep D8C1 as optional evidence only for its registered DLF1 history.** The TKN1 and DLF1 public verifiers accepted their own genuine payments and rejected the other program's genuine proofs even after reframing them in the expected suite. The packets have identical widths. Deploying assets of value needs a separate cryptographic and monetary review. [Cross-key results](CROSS_KEYS.json) · [Security budget and external review](ASSURANCE.md)

## What decided the choice

DLF1 proves ownership of a private tree member, derives its public nullifier, and constrains one bounded integer balance. Attaching a token quantity to its encrypted receipt adds no verifier-enforced token equation. The first prototype needs both native change and token change while paying a native fee. A note with two private integers offers both in a single change output. This directly addresses the monetary gap while retaining the tested proof engine and offline wallet. Increasing only the FRI query count would leave the original scalar relation intact. [Monetary review](money/REVIEW.md)

TKN1 binds a fixed token lane and a native lane to each note. It folds a domain-separated digest of the token amount and secret opening randomness into the randomness used by the commitment and nullifier. A spend consumes the entire vector. Four per-note token range checks and an independent balance equation make tokens conserved. The native lane pays exactly three native units. Dummy inputs contribute zero in both lanes. The 62-bit limits make both sums strictly smaller than the Goldilocks modulus. This design permits one genuinely funded note and a dummy, or two independently authenticated real notes. The public statement reveals the selected profile and fee. It carries no per-transfer public token amount or token-used flag. [Registered relation](candidate/profile.rs) · [Verifier dimensions](PARAMETERS.json)

The decisive functional run used four fresh spend proofs and two independent initial payers. Balances below are deliberately disclosed research fixture values in the order (native, token). A chain observer cannot read them from the statement alone.

| Payer | Payee | Paid | Change | Funding |
|---|---|---:|---:|---|
| A | C, offline | (0, 40) | (197, 80) | Two positive funded vectors |
| B | C, offline | (70, 65) | (127, 55) | Two positive funded vectors |
| C, restored | D, offline | (41, 75) | (26, 30) | Both external receipts, including the zero-native note |
| D, restored | B | (12, 14) | (26, 61) | Its only received note and a zero dummy |

Each offline recipient exited before any payment. Its new wallet process began with just a 32-byte seed, scanned the common history, decrypted the incoming receipts, matched commitments, rebuilt paths and proved a successor. The fresh public node took a pinned 488-byte genesis and the four complete blocks, verified all proofs, and reconstructed the fee sink and endpoint. The final wallets held 388 spendable native units and 240 tokens. The remaining 12 native units were charged as fees. The authorized launch inventory contained 400 and 240 respectively. The lab fee sink is irreversible. Integrating the ordinary miner fee recipient requires crediting the same fees exactly once and rollback with the block. [Raw public blocks and observations](candidate/evidence) · [Independent replay command](reproduce.py)

The negative controls distinguished three failures. A witness with one excess output token retained correct native accounting and internally consistent note openings. The prover rejected it. Altering one canonical public fee word in a genuine proof failed public verification. Replaying an unchanged valid proof after inclusion reached the spentness check and left the state intact. A separate wallet test placed a decryptable receipt beside the wrong public commitment. The wallet skipped that delivery, retained the public tree root and recovered a later valid output. [Control implementations](candidate/campaign.py)

## Measured resources

| Quantity | DLF1 released reference | TKN1 author run |
|---|---:|---:|
| Gates before blinding / padded rows | 455 / 4,096 | 468 / 4,096 |
| Complete proof including public words | 139,594 B | 139,594 B |
| Two offline receipts / framing | 3,584 B / 9 B | 3,584 B / 9 B |
| Complete wallet packet | 143,187 B | 143,187 B |
| Prover setup CPU / wall, mean | 2.463 / 1.316 s | 2.680 / 1.444 s |
| Proof CPU / wall, mean | 7.131 / 3.630 s | 7.478 / 3.825 s |
| Wallet process peak RSS | 452,384 KiB | 452,044 KiB |
| Warm public verification, mean CPU | 12.31 ms | 6.76 ms |

The four TKN1 proofs retained the same FRI trace size despite 13 additional preblinding gates. A validator checks roughly 140 kB of proof per transfer, even when the token amount is zero. Public verifier initialization took 2.707 CPU-s and 1.473 wall-s, with a process high-water mark of 200,832 KiB. Timings come from separate runs with two Rayon workers, including a historical DLF1 run. They establish operating costs on these machines. They do not establish a speedup. A framed local transfer adds four bytes to the packet. One copy of the direct payment packets at 100M/year is **14.3187 TB**. The measured TKN1 block carries one payment and adds 184 B, projecting **14.3371 TB/year**, before forks, replication and indices. No TKN1 archival compression credit is justified. [TKN1 numbers and definitions](RESOURCES.json) · [DLF1 raw cost ledger](../payment-architecture/direct/evidence/author/COSTS.json)

## Independent reproduction

A reviewer who did not implement the wallet, circuit, ledger or parameter decoder cloned public candidate revision `ee0da6c9ade4c4342203e63cb274e19efa6df5e9` into a new directory. The reviewer derived the same key, verified the author's four payments, generated four different payments on new keys, restored both offline recipients and verified all four new payments. Both runs ended with 388 spendable native units, 12 native fees and all 240 tokens. The reviewer additionally rebuilt the founding commitments and public state with a separate calculation. Mean fresh proof time was 3.549 wall-s and 6.973 CPU-s, with 452,304 KiB peak wallet RSS; mean warm verification was 6.315 ms CPU. [Review and exact commands](review/CLEAN.md) · [Fresh public corpus](https://github.com/jouliene/pq-private-chain/releases/download/token-spend-profile-2026-11-20/independent-public.tar.gz)

## Security and integration boundary

* Both proof levels use the original Poseidon transcript, a quadratic Goldilocks extension, and a 26-query FRI configuration with no grinding. The decoded constructor screen gives 130 before the field-size cap of 128. Classical and quantum knowledge soundness, full hiding of the adaptive transcript, and security of the concrete hashes under their uses remain external-review obligations. ML-KEM-1024 and authenticated receipt encryption protect different properties. The public receipt digest binds the bytes the sender supplied. The recipient checks that a decrypted opening matches its commitment. A dishonest sender can publish an unusable receipt. [Actual transcript, conditional bounds, losses and sources](ASSURANCE.md)
* Reanchoring a previously seen wallet intent linked the attempts through a shared real nullifier. The measured DLF1 conflicting two-real-input pair shared both nullifiers. TKN1 inherits deterministic real nullifiers; the TKN1 experiment has no persistent retry driver of its own. Independently funded payments at the same anchor shared neither. Different randomized ciphertexts and new proofs do not remove the link for someone who receives both attempts. Reused addresses off chain, a tiny funded population, timing and later seed disclosure further limit anonymity. TKN1's profile publicly identifies the fixed asset universe. [Public measurements, negative control and observer models](privacy/PRIVACY.md)
* D8C1 registers the old direct key as a constant in all eight recursive verifiers. It remains executable for DLF1. On this revision a reference replay validated 63 stored PoW cores from an empty validator, then the previously restored recipient's genuine successor, ending at height 62. A TKN1 archive needs its own registered recursive relation, typed state/effect identity, extraction review and cold verification after dropping originals. The cost of that version has not been measured. [Reference command and accounting](../delayed-eight/README.md)
* The TKN1 fixture admits one operator-approved genesis and an ordered, PoW-sealed history. It checks both selected headers and previous work linkage. It implements no P2P fork selection, migration from DLF1, new token issuance, or arbitrary asset creation. Source-built local binaries are trusted. This milestone leaves existing devnet consensus and wallet defaults intact. Persistent wallets, scalable note selection and rollback on competing typed chains belong to integration. [Ledger and deployment boundary](candidate/ledger.py)

**Next integration experiment.** In a separately identified local devnet, bind this exact verifier, approved typed genesis and fixed token identifier to its network. Allow mining to credit only native subsidy and one copy of each native fee. Feed ordinary wallet payments across a competing branch. Recompute both lane supplies and spentness from genesis on a fresh node, then restore and spend on the selected branch. Keep direct inclusion available. General private assets, indivisible two-owner swaps, and multi-archivist endurance remain on the roadmap. No owner acceptance of annual archive costs is assumed.

## Reproduce

Use x86-64 Linux, Git, Python 3.11+, a C build toolchain, Rust 1.93.0 via rustup, and bubblewrap with usable unprivileged namespaces. The initial build fetches the pinned public Qnero source and locked Cargo dependencies. Public verification accepts only the source-derived keys. From a fresh checkout:

~~~sh
git clone https://github.com/jouliene/pq-private-chain.git
cd pq-private-chain
git checkout --detach token-spend-profile-2026-11-20
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
python3 -IB experiments/token-profile/reproduce.py "$lab/fresh"
~~~

Use a different new work directory and add `--public-only` to verify the four committed payments without creating wallets. The full command also generates new private seeds, four new proofs and two recovery spends. Local secret files are temporarily created on tmpfs. The public-only audit and the transcript comparison can be run separately:

~~~sh
python3 -IB experiments/token-profile/parameters.py --check
python3 -IB experiments/token-profile/money/check.py
python3 -IB experiments/token-profile/privacy/observe.py
python3 -IB experiments/token-profile/measure.py
~~~

The privacy comparator fetches a size- and hash-pinned earlier public release artifact. Its `--direct-archive` flag accepts an existing copy. The other three commands in this group read only tracked public data. The global permissionless private blockchain project remains active.
