# Live private-token payments on the local PoW devnet

Use TKN1 for the live fixed-token research network. A new offline wallet can receive tokens with zero native value, recover its notes from a 32-byte seed, acquire native funds from a different sender, and pay tokens and a native fee. Two independent CPU miners run while wallets prove and recipients recover. The stronger TKQ1 complete proof exceeds the current direct packet ceiling. [Monetary reconciliation](money/README.md) · [Proof comparison](comparison/README.md)

## Run it

Use x86-64 Linux, Git, Python 3.10+, a C toolchain, rustup and bubblewrap with usable unprivileged namespaces. The first start fetches a pinned Qnero commit and locked Cargo dependencies. It derives the verifier locally and checks it against the approved TKN1 key. The project chooses a fresh founding public key for each newly created lab. The per-lab network and genesis digests appear in the node status.

```sh
git clone https://github.com/jouliene/pq-private-chain.git
cd pq-private-chain
git checkout --detach live-token-pow-2026-11-20
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
./pqd token --home "$lab/live" walkthrough
```

The command starts three independent node processes, initially enables mining on A and B, then uses ordinary wallet commands. It starts a fourth node with an empty chain database for cold replay. The driver changes peer connections and mining controls. Each node independently checks each block and chooses its valid chain. The walkthrough stops its processes, leaves local wallets and records in the private home, and prints the path to the public capture. Use a new home for each fresh walkthrough. During normal use, `start` on an existing home reuses its selected network and installed runtime.

A separate persistent lab can be run interactively. Start the miners and wait until a mined reward to each miner has a few successors. Use `balance miner-a` and `balance miner-b` to inspect their reward counts. The commands below run on one machine. Only the exported public address is needed while a payee is offline. The seed remains local to its owner.

```sh
net="$lab/interactive"
token() { ./pqd token --home "$net" "$@"; }
token start
token create alice
token export-address alice "$lab/alice.addr"
token backup alice "$lab/alice.seed"
token send miner-a "@$lab/alice.addr" 0 70 --intent token-funding --wait 180
token restore alice-restored "$lab/alice.seed"
token send miner-b "@$lab/alice.addr" 23 0 --intent native-funding --wait 180
token create bob
token export-address bob "$lab/bob.addr"
token send alice-restored "@$lab/bob.addr" 9 45 --intent first-token-invoice --wait 180
token balance bob
token create carol
token send bob carol 4 13 --intent onward --wait 180
token balance carol
token stop
```

Amounts following the recipient are native first, token second. Each of the five payment intents in the automated scenario pays three native units upon canonical inclusion. Two distinct packets authorize the shop payment across the competing branches. The interactive transcript above makes four payments. Use a distinct intent ID per invoice. After an ambiguous acknowledgement or a branch change, `token resume SENDER INTENT --wait 180` consults the sender's private journal and reconciles its reserved inputs with the selected branch. Wallet recovery rederives the spending and receiving keys and rescans common history. Resuming a sender's off-chain intent also requires its private outbox.

## Results from the first mined network

| Step | Recipient receives (native, token) | Sender change (native, token) |
|---|---:|---:|
| Founder pays the offline recipient | 0, 70 | 97, 170 |
| Second miner spends reward funding | 23, 0 | 74, 0 |
| Restored recipient spends both incoming notes, fee 3 | 9, 45 | 11, 25 |
| Second restored wallet spends its received note, fee 3 | 4, 13 | 2, 32 |
| First recipient's remaining change pays the shop, fee 3 | 3, 7 | 5, 18 |

The first three nodes mined a common prefix to H20. The losing branch reached H24 with 15 cumulative fees. The heavier branch reached H30 with 12. Four rewards to the losing miner totalling 403 disappeared on the heavier branch. A fresh fourth node validated from genesis, first selected the losing history, then adopted the higher-work branch from a different peer. Node A reopened its database and agreed with the other nodes. The restored sender's newly authorized shop payment brought the selected branch to H31 with five payments, 15 recycled fee units, 3,100 native units issued and all 240 founding tokens accounted for. Distinct branch tips and sealed blocks are retained in the public corpus. Heights, miner allocations, timing, fresh packet IDs and founding digest vary by run. [Public corpus](evidence/author-public.tar.gz) · [Cryptographic replay](evidence/author-crypto-replay.json) · [All eight controlled balances](money/AUTHOR.json)

The one-real-input shop retry exposed **one identical nullifier** in two valid proofs. Its anchor, packet ID, both output commitments and both receipt strings changed. Relayers or archivists who saw both authorizations can link their funding. The local intent name, transfer amounts, change and names in the walkthrough come from consenting test wallets. Replaying identical bytes to the receiving node before mining returned the same transaction ID and `duplicate=true`. Only the replacement was present on the selected chain. [Public proof comparisons](evidence/author-crypto-replay.json)

An independent operator cloned the published code, generated a different founder and six new proofs, and ran the ordinary commands. This second run had a common H31, a losing H37 (15 fees), and a winning H41 (12 fees). Its final H44 issued 4,400 native units and conserved 240 tokens. The losing miner fell from 603 native to zero and its subsequent ordinary send had insufficient funds. A read-only observer saw the fourth node visit genesis, losing tip, heavier tip and final tip in order. The six complete packets had no common packet ID with the author's run. The independent public capture and final revision readback accompany the release. [Clean-clone report and commands](review/CLEAN.md) · [Release assets](https://github.com/jouliene/pq-private-chain/releases/tag/live-token-pow-2026-11-20)

## Network and monetary rules

* Each installation explicitly selects the TKN1 verifier by SHA-256, the fixed asset identifier, the approved 216-byte founding record, and the PoW rule tuple. The founding record commits to one public allocation of **0 native and 240 fixed tokens**. Validators recompute the typed note, first tree root and genesis header. The local installation pins the founding digest outside peer negotiation. A new lab with another founder has a different network. The four nodes in one lab share this operator configuration and keep separate databases and mempools. [Founding bytes and identity derivation](policy.py) · [Node installation](stage.py)
* The ordered block format uses `TKDEVBL1`, its network ID, fixed 22-bit PoW target, actual parent, height, miner, reward, resulting state and tree root, up to four complete packets and a nonce. A node independently checks the TKN1 proof against its approved verifier, the branch anchor (accepted age 1–8), both nullifiers, both new commitments, the native fee, state transition and seal. The inherited transactional selection counts cumulative work, then uses the smaller tip ID to resolve a tie. [Base PoW and rollback rules](../../devnet/CONSENSUS.md)
* A real spend opens each input under its spend authority and proves private occurrence membership. Each private amount is bounded to 62 bits. The two token input amounts sum to the two token output amounts. Native input amounts sum to native outputs plus three. A dummy contributes zero in both lanes. A miner receives one note with `native = 100 + included native fees` and `token = 0`. At selected height H, native issuance is exactly 100H and token issuance is 240. A proof authenticates the digest of both ordered ciphertexts; a receiving wallet decrypts and checks its commitment. [Registered relation](../token-profile/candidate/PROFILE.md) · [Wallet paths](wallet/README.md)
* One input may carry only tokens and the other only native currency. A recipient output **and a single change output** each have both lanes. The measured (11,25) change required no extra output. The current wallet selects at most two real notes, including when fragmented balances exceed that capacity. The encrypted receipt uses ML-KEM-1024 and ChaCha20-Poly1305. Public founding and miner rewards expose their allocations; ordinary transfers expose their fee, anchor, nullifiers, commitments and ciphertexts. [Receipt implementation and privacy analysis](../token-profile/privacy/PRIVACY.md)

## Replay the published public evidence

For the author's capture the externally pinned founding SHA-256 is `a45acce896ccdce3b73e8568a14a34d81d9f203baec04bc466bf6a8abdf6e830`. The archive SHA-256 is `cdbdcd402a107bf353a311896636a785b0394a601f1d58531c3385e6d646c0e2`. The following commands use the role and clean upstream sources produced by the one-command walkthrough above. The verifier runs without wallet files. The independent helper builds from the unmodified pinned upstream tree. Its separate target can be kept for further public replays.

```sh
t=experiments/token-devnet
pin=a45acce896ccdce3b73e8568a14a34d81d9f203baec04bc466bf6a8abdf6e830
mkdir "$lab/author"
tar -xzf "$t/evidence/author-public.tar.gz" -C "$lab/author"
python3 -IB "$t/check_policy.py" "$lab/author/public" --approve-genesis "$pin"
python3 -IB "$t/money/reconcile.py" "$lab/author/public" --approve-genesis "$pin" | cmp - "$t/money/AUTHOR.json"
set -- "$lab"/live/source-build-*/build
python3 -IB experiments/token-profile/review/build.py "$PWD" "$1/upstream" "$lab/arithmetic"
bin="$lab/live/deployment/runtime/native"
python3 -IB "$t/review/network.py" --public "$lab/author/public" --genesis-sha "$pin" \
  --binary "$bin" --binary-sha "$(cat "$lab/live/deployment/devnet/approved-native.sha256")" \
  --keys "$lab/live/deployment/keys" --helpers "$lab/arithmetic"
```

The public oracle reconstructs both branches and verifies every unique authorization. It compares exact public rows with a local database only if asked with `--db`. The monetary checker also reconciles named wallets using the numerical disclosures in RUN.json. To verify a different deployment, obtain its operator-approved founding digest independently. The walk-through's cold fourth peer shares the original deployment approval and downloads its history over loopback.

## Architecture decision and next experiment

Keep TKN1 for fixed-supply token work on this research devnet. The full direct packet is **143,187 bytes**. TKQ1 proved the same two-real-input/two-output relation, changed the argument commitment and challenger hash to full-width Keccak-256, and increased FRI queries from 26 to 64. Its **383,033-byte** packet exceeds the existing 262,144-byte limit by 120,889 bytes. It retains the original algebraic public-input hash. The conditional query exponent improves for a fixed agreement set. A full adaptive quantum knowledge and hiding analysis remains open. The per-payment body alone projects to 14.3187 or 38.3033 decimal TB per 100M included payments, respectively. Relay, PoW framing, forks, replicas, pruned storage and recovery have additional costs. [Parameter checks, measurements and explicit models](comparison/README.md) · [Security obligations](../token-profile/ASSURANCE.md)

For the next milestone, demonstrate two unrelated users registering distinct fixed-supply assets on the **same** PoW chain. Use a versioned issuance descriptor, a consensus-authenticated asset ID and supply record, and per-ID value conservation in spends. Specifically test that an opening for asset A cannot fund a B transfer, mining emits only native units, replay cannot duplicate either issuance, and undo/replay removes an orphaned issuance and its dependent payments. The TKN1 encrypted token field currently denotes a quantity of the one network-selected token. It has no per-note discriminator for two different token IDs. Wallet inventory, the authorized relation and its verifier, and founding/issuance indexing all need this distinction. Reuse the mined native fee, private receipt, change and live reorganization paths. Multi-owner swaps and token archival certificates remain future work.

Mainnet issuance policy, adversarial network privacy and receipt unlinkability, concrete post-quantum knowledge soundness and full-transcript zero knowledge, independent archive affordability, production consensus and economic security remain open. The global permissionless blockchain objective stays active.
