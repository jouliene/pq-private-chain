# Funded recovery after archive loss

This walkthrough funds the same offline address at heights 12 and 13 of the existing A/B PoW network. Two full nodes replicate the original bodies into separate SQLite stores. The original funding peers go offline. The test removes access to the H12 original on both surviving servers, starts an empty validating node and restores a wallet from its pre-funding backup. Only the second archive restores access to H12. The home node verifies the rest of the history, and the wallet spends both funded notes in one B payment. A deeper competing branch removes the first inclusion and a signed mint. The wallet confirms the payment again on the winner.

## Run with fresh funds

Use x86-64 Linux with a GCC toolchain, Cargo/rustup, Git, curl, xz, Bash, Python 3.10+ with SQLite/dbstat, and bubblewrap with working nested user namespaces. The network roles use loopback TCP. Wallet roles have a separate network namespace and a single mounted public Unix socket. Use a short private result path to fit Unix socket names. From the checkout run

```sh
bash experiments/archive-recovery/reproduce.sh /tmp/ar-fresh
```

The directory must be new. The script pins Rust 1.93, uses the funded builds and Cargo locks, checks the Node binary distribution and previous public capture, and builds the two independent replay helpers. Its own funding, blocks, competing branch, two proved spends and role stores are new. Original funding uses the release's operator harness. The recovery driver uses that harness's seed, a public destination address and pinned deployment. The driver handles test outages and forwards the home-admitted public packet to a miner over a local socket. Each node checks the submitted bytes. Fresh keys and PoW mean that identifiers, elapsed times and physical disk allocation differ.

The private result contains seeds and wallet databases. Only the allowlisted public graph and reviewed summaries are suitable for release. The separate public graph reader takes no wallet input:

```sh
python3 -IB experiments/archive-recovery/review/replay.py PUBLIC NETWORK/deployment HELPERS NODE_BINARY
```

The reader checks original proofs, issuer and swap signatures, branch rules, ordered effects, roots, spent inputs, fee credits and disclosed fixture totals. The independent seed check links the actual two accepted nullifiers back to the particular A/B receipts. The peer checker matches observed range and body requests against the graph. The restart checks reuse a checksum-pinned prior graph for equal-work fork choice, interruption and damage handling. See [the wallet contract](WALLET.md) for the amounts, backup boundary and network observations.

To check the published author's original graph after the fresh build, use the following commands from the checkout. Replace `out` with the private directory created above.

```sh
out=/tmp/ar-fresh
here=experiments/archive-recovery
url=https://github.com/jouliene/pq-private-chain/releases/download/funded-archive-recovery-2026-11-21
curl -fsSL "$url/funded-archive-recovery-public.tar.gz" -o "$out/funded-archive-recovery-public.tar.gz"
(cd "$out" && sha256sum -c -) < "$here/RELEASE.sha256"
mkdir "$out/published-capture"
tar -xzf "$out/funded-archive-recovery-public.tar.gz" -C "$out/published-capture"
python3 -IB "$here/review/replay.py" "$out/published-capture/public" "$out/network/deployment" "$out/helpers" "$out/node-v24.22.1-linux-x64/bin/node" | cmp - "$here/PUBLIC.json"
```

## Storage and trust boundary

The fresh home asks archives for selected-height inventory and original blocks. It decides validity locally under the local funded verifier registrations, pinned genesis, PoW and ledger rules. Advertisements guide fetching. Each extension commits only after validation. A known gap persists as incomplete and disables wallet history and spending. A reorganization stages the candidate in a second, independently validated pruned database. A locally derived checksum and SQLite protect the stored state against accidental damage within the stated storage model. The wallet trusts its own validating node for selected payment validity and common records.

The home retains the three latest original block bodies, the selected history's headers/frontiers, compact wallet records with encrypted receipts, transactions' locations, commitments, spent IDs, assets and reward indexes. Compact records still grow. A restarted home can scan its stored selected records for a seed holder. An empty independent validator or a home replacing a branch needs the original evidence. If no copy serves a required proof/body, surviving roots, receipt projections and seeds cannot recreate its historical proof or prove that branch valid. A seed holder also needs the relevant encrypted receipt and public history to rediscover a note and construct its witness. Participation depends on surviving, reachable suppliers of those distinct data. Multiple processes on one machine demonstrate software behavior; they do not measure geographically independent availability.
