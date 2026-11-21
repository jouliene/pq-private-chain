# Upgrade an already-funded private PoW chain

Run on x86-64 Linux with Python 3.10+, Git, rustup, a native C build toolchain, working unprivileged bubblewrap namespaces, curl, xz, tar and SHA-256 utilities. The author ran the co-located lab on a 32 GiB machine. The runner uses Rust 1.93.0, Qnero commit f04c91307837c0231668383bec76ba98d89d2652 and checksum-pinned Node 24.22.1. Leave room for fresh Rust targets, a private wallet lab and peer databases. The chain runs on loopback, using distinct peer and wallet processes. Internet access is needed for the pinned sources, toolchain and public artifacts.

~~~bash
work=$(mktemp -d) &&
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=false \
git -c credential.helper= clone -q --branch funded-upgrade-2026-11-21 \
  https://github.com/jouliene/pq-private-chain.git "$work/src" &&
bash "$work/src/experiments/funded-upgrade/reproduce.sh" "$work/result"
~~~

The command first installs released A, runs real nonce search and funds new wallets. It stops the nodes at height 12. B is then built and registered from source. The node processes restart on their original databases and wallets retain their original backups. The runner exercises the A/B overlap, competing branches, seed recovery, second spend and signed swap. A further empty node must validate the winning ancestry from genesis. The independent public reader derives fees, supply, spentness, work, roots and swap signatures from the block bytes on both sides of the fork. The measured-crypto probe selects an actual competing A/B input from the new capture; the historical A swap used for an equally warmed cryptographic comparison comes from a separate pinned release. [Protocol](PROTOCOL.md) · [Decision and measured costs](DECISION.md)

| Result under the new work directory | What it checks |
|---|---|
| `network/public/RUN.json` | Local funded scenario, wallet balances and proof costs, branch controls and fresh-node outcome |
| `fresh-public.json` | Independent reconstruction of this run's public PoW histories |
| `fresh-owner-checks.json` | Two original backups independently opened by both roles and matched to the actual spent notes |
| `fresh-boundary.json` | Candidate-height admission and retirement on an independently mined public fork |
| `fresh-costs.json` | Full signed pair or ordinary proof checks, registration startup, cross-version proof rejection and statement mutation |
| `released-public.json` | Same monetary and signature reconstruction from the published author archive, compared exactly with the committed result |

To inspect the registrations without building or contacting a peer, run `python3 -IB experiments/funded-upgrade/profile.py`. The calculator decodes the four approved verification keys, accounts for all opening and terminal data and derives the complete physical and submission lengths. The native cross-check compares these lengths with genuine proofs.

After the walkthrough the nodes have stopped. The signed bundle and public block files can be inspected without importing wallet contents. Keep the network home private. Each owner's recovery test uses its original 32-byte seed and the common history, including encrypted receipts. The tagged release contains the 27-block fork graph, a separately mined activation-boundary block and a signed public swap. [Reproduction script](reproduce.sh) · [Downloadable public cases](https://github.com/jouliene/pq-private-chain/releases/tag/funded-upgrade-2026-11-21)

The upgraded client entry is `./pqd upgrade --home HOME --node c`. Its automatic mode selects the proof for the next block on the wallet's selected branch. With peers running, operational examples are `balance NAME`, `restore NEW_NAME PRIVATE_SEED_FILE` and `send NAME @RECIPIENT_ADDRESS_FILE NATIVE ASSET_ID QUANTITY --intent LABEL`. Negotiation uses `terms`, `leg`, `authorize` and `combine` with each party's own wallet. The original `pqd swap` entry remains available for A and is used to fund the prefix.
