# Local proof-of-work devnet

Run on Linux x86-64 with Python 3.10+, git, a C toolchain, rustup, bubblewrap with working unprivileged user namespaces, and outbound access for a first source build. On Ubuntu with rustup already installed, the additional packages are `build-essential git python3 bubblewrap`. The first launch fetches pinned Qnero source and locked Cargo dependencies, installs Rust 1.93.0 when necessary, builds the verifier and wallet and checks the committed public verifier registry. Budget 3 GiB of RAM and several GiB of build space. Keep the generated wallets and their backups private. All amounts below are integer devnet units.

```sh
./pqd start
```

This launches A and B mining independently on ordinary CPUs and C validating. They communicate over separate loopback TCP ports printed by `./pqd status`. Each has its own database, pending payments and isolated native verifier. The three nodes start with zero created currency. New blocks mint 100 units; a miner can spend its own reward at the next eligible height. The process that starts the network can exit. Use `./pqd stop` to stop the nodes and miners; a subsequent start reopens their databases and wallets.

### Pay an offline recipient

Alice can export her receiving address before going offline. Her 32-byte seed is the private backup. Exchange only the address file using an authenticated channel.

```sh
./pqd create alice
./pqd export-address alice "$HOME/alice.pqaddr"
./pqd backup alice "$HOME/alice-pqdev.seed"
```

From the sender's wallet, use the public address file once there are at least 40 confirmed units. A 100-unit input pays 37, recycles the fixed fee of 3 and returns 60 change. The wallet supports one or two positive-value inputs.

```sh
./pqd balance miner-a
./pqd send miner-a "@$HOME/alice.pqaddr" 37 --intent invoice-17 --wait 180
```

`submitted` means the validating node acknowledged a pending packet. `confirmed` means the payment appeared on the locally selected branch at the observed cursor. If a connection drops or the sender closes the client, use the saved intent on reconnection. `resume` uses the sender's original private wallet directory and needs no further copy of the address file. A fork can undo a confirmation.

```sh
./pqd intents miner-a
./pqd resume miner-a invoice-17 --node b --wait 180
```

An intent permanently binds the recipient, amount and its selected real inputs. Reusing its ID returns the same logical payment. Supply a new ID for a deliberately separate transfer, including a second transfer of the same amount to the same address. Without `--intent`, the wallet derives a stable local ID for the address and amount. With no `--wait` the command returns on acknowledgement. `--wait` allows polling for selected inclusion; proof work and bounded RPCs take their own time. When a reserved input becomes unavailable on the selected branch, the intent reports that state and retains its reservation.

Alice can restore on a fresh wallet installation connected to her validating node and spend after opening her encrypted receipt. To resume an interrupted restoration, rerun the same command, or use `balance` on the already installed wallet. `--max-blocks N` explicitly limits a restore invocation and reports whether its selected prefix is complete.

```sh
./pqd restore alice-restored "$HOME/alice-pqdev.seed"
./pqd balance alice-restored
./pqd send alice-restored miner-b 11 --intent return-11 --wait 180
```

Balance, send and restore now use a persistent private cursor, inventory, spent state and local membership paths. An unchanged head requires zero historical payload; new data are requested in common ranges of at most 16 blocks. Cold recovery chooses a fixed validated prefix, commits completed pages, then samples a fresh head for bounded catch-up. A retained checkpoint handles shallow forks. A deeper divergence triggers replay of the replacement history from genesis. Protect the private wallet directory: the seed restores on-chain holdings; the local outbox additionally preserves off-chain intentions, input reservations and previously transmitted packets. Stop wallet commands before copying the entire private wallet directory for an operational backup.

### Reproduce the ordinary wallet milestone

```sh
./pqd wallet-walkthrough
```

Install the GNU `time` utility for the measured walkthrough. It starts a fresh isolated network, exercises normal CLI commands at two real mined history sizes, interrupts a restore during active mining, disconnects a sender before submission and after a valid acknowledgement, and checks a fresh recipient spend. It writes measurements and public artifacts to the printed evidence directory. [Wallet measurements](WALLET_RESULTS.md) · [Wallet sync and intent design](WALLET_PROTOCOL.md)

### Reproduce the acceptance walkthrough

```sh
./pqd walkthrough
```

The command creates a fresh isolated home, starts three real peers, and later starts a fourth empty peer. It directs miners to search for a bounded number of actual blocks, partitions and reconnects peers, then stops all its own daemons. Each node invokes the same block validator and cumulative-work selector. No command appoints a winning tip. The command prints the path to `evidence/RESULT.json`. The sibling `blocks/` directory holds complete public blocks from both branches. An explicit path is also supported, e.g. `./pqd --home "$PWD/.work/first-pow-demo" walkthrough`; it must be empty or absent. A working source build can be reused across homes with `--runtime DIR` before the subcommand.

The walkthrough checks zero genesis, direct lone submission, duplicate-spend rejection, an independently mined reward, an encrypted receipt, seed-only restore followed by a new authorized spend, two independently funded payments in one block, and a competing fork with a losing reward and a losing payment. The isolated node had ten selected blocks above the fork and a local undo horizon of eight. The healthy peers serve public blocks. Each node chooses its own branch, and the recovering node revalidates available history from genesis. A fourth node starts at zero and downloads the winner. The test compares work, tip, anchor, funded root, spent-set digest, fee and issuance counters. It restarts the recovered node before shutting down. The fixed target and PoW randomness affect run time.

### Trust and scope

All peers reverify payment proofs, both ciphertext bindings, ordering, current nullifiers, anchored membership eligibility and the exact reward commitment. The block body contains each complete APV2 singleton. Validators select their own archived, fully validated greatest-work chain. The wallet delegates chain selection and spentness to its chosen local validating node. It checks the funded root and maintains private membership paths from common public data. The code retains full public history, including known side blocks, with bounded block size and a 64-entry mempool. Deep competing branches can trigger costly repeated validation.

The devnet exposes the mining beneficiary and public coinbase openings. A mining beneficiary's publicly derivable note information needs to be considered when assessing reward-spend linkability. Loopback topology and public submission provide no network anonymity. This fixed-difficulty research network has no production difficulty adjustment, finality or permissionless economic-security result. Finite proofs and receipt tests do not establish end-to-end quantum knowledge soundness, zero knowledge or recipient anonymity under composition. Archive affordability remains open. Private native assets with native fees and indivisible two-owner swaps remain on the versioned roadmap. CP03 and WHIR retain their existing independent reproduction paths.

See the [measured results and decision](RESULTS.md), [continuous-miner payment experiment](LIVE.md), [consensus and monetary rules](CONSENSUS.md), [wallet implementation](wallet.py), [native crypto build and checks](crypto/) and [independent review](review/REVIEW.md).
