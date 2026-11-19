# Local proof-of-work devnet

Run on Linux x86-64 with Python 3.10+, git, a C toolchain, rustup, bubblewrap with working unprivileged user namespaces, and outbound access for a first source build. On Ubuntu with rustup already installed, the additional packages are `build-essential git python3 bubblewrap`. The first launch fetches pinned Qnero source and locked Cargo dependencies, installs Rust 1.93.0 when necessary, builds the verifier and wallet and checks the committed public verifier registry. Budget 3 GiB of RAM and several GiB of build space. Keep the generated wallets and their backups private. All amounts below are integer devnet units.

```sh
./pqd start
```

This launches A and B mining independently on ordinary CPUs and C validating. They communicate over separate loopback TCP ports printed by `./pqd status`. Each has its own database, pending payments and isolated native verifier. The three nodes start with zero created currency. New blocks mint 100 units; a miner can spend its own reward at the next eligible height. The process that starts the network can exit. Use `./pqd stop` to stop the nodes and miners; a subsequent start reopens their databases and wallets.

### Try a payment yourself

```sh
./pqd create alice
./pqd balance miner-a
# Once miner-a has at least 40 confirmed units:
./pqd send miner-a alice 37
./pqd balance alice
```

The send command displays the miner wallet's selected input total, amount, fixed three-unit fee, change, transaction ID and packet size. A 100-unit input yields 60 units of change. Submission places a pending transaction in validator C's own mempool. Run the balance command again after inclusion. Reading a balance scans the selected branch locally. The current devnet wallet can combine at most two positive-value inputs. A fork or expiry during proving may require a fresh balance scan and proof. An acknowledged payment is pending until it is included on the selected branch. Check its receipt before sending another payment.

```sh
./pqd backup alice "$HOME/alice-pqdev.seed"
./pqd restore alice-restored "$HOME/alice-pqdev.seed"
./pqd balance alice-restored
./pqd send alice-restored miner-b 11
./pqd stop
```

The binary seed file contains the complete spending and viewing authority for this wallet. Keep it outside Git, accessible only to the owner. Restoration creates a new wallet from that file and the public selected history. The local demo runs under one OS account; each wallet role sees only its own seed directory and public material. The optional control socket restricts mining, topology and stop commands to the owner. Loopback clients may submit public payments and public blocks.

### Reproduce the acceptance walkthrough

```sh
./pqd walkthrough
```

The command creates a fresh isolated home, starts three real peers, and later starts a fourth empty peer. It directs miners to search for a bounded number of actual blocks, partitions and reconnects peers, then stops all its own daemons. Each node invokes the same block validator and cumulative-work selector. No command appoints a winning tip. The command prints the path to `evidence/RESULT.json`. The sibling `blocks/` directory holds complete public blocks from both branches. An explicit path is also supported, e.g. `./pqd --home "$PWD/.work/first-pow-demo" walkthrough`; it must be empty or absent. A working source build can be reused across homes with `--runtime DIR` before the subcommand.

The walkthrough checks zero genesis, direct lone submission, duplicate-spend rejection, an independently mined reward, an encrypted receipt, seed-only restore followed by a new authorized spend, two independently funded payments in one block, and a competing fork with a losing reward and a losing payment. The isolated node had ten selected blocks above the fork and a local undo horizon of eight. The healthy peers serve public blocks. Each node chooses its own branch, and the recovering node revalidates available history from genesis. A fourth node starts at zero and downloads the winner. The test compares work, tip, anchor, funded root, spent-set digest, fee and issuance counters. It restarts the recovered node before shutting down. The fixed target and PoW randomness affect run time.

### Trust and scope

All peers reverify payment proofs, both ciphertext bindings, ordering, current nullifiers, anchored membership eligibility and the exact reward commitment. The block body contains each complete APV2 singleton. Validators select their own archived, fully validated greatest-work chain. The wallet delegates chain selection and spentness to its chosen local validating node. It checks the funded tree and recomputes membership locally from common public data. The code retains full public history, including known side blocks, with bounded block size and a 64-entry mempool. Deep competing branches can trigger costly repeated validation.

The devnet exposes the mining beneficiary and public coinbase openings. A mining beneficiary's publicly derivable note information needs to be considered when assessing reward-spend linkability. Loopback topology and public submission provide no network anonymity. This fixed-difficulty research network has no production difficulty adjustment, finality or permissionless economic-security result. Finite proofs and receipt tests do not establish end-to-end quantum knowledge soundness, zero knowledge or recipient anonymity under composition. Archive affordability remains open. Private native assets with native fees and indivisible two-owner swaps remain on the versioned roadmap. CP03 and WHIR retain their existing independent reproduction paths.

See the [measured results and decision](RESULTS.md), [continuous-miner payment experiment](LIVE.md), [consensus and monetary rules](CONSENSUS.md), [wallet implementation](wallet.py), [native crypto build and checks](crypto/) and [independent review](review/REVIEW.md).
