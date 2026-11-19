# Independent wallet review

Baseline public implementation `82c803961996864782a5dee050a02b60b4341c0e`. The original walkthrough used complete selected-history snapshots. The new milestone concerns actual wallet operation while blocks continue arriving. This registration precedes the candidate implementation. Fresh measurements and the tested revision will be recorded separately.

## Independently reproduced outcome

The functional wallet milestone passes on the positive-path execution revision `2b6ae99f4f91135ef5974b69fbef987357336711`. A new detached checkout fetched the pinned Qnero source, compiled a new native executable into an initially absent Cargo target, then ran `./pqd --home "$lab/home" wallet-walkthrough` with a fresh network and wallet homes. The 76-second cold build used installed Rust 1.93.0 and cached Cargo downloads. The walkthrough took 279.84 seconds. The product and fetched upstream checkout remained clean. The later first-reservation fix `f87dd7292f80739fffcee91f1444358f189c47b6` received a separate source review. It atomically installs the first actual packet and its real-input reservations after proving succeeds, before network exposure. New attempts retain the same real inputs under the sender's operation lock. [Build and revision identities](evidence/clean/CLEAN.json)

| Actual wallet operation | Short history | Long history |
| --- | ---: | ---: |
| Cold restore at H4 / H40, history payload | 1,229 B | 12,227 B |
| Cold restore, request + reply frames | 5,374 B | 17,986 B |
| Cold restore, CLI wall time / reported peak | 0.237 s / 31,244 KiB | 0.231 s / 31,228 KiB |
| Unchanged balance, history payload / wall time | 0 B / 0.174 s | 0 B / 0.172 s |
| One empty successor, balance history payload / wall time | 314 B / 0.186 s | 314 B / 0.184 s |
| One empty successor, send history payload / wall time at H6 / H42 | 314 B / 14.036 s | 314 B / 13.867 s |
| Send, request + reply frames including authorization | 235,303 B | 235,830 B |
| Sender native setup + genuine proof CPU | 24.856 s | 24.688 s |
| Native sender high-water RSS | 1,090,572 KiB | 1,090,924 KiB |
| Original full scanner, public input at H4 / H40 | 676 B | 5,572 B |

Each warm suffix included one real mined reward block. The H4/H40 starting prefixes contained no ordinary payments and one wallet-owned reward each. The proofs authorize independent transfers from that reward on two branches. Both complete packets were 230,206 B. These are two finite matched measurements. The GUI-free CLI wrapper counted 0.20 / 0.17 seconds of user-plus-system CPU for the two sends and about 31 MiB RSS. The isolated native prover measured its own CPU and peak above. Reporting the wrapper alone would omit the dominant cost. The full scans and durable wallet had identical owned inventories. The newer cold format carries a header and branch context per block. Its smaller warm delta has a different denominator from legacy full-wallet input. [Normal CLI, actual transport and full-scan measurements](evidence/clean/WALLET.json)

A separate readback reconstructed the H4/H40 databases and their extensions from the actual accepted blocks. An unchanged view returned 216 logical metadata bytes and zero history payload. Fresh SQLite connections issued 8,208 / 12,304 main-file bytes at H4/H40, including B-tree page reads. Immediate repeats issued 16 B each. A single empty successor likewise used 16 B on immediate repeat. A single paid successor used 3,616 B each. The hot OS page cache supplied these service reads. In a separate real `Chain.offer` on H6/H42, the node read 20,496 / 24,592 main-database bytes, charged 0 / 4,096 physical input bytes and charged 262,144 write bytes each. Native public verification consumed 10.10 / 10.20 ms CPU. The complete traced admission took 21.22 / 21.53 ms. These admission probes include the mempool insert and exclude mining and subsequent block inclusion. [Database syscall traces](evidence/clean/SQL_READS.json) · [Actual proof admission](evidence/clean/ADMISSION.json)

The receiver exported its address and went offline. Its separate restored wallet discovered 46 across two external receipts, paid 37, paid a 3-unit fee and retained 6. The live sender's 29-unit obligation created three valid authorizations under disconnection, expiry and a lost node reply. The registered verifier checked them all, and each used the same actual real nullifier retained privately by the sender. The selected history contained exactly one at H86 and charged its fee once. The recipient spend reached H101. The original H102 capture had one successor. One additional ordinary block on the same restarted three-node network supplied a second successor at H103, with the receipt spend still selected and a freshly scanned balance of 6. A separate wallet-free replayer accepted all 115 original archived fork blocks and the three candidate authorizations. A public replay of the extended winner returned 10,300 issued, 12 fees and eight spent slots. [Public replay](evidence/clean/PUBLIC_REPLAY.json) · [Successor observation](evidence/clean/TERMINAL.json) · [Extended public replay](evidence/clean/PUBLIC_TERMINAL.json)

The shallow switch rewound one block. The deeper switch discarded an H14 wallet cursor and recovered from genesis. An already-confirmed losing intent whose pinned funding was consumed on the winner could not take an unrelated input. A cold restore interrupted before its second page resumed at height 17 and completed the fixed prefix while the public chain advanced. Five local full-history comparisons checked differently funded wallet states against the separate version-1 scanner, including the restored recipient and the live miner. All 402 positional siblings across 34 positive unspent paths matched the upstream tree on these five views. The explicit wallet-crash check applied a real owned H1 reward, terminated after the owned-row write and before the height cursor write, then recovered the empty cursor. The observed SQLite hot journal was 21,032 B. An invalid root also rolled back, and the valid reward was accepted on retry. [Private comparisons, atomicity and synthetic boundary controls](evidence/clean/DIFFERENTIAL.json)

The compact stream relies on the selected, validating node and the admitted history projection for complete receipt delivery and transaction identities. A client can recompute its owned openings, funded root, ordered monetary transition and membership against the delivered header. Proving and replaying complete blocks is a separate check. Seed recovery reconstructs selected-chain ownership. Persistence of an unconfirmed sender-only intent depends on the sender's private outbox. The measured service used loopback TCP and local PoW. The global PQ/privacy, long-horizon service and archival questions remain open. [Allowlisted complete public blocks and attempts](evidence/clean/public-capture.tar.gz) · [Release-file digests](evidence/clean/SHA256SUMS)

## Acceptance checks

| Property | Discriminating observation |
| --- | --- |
| Cold streaming | Select a fixed public prefix, then append blocks during transfer. Check continuity, record order, length bounds, funded root, input spentness and successful completion of that prefix. Advance to the new tip on another call. Reject a discontinuous chunk without advancing the wallet's durable cursor. Check node read spans and native/Python peak memory independently of advertised page sizes. |
| Warm continuation | Reopen a wallet with an actual prior committed scan. Compare one fixed suffix after different amounts of prior history, plus the same-height no-change case. Observe real TCP frames, data records and database read effort. Verify that any node-side query, checkpoint load, startup or witness preparation that still grows with old history is disclosed. |
| Atomic crash recovery | Interrupt before and after committing a scanned unit. Reopen under the same seed and network, verify durable state is an actual selected prefix, then complete the suffix. Compare the resulting balance, inventory, spend observations and prover anchor with a seed-only cold restore. |
| Competing branch | Put an incoming payment, a mining reward or spending event on a selected branch and detach it. The common prefix must survive. Reject the old branch checkpoint, undo detached ownership and spentness, then scan the replacement. Compare the result with fresh recovery from public genesis. Exercise a checkpoint deeper than retained undo if supported. |
| Spending witness | Verify full upstream four-ary tree roots and circuit-format witnesses on known public positions across depth growth, padding and asymmetric siblings. Require a genuine ordinary proof using a restored external receipt, independently verified by public node software against its effective retained anchor and current spentness. |
| Durable intent | Record a new obligation before network exposure and its exact attempt before the first possible write. Lose an ACK after actual node admission, stop/reopen the client and reconnect. Inspect every observed public attempt and selected block. Derive whether multiple attempts have mutually exclusive real input authorizations. Check disconnection, anchor expiry, changed wallet inventory, repeated reconciliation, reorg of a confirmed payment and a conflicting concurrent invocation. Each obligation has at most one selected economic effect and one selected fee. Pending/ambiguous outcomes must remain visible across process restart. |
| Recipient and privacy | An offline wallet supplies a portable address to a different payer. Confirm the sender requires no recipient directory or private data. A separate receiver restores and spends an external receipt. Inspect passive RPC request fields and framed bytes for two differently owned wallets scanning exactly the same public prefix. Inspect private persistence and permissions locally without emitting any opening, key or derived private identifier. |

Independent accounting will distinguish reported application counters from separately observed frame lengths, logical SQL work, kernel read calls and physical I/O. A hot page cache can make physical reads zero. Measurements will identify the role and operation actually observed. Public evidence may include known fixture amounts, chain data and operation counts. Encrypted wallet files, seeds, openings, private positions, raw syscall payloads and local private logs are excluded.

### Early measurement and correction

An unchanged H4 wallet answered from two SQL results containing 216 bytes of metadata. The initial schema nevertheless issued 171 pread64 calls and read 691,484 bytes from the public SQLite file on an immediate repeat. The database held three actual full payment packets. The header lookup went through the primary B-tree of a WITHOUT ROWID table storing those packets. The H15 repeat read 230,501 bytes. Both probes returned zero receipt/history payload to the wallet. A scratch comparison using a forced narrow covering index for header metadata reduced the repeat to one 16-byte SQLite lock-header read at both heights. An index without an explicit plan requirement left SQLite selecting the original expensive path. The OS served all these measurements from its page cache. The process's charged physical input was zero. [Unmodified and experimental traces](evidence/PRELIMINARY_SQL.json)

The public synthetic path test compares every selected logical sibling and every sorted circuit-format path to the pristine upstream Qnero full tree, including right-edge growth after 4, 16, 64 and 256 leaves. A positional permutation with the same unordered sibling set must fail. The control spans 14 prefix lengths, 1,023 public enumerated paths and 12,309 positional siblings. The private differential separately replays raw actual selected blocks through the original wallet in an isolated seed-only directory, compares all owned status/value/source entries and obtains each positive unspent note's path from the new prover's own data store. It emits only result counts. [Reference source](reference_paths.rs) · [Local differential](private_compare.py)

## Reproduction inputs

The original published reference wallet and new incremental wallet accept the same seed format, fee and verifier profile. The differential runs the old wallet in its own sandbox with only a private temporary seed and the public history reconstructed from complete selected block bodies. Reproduce the older native build using the ordinary devnet prepare path in a separate checkout of `82c803961996864782a5dee050a02b60b4341c0e`. The actual independent run used the previous clean source-built reference executable with SHA-256 `0d74f63ee0a201fd49f62f91b269fa959b5388a17b4665a14dbb77200f9b0634`.

Build the full path oracle against upstream Qnero revision `f04c91307837c0231668383bec76ba98d89d2652` in its own tree. From the project root, the commands below assume `lab` is a fresh private working directory and `$lab/upstream` is that separate, pristine upstream checkout.

```sh
repo=$(pwd)
ex="$lab/upstream/crates/qnero-prover/examples"
mkdir -p "$ex"
cp "$repo/devnet/wallet-review/reference_paths.rs" "$ex/devnet_public_reference_paths.rs"
(cd "$lab/upstream" && CARGO_TARGET_DIR="$lab/ref-target" rustup run 1.93.0 cargo build --locked --release -j2 -p qnero-prover --example devnet_public_reference_paths)
oracle="$lab/ref-target/release/examples/devnet_public_reference_paths"
```

The release walkthrough allocates new test wallets. Keep the home and all logs private. The following post-run commands use the captured public blocks, standard Linux strace, plus the sender or receiver private wallet only for the designated local comparisons. Set `legacy` and `legacy_runtime` to the original verified checkout and its prepared runtime.

```sh
./pqd --home "$lab/home" wallet-walkthrough
rv="$repo/devnet/wallet-review"
rt="$repo/.work/devnet-runtime"
ev="$lab/home/evidence"
python3 -IB "$rv/check_public_reads.py" "$ev" "$rt"
python3 -IB "$rv/check_admission_reads.py" "$ev" "$rt"
python3 -IB "$rv/private_compare.py" --home "$lab/home/receiver" --wallet recipient --node-database "$lab/home/nodes/c/chain.sqlite" --runtime "$rt" --legacy-product "$legacy" --legacy-runtime "$legacy_runtime" --oracle "$oracle"
python3 -IB "$rv/private_intent.py" "$lab/home/client/wallets/live" "$ev" "$lab/home/nodes/c/chain.sqlite" "$rt" offline-order
python3 -IB "$rv/check_scan_atomic.py" --miner-private "$lab/home/wallets/miner-a" --node-database "$lab/home/nodes/a/chain.sqlite" --runtime "$rt" --legacy-product "$legacy" --legacy-runtime "$legacy_runtime" --oracle "$oracle"
```
