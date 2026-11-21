# Independent anonymous public reproduction

I cloned `https://github.com/jouliene/pq-private-chain.git` into a new directory with an empty HOME, cleared environment, disabled system/global Git configuration, disabled credential helpers and prompts, and disabled the file transport. The checkout had no object alternates or local source fallback. The clone's HEAD and origin/main were both `ca07f7bf06fbab92210076292639c64096a4d393`. I checked ancestry of the opening baseline `ceab1e4fd786e8f9ac0a99cc9a805423fe4a3b73` and the tested revision on origin/main, then checked out the tested revision detached. [Tested source](https://github.com/jouliene/pq-private-chain/tree/ca07f7bf06fbab92210076292639c64096a4d393)

From that checkout I ran the published command below. It completed with exit status zero. The Rust 1.93.0 build fetched the locked crates into a fresh Cargo home and built into an empty target directory. The downloaded Node 24.22.1 executable and archive passed both checksums. It reported OpenSSL 3.5.9. The release capture was 998,809 bytes with SHA-256 `a2c86306cb1d4385d7638a876e17fe431cd6d2e2bd99e538ce2fc6a66b139051`. Both prior FTL1 release archives passed their original checksums. The source checkout remained clean. [Release capture](https://github.com/jouliene/pq-private-chain/releases/tag/new-note-2026-11-21)

```sh
bash experiments/new-note/reproduce.sh "$(mktemp -d)/independent" --controls
```

## Funded results

The isolated public-only verifier replayed three released blocks, including all four genuine proofs. The final tip, note root, spent digest, issuance and fee totals matched the published receipt. I then ran four new one-seed wallets on a fresh founding record. The new recipient process had an empty wallet directory and its own backup. It discovered the received (4 native, 13 A), combined it with its independently funded 8 native, paid (5 native, 3 A) plus 3 fee, and retained (4 native, 10 A). The two swap wallets verified both proof-bearing legs, decrypted their incoming notes and change, and approved the same pair. After settlement, Carol had (7 native, 7 A, 30 B) and Dana (7 native, 7 A, 5 B). Independent replay of the new chain recovered 15 leaves, eight spent nullifiers, 37 native including 9 miner fees, 48 A and 35 B. Its founding digest, final tip and note root differed from the released history.

| Funded role | Released proof B | Fresh proof B | Fresh submitted packet or signed leg B |
|---|---:|---:|---:|
| Ordinary transfer | 226,816 | 231,427 | 235,268 |
| Recovered onward spend | 237,092 | 236,179 | 240,020 |
| Swap side one | 231,235 | 231,523 | 252,537 |
| Swap side two | 233,781 | 235,558 | 256,572 |

The fresh complete swap bundle occupied 509,121 bytes and its block 509,301 bytes. A second calculation using the physical query indices in each of the eight captured proofs reconstructed every compressed body length. An additional independent 237,526-byte relation-only proof passed. All six public-statement changes and seven invalid witness cases returned nonzero. The funded controls rejected altered root/count, receipt, proof, signature, foreign network, incomplete swap, spent inputs and incompatible old/new envelopes.

Fresh native proving and internal verification across the four wallets used 5.60–5.82 s wall, 16.50–17.03 core-s and up to 1,855,776 KiB individual peak RSS. Full wallet preparation including replay took 6.05–10.54 s. On clean replay of the independently generated capture, complete native verification took 1.983–2.039 s per proof, 4.85–5.03 core-s and up to 729,256 KiB individual peak RSS. Specialization took 1.822–1.868 s, and decoding, decompression, canonical recompression and proof checking took 12.03–12.77 ms. The sampled wall and CPU bounds refer to this host and four funded proofs.

## Decision

The historical byte counts, SHA3 price, new frame geometry and public-row component matched. The measured candidate fits its isolated 272-KiB frame, and its 267,134-byte maximum signed shape exceeds the live 262,144-byte frame by 4,990 bytes. The 542,316,880-byte N3B1 body was priced from the full relation and codec. The independently funded run supports keeping the live registrations, retaining the new pool for research and testing a fixed-verifier design. Quantum knowledge, adaptive joint hiding and sustained network or wallet service remain open. [Design review](REVIEW.md) · [Decision](../DECISION.md)

## Replay the independent funding capture

Use the clean checked-out source and the tool directory from a completed reproduction above. Set `work` to the output directory passed to the script. The second archive contains only the public genesis record and the three numbered public blocks. The separately pinned founding ID authenticates the selected genesis. Compare the result with the fresh public replay state in the [raw measurements](FRESH.json).

```sh
capture=$(mktemp -d)
curl -fsSL https://github.com/jouliene/pq-private-chain/releases/download/new-note-2026-11-21/independent-notes.tar.gz -o "$capture/independent-notes.tar.gz"
(cd "$capture" && echo '1a04bdd9ccb9c6467d8d05220b9fd49d31bed1cd79a4e92a1c9d412375b062da  independent-notes.tar.gz' | sha256sum -c -)
tar -xzf "$capture/independent-notes.tar.gz" -C "$capture" public/genesis.json public/block-0001.bin public/block-0002.bin public/block-0003.bin
echo 'e009a8fcf4e2a9cdb418a09c88946fcebc02a90bf3d0cc4acc574ef1fbe33f1efef63d9b5c4c6bb410bb3e710d7b8bea' > "$capture/founding-id"
python3 -IB experiments/new-note/lab/run.py verify "$work/target/release/n7p1" "$work/tools/node-v24.22.1-linux-x64/bin/node" "$capture"
```

I downloaded that independent archive anonymously after publication, checked its SHA-256, unpacked precisely those four public files into another empty directory and ran the command with my freshly built binary. Its separate verifier checked all four proofs and reproduced the same exact public state as the newly generated branch.

## Public CI

An anonymous GitHub Actions API readback returned status `completed`, conclusion `success`, and head SHA `ca07f7bf06fbab92210076292639c64096a4d393` for both workflows. The payment and PoW workflows cover their established network paths. The clean-clone run above independently exercised the new pool. [Research payment smoke, run 44868206834](https://github.com/jouliene/pq-private-chain/actions/runs/44868206834) · [Local proof-of-work devnet, run 44868206872](https://github.com/jouliene/pq-private-chain/actions/runs/44868206872)
