# Independent funded spend and swap measurements

Keep MNG1/SWP1 available as a research baseline. The isolated K384 candidate completed the same economic exchange and backup recovery. Its complete ordinary packet and both swap frames exceeded the live 262,144-byte bound, including after canonical compression. Neither profile establishes the target of 128 bits of post-quantum work for the funded composition. [Registered target](../TARGET.md) · [Assurance review](../assurance/REVIEW.md)

An independent reviewer fetched baseline `3f08bff0089096d7fb27279bc0d444006e9147ce` anonymously, reused both previously independently rebuilt and hash-checked binaries, and mined a fresh forked PoW history. The baseline reader reconciled all 38 available blocks and four peer databases. The selected history contained 12 logical payments, 2,700 native units issued and 36 units in fees at height 27. Private local checks linked the two restored wallets' onward spends to their actual incoming commitments. [Baseline measurements and packet hashes](BASELINE.json)

The candidate checkout was a separate anonymous fetch of `2a3a4c4671af54dd7d1171c77b826339d12d8cbf`. Starting with a fresh Cargo target and a pristine upstream clone, the reviewer rebuilt both native roles in 90.89 s. Both executable digests, both new verifier key files and both registration summaries matched the published candidate. Newly generated wallets completed the matched fixture in 112.74 s on an isolated funded commitment tree at synthetic height 1. The independently measured baseline PoW walkthrough took 233.58 s. These elapsed times cover different scenarios. [Build hashes, raw receipt references and timeline](INDEPENDENT.json)

## Matched economics and limits

Both runs started the swap with Alice holding 15 fixed units and 20 native units on her mixed note, and Bob holding 80 managed units and 18 native units on his. Each leg used one real input and one dummy. Alice sent 7 fixed and retained 8 fixed plus 17 native. Bob sent 30 managed and retained 50 managed plus 18 native. Alice paid the single fee of 3 native. Each restored owner forwarded the actual received asset. The featured ordinary spend used the incoming 30 managed units plus a separate native fee note, two real inputs. Amounts and note-source counts are participant disclosures. The public effects reveal nullifiers, commitments, receipt pairs and fee.

The candidate funding reader separately validated four actual MNG1 proofs, the fixed issuance of 70, the managed registration of 300, the authorized mint of 40, and the holder burn of 10. Both native and OpenSSL verified the two issuer signatures. OpenSSL rejected 26 altered issuer bindings. The reviewer recomputed the three funded proof receipt digests and verified both final swap signatures using the separate OpenSSL provider, which rejected 18 alterations. The candidate used the established funded note representation and an isolated domain and ledger. The baseline demonstrated live membership, replay and reorganization. The candidate exercised old-note input and onward compatibility within its synthetic funded fixture.

| Public size in bytes | MNG1/SWP1 | K384 | K384 after compact encoding |
| --- | ---: | ---: | ---: |
| Ordinary complete submission | 143,233 | 495,975 | 399,768 |
| Swap complete submission | 320,905 | 1,026,389 | 840,419 |
| First physical swap frame | 160,446 | 513,188 | 421,307 |
| Second physical swap frame | 160,446 | 513,188 | 419,099 |

The compact codec ran on each actual public proof, then expanded each back to its original canonical bytes. Rebuilding the complete submissions preserved all six encrypted receipts and both authorization signatures. Fresh registered verifiers accepted the reconstructed ordinary spend and both signed legs. An independently assembled compact wire exactly matched the reference encoder for both complete submissions. On these openings the reference codec's three separate encode calls took 22.0–22.8 ms each and decode took 20.8–21.3 ms each, including process launch and its public proof check. Different proof-derived query paths can change these sizes.

## Process costs

One Intel Core i7-8700K ran with two Rayon threads. Wallet rows show the first funded proof call, including lazy prover setup. Baseline CPU uses a before/after reading from the native process. Candidate CPU sums the native lazy-setup and proof timers within that call. Candidate proof-only wall was 5.027, 5.040 and 4.963 s respectively. The two additional candidate final signing calls took 89.85 and 88.61 ms wall. RSS is a separate process high-water mark for each row.

| Wallet role | Baseline wall s | CPU s | Peak KiB | Candidate wall s | CPU s | Peak KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ordinary, two real inputs | 4.835 | 9.380 | 451,940 | 7.344 | 13.480 | 1,837,064 |
| Swap A, one real input | 4.854 | 9.400 | 452,196 | 7.378 | 13.527 | 1,837,184 |
| Swap B, one real input | 4.866 | 9.450 | 451,936 | 7.328 | 13.430 | 1,837,048 |

Cold rows report the median launch-to-verdict of three independent verifier processes. Warm rows report the median of five complete calls after one warmup. The node-side driver checks the complete public envelope, signed statement and returned effects using a native process given only its verifier key. Swap includes two proof checks and both authorizations. Peak values are the largest native process RSS in each series. The timed boundary excludes network I/O, PoW and chain-database insertion. Individual RPC, CPU and setup samples are in the public archives.

| Public workload | Cold wall s | Cold CPU s | Cold peak KiB | Warm wall ms | Warm CPU ms | Warm peak KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline ordinary | 1.312 | 2.404 | 201,100 | 6.41 | 6.27 | 201,104 |
| Baseline whole swap | 1.324 | 2.405 | 201,132 | 23.53 | 23.08 | 201,136 |
| K384 ordinary | 2.487 | 4.024 | 685,116 | 8.81 | 8.51 | 684,892 |
| K384 whole swap | 2.490 | 4.057 | 685,008 | 29.73 | 28.82 | 685,004 |

The WHIR port probe used the four funded public output commitments from this baseline swap. One synthetic four-child Goldilocks parent required 2,536 R1CS rows, including 1,416 S-box multiplication rows. Its root `1d3b3b3252140caedbf442666ab7dfd1845b250ffb8f627f0dd5995ca6653707` matched the independent pinned upstream native reference. The altered parent failed. The probe covers one hash. A full funded monetary relation, its receiving interface, proof generation, verification and target-level analysis remain to be demonstrated for WHIR.

## Public release files

| Allowlisted release archive | Bytes | SHA-256 |
| --- | ---: | --- |
| `SPEND-baseline-public.tar.gz` | 461,798 | `7efdf6c3d679422af39b0c042b9d82808ddb43515b70f6103128a9e1be5048a7` |
| `SPEND-baseline-PoW-public.tar.gz` | 5,936,434 | `142e5eeaa33cdd273739e0972db06fd1fdddddef4051656b23aeca5b56bdaf5a` |
| `SPEND-K384-independent-public.tar.gz` | 3,362,801 | `4a6a4141c522e2488cb262163f6c693d27730428fbdd5de42e21fa85b3461e90` |

All three archives contain regular files with a checked `SHA256SUMS` manifest. The baseline specimen has two submissions, public verification samples, aggregate funded and local-wallet reconciliation results. The graph archive contains the complete public block graph, packets and controls. The candidate archive has 21 entries, including four signed-or-proof-authorized historical operations, the full and compressed ordinary and swap submissions, registration receipts, numeric wallet/node/codec meters, UTC timeline and independent checks. The tracked machine report lists each candidate entry. On extraction into separate empty directories, run `sha256sum -c SHA256SUMS` in each directory.
## Reproduce

Use Linux, the repository's pinned Rust 1.93.0 toolchain and a Node 24.22.1 executable reporting OpenSSL 3.5.9. Set `W` to an unused absolute working directory and `NODE24` to that executable. Shell commands start in this report's repository. The historical walkthrough mines new funds and creates new wallets. Readers with the published specimens can skip wallet generation and supply their extracted public directories to the verifiers.

```sh
set -eu
export RAYON_NUM_THREADS=2
S="$PWD/experiments/spend-proof-decision"
mkdir -p "$W"
git clone https://github.com/jouliene/pq-private-chain.git "$W/baseline-src"
git -C "$W/baseline-src" checkout --detach 3f08bff0089096d7fb27279bc0d444006e9147ce
"$W/baseline-src/pqd" swap --home "$W/net" walkthrough
set -- "$W/net"/source-build-*/build
B=$1
python3 -IB "$S/review/export_baseline.py" "$W/net" "$W/base-public"
python3 -IB "$W/baseline-src/experiments/user-assets/review/build_helpers.py" "$B/upstream" "$W/helpers"
git clone https://github.com/jouliene/pq-private-chain.git "$W/candidate-src"
git -C "$W/candidate-src" checkout --detach 2a3a4c4671af54dd7d1171c77b826339d12d8cbf
C="$W/candidate-src/experiments/spend-proof-decision"
python3 -IB "$C/candidate/reproduce.py" "$W/k384" "$B/upstream" "$B/roles"
python3 -IB "$C/candidate/build_compact.py" "$W/codec" "$B/upstream" "$W/k384/target"
A="$W/k384/roles"
K="$W/k384/public"
H="$W/helpers/roots"
pin() { sha256sum "$1" | cut -d' ' -f1; }
ok=$(pin "$C/candidate/registry/managed.vk")
sk=$(pin "$C/candidate/registry/swap.vk")
height=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["swap_height"])' "$W/base-public/funded-receipt.json")
meters() {
  profile=$1; pub=$2; ordinary=$3; leg=$4; inclusion=$5
  python3 -IB "$S/review/measure_public.py" --profile "$profile" --inclusion-height "$inclusion" \
    --ordinary "$pub/ordinary.bin" --ordinary-binary "$ordinary/native" --ordinary-sha "$(pin "$ordinary/native")" \
    --ordinary-key "$ordinary/registered/managed.vk" --ordinary-vk-sha "$ok" \
    --swap "$pub/swap.bin" --swap-binary "$leg/native" --swap-sha "$(pin "$leg/native")" \
    --swap-key "$leg/registered/swap.vk" --swap-vk-sha "$sk" > "$W/$profile-verification.json"
  python3 -IB "$S/review/inspect_public.py" "$profile" "$pub/ordinary.bin" "$pub/swap.bin" "$H" "$NODE24"
}
meters baseline "$W/base-public" "$B/roles" "$B/swap" "$height"
meters k384 "$K" "$A/ordinary" "$A/leg" 1
python3 -IB "$S/review/check_candidate.py" "$K" "$B/roles" "$NODE24" "$H" "$(pin "$B/roles/native")"
python3 -IB "$S/review/roundtrip.py" "$K" "$A" "$W/codec/compact" "$W/roundtrip" "$H" "$NODE24" \
  --ordinary-vk-sha "$ok" --swap-vk-sha "$sk" --codec-sha "$(pin "$W/codec/compact")"
python3 -IB "$C/compact/compare.py" "$W/codec/compact" "$K" "$W/canonical"
cmp "$W/roundtrip/ordinary.compact" "$W/canonical/ordinary.compact"
cmp "$W/roundtrip/swap.compact" "$W/canonical/swap.compact"
set -- "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/qp-poseidon-core-3.1.0/src/poseidon2.rs
python3 -IB "$C/whir_port.py" "$1" "$H" "$W/base-public/swap.bin"
```

To replay all mined blocks, use the baseline checkout's independent reader with the generated deployment and upstream helper binaries. To check local wallet disclosures, run its separate wallet-joins script against the generated home. The same reader accepts the public PoW release archive's `public/` directory. [Graph and optional local-wallet commands](../../atomic-swap/review/CLEAN.md#reproduction)
