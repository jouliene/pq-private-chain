# Recursive historical certificate

D8C1 checks eight direct DLF1 proofs inside one fixed recursive circuit. The wallet has already made and transmitted its ordinary hiding DLF1 packet. The builder has neither wallet keys nor note openings. Only an archivist wishing to replace ordinary proof sources uses this role; a producer can continue to receive individual payers. [Preregistered relation and wire](PROFILE.md)

## Measured, distinct historical authorizations

The full certificate covers eight independent two-positive-input, two-output wallet authorizations with fee three each. They were included at H21, H25, H28, H32, H40, H43, H50 and H56 and refer to eight distinct anchor heights H18, H21, H26, H28, H32, H40, H44 and H50. The second certificate covers the two distinct public source files 7 and 8, both anchored at H50. A separate approved DLF1 verifier checked all nine supplied unique sources. A fresh D8C1 verifier returned identical 3,756-byte public rows for every real slot, including both ordered ciphertexts.

| Operation | 8 real slots | 2 real slots |
|---|---:|---:|
| Original complete packets (143,187 B each) | 1,145,496 B | 286,374 B |
| D8C1 proof, including 210 public field elements | 179,806 B | 179,806 B |
| Receipts + certificate framing | 28,672 + 9 B | 7,168 + 9 B |
| Complete certificate | 208,487 B | 186,983 B |
| Certificate B per used payment | 26,060.875 | 93,491.5 |
| Warm source validation and assignment (wall / CPU) | 0.0568 / 0.0567 s | 0.0179 / 0.0179 s |
| Warm proving (wall / CPU) | 56.623 / 111.026 s | 56.316 / 110.379 s |
| Builder process lifetime peak RSS | 6,837,596 KiB | 6,838,312 KiB |
| Public certificate verification (wall / CPU) | 11.493 / 11.492 ms | 8.845 / 8.845 ms |
| Verifier process lifetime peak RSS at first positive check per width | 4,424 KiB | 4,696 KiB |

The builder's cold source-derived setup took 25.423 s, 47.006 CPU-s and 2,717,216 KiB peak RSS. Separate registration took 25.484 s and 46.791 CPU-s. Native cold verifier decoding took 0.104 ms with 3,256 KiB peak RSS; launching its isolated role, reading and checking its keys, and receiving its ready signal took 19.97 ms on this installation. Each native prover used at most two Rayon threads. Wall measurements here omit waiting for wallets, chain updates and archives. The two widths use the same number of recursive verification gadgets; lowering occupancy reduced ciphertext bytes and input preparation but did little for the heavy proof work. Each cited positive proving/verification time is a single observation. The refund of archive bytes occurs only after the rest of the chain can reconstruct its validated cores and receipts. [Public measurements and mutation outcomes](CERTIFICATES.json)

Fully populated service at 100M included payments in 365 days requires about 22.5 warm builder service-seconds and 44.0 builder CPU-seconds per wall second at this rate. Twenty-three such workers at the observed process high-water mark sum to roughly 150 GiB. This is a capacity projection before queue growth, contention, idle workers, registration and storage. Certificate bytes alone project to 2.606 TB/year at eight useful slots or 9.349 TB at two. Every wallet still sends its original complete direct authorization; eight encoded submit requests under the tested DLF1 RPC total 1,145,680 B. Retained core, manifest, archive framing, sparse tails, orphan copies, hot sources, availability services, replication and cold wallet traffic belong to the complete architecture comparison.

## Binding and privacy boundary

The inner key is compiled into the outer constraints as constants. The verified inner proofs each contribute precisely the 26 DLF1 public fields, in order, to the registered outer relation. A nonempty Boolean active prefix determines the authenticated real count. For an inactive slot all 26 fields equal the preceding slot, and its proof still verifies. The producer uses the last real public proof for this padding. The decoder checks the public domain and active count, exact source/receipt lengths, byte-canonical proof encoding, padding, fee, receipt encoding and digest, and distinct real inputs and outputs within the whole certificate. Fresh admission/replay must check placement and historic anchor, nullifiers, commitments, reward and state elsewhere. A valid certificate alone carries no entitlement to apply its extra slots to a branch. [Fixed verifier circuit and packet logic](main.rs) · [Pinned upstream constant-key helper](https://raw.githubusercontent.com/DigitalGuards/qnero/f04c91307837c0231668383bec76ba98d89d2652/crates/qnero-aggregator/src/recursive.rs)

DLF1's hiding spend is unchanged. The outer circuit's own witnesses can be derived from the original public direct proofs and the disclosed active count. Choosing a non-hiding outer saves its blinding overhead and makes no secrecy promise about those public proof transcripts to an archive-only observer. Spending privacy still depends on the blinded inner proof, ciphertext privacy and the chain/network setting. The 130-bit raw query parameter product is a conditional screen; it is not an end-to-end QROM, privacy or post-quantum knowledge-soundness proof.

The outer verifies against locally approved `direct.vk`, and the fast verifier reads its locally approved `eight.vk`. Their SHA-256 digests, byte lengths and dimensions are pinned in the operator's registry. The public network sends only a certificate. `CertificateVerifier` and `CertificateBuilder` check both artifact hashes and the caller's approved native executable digest before mounting the two-key directory read-only inside bubblewrap. The public services have no network or wallet mount. Calling the native binary directly with an arbitrary key directory would entrust program selection to that directory's owner. [Registry](registry.json) · [Operator launch API](certrole.py)

## Reproduce

Use the platform and rustc 1.93.0 from the DLF1 build. Point `qnero` to a clean checkout of upstream commit `f04c91307837c0231668383bec76ba98d89d2652`. Populate its locked Cargo dependencies before the offline build. The example temporarily overlays sources into this disposable checkout and removes them on exit. Keep one writer per checkout and target. A new installation may yield a different executable hash; the source-derived verifier bytes must match.

```sh
(cd "$qnero" && rustup run 1.93.0 cargo fetch --locked)
python3 -IB experiments/delayed-eight/crypto/build.py "$qnero" "$cargo_target" "$work/native-build"
python3 -IB experiments/delayed-eight/crypto/register.py "$work/native-build" "$work/keys" > "$work/registration.json"
cmp "$work/keys/direct.vk" experiments/delayed-eight/crypto/keys/direct.vk
cmp "$work/keys/eight.vk" experiments/delayed-eight/crypto/keys/eight.vk
python3 -IB experiments/delayed-eight/crypto/run.py "$work/native-build" "$work/keys" "$dlf_deploy" "$capture/packets" "$work/certificates"
python3 -IB experiments/delayed-eight/crypto/run.py "$work/native-build" "$work/keys" "$dlf_deploy" "$capture/packets" "$work/certificates" --replay
```

The default source grouping is indices 0–7 for the full certificate and indices 7,8 for the partial certificate. `run.py` writes each completed certificate atomically before starting the next. Its replayer derives the expected effects from ordinary public DLF1 proofs for this differential check. The installed archive verifier uses only certificates, registered keys and the committed cores. To reuse it in Python, open `CertificateVerifier(binary, approved_binary_sha256, keys)` as a context manager and call `verify(certificate_bytes)`. It returns an ordered list of authenticated public byte rows and raises `ValueError` for invalid data. After closure the `meters` attribute contains the native CPU, elapsed and resident high-water metrics. The builder exposes the corresponding `prove(public_direct_packets)` method. Stored keys occupy 1,481 and 1,713 B. [Exact build inputs](BUILD.json) · [Harness](run.py)
