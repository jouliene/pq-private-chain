# Reproducing the advancing-chain payment experiment

Use a clean checkout of the published revision. The APV2 roles were tested on Linux x86-64, with Python 3.11+, SQLite with dbstat, a C linker, Git, rustup, unprivileged bubblewrap user namespaces, /proc and private tmpfs at /dev/shm. Build and proving are substantial. Use a fresh output directory for each invocation; the commands intentionally refuse to overwrite results. An independently supplied registry fingerprint selects the payment program. The author and reviewer used separate clean upstream sources, builds, approved deployment registries, fresh wallet keys and funding. The archived measurements identify their physical test host.

From the project root in Bash, prepare the locked dependency closure once. The build driver checks the upstream Git revision and clean tree, original configuration hash, restores the disposable checkout and records overlay, compiler, lockfile and final executable identities. Source paths and compiler environments can change a binary identity. Inspect the build before approving that locally produced binary. The expected verifier registration is identical across reproductions.

```sh
set -euo pipefail
lab=$(mktemp -d)
d=experiments/advancing-payments
rustup toolchain install 1.93.0 --profile minimal
git clone https://github.com/DigitalGuards/qnero.git "$lab/qnero"
git -C "$lab/qnero" checkout --detach f04c91307837c0231668383bec76ba98d89d2652
(cd "$lab/qnero" && rustup run 1.93.0 cargo fetch --locked)
python3 -IB "$d/crypto/build.py" "$lab/qnero" "$lab/target" "$lab/crypto" > "$lab/build.json"
exesha=$(sha256sum "$lab/crypto" | cut -d' ' -f1)
profile=af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1
base=(--binary "$lab/crypto" --binary-sha "$exesha" --keys "$lab/keys")
python3 -IB "$d/run.py" register "${base[@]}" > "$lab/registration.json"
python3 -IB "$d/assurance/check.py" --registry "$lab/keys" --approve-manifest "$profile"
deploy=("${base[@]}" --profile-sha "$profile")
```

The repository also includes the public registry (20,094 B total). A verifier can point `--keys` at `experiments/advancing-payments/evidence/public-registry` with the same approved hash. To validate the build/registration correspondence, compare all 16 files using `diff -qr "$lab/keys" "$d/evidence/public-registry"` after fresh registration.

The fast public-only reproductions require no private data or historical wallet. They reconstruct every recorded block from the exact framing and stored proof/ciphertext packet. They verify each payment anew, reconstruct competing selections, re-execute rejection controls and compare both archival and pruned state. The separate direct sequence verifies every paid and empty opportunity.

```sh
main_genesis=6456501cfd69a57a85ab4cb734ced5ef36d5b4b20c8e9cc6e05e9684981ae55e
direct_genesis=bce5f8065b45b1d1c1238977c1956aa5c7db7d6ac6095c495fd5787a1f9640c0
python3 -IB "$d/run.py" replay "${deploy[@]}" --genesis-sha "$main_genesis" \
  --evidence "$d/evidence/main" --work "$lab/public-main"
python3 -IB "$d/run.py" replay-direct "${deploy[@]}" --genesis-sha "$direct_genesis" \
  --evidence "$d/evidence/direct" --work "$lab/public-direct"
python3 -IB "$d/incoming_only.py" replay "${deploy[@]}" --genesis-sha 8718d0efa7401164b837061bcaa91ed79a8c392b79afec865574471fa609745e \
  --evidence "$d/evidence/incoming" --work "$lab/public-incoming"
python3 -IB "$d/assurance/extensions/controls.py"
python3 -IB "$d/assurance/pending_failover.py" "${deploy[@]}" --main "$d/evidence/main" --genesis-sha "$main_genesis" --worker absent
```

Run the measured campaigns in sequence on an otherwise idle host. Wallet secrets are freshly generated inside isolated processes with a private temporary backup mount. Published evidence consists of proofs, encrypted receipts, public funding commitments, block headers, selected states, public negative controls and resource counts. Fresh keys, fresh proof randomness and local clock variation necessarily change the exact funding, packet digests and timings.

```sh
python3 -IB "$d/run.py" campaign "${deploy[@]}" \
  --evidence "$lab/fresh-main" --work "$lab/node"
python3 -IB "$d/direct_live.py" "${deploy[@]}" \
  --evidence "$lab/fresh-direct" --work "$lab/direct-node"
python3 -IB "$d/incoming_only.py" trial "${deploy[@]}" \
  --evidence "$lab/fresh-incoming" --work "$lab/incoming-node"
python3 -IB "$d/storage.py" "$lab/node/selected.sqlite" "$lab/node/peer.sqlite" \
  "$lab/compacted" > "$lab/STORAGE.json"
```

Run the independent-clock aggregation from the four public wallet submissions in either complete **main** capture. A fresh aggregation requires a warm-capable prover but has no wallet keys or reopening data. The public replay consumes the supplied outer proof and verifies every mapped singleton and epoch decision.

```sh
python3 -IB "$d/aggregate_clock.py" replay "${deploy[@]}" --genesis-sha "$main_genesis" \
  --main "$d/evidence/main" --evidence "$d/evidence/clock" --work "$lab/replay-clock"
python3 -IB "$d/aggregate_clock.py" trial "${deploy[@]}" --genesis-sha "$main_genesis" \
  --main "$d/evidence/main" --evidence "$lab/fresh-clock" --work "$lab/fresh-clock-db"
python3 -IB "$d/costs/roles.py" "$d/evidence/main" --replay "$d/evidence/PUBLIC_REPLAY.json" \
  --storage "$d/evidence/STORAGE.json" --direct "$d/evidence/direct/DIRECT.json" --clock "$d/evidence/clock/CLOCK.json"
```

The same pending-failover command supports `exited`, `disconnect` and `healthy` with a real registered width-two builder. The disconnect case terminates it after it receives both honest input packets. The healthy case constructs a fresh outer proof.

The non-author review includes the independent upstream full-tree/header oracle, all slot and ciphertext correspondences, verification and whole-chain reconstruction, negative admission cases, durable mid-switch interruption and receipt/ACK boundaries. See [independent review](review/REVIEW.md), [crash/retry checks](assurance/durability/) and [traffic and cost calculations](costs/ROLE_COSTS.md).
