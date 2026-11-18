# Native FRAME dispatch of a newly wallet-created public payment

The first comparator retained the ordinary extrinsic and anchor identity. Reconstructing the precise funded fixture in FRAME also needs its public coinbase inner, funded commitment and anchor header fields. This separate run generates a **fresh** transaction with those extra public readbacks. It does not infer the old note's opening from its private proof. The note opening and seed stay in the wallet, and the pallet process starts after temporary private storage is gone.

In a second pinned upstream checkout, `stage.py` installs an additive wallet test (the first measured wallet driver plus public exports) and a test-only pallet module. The only change to tracked upstream source is a single `#[cfg(test)] mod` registration. The test uses real `frame_system`, `pallet_zk_tree`, `pallet_shielded`, release build-generated N=6/n=53 verifiers and upstream `TestExternalities`. Its independent Test runtime has its own pallet indexes, so it checks the published 4/24 outer preamble and selector, then SCALE-decodes the unchanged shipped pallet call before dispatch.

The test recreates the funded coinbase via the real inherent and the same `CoinbaseSink` called by mining rewards, with an explicit 1,000-step laboratory reward. It folds the funding leaf, compares the commitment and root to the wallet's fixture, recomputes the captured anchor hash, and registers that historical anchor at height 2. The full header preimage is public. Its state/extrinsics roots come from the wallet's laboratory source; this trusted fixture is not a replay-derived FRAME system state root or proof of chain work. The transaction is admitted through three production paths: external pool validation, pre-dispatch and dispatched runtime call. Assertions cover two permanent nullifiers, two expected leaf commitments and heights, real post-fold membership, eight fee steps, the burn/author split, pool balance and replay refusal. A separate wallet receipt/seed-only scan uses the ordinary wallet on the public RPC fixture. No mining, peer gossip, governance, whole-block execution or disk pruning is exercised.

From this directory, with Linux, 1.93.0, a native C toolchain and the same Python/tmpfs prerequisites as the comparator:

```sh
git clone https://github.com/DigitalGuards/qnero.git /tmp/qnero-pallet-src
git -C /tmp/qnero-pallet-src checkout --detach f04c91307837c0231668383bec76ba98d89d2652
(cd /tmp/qnero-pallet-src && rustup run 1.93.0 cargo fetch --locked --target x86_64-unknown-linux-gnu)
(cd /tmp/qnero-pallet-src/chain && rustup run 1.93.0 cargo fetch --locked --target x86_64-unknown-linux-gnu)
python3 -B run.py /tmp/qnero-pallet-src /tmp/qnero-pallet-result
```

The input checkout must be clean or contain exactly the staged overlays. Every output label is new. Existing caches can be reused through `CARGO_TARGET_DIR`; dependencies and both lockfiles are pinned. The funded output in the receipt includes a public coinbase inner and a public value. The two public nullifiers are the exact pair in the submitted real slot, never a log of private paths or future unpublished nullifiers. The test rechecks the authenticated release private verifier before generating a transaction.

The existing ordinary comparator [describes the exact proof and ciphertext encoding](../README.md). The additional [native test](anchored_wallet_replay.rs) and [runner](run.py) isolate the missing dispatch observation.

The local run passed the production pallet checks. Minted pool value was 1,000 steps, the settled pool held 992 and four steps were pending for the author; the remaining four steps were burned. The single funded leaf became three leaves. Both new leaves had valid paths and creation height 3. The two real-slot nullifiers entered used state. Pool validation, pre-dispatch and dispatch each rejected the same replay, preserving the state checked by the harness. The complete test took 0.03 s in native TestExternalities. Cargo plus the release build, both default verifiers and test took 410.87 s elapsed and 5,396,172 KiB peak RSS. That build figure includes compilation. [Summary](evidence/summary.json), [source identity](evidence/source.json), [actual Cargo/test output](evidence/pallet.log).

The retained [public input directory](evidence/public) suffices for a direct FRAME replay without a wallet. Apply `python3 stage.py /tmp/qnero-pallet-src` as above, then run:

```sh
public_dir="$PWD/evidence/public"
(cd /tmp/qnero-pallet-src/chain && QNERO_PUBLIC="$public_dir" rustup run 1.93.0 cargo test \
  --release --locked --offline -j2 -p pallet-shielded --lib -- --exact \
  anchored_wallet_replay::funded_public_wallet_dispatch --nocapture)
```
