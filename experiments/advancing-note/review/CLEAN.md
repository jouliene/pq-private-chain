# Independent public reproduction of N7P2

I cloned the public HTTPS repository into an empty directory. The clone ran with an empty environment except for a system executable path and explicit Git controls disabling credentials, config files, prompts and protocols other than HTTPS. Object alternates were absent. Public main and the version tag both resolved to `3351123a8947dfb2c22987e2d08eab808ba40f09`. I verified ancestry from `777df53e5681c2ecc11b64c8b7c1a50f68bb5667`, checked out the tested revision detached, and ran its published command to successful completion. The checkout remained clean. The compiler was the installed Rust 1.93.0 toolchain. Dependencies, targets, Node distribution, verification key, public capture and wallets were obtained or created afresh. [Tested source](https://github.com/jouliene/pq-private-chain/commit/3351123a8947dfb2c22987e2d08eab808ba40f09) · [Operator command](../README.md)

## Verification and recovery

The rebuilt 1,764-byte registration matched byte for byte. The native test exercised all 49 scalar and quartic gate equalities independently of challenge derivation. The public service rejected mutations at each of the 49 statement coordinates and all three malformed proof encodings, then accepted a valid proof. Fresh failing prover assignments covered ownership, position, amounts, asset identity, path and incorrect expected public effects. The size calculator also reproduced the exact length of the independently generated native control proof, 228,546 bytes.

The released archive matched SHA-256 `b5bfc4a6e01c79c15c7d8958e301349607b965e6e0159589f6eb0f69c52596ba`. The independent byte reader reproduced the complete released wire report. Three fresh two-core processes each admitted all ten durable released blocks, including eleven proof checks and both swap approvals. The complete selected state matched the author's report. The synthetic SQLite calibration and the forced process-exit report also reproduced exactly. After the exit between block/directory fsync and index commit, restart recovered the funded payment. Nine subsequent disconnects from the ten-block history exercised verified deep-prefix reconstruction. Restart agreed on the resulting height-one state. [Released wire quantities](../WIRE.json) · [Storage control](../STORAGE.json)

My separate fresh funding campaign made 13 genuine proofs. Eleven entered the selected chain. The two additional proofs exercised a funded alternative spend and a detached anchor. All 13 proof bodies differed from all 13 in the released run. A recipient with zero genesis credit recovered exactly one note containing 7 native and 13 asset A. Its seed-only process paid 2 native and 3 A onward, leaving 2 native and 10 A after the fee. The restored wallet needed 0.465 s to recover on the short prefix and 5.898 s to prepare the onward spend. Its native prover ran for 3,390.502 ms. An unrelated payment began durable admission 7.434 ms into this interval and completed admission 17.475 ms later.

The competing valid spend failed on current spentness, succeeded after disconnect and was subsequently reversed. The detached-only root failed before and after restart. A genuine payment remained eligible at anchor age 63 and expired at age 64. The signed swap's two anchor ages were nine and zero blocks. The fresh selected state had height 10, 30 commitments, 22 nullifiers and 30 units of miner fees. My byte reader independently reconciled its public tip, spent-set digest and amounts of framed data. The second signed bundle was 503,983 bytes, including both approvals. [Second founding identity](INDEPENDENT_FOUNDING_ID) · [Fresh measurements and selected state](FRESH.json)

## Independent measurements

Three fresh nodes processed the same ten distinct operations from my new funding history on two different physical cores of an i7-8700K. Cold genesis startup took 58.0–60.0 ms. The three warm ten-operation batches used 0.2492, 0.2460 and 0.2550 core-seconds inside durable admission. Median request-boundary throughput was 31.73 operations/s. Warm native proof checking took 10.67–13.23 ms per leg. All wallets and nodes used the same registered verifier. [Per-role results](FRESH.json)

At 100M included operations/year with this 90/10 mix, the measured sample projects to 0.079 cores of durable admission work and 26.13 TB/year of full blocks. Four peers receiving a complete body once require 26.49 Mbit/s outbound before other traffic. The two-core comparison passes on the short history. The modeled 20 Mbit/s four-peer link and long-lived 2 TB archive remain limiting. The small index calibration supplied an occupancy estimate. It did not measure years of random I/O or full-history recovery. The experiment leaves quantum same-witness knowledge and joint proof/receipt privacy unqualified. [Detailed assurance and service bounds](DESIGN.md)

GitHub's public Actions API reported completed success for both automatic push regressions on the exact tested commit `3351123a8947dfb2c22987e2d08eab808ba40f09`. These workflows exercise the released payment and PoW paths. I ran the new funded experiment independently from the public checkout as described above. [Research payment smoke 44880000507](https://github.com/jouliene/pq-private-chain/actions/runs/44880000507) · [Local proof-of-work devnet 44880000539](https://github.com/jouliene/pq-private-chain/actions/runs/44880000539)

## Recheck the independent public archive

The evidence revision carries the independent founding identity and SHA-256 separately. The second archive contains 15 regular public files comprising the genesis, ten selected blocks, two earlier branch blocks and two alternative packets. I read every archive member back and compared its bytes with the fresh public run. After publication an anonymous HTTPS download matched my original 3,573,014-byte archive byte for byte. Its SHA-256 is `de470f0fef7a02cf84e616d9a801510e6f762bc50b20e19fc9df69613df32607`. [Checksum](INDEPENDENT.sha256) · [Public asset](https://github.com/jouliene/pq-private-chain/releases/download/advancing-note-2026-11-21/advancing-independent.tar.gz)

From the checked-out evidence revision, use the binaries in the output directory of the main reproduction. With that directory in `result`, run

```sh
experiment=$(realpath experiments/advancing-note)
independent=$(mktemp -d)
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  https://github.com/jouliene/pq-private-chain/releases/download/advancing-note-2026-11-21/advancing-independent.tar.gz \
  -o "$independent/advancing-independent.tar.gz"
(cd "$independent" && sha256sum -c "$experiment/review/INDEPENDENT.sha256") &&
tar -xzf "$independent/advancing-independent.tar.gz" -C "$independent" &&
cp "$experiment/review/INDEPENDENT_FOUNDING_ID" "$independent/founding-id" &&
python3 -IB "$experiment/lab/run.py" check "$result/target/release/n7p2" \
  "$result/tools/node-v24.22.1-linux-x64/bin/node" "$independent"
```
