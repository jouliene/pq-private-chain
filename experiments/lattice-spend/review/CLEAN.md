# Clean public reproduction of the lattice spend decision

I anonymously cloned `https://github.com/jouliene/pq-private-chain.git` into an empty directory. Git advertised both `HEAD` (symbolic to `refs/heads/main`) and `origin/main` at `ebb732a94640c5be3a9d60ea4b14bb0e2580dd10`. I detached at that commit, checked the ancestry of `10cbb07909a62b6293518cbe70aba4213e0faa4c`, and verified that there was no object alternate. The clone used an empty home, no system/user Git configuration, no credential helper, no prompts and only the HTTPS transport.

## Inputs

The Poseidon crate matched SHA-256 `5872607e25ea4ee5fb37e64bf1462168e1a36a4e719cdc8a105533c708253918`. The historical funding archive matched `06c6e392a7896aa8670c365e3895e3d673f676e75919b143be36c823851d4673` and all 25 manifest entries. I used my own previously mined private-wallet home and previously independently built released capture roles for the new funded checks. Each fresh wallet process had its own seed and replayed the selected public chain. The published archive and my private home come from my earlier independent funding campaign. [Funding and public inputs](../../packed-tcith/encoding/README.md)

I built LaZer `b958e247a2fdb9593b3c25c9603c6c5305c19420` and LaBRADOR `c1ae0e612d5accd9e7d9d1c264951c1afe949c83` from new HTTPS checkouts, with the experiment's 1,216-byte quadratic-coefficient hash correction (SHA-256 `93939b981d7b0dff72cdb3b123dabde98ab7abbeeda62eacffa961780c8c75e1`). I built with GCC 13.3.0 and ran each membership role on one Intel Core i7-8700K core under Intel SDE 10.13.1 in Tiger Lake mode. The emulator archive matched the vendor's SHA-256 `94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50`. I used a fresh extraction of that public tool, plus a locally extracted Ubuntu MPFR development package. The backend timings below are specific to instruction emulation. [Build and emulator instructions](../lazer/README.md) · [Intel's archive digest](https://www.intel.com/content/www/us/en/download/684897/intel-software-development-emulator.html)

## Commands

The shell variables denote new local build/output directories, the preexisting independent private lab and its capture tools, and the downloaded public constants. The membership tools were constrained to one permitted CPU. I ran these commands from the detached repository, comparing the public and four-role reports with their checked-in counterparts.

```sh
d=experiments/lattice-spend
bash "$d/reproduce.sh"
bash "$d/lazer/build.sh" "$build"
python3 -IB "$d/lazer/run.py" "$build" "$replay" --sde "$sde" --cpu 2 \
    --profile shared40 --replay "$d/lazer/public" --positive-only
python3 -IB "$d/funded/roles.py" "$funding_home" "$capture" "$constants"
bash "$d/funded/price.sh" "$build" "$sde"
python3 -IB "$d/lazer/run.py" "$build" "$fresh" --sde "$sde" --cpu 2 \
    --profile stock64 --positive-only
```

## Observations

The public entry point regenerated both complete conversion censuses, wire and memory decisions, exact LLNW counts, fixed-parent parameter screen and branch checks. My independent incremental reader reproduced the archived preexisting roots at all 13 heights and matched the common spent set over ten public nullifiers. The adjacent selected swap block yielded 27 funded leaves and 14 spent nullifiers. [Independent bounds and history](REVIEW.md)

A cold build took 39.41 s. The common public checks took 46.09 s. My four separate wallet processes generated fresh released proofs for the ordinary payment, both swap legs and the recovered onward payment. Both the complete nonnative conversion and the fixed-parent arithmetic passed on each private assignment. Every old effect, including nullifiers, matched. The recovered owner spent the actual 8-unit output as 5 plus the 3-unit fee. The four-role run took 118.63 s. Its output was byte-identical to the published four-role receipt. These were released proofs with two additional private arithmetic checks.

The native planner independently selected 15 rounds with the ZK round at zero-based index 6 for both complete conversion layouts. Its estimate was 126.47 KiB and the complete fixed-width native array shape projected to 208,384 B per proof. The two-suite probe took 41.81 s. Full funded lattice-proof timings and compressed bytes remain unmeasured.

| Public membership operation | Complete frame (B) | Arrays (B) | Backend wall (s) | Backend CPU (s) | Process wall (s) | Process peak RSS (KiB) |
|---|---:|---:|---:|---:|---:|---:|
| Published two-path, height 40, verify | 136,741 | 196,096 | 105.233 | 104.880 | 114.65 | 1,011,940 |
| Fresh one-path, height 64, prove | 136,729 | 196,096 | 189.198 | 188.568 | 198.87 | 1,069,912 |
| Same fresh proof, independently verify | 136,729 | 196,096 | 102.975 | 102.588 | 112.01 | 1,016,572 |

The fresh height-64 case matched the published stock64 root and produced different proof bytes with fresh proving randomness. Both verifiers reconstructed the statement and parameters in a separate process from the framed public input. The 553-byte framing portion includes the 512-byte root. The published two-path frame SHA-256 was `e8fc1b94830cb04bbba1e13b637f47316b718a8140418ce7b968fc9323be2b77`. The newly generated height-64 frame SHA-256 was `dc0ea328212d1153dc19535152e2fcbf90d267c1d333eadd3061aad6316613e0`. These measurements establish membership in the toolkit’s synthetic tree. The funded integer and migration checks above kept the released wallet proof separate. No new funded lattice or fixed-parent TCitH proof was generated. The final detached tree remained clean. [Public machine receipt](CLEAN.json)
