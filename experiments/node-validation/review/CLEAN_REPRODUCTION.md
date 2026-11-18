# Non-author reproduction and disposition

**Defer both integrations.** On the tested generic implementation the matrix component alone exceeds the two-core, 90-day catch-up budget of 0.12476 CPU seconds per ordinary payment. A nonuniform salted proof profile can meet the block-only network scenario. The fallback's real transparent proof certifies only the Keccak accelerator workload. The full CP03 verifier guest, state transitions and resolved outer receipt, compatible strength and timely production have yet to be demonstrated. The current experiments support prioritizing the structured verifier test in the decision. Neither route produced a complete new payment, receipt or subsequent spend in this milestone.

## Independent execution

I used the separate clean checkout left by the previous public size review. It had no changes in tracked files or untracked non-ignored files. I fetched the immutable objects from the project's local repository, checked out detached `37c9b4587507367fcf339cffce700fc60216d5ef` for primary/dimensions/roles, then detached `6efae8b29ed9a854768a5e5ec5d69fbceee216c0` for the fallback. The only differences between them are seven aggregate source/evidence files. The final review checkout was also clean.

I explicitly reused the previous reviewer's local approved reference installation at `.work/sizerev01/fresh/installation.json`, SHA-256 `f885a09c9768b383cf4004ed92786f25e4b40610089f76b7de489358e06ebb46`. Its source, Cargo lockfile, scripts and vendored dependencies have no changes from the previous independent revision to the new freeze. The runner validated that installation, compiled the current probes against its pinned local artifacts, and ran the probes. For the fallback I reused the clean pinned external source and completed dependency target. I freshly relinked the experiment binary, generated a new proof and ran separate verifying processes. This is a clean experiment-source reproduction with reused dependency builds on the same physical machine. An independent upstream build from empty caches was outside this run.

| Check | Independent result |
|---|---|
| Lower all active CP03 2x2 AIR constraints and change one trace word | Matched the committed dimensions byte for byte. The honest fixture gave zero residuals and the negative gave 33. |
| Three independent statement-specific matrix evaluations | All three public digests, nonzero terms and allocation sizes matched. The guarded main-fold component used 0.2234–0.2286 CPU seconds per payment on one pinned thread. |
| Two first-stage EF5 Reed–Solomon rows of length 2^21 | All eight Horner cross-checks matched the original outputs. The two transforms used 0.3325 and 0.3250 CPU seconds. Each emitted 83,886,080 bytes. |
| Two committed small transcripts and one fresh guarded transcript | Both committed outputs matched byte for byte, with 36 and 40 rejections including whole-proof framing and statement controls. A new 5,672-byte guarded public proof passed a new process and 40 rejections. This is a small relation. The random count of duplicate/opened query positions can change its encoded length. |
| Guard/check and source size schedules | Algebra/rank control report and the author's selected full-size profile matched byte for byte. The independent Decimal schedules and both public 2x2 Merkle-work checks also reproduced. |
| Participant model | 95% and 100% cases passed the recalculation of frame, custody, forwarding, burst and recovery accounting. An additional sensitivity rounded the 262,850.011-byte profile up to 262,851 B per payment and used its 272,556-byte cap. The conditional block-only burst/drawdown pass held. |
| Fresh real accelerator execution | 67 actual public CP03 sponge-state inputs. Proving used 15.50 s elapsed, 31.01 CPU s, peak 462,336 KiB. Fresh verification passed for the 400,392-byte seal. A mismatched public claim and damaged proof triggered their distinct expected failures. |
| Separate verification of the frozen reference seal | The freshly linked verifier checked the published seal against the expected public transcript. The independent proving invocation emitted identical bytes for this fixed public input. |
| Historical 96-proof workload | Read the released digest-pinned 442 MiB public archive and matched WORK.json byte for byte. The 3,600,891 nonfixed Merkle permutations imply at least 2,749 PO2-18 internal seals under the selected accelerator geometry. No new 96-payment block proof was produced. |

See [raw timings, digests and control counts](CLEAN_RESULTS.json), [wire and construction review](ASSESSMENT.md) and the [implementation decision](../DECISION.md). Hash-authenticated traces, scenario arithmetic, genuine tiny arguments and public verifier kernels remain separate evidence.

## Commands

Start from the indicated frozen review checkout and create a new output directory. The approved CP03 installation must belong to this checkout. Use its own reviewed digest and directory if reproducing on a different installation. Run the standard pinned-source Keccak dependency build according to the aggregate README when a compatible target is unavailable.

```sh
out=$(mktemp -d)
root=$PWD
install=.work/sizerev01/fresh/installation.json
approve=f885a09c9768b383cf4004ed92786f25e4b40610089f76b7de489358e06ebb46
dims=experiments/node-validation/dimensions
taskset -c 4 python3 -I -B "$dims/run.py" --installation "$install" --approve-installation "$approve" > "$out/dimensions.json"
diff -u "$dims/RESULT.json" "$out/dimensions.json"
taskset -c 4 python3 -I -B "$dims/run.py" --installation "$install" --approve-installation "$approve" --measure-matrix > "$out/matrix.json"
taskset -c 4 python3 -I -B "$dims/run.py" --installation "$install" --approve-installation "$approve" --first-row > "$out/fft.json"

cd experiments/node-validation/primary
python3 -B probe.py verify toy-public.proof --controls > "$out/plain.json"
diff -u toy-public.json "$out/plain.json"
python3 -B probe.py verify guarded-toy-public.proof --guarded --controls > "$out/guard.json"
diff -u guarded-toy-public.json "$out/guard.json"
python3 -B probe.py prove "$out/fresh.proof" --guarded
python3 -B probe.py verify "$out/fresh.proof" --guarded --controls
python3 -B controls.py > "$out/algebra.json"
diff -u algebra-controls.json "$out/algebra.json"
python3 -B budget.py --rows 614387 --private 612532 --public 49 --guard-words 296448 --guard-checks 4 --fold 4 --terminal-log 8 --ratios 16,256,2048,512 > "$out/selected.json"
diff -u selected-profile.json "$out/selected.json"
cd "$root"

python3 -I experiments/node-validation/roles/check.py
python3 -I experiments/node-validation/roles/project.py --masked-body-bytes 262851 --masked-max-body-bytes 272556 --aggregate-proof-bytes 200000 > "$out/role.json"
python3 -I experiments/node-validation/review/schedule_check.py > "$out/schedule.json"
diff -u experiments/node-validation/review/schedule-check.json "$out/schedule.json"
python3 -I experiments/node-validation/review/merkle_work.py
agg=experiments/node-validation/aggregate
python3 -I -B "$agg/run.py" "$RISC0_CHECKOUT" "$RISC0_TARGET" "$out/keccak"
RAYON_NUM_THREADS=2 "$out/keccak/accelerator" verify "$out/keccak/public.leaf" "$out/keccak/leaf.sha3" "$agg/leaf.seal"
python3 -I -B "$agg/trace_work.py" "$PUBLIC_CLOSURE_TAR" > "$out/trace.json"
diff -u "$agg/WORK.json" "$out/trace.json"
```

The source confirms the block-only accounting assumes actual access to ordered public payment capsules. Bound roots alone cannot serve that data. A different matrix evaluator, prover schedule, hardware or outer proof system could change the research decision. These checks establish neither a production deployment nor a whole-protocol PQ/privacy theorem.
