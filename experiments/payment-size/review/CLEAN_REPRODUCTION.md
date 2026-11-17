# Independent reproduction and disposition

**Publish the experiment. Keep CP03 as the working ledger reference.** The
reviewer reproduced a 15.599% reduction in mean complete body bytes on three
new 2x2 payments. The measured candidate misses the 175,126-byte research screen.
This is an encoding of the complete CP03 argument; the direct WHIR proof and
recursive alternative did not produce complete payments in this experiment.

## Clean execution

The reviewer cloned the public Git URL at
`8f9bae9b96248e6c147acf9664fd34bb727cb756` into
`/tmp/pq-payment-size-review-20261118-01`. During execution the filesystem
root was read-only, the original project and research directories and Cargo
registry/git caches were hidden, and a new temporary directory, PID and network
namespaces were used. The public Node executable matched the hash in BUILD.md.
Runtime discovery and approval preceded a new offline, locked, one-job build
with Rust 1.99.1. Cargo took 114.411 s and 424,036 KiB peak RSS. Eight provider
controls and the installed private-parent probe passed.

Three independent private cycles (`psizerev01`, `02`, `03`) created fresh keys,
credits, 2x2 transfers and newly proved backup-only spends. The reviewer
cross-checked the three distinct chain, statement, proof and body identities
and their public workload/parent associations. Each ledger reached height 3,
six leaves, fees 6,341,197 and zero remaining issuance liabilities. Only the
payer proof from each cycle enters the table. The unchanged prover took
1.829–1.990 s of worker wall time and peaked at 168,172–168,304 KiB.

The clean checkout then fetched the frozen experiment commits. A Git diff
against the public baseline showed no changes to CP03 source, build scripts,
manifests, lockfile, vendor or fixtures. The final candidate revision was
`9dce9420fa4fa96a01b63c70fdbea8e6dde08012`. The reviewer linked its new
executable against the approved, newly built installation. The complete
executable was 6,201,072 bytes. Initial comparison revision `90549a5` attributed
only launcher CPU and peak RSS to its verification process. Revision `87f69df`
added a child meter. The final measurements below use GNU time **inside** each
fresh public-verification namespace and include outer elapsed time. All three
versions produced the same candidate bytes for each payment.

| Payment | CP03 body B | Candidate body B | Candidate proof B | Pack elapsed s | Verify elapsed s | Verify CPU s | Verify peak KiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| 01 | 1,746,582 | 1,475,378 | 1,470,502 | 0.908 | 0.868 | 0.85 | 86,404 |
| 02 | 1,749,398 | 1,478,474 | 1,473,598 | 0.809 | 0.816 | 0.79 | 86,404 |
| 03 | 1,754,198 | 1,477,338 | 1,472,462 | 0.845 | 0.822 | 0.81 | 86,404 |

Each complete body includes its 528-byte canonical statement, two 2,164-byte
envelopes and all proof framing. The named verification interface also receives
a separate 528-byte expected instance. Fixed preprocessing saved 215,044–215,876
bytes and duplicate query material saved 55,432–60,984 bytes. No out-of-band
proof or prover-supplied setup was needed. On this Intel i7-8700K, cold
preprocessing for the extra fixed table took 0.164–0.204 s and the original
registry took 0.583–0.589 s. Cold verification of the original proof and
statement alone took 0.634–0.642 s and peaked at 63,228–63,360 KiB. Packing
includes reconstruction and an actual complete check. No long-running verifier
amortization or annual network load was executed.

## Controls and security review

The final compact verifier accepted each independently selected original
statement. Providing the correct compact body for one payment and the authentic
expected statement of another produced `ExpectedStatement` for all three cyclic
substitutions. Each call ran in a fresh namespace with only the required public
files, executable and runtime dependencies.

Changing actual ciphertext, a canonical trace opening, a noncanonical field,
minimum fee, length or trailing bytes produced the distinct expected rejections.
Five coherent changes to the *expanded* proof's public inputs reached the
original cryptographic verifier and failed. The final valid recheck passed.
A separate unchanged prover run took a canonical, intentionally public test
witness and produced a real proof. It rejected all seven semantic mutations
without emitting a proof. These included ownership, second membership path,
index bound, nullifier, output commitment, isolated integer imbalance and
out-of-range value.

The decoder derives omitted positions and fixed data from its installed program
and public transcript; the original cryptographic verifier then checks the
reconstructed argument. Honest encodings disclose a deterministic function of
a public CP03 transcript. This preserves CP03's existing qualified security
basis. The initial trace-column review found an unmasked terminal disclosure in
a direct WHIR port, which this encoding avoids. These results cover complete
proof verification and receipt binding. Ledger replay/spentness and accepted
anchor selection remain separate CP03 admission responsibilities; the candidate
has a distinct format and was not activated on the ledger.

## Reproduction and evidence

Use the commands in [the experiment README](../README.md) at the final revision.
The reviewer used build label `sizerev01`, private attempts `psizerev01`,
`psizerev02`, `psizerev03`, candidate output `.work/size-encoder-rev03` and
comparison output `.work/size-comparison-rev03`. New installations and samples
have their own digests. The exact outer boundary, measured worker values,
additional public control command, receipts and final source/binary identities
are recorded in [the evidence index](CLEAN_INDEX.json),
[cycle readback](CLEAN_CYCLES.json), [final comparison](CLEAN_COMPARISON.json),
[public controls](CLEAN_PUBLIC_CONTROLS.json) and
[witness controls](CLEAN_WITNESS_CONTROLS.json).
