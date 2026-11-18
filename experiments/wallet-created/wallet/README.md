# Wallet-created ordinary payments

The harness funds two independently randomized 50,000,000-unit notes for A from a separately approved local genesis. A pays both outputs to B, B pays both to C, and C pays both to A. Each transfer consumes its own two funded inputs, charges 2,112,248 native units and proves the complete ordered two-input/two-output CP03 relation. The next owner decrypts both outputs. An unrelated wallet opens zero. The experiment uses CP03's real wallet keys, occurrence tree, private receipt adapter and statement codec. The three owner handles run in one coordinator for this test. Spending witnesses reach only their wallet-side prover via stdin, and each new verifier namespace receives only the canonical statement and proof. The synthetic endowment is an explicitly trusted test input.

The published binary bodies are complete. The 20-byte header precedes the 528-byte statement, two 2,164-byte encrypted envelopes, then the proof starting at byte 4,876. The entries for detached statements/proofs in the [run receipt](evidence/RESULT.json) are reproducible slices, so this directory stores each byte once. A funding digest identifies the selected history. A recipient needs its separately retained private receiving keys. The public replay reads only the approved genesis, the three bodies and installed public verification code and libraries. It checks all twelve invalid submissions and replays. The [reference run receipt](REFERENCE.json) records a separate CP03 control on freshly chosen notes and keys.

## Reproduce

On Linux x86-64 complete the pinned installation in [BUILD.md](../../../BUILD.md). Run the following from the repository root. Review and set the installation path and digest for your own completed build. The retained genesis digest belongs to this fixed public fixture only.

```sh
d=experiments/wallet-created
: "${inst:?set the path to the reviewed installation.json}"
: "${approve:?set its approved SHA-256}"
run_dir=$(mktemp -d)
python3 -IB "$d/structured/build.py" --installation "$inst" --approve-installation "$approve" --output "$run_dir/proof" > "$run_dir/build.json"
candidate_sha=$(sha256sum "$run_dir/proof" | cut -d' ' -f1)
gen=22b5472abbab3669f7b8987258e12cd08eee95a0943368b16befb74f05459727
args=(--installation "$inst" --approve-installation "$approve" --candidate "$run_dir/proof" --approve-candidate "$candidate_sha")
python3 -IB "$d/wallet/run.py" "${args[@]}" --output "$d/wallet/evidence" --public-genesis "$gen"
python3 -IB "$d/wallet/run.py" "${args[@]}" --output "$d/wallet/evidence" --public-genesis "$gen" --durable-dir "$run_dir/db"
python3 -IB "$d/wallet/run.py" "${args[@]}" --output "$run_dir/new-wallets"
python3 -IB "$d/review/structured_public.py" --help
```

The durable path prepares the registered matrix once, verifies all three pairs of public inputs, and checks their ordered state transitions in SQLite. Each accepted payment creates one FULL-synchronous commit over fees, spentness, funded occurrences, tree frontier and the complete public body. The entire three-payment sequence is not one database transaction. The scope is a newly created database and a trusted current head. This harness has no persistent network service or fork-selection rule.

The [durable measurement](evidence/DURABLE.json) records verifier process CPU and RSS, post-preparation cryptographic thread CPU, ledger CPU and total elapsed wall time with one preparation. Ledger CPU includes the JavaScript coordinator and its visible waited helper children, with 100 Hz aggregate child accounting on this host. Adding the three cryptographic thread times to the disjoint ledger interval estimates warm service for the group. This sum excludes setup and launch, disk/cache growth, block processing, networking and forks. The measured on-disk file includes all three full payment bodies; it is not an annual pruned-state measurement.
