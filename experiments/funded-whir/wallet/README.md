# Matched funded wallet proofs

The input is a completed native-for-token walkthrough. Its archive holds mined blocks from genesis, and its local backup directories hold the original recipient seeds. The comparison constructs a fresh two-real-input ordinary payment and a two-owner swap from the walkthrough's selected common ancestor. These are parallel alternatives on that funded prefix. Each proof uses newly generated output randomness and fresh receipts. Alice pays 20 units of the registered managed asset. Bob pays Alice 8 native units and pays the 3-unit fee. The public test report deliberately discloses those fixture amounts and the test asset ID.

After both legs verify, both owners issue one joint authorization over the released proof-bearing legs and a different authorization over the candidate legs. The changed digest invalidates the old signatures. The released pair enters a newly mined block on a disposable fork. After all three original processes exit, a new wallet process restores Alice from her original seed, replays the PoW history and the new block from genesis, reopens the 8-unit receipt from each encoding and derives the same spent identity. It produces both ordinary proof versions to transfer 5 and pay 3. The released validator admits the ordinary onward payment. The experimental verifier accepts the separate candidate packet.

## Reproduce

Run on Linux with working nested unprivileged bubblewrap namespaces, Python 3.11+, GNU time and the pinned Rust toolchain. Use an existing completed matching home or create one using the [native currency walkthrough](../../atomic-swap/NATIVE_CURRENCY.md). The matrix directory must contain the registered MNG1 and SLG1 files. The research binary must implement the funded-WHIR prove and verify commands. The pinned Poseidon2 constants are in the Qnero dependency source installed during the cold build.

~~~sh
umask 077
lab=$(mktemp -d)
./pqd swap --home "$lab/net" native-walkthrough
git init -q "$lab/qnero"
git -C "$lab/qnero" fetch --depth=1 https://github.com/DigitalGuards/qnero.git f04c91307837c0231668383bec76ba98d89d2652
git -C "$lab/qnero" checkout --detach FETCH_HEAD
python3 -IB experiments/funded-whir/wallet/build.py "$lab/capture" "$lab/qnero" "$lab/cargo-target"
matrix_dir="$lab/whir"
python3 -IB experiments/funded-whir/prepare.py "$matrix_dir" > "$lab/whir-tools.json"
funded_whir_binary="$matrix_dir/build/release/funded-whir"
constants=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["constants"])' "$lab/whir-tools.json")
python3 -IB experiments/funded-whir/wallet/fixtures.py "$lab/net" "$lab/capture" \
    "$constants" "$matrix_dir" "$funded_whir_binary" "$lab/public-comparison"
~~~

Every owner process independently replays the archived selected blocks with the released node backend. Its mount namespace grants one read-only seed, the three public addresses, the released and research binaries, public matrices, the public proof exchange and an owner-specific output directory. The coordinator exchanges public artifacts and never opens a seed. Each authorizing wallet verifies both final candidate packets, compares their exact public fields and ordered ciphertexts against the released proofs, checks the selected anchor, roles, fund conservation, incoming committed amount under its own spend key and its own change. The original prover runs in a nested wallet sandbox and emits its opening into a kernel FIFO accessible to that owner. The frontend checks the assignment locally, then pipes the binary words into the candidate prover. Private assignments, openings, session nonce and private terms salt never become file contents. Core dumps are disabled for the process tree. This is a disposable same-host test, with one trusted operator provisioning the participants.

The public comparison directory contains the common-head descriptor, funding projections, released and candidate packets, exact public statements and receipts, both signed bundles, the released swap block and restored onward proofs. SOURCE.json records the actual fresh packet hashes and sizes. The candidate measurements launch a new process for every prove and verify and include matrix loading. The isolated proving RSS is the maximum resident memory of that child. The frontend timer includes constraint assignment in Python. The released wallet proof timer covers the local wallet IPC operation with the registered prover, and its native RSS is the role process high-water mark. Replaying the funded branch, compiling keys, exercising independent matrix controls, swapping signatures, and mining a new block have different scopes and are excluded from the individual candidate proof timers. COMPLETE.json is written after restored onward admission.

The first independent run at `98bed42` stopped before releasing an authorization. The fixture passed the managed asset ID when its expected token amount was zero and used the swap slot convention to identify a shuffled ordinary receipt. An older author deployment had accepted that expectation. The corrected driver imports both swap policy modules from the checkout and records their hashes. It supplies the native zero ID for every zero-token receipt, checks swap roles in their fixed slots and checks the ordinary wallet's authenticated incoming/change marker in either slot.
