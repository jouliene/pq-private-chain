# Two independently created payments in one retained proof

This bounded alternative asks whether two different payers can reduce archival proof duplication while both keep their spending witnesses and unblinded leaf proofs local. It uses the pinned Qnero circuit and recursion library as components of a new experiment. The [stock six-slot wallet](../qnero/README.md) is the comparison control. This experiment registers a one-slot wallet circuit and a new two-submission wrapper. Both wrapper circuits request row blinding. Their verifier keys are derived from the installed code. A builder cannot supply its own verifier program to a node.

## Experiment boundary

Two isolated wallet processes each create a fresh spending key and fund two private openings (40 and 60) in a common, explicitly authorized laboratory genesis. Their public setup messages each contain a 1,601-byte receiving address and two 32-byte funded commitments. The 128-byte genesis contains all four commitments. In each wallet the prover consumes **both real notes**, creates a 50-unit payment and 47 change, and charges a fee of 3. The sender randomly orders both outputs. Witnesses, raw non-hiding leaf proofs and opened receipt plaintexts never cross that wallet's namespace. For receipt scanning the harness exports only an aggregate count from each test wallet. This count is instrumentation and would not be sent to a peer.

The builder's entire payment input consists of the two finished blinded wallet proofs with their public inputs and ciphertexts. The outer circuit runs two recursive verifiers against constant verifier data, constrains one shared anchor and height, and forwards all 52 inner public words under a fixed version field. The outer proof contains the resulting 53 public words. The final packet contains that proof and all four original ciphertexts in order. It does not retain the two incoming proof objects. Canonical proof decoding/verification, admissible public anchor, distinct funded commitments and nullifiers, receipt digest, ciphertext encoding and fee effects are checked again by a separately started node. Wallets read a common four-row history after the selected node accepts. Each recognizes its incoming 50 and its 47 change via the private receipt operation. One recipient originates a new 2×2 spend against the updated anchor; the node validates it independently.

The length-prefixed public test frames use a 4-byte little-endian length on each local pipe. Canonical wallet and pair objects already have an 8-byte version/length header. The two wallets, builder and public node run in separate namespaces. Builder and node print only role timing/peak RSS aggregates to their controlled stderr. Node and builder exchange verifier identities with the harness for cross-checking; their keys are always independently regenerated. Role setup, local wallet receipt counts, node test responses and malformed-packet controls are separate from ordinary protocol traffic.

## Distinct protocol semantics and assumptions

The note hash and nullifier are Qnero primitives. The spend circuit allows zero-value dummy inputs while the three generated payments all use two real inputs. The depth-20 quaternary tree has maximum capacity 2^40. Its sorted children establish private content membership. The prototype rejects duplicate commitments and validates its own current ledger header, which binds the ordered public leaf list and funded root. Wallets rely on the selected validating source for the admitted history. CP03 uses two private ordered index/occurrence proofs in a binary depth-40 tree, including bounds against the funded count. Migration, safety across chains and equivalence of these different nullifier identities have no integration approval. The native fixture's 16-word input limit bounds the test genesis, and its node rebuilds the tree from the retained list. No production-scale pruning or optimized replay was measured.

The source circuit includes the ciphertext digest in its public inputs. The node checks this digest against the two supplied ciphertexts in each slot. As with ordinary sender-generated receipts, this matching cannot enforce that a dishonest sender gave each intended recipient decryptable data. Each wallet uses the pinned ML-KEM-1024/ChaCha20-Poly1305 receipt suite. Receiving anonymity and correlated disclosure under later key compromise, intermediary observation of incoming public proofs and source address/timing remain relevant. The builder and any observer with both submissions can match their public nullifiers/commitments and ciphertexts to the final pair. There is no privacy claim for payer-to-builder traffic. Blinding and hash-based recursion require a security model for the **complete recursive stack**. The upstream 100-bit conjectured FRI setting, original Poseidon proof hash and EF2 differ from the WHIR profile. See the [independent cryptographic review](../review/QNERO.md).

Each payer's two input nullifiers, output commitments, public fee, accepted anchor and receipt digest have fixed slots. The node can charge both fees atomically for this experiment because both proofs authorize ordinary payments. Two independent ordinary payments bundled by a builder do not authorize a two-owner swap. [Future versioned operations](../EXTENSIONS.md)

## Reproduce

Use a clean disposable upstream checkout, Rust 1.93.0 on Linux x86-64, Cargo/its locked upstream dependencies, a system C toolchain, Python 3, bubblewrap with user namespaces and the shared libraries of the resulting binary. Commands below use Bash. The build verifies the upstream commit and reads its unchanged lockfile. A new Cargo target is supported; an existing trusted compiled-dependency cache shortens the build. The host-level build is outside payment proving time. The restricted processes link their normal runtime libraries and read OS entropy; there is no trusted witness setup file.

```sh
d=experiments/wallet-created/native
run_dir=$(mktemp -d)
git clone https://github.com/DigitalGuards/qnero.git "$run_dir/src"
git -C "$run_dir/src" checkout --detach f04c91307837c0231668383bec76ba98d89d2652
rustup toolchain install 1.93.0 --profile minimal
python3 -IB "$d/build.py" "$run_dir/src" "$run_dir/target" "$run_dir/exe" > "$run_dir/build.json"
sha=$(sha256sum "$run_dir/exe" | cut -d' ' -f1)
python3 -IB "$d/run.py" "$run_dir/exe" "$sha" "$run_dir/fresh"
gen=$(sha256sum "$run_dir/fresh/genesis.bin" | cut -d' ' -f1)
python3 -IB "$d/run.py" "$run_dir/exe" "$sha" "$run_dir/fresh" --replay "$gen"
python3 -IB experiments/wallet-created/review/native_wire.py "$run_dir/fresh/a.body" "$run_dir/fresh/b.body" "$run_dir/fresh/pair.block"
```

## Published artifacts

The [complete run](evidence/RESULT.json) records creation, verification, both wallet scans, all public pipe lengths and measured CPU/peak RSS. The [byte-level check](evidence/WIRE.json) matches all 52 inner words and all four ciphertexts against the outer packet. Independent node replay needs only `genesis.bin`, `pair.block` and `recipient.body` in the evidence directory. The two inner submissions are published here to make pre-inclusion costs and equality checkable. The experiment does not require archival nodes to keep them after accepting a valid pair. Set `gen` to the independently approved genesis digest `3ae5613ac227880476a57eb912cba7e033588655b38e90d9f6d77e2e046713ff` and use `"$d/evidence" --replay "$gen"` in the command above. [Build receipt](evidence/BUILD.json)
