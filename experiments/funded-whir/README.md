# Verify WHIR payments on funded MNG1 notes

The experiment runs the released and experimental verifiers on identical disposable funded inputs and identical receipt bytes. Three independent wallets supply one two-input transfer and two legs of a token-for-native swap. A fourth process restores the swap recipient from its seed and proves an onward spend under both profiles. The live network retains the released verifier registrations. [Architecture decision](DECISION.md) · [Parameters registered before proving](PROFILE.md) · [Complete constraints and negative assignments](relation/README.md)

## Check the public proofs without a wallet

Use x86-64 Linux, Rust 1.99.1, Python 3.11+, GNU tools and unprivileged bubblewrap. Start at the published revision. The Rust dependencies have a committed lockfile, and the field/DFT implementation is in the repository. The build obtains qp-poseidon-core 3.1.0 from the Cargo registry. The matrix generator checks the source constants. The binary pins both generated matrix hashes. Each check below launches a new verifier with a read-only matrix and a single public packet in its namespace.

~~~sh
umask 077
d=experiments/funded-whir
work=$(mktemp -d)
python3 -IB "$d/prepare.py" "$work" > "$work/tooling.json"
curl -fL --retry 2 -o "$work/independent-public.tar.gz" \
  https://github.com/jouliene/pq-private-chain/releases/download/funded-whir-2026-11-20/independent-public.tar.gz
(cd "$work" && sha256sum --check --ignore-missing "$OLDPWD/$d/RELEASE.sha256")
(cd "$work" && tar -xzf independent-public.tar.gz && sha256sum -c SHA256SUMS)
python3 -IB "$d/packet_controls.py" "$work/build/release/funded-whir" "$work/public" "$work"
python3 -IB "$d/review/profile.py" | cmp - "$d/review/PROFILE.json"
python3 -IB "$d/frame_budget.py"
~~~

The asset can also be downloaded from the [release page](https://github.com/jouliene/pq-private-chain/releases/tag/funded-whir-2026-11-20). Use the published SHA-256 in the handoff to identify the archive. Its manifest covers the public funding blocks, all four candidate packets (the signed bundle contains both legs), the previous profile's proofs and the review records.

For the independent public transcript/receipt comparator and SLH-DSA signatures use Node 24.22.1 with its bundled OpenSSL 3.5.9. With that Node on PATH, run the following from the same checkout.

~~~sh
p="$work/public"
python3 -IB "$d/review/public.py" "$p/ordinary.released" "$p/released.swap" \
  "$p/ordinary.candidate" "$p/candidate.swap" "$(command -v node)"
~~~

## Create new payments and restore the recipient

The following commands create a separate disposable funded PoW network, then generate new private payments. They need working nested unprivileged namespaces, GNU time, the native C toolchain, Rustup with 1.93.0 for Qnero and 1.99.1 for the WHIR backend, and the network dependencies listed in the [devnet operator instructions](../atomic-swap/NATIVE_CURRENCY.md). Run from the repository root with the variables from the previous commands. A clean run can omit the public release download.

~~~sh
net="$work/network"
./pqd swap --home "$net" native-walkthrough
upstream=$(find "$net" -path '*/build/upstream/.git' -type d -print -quit)
upstream=${upstream%/.git}
test "$(git -C "$upstream" rev-parse HEAD)" = f04c91307837c0231668383bec76ba98d89d2652
python3 -IB "$d/wallet/build.py" "$work/capture" "$upstream" "$(dirname "$upstream")/target"
constants=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["constants"])' "$work/tooling.json")
python3 -IB "$d/wallet/fixtures.py" "$net" "$work/capture" "$constants" "$work" \
  "$work/build/release/funded-whir" "$work/fresh"
python3 -IB "$d/packet_controls.py" "$work/build/release/funded-whir" "$work/fresh" "$work"
python3 -IB "$d/node_cost.py" "$net/deployment" "$work/build/release/funded-whir" \
  "$work" "$work/fresh/candidate.swap"
~~~

The default native walkthrough fetches its pinned upstream. For an already installed network without a build tree, the [wallet instructions](wallet/README.md) include the exact upstream fetch. The original prover in each owner's namespace supplies a local private comparison assignment to the WHIR frontend. The public verifier requires only its registered matrix and the candidate packet. No released proof or wallet data enters its proof calculation. The companion signed-pair check also uses the public SLH-DSA verifier. Funding replay, mining, independent arithmetic controls and proving have separate measurements. The new packets are comparison types. The subsequent spend settles against the released version of the matched swap, which has identical commitments, nullifiers and ordered ciphertexts.
