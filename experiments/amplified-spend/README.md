# Reproduce the wallet-proof architecture decision

The required runtime for the decision checks is Python 3.10+; the pinned Picnic reference verifier also requires Clang and make. A funded-wallet binary or a prover installation is unnecessary for the two size exclusions. All commands start at the repository root on Linux. The independently tested executable revision is `14df7c9ad4e104a8da845e81a126bbfa4cf62add`. [Decision](DECISION.md) · [Security assumptions](SECURITY.md) · [Network costs](NETWORK.md) · [Independent run](review/CLEAN.json)

~~~sh
set -euo pipefail
d=experiments/amplified-spend
python3 -IB "$d/primary/model.py" | cmp - "$d/primary/MODEL.json"
python3 -IB "$d/primary/check.py" | cmp - "$d/primary/CHECK.json"
python3 -IB "$d/kkw/gate_count.py" | cmp - "$d/kkw/GATES.json"
python3 -IB "$d/review/audit.py" | cmp - "$d/review/AUDIT.json"
python3 -IB "$d/opening_risk.py" | cmp - "$d/OPENINGS.json"
tmp=$(mktemp -d)
curl -fL -o "$tmp/funded.tar.gz" \
  https://github.com/jouliene/pq-private-chain/releases/download/funded-whir-2026-11-20/independent-public.tar.gz
python3 -IB "$d/traffic.py" "$tmp/funded.tar.gz" | cmp - "$d/TRAFFIC.json"
~~~

Run the short [known-answer build and verification commands](kkw/README.md#reproduce) to check the real serialization and public verification of Picnic3-L1/L3/L5. The shell pipeline must stop on error. To recount the funded S-boxes and both matrices, use the optional `--constants` argument to `gate_count.py` with the pinned Poseidon2 source. [Pinned funding constants and generator](../funded-whir/relation/README.md)

## Recheck the deployed verifier

First provision the released public role using the [funded walkthrough](../funded-whir/README.md#create-new-payments-and-restore-the-recipient). Set `dep` to the absolute path of that walkthrough's `deployment` directory. The command below reads only public verifier keys, binaries, signed data and emitted meters. The earlier funded capture contains an onward transfer proved after seed restoration. The measured trials here revalidate those public packets at an eligible height. They do not restore a new wallet or execute a new chain transition.

~~~sh
test -n "${dep:?set dep to the absolute deployment directory}"
tar -xzf "$tmp/funded.tar.gz" -C "$tmp" public/restored-onward.transfer public/released.swap
python3 -IB experiments/spend-proof-decision/review/measure_public.py \
  --ordinary "$tmp/public/restored-onward.transfer" --swap "$tmp/public/released.swap" \
  --ordinary-binary "$dep/runtime/native" --ordinary-key "$dep/keys/managed.vk" \
  --ordinary-sha "$(cat "$dep/devnet/approved-native.sha256")" \
  --swap-binary "$dep/swap-runtime/native" --swap-key "$dep/swap-keys/swap.vk" \
  --swap-sha "$(cat "$dep/devnet/approved-swap-native.sha256")" --inclusion-height 13
~~~

Actual packet identities, pinned verifier keys/binaries and each cold and warm call are in [the raw baseline measurement](LIVE_VERIFY.json). Timings vary by host. The byte calculations and public reference vectors are deterministic. The original funded experiment mined the swap at height 13 and admitted the restored onward payment against the updated branch. The offline pair check uses height 13 for expiry. The ordinary verifier checks public effects without a branch database.
