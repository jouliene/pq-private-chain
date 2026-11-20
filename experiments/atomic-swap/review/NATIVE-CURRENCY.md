# Independent token-for-native exchange

The seller began with 100 managed dollars and zero native units. Alice exchanged 20 dollars for 8 native, then restored her original 32-byte seed into an empty wallet. Her ordinary 5-unit payment consumed that single 8-unit receipt and paid the ordinary 3-unit fee. She ended with 80 dollars and zero native. Bob paid the swap fee of 3. The two paying blocks each credited their miner 103, including the 100-unit subsidy. [Machine receipt](NATIVE-CURRENCY.json)

The reviewer anonymously fetched public implementation `19ab038415951aaae5dfc14cf8724bda2c408967`. A new mined network, new wallets and new issuer produced 32 captured blocks across three branches in 193.82 s. The two previously independently rebuilt MNG1/SLG1 binaries and both verifier keys matched the preceding public release byte for byte. From raw blocks a separate reader verified PoW, membership, conservation effects, receipt order, both signatures, each spent set, branch supplies and miner rewards. Four read-only peer databases matched the winning state. All four peers were independently observed at its tip, `000000d3e924143ee527a143dcb927c128dd6435f642ad5e164b230f4d1f7fd7`. The same independent reader and private joins also passed on the author's separately generated 32-block run. [Public audit](native_currency_audit.py) · [Private wallet checks](native_currency_wallet.py)

| Selected stage | Height | Alice managed / native | Bob native | Ordinary recipient native | Total fees |
| --- | ---: | ---: | ---: | ---: | ---: |
| Funded | 11 | 100 / 0 | 25 | 0 | 15 |
| Swap included | 13 | 80 / 8 | 14 | 0 | 18 |
| Ordinary payment included | 14 | 80 / 0 | 14 | 5 | 21 |
| Competing branch selected | 19 | 100 / 0 | 20 | 0 | 18 |
| Swap and payment restored | 21 | 80 / 0 | 14 | 5 | 21 |

Bob's conflicting ordinary payment sent 2 native to the rival and paid a fee of 3, consuming Bob's original swap input. On that fork all four swap outputs and both dependent ordinary outputs disappeared. On the winning fork the two fees returned once apiece. Its seven logical payments accounted for 21 fees, 2,100 native units issued and 2,121 miner credits. Managed supply stayed at 100, and the independent fixed asset used in the currency-substitution control stayed at 8.

The reviewer restored both pre-negotiation backups under the previously released MNG1 wallet binary. Of the four swap outputs, the seller opened her exact 8-unit incoming output and her 80-dollar change. The buyer opened his 20 dollars and 14 native change. The opposite recipient keys missed. The ordinary intent pinned the seller's incoming commitment as its only source. Its verified public proof included the nullifier independently derived from that note and the restored spend key. The recipient's inventory identified its 5-unit incoming output. These links use privately held wallet evidence. Only aggregate checks are published.

Two mathematically valid competing B offers reached Alice's incoming-receipt check. The historical registered SLG1 verifier accepted each. Alice's independently restored key opened 7 native from one and 8 units of the substitute token from the other. The live wallet recorded neither a final signature nor a submission for either offer, and both alternative sessions were aborted. The two positive signatures covered the same V2 terms commitment, exact complete legs, order, fee payer, expiry and network. A separate OpenSSL provider verified both and rejected 50 altered statements or signatures.

A fresh database using the preceding `998b39809b4464a9901161530d60f670b9bfaa7a` node installation independently replayed the published blocks through both detachments and restorations. It rejected incomplete, altered, expired and conflicting swaps and malformed block templates. The native-aware installation also accepted an actual separately funded historical token/token swap, both original signatures, the legacy private agreement and its original payer. [Historical validator replay](native_currency_prior.py) · [Legacy wallet and packet check](native_currency_legacy.py)

One copy of each private negotiation file totaled 324,039 bytes, comprising the 3,361-byte V2 agreement, two 143,251-byte unsigned legs and two 17,088-byte signatures. The initial size calculation used the 3,358-byte legacy agreement. The final receipt uses the observed V2 file length with the original verifier timings. The swap upload was 320,905 bytes, two frames of 160,446 bytes. Alice's proof call took 4.836 s wall and 9.39 s CPU, with a process peak of 451,940 KiB. Bob's took 4.868 s wall and 9.44 s CPU, with a process peak of 452,072 KiB. The complete public verifier took 1.321 s from launching the process through shutdown. After one warmup, five checks had a median of 24.53 ms wall and 24.04 ms CPU, with a native process peak of 201,140 KiB. The experiments establish behavior on these funded cases. The previously documented proof-knowledge, recipient-privacy and quantum-composition questions remain open.

The independent release attachment `independent-public.tar.gz` contains 57 allowlisted regular files, 4,549,717 bytes, SHA-256 `c32a4cece791e16a7e3af8360ae467900478733179be03d3ed2bf00b2fa07ef5`. It contains the public graph, packets, control wires, peer observations and aggregate review receipts. The reviewer read back each archive member against its digest. After verifying the archive digest, extract it into a new directory and run `sha256sum -c SHA256SUMS` there. [Allowlist packer](native_currency_package.py)

After the audit freeze at `f9d2cd2d7f389f8ac696ea035e5c3005041390c9`, the private join also checked for an absent signature file and the refused offer status. The machine receipt pins the final audit sources by SHA-256. From a detached checkout of `d99750538c75f259dc3a3a6fc74ff67b9e76fa22`, the reviewer ran the corrected standalone receipt diagnostic against a deployment staged from the original 998b398 software. Isolated wallets restored from their two 32-byte backups accepted the two genuine incoming receipts and rejected changes to the owner, role, amount, currency, fee and ciphertext.

## Reproduction

Use the Linux toolchain, bubblewrap, Node 24.22.1/OpenSSL 3.5.9 and Rust 1.93.0 from the build guide. Set `W` to a new absolute working directory and `NODE24` to the Node executable. Run from the checkout containing these review scripts. An independently built MNG1/SLG1 pair with matching generated sources and registered keys may also be supplied with `--managed-build` and `--swap-build`. This run reused the two roles previously cold-built by the same reviewer.

```sh
set -eu
export RAYON_NUM_THREADS=2
R="$PWD/experiments/atomic-swap/review"
mkdir -m700 "$W"
git clone https://github.com/jouliene/pq-private-chain.git "$W/source"
git -C "$W/source" checkout --detach 19ab038415951aaae5dfc14cf8724bda2c408967
python3 -IB "$R/native_currency_observe.py" "$W/net" "$W/peers.json" --source "$W/source"
set -- "$W/net"/source-build-*/build
B=$1
python3 -IB "$W/source/experiments/user-assets/review/build_helpers.py" "$B/upstream" "$W/helpers"
D="$W/net/deployment"
P="$W/net/public"
set --
for n in a b c d; do set -- "$@" --db "$W/net/nodes/$n/chain.sqlite"; done
python3 -IB "$R/native_currency_audit.py" --public "$P" --deployment "$D" --helpers "$W/helpers" --node "$NODE24" \
  --observations "$W/peers.json" "$@" > "$W/clean-public.json"
python3 -IB "$R/native_currency_wallet.py" "$W/net" "$W/clean-public.json" > "$W/clean-wallet.json"
git clone https://github.com/jouliene/pq-private-chain.git "$W/old"
git -C "$W/old" checkout --detach 998b39809b4464a9901161530d60f670b9bfaa7a
mkdir -m700 "$W/old-runtime"
python3 -IB - "$W/old/experiments/atomic-swap" "$B" "$W/old-runtime" <<'PY'
import json, sys
from pathlib import Path
src, build, home = map(Path, sys.argv[1:])
sys.path.insert(0, str(src))
import stage
m, s = build/'roles', build/'swap'
sha = lambda p: json.loads((p/'BUILD.json').read_bytes())['binary_sha256']
stage.install(home, m, sha(m), s, sha(s))
PY
python3 -IB "$R/native_currency_prior.py" "$W/old-runtime/deployment" "$P" "$W/old-chain" > "$W/prior-check.json"
python3 -IB "$R/../measure.py" "$D" "$P/SWAP.bin" \
  --private-terms-bytes "$(stat -c %s "$W/net/negotiation/accepted.terms")" > "$W/measure.json"
python3 -IB "$W/source/experiments/atomic-swap/controls.py" "$D" "$P/SWAP.bin" > "$W/packet-controls.json"
```

The public and historical-node audits also accept the verified release archive's extracted `public/` as `P`. Omit the database arguments for public-only verification; the archive supplies the peer trace as `review/peers.json`. The strict optional `--require-published-elf` checks the historical x86-64 executable bytes as well as the registered keys. The separate private wallet join uses only a disposable home generated by the operator.

For the older 7-for-30 exchange, extract the previously published `SPEND-baseline-public.tar.gz` and run `native_currency_legacy.py "$D" /path/to/extracted/swap.bin`. A participant with a retained historical agreement can additionally supply `--local-old-terms`. Our run used the reviewer's actual historical agreement to check the preserved V1 encoding and signed terms commitment. [Preceding release](https://github.com/jouliene/pq-private-chain/releases/tag/funded-spend-proof-2026-11-20)
