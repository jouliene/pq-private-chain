# Acquire native fee funds in a private atomic swap

A holder starts with 100 managed test dollars and zero native coins. A counterparty offers 8 native coins for 20 dollars and pays the 3-unit swap fee. The holder can restore the swap proceeds from the original 32-byte wallet seed and use the entire 8-unit note to send 5 coins and pay an ordinary fee of 3.

## Run the wallets and miners

Use x86-64 Linux, Python 3.10 or newer, Git, a C toolchain, Rustup, network access for the pinned sources, and working unprivileged bubblewrap. Start in the repository root. Keep the scratch directory private.

~~~sh
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
./pqd swap --home "$lab/net" native-walkthrough
python3 -IB experiments/atomic-swap/wallet/check_receipts.py "$lab/net" \
  "$lab/net/negotiation/accepted.terms" "$lab/net/negotiation/a.leg" \
  "$lab/net/negotiation/b.leg" alice bob
python3 -IB experiments/atomic-swap/measure.py "$lab/net/deployment" \
  "$lab/net/public/SWAP.bin" --private-terms-bytes 3361
~~~

The walkthrough builds and registers the pinned role executables, launches three separate PoW nodes and stops them when finished. Both parties run ordinary wallet commands. They exchange a private terms file, proved offers and final authorizations. The harness mines on separate branches and starts a fourth empty validator for replay. Use a fresh home for a new run. The complete commands for negotiating with independently exported addresses are in the [two-wallet guide](wallet/README.md).

| Selected state | Seller dollars | Seller native | Buyer dollars | Buyer native | Onward recipient native | Fees since funding |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Funded | 100 | 0 | 0 | 25 | 0 | 0 |
| Settled | 80 | 8 | 20 | 14 | 0 | 3 |
| Restored seller sends 5 | 80 | 0 | 20 | 14 | 5 | 6 |
| Conflicting buyer payment wins | 100 | 0 | 0 | 20 | 0 | 3 |
| Swap and onward payment win again | 80 | 0 | 20 | 14 | 5 | 6 |

The conflicting buyer payment transfers 2 native units to a different recipient and pays its own fee of 3. The buyer also holds eight units of an unrelated fixed asset used for the substitution check. The five preparatory transactions cost 15 native units. Every included block earns a subsidy of 100. Fees move existing units to miners. They do not increase issuance.

## Why the public protocol can stay in place

In the released SLG1 circuit each leg already conserves native and token value separately. A transfer can produce a positive native amount with zero token amount and the zero asset ID. The public SWF1 frame already binds the fee-paying side. The earlier wallet only offered positive token quantities and always placed the fee on side A. This change extends private negotiation, coin selection, receipt checks and joint authorization. It preserves previously funded notes and uses the public SLG1 and ordinary MNG1 verifiers registered at `998b39809b4464a9901161530d60f670b9bfaa7a`. [Registered proof relation](native/PROFILE.md) · [Frame and signature binding](swap_wire.py)

The buyer spends one 25-unit native note and receives 14 native change. The seller spends one token-only note and receives 80 dollars in change and a separate 8-unit native note from the buyer. Before signing, each wallet verifies the peer's complete public proof, opens the expected incoming receipt under its own spending key and checks both amount lanes, currency and output position. It checks its own change, reserved funding, fee, expiry and branch anchors. The two final signatures cover both complete offers. Both must authorize the same terms and ordered outputs. The two-slot admission rule remains unchanged.

An observer can identify a swap, link both legs and their retries, and see the fee-paying side, anchor, expiry, public effects and ordered ciphertexts. Seat B paying the fee rules out the legacy seat-A-only wallet policy. The public bytes carry neither the private asset identities nor the negotiated exchange amounts. The walkthrough discloses those values for verification. The price, addresses and private agreement require a confidential authenticated handoff. Recovery from seed covers confirmed notes. Pending authorizations require the private negotiation journal. Concrete end-to-end quantum knowledge, joint privacy, network metadata protection and production economics remain open. Offer discovery and a complete typed WHIR port remain separate work. [Proof review](../spend-proof-decision/DECISION.md)

## Measured live exchange

Implementation revision `19ab038415951aaae5dfc14cf8724bda2c408967` produced the following local measurements. The two wallets offered their legs at heights 11 and 12. The swap was mined at height 13 and the recovered seller's onward payment at height 14. On the conflicting branch at height 19, the validator removed both payments. At height 21 all four nodes selected the branch containing both. The final 2,121 native units credited to miners include 2,100 issued units and 21 in fees. Both winning payment blocks credited exactly 103. [Public author measurements and branch records](evidence/NATIVE-CURRENCY-RUN.json)

| Measured item | Result |
| --- | ---: |
| Two complete prepared leg offers | 143,251 bytes each |
| Two signed physical frames | 160,446 bytes each |
| Joint submission / complete RPC request | 320,905 / 320,928 bytes |
| Swap-only mined block / growth over an empty block | 321,122 / 320,900 bytes |
| Ordinary onward-payment block | 143,459 bytes |
| Private agreement + two offers + two signatures, one copy each | 324,039 bytes |
| Seller prover, wall / CPU / peak RSS | 4.793 s / 9.30 s / 451,936 KiB |
| Buyer prover, wall / CPU / peak RSS | 4.809 s / 9.32 s / 452,064 KiB |
| Full public verifier after warmup, median wall / CPU / peak process RSS | 24.89 ms / 24.33 ms / 201,012 KiB |

The public verifier measured five pairs after one warmup. The wallet timings cover fresh leg creation. [Raw verifier samples](evidence/NATIVE-CURRENCY-COST.json)

These times exclude builds, seed recovery, mining and file transfer. The private agreement width increased by three bytes. Its version is hidden from a verifier with just the opaque terms commitment. Supply 3,361 to the measurement command when the private agreement version is known.

## Replay the published exchange

The [release](https://github.com/jouliene/pq-private-chain/releases/tag/native-currency-swap-2026-11-20) contains public blocks from all three branches, packet bytes, rejected public submissions, checksums and disclosed test balances. Replay it using the full registered verifiers in the walkthrough deployment. An empty temporary ledger is created solely from those public inputs. This command does not read a wallet or an issuer key.

~~~sh
capture=$(mktemp -d)
gh release download native-currency-swap-2026-11-20 --repo jouliene/pq-private-chain \
  --pattern author-public.tar.gz --dir "$capture"
(cd "$capture" && echo '6d906dd2bb7ba04e0dd837f57e3cef444031b8d0fcdffb279946dd754cdb4840  author-public.tar.gz' | sha256sum -c - \
  && tar -xzf author-public.tar.gz && sha256sum --quiet -c SHA256SUMS)
python3 -IB experiments/atomic-swap/review/native_currency_prior.py \
  "$lab/net/deployment" "$capture/public" "$capture/replay"
~~~

The public check can establish valid spends, both fee credits and fork handling. Establishing that the ordinary payment consumed precisely the seller's acquired note requires a local opening under that holder's spending key. Freshly generate that private check from the local walkthrough and follow the independent review. Public releases exclude the private terms, offer salt, seeds, note openings and negotiation journals.

A non-author also reconciled four peer databases against a second mined graph and opened both genuine rejected offers with the seller’s independently restored key. The independent archive contains the public replay and aggregate wallet findings. [Independent results and reproduction](review/NATIVE-CURRENCY.md) · [Machine receipt](review/NATIVE-CURRENCY.json)
