# Independent review of stranger discovery and funded settlement

A fresh wallet found both makers with one discovery relay stopped. The makers offered 7 and 8 native for 20 managed dollars. The taker chose 8. The original SLG1 proofs and authorizations were mined together at height 11. The taker restored from seed, spent the single received 8-unit note on an ordinary payment of 5 plus its 3-unit fee, and finished with 80 dollars and zero native. The selected maker finished with 20 dollars and 14 native. The beneficiary independently opened the actual 5-unit output. [Machine results](REVIEW.json)

The reviewer anonymously fetched public revision `9bb62eab924bf85b35ad04884eb85b5548ffea9a` and ran the ordinary walkthrough in a new private home with independently generated identities, funding, quotes and PoW. That run took 120.82 seconds on one Linux host with separate wallet, relay and node processes. Both native programs were the reviewer's earlier independent cold builds. Their executable and registered key hashes matched the previous release exactly. A second public replay verified the author's distinct two-host capture. The local private funding and receipt checks apply to the reviewer's own run. Each replay independently verified 12 raw blocks from genesis, all three node databases, the managed supply of 100, two different SLH authorizations, transaction inclusion, 1,200 units of mining issuance and all 18 fees. [Settlement reader](settlement.py) · [Private receipt checks](wallet.py)

## What the observations established

- Across the two runs each pair of newly generated maker identities registered with both relays. A separate implementation of ML-DSA-65 verified all four advertisements. Ten changes per advert to the signed fields, key or signature were rejected. The strict schema exposed the network, service, lifetime, endpoint and ephemeral public authentication material. The aggregate test compared the actual signed advert bytes with private addresses, capabilities, quote entropy and funded legs. Privacy also depends on honest content in otherwise valid fields, on endpoint correlation and on the transport observers. [Advertisement checker](adverts.py)
- In the independent participant stores, three genuine firm quotes each had one reserved funded input, an old-verifier-approved leg and a native output the seller could open. The 7- and 8-native makers controlled distinct keys and sources. Private quote commitments matched at both ends. Reapplying one maker's real firm quote to the other maker's request failed in both directions. The expired and disconnected 7-native sessions had neither final signature. Only the selected 8-native quote matched the published pair. The chosen ordinary beneficiary landed in output slot 1 in the independent run. The local check tried both slots with the restored beneficiary seed. [Local firm quote reconciliation](quotes.py)
- Before selection, the participant gateway saw 39 RPCs and zero submissions. All three peer mempools were empty. The two intervening blocks had no payment frames, the spent set stayed constant and fees stayed at 12. The entire selected history contained four funding actions, one swap and the restored wallet's ordinary payment. Only the last two packets were submitted through the participant gateway. This establishes the result for the observed devnet path; the maker and relays still received off-chain traffic. [Traffic reader](traffic.py)
- The live wrong-peer connection and post-preparation disconnect both sent zero private application bytes. Separate transport controls rejected an unpinned certificate, a wrong live ML-DSA exporter signer and a classical-only endpoint. An independent passive forwarding fixture parsed the clear TLS 1.3 ServerHello. It observed group 0x11ec (X25519MLKEM768), its 1,120-byte server key share, and AES-256-GCM. The live maker authenticates to the anonymous taker. Both private parties can see proposed terms and receiving addresses. Relay and network observers can correlate endpoint, timing and sizes; a ledger observer sees the ordered physical pair and public fee. A second process, identity or host cannot establish economic independence or resistance to Sybil identities. The earlier quantum-proof and private-receipt assurance limits still apply. [TLS byte observer](tls_bytes.py)

## Measured bytes and inclusion

Directions below are from the taker transport or client to the service and back. Directory totals include both makers' four framed registrations and the taker's discovery. Negotiation totals include the stale quote, refused sessions, comparison and final exchange. Each stream is counted once at its indicated observation point.

| Observation | Independent, one host | Author, two hosts |
| --- | ---: | ---: |
| Directory application bytes, sent / received | 29,603 / 15,059 | 29,603 / 15,059 |
| Private JSON bytes, sent / received | 225,069 / 617,303 | 225,069 / 617,303 |
| TLS TCP payload at taker, sent / received | 235,927 / 647,081 | 235,927 / 647,075 |
| TLS TCP payload at forwarder, to maker / to taker | 235,927 / 650,598 | 235,927 / 650,592 |
| Swap node RPC, request / acknowledgement | 320,928 / 120 | 320,928 / 120 |
| Selection to observed inclusion | 26.33 s | 26.85 s |
| Submission to observed inclusion | 12.55 s | 7.75 s |

All five authenticated socket byte pairs matched the corresponding forwarding observations in each run. The wrong-peer failure delivered 1,874 encrypted bytes to the independent client while its tap counted 5,391 in that direction. On the two-host run the counts were 1,873 and 5,390. The second failed session contributed 1,406 outbound bytes and no inbound bytes at either point. These are measured TCP payloads including TLS handshakes. TCP/IP headers, retransmission and SSH tunnel overhead lie outside the counters. The published SWB1 bundle occupied 320,905 bytes. Its physical frames added 320,900 bytes to a 321,122-byte block. The two explicit confirmed-frame reads together sent 182 and received 320,954 node RPC bytes. Timings cover one 12-second-period miner in each run. [Per-operation results](REVIEW.json)

## Reproduce

Use the Linux dependencies and pinned Node binary from the [workflow](../../../.github/workflows/stranger-swap.yml). Run the release checkout in a new directory with `W` set to fresh absolute scratch storage and `STRANGER_NODE` to that Node executable. The default walkthrough builds both proof roles and generates all wallet inputs locally.

```sh
set -eu
umask 077
export STRANGER_NODE RAYON_NUM_THREADS=2
mkdir -p "$W/provider"
python3 -m pip download --no-deps --only-binary=:all: --dest "$W/provider" dilithium-py==1.4.0
./pqd market --home "$W/run" walkthrough
set -- "$W/run"/source-build-*/build
python3 -IB experiments/user-assets/review/build_helpers.py "$1/upstream" "$W/helpers"
R=experiments/stranger-swap/review
set --
for n in a b c; do set -- "$@" --db "$W/run/nodes/$n/chain.sqlite"; done
python3 -IB "$R/verify.py" --public "$W/run/public" --deployment "$W/run/deployment" \
  --helpers "$W/helpers" --node "$STRANGER_NODE" --provider-wheel "$W"/provider/*.whl \
  --output "$W/receipts" --private-home "$W/run" "$@"
python3 -IB "$R/tls_bytes.py"
python3 -IB experiments/stranger-swap/transport_check.py
python3 -IB experiments/stranger-swap/wallet_check.py
```

For a public-only readback, extract the independent release attachment to a new directory, verify its SHA256SUMS there, and point `--public` at the extracted `public` directory. Supply the same registered public runtime and helpers. Omit `--private-home` and `--db` and choose a new output directory. The verifier checks the independent ML-DSA provider wheel's pinned digest before use. The optional `--require-published-elf` reproduces the historical binary identity check on matching builds. [Command](verify.py) · [Archive allowlist](package.py)
