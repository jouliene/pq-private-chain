# Metering one ordinary wallet payment over HTTP

The driver creates two funded notes worth 54 and 59 steps for one fresh wallet. Its normal note selection must spend both to cover a 100-step payment plus its default eight-step fee; the other output is five steps of change. It calls the original `Wallet::prepare_spend` and the complete `Wallet::submit_spend` including pre-submission genesis binding, inclusion polling, block lookup and the settled-nullifier checks. Those are the same two wallet methods an ordinary successful send uses. A separate wallet receives from history, and a new empty store recovers it from the seed backup.

An additive copy of upstream's loopback HTTP fixture counts bytes as read from each request line and header (including its terminating empty line), counts exact JSON body lengths, and records the byte length of the entire returned HTTP status line, headers and body. It returns valid authenticated public fixture state and applies prepared public changes only on `author_submitExtrinsic`, so the same real client confirms inclusion and spentness. No raw HTTP request, address, note opening or seed is logged by the meter. The generated release proof and public data may be independently checked; the FRAME replay of another fresh funded transaction is [separate](../pallet/README.md). This is plaintext HTTP/1.1 loopback with one successful inclusion. TCP/IP, DNS, TLS, external node discovery and mining were outside the captured byte stream. Poll timing changes on a real network.

The byte accounting below has five disjoint phases. All functional HTTP bytes must equal their sum. A subsequent forensic `chain_getHeader` obtains the selected public fixture block header for encoding and is outside all roles. The funding sync's metadata is the pinned fixture's matching release parameters; measuring a particular CLI startup that additionally fetches the runtime metadata requires charging its corresponding RPC exchange.

`/transactions/1` emits one SCALE vector containing precisely the encoded extrinsic. The ordinary codec is exercised by decoding the length-prefixed opaque extrinsic and re-encoding a one-element vector. The laboratory block is serialized independently with the pinned runtime's header field order, fixed u32 block height, raw digest items, and its complete extrinsic vector. The body recomputes its header's extrinsics root, and the wallet recomputes the header hash. This block has one transfer, no timestamp/coinbase inherent and no PoW seal. Shared header and vector bytes therefore apply to this fixture alone, not all consensus-valid blocks. A live peer connection is not needed to reproduce the native application notification bytes. [Pinned notification code](https://github.com/DigitalGuards/qnero/blob/f04c91307837c0231668383bec76ba98d89d2652/chain/client/network-transactions/src/lib.rs), [runtime header](https://github.com/DigitalGuards/qnero/blob/f04c91307837c0231668383bec76ba98d89d2652/chain/primitives/header/src/lib.rs).

To reproduce with the earlier [prerequisites](../README.md), use a third clean upstream checkout at the same pin. Only the generated additive test driver and its instrumented test fixture are installed.

```sh
git clone https://github.com/DigitalGuards/qnero.git /tmp/qnero-http-src
git -C /tmp/qnero-http-src checkout --detach f04c91307837c0231668383bec76ba98d89d2652
(cd /tmp/qnero-http-src && rustup run 1.93.0 cargo fetch --locked --target x86_64-unknown-linux-gnu)
python3 -B run.py /tmp/qnero-http-src /tmp/qnero-http-result
```

## Measured HTTP and serialized block

| Functional phase | Requests | Request lines B | Headers incl. blank lines B | JSON bodies B | Total outbound B | Complete inbound HTTP B |
|---|---:|---:|---:|---:|---:|---:|
| Sender funding sync | 13 | 221 | 1,504 | 2,536 | 4,261 | 9,660 |
| Sender prepares payment | 11 | 187 | 1,271 | 1,598 | 3,056 | 6,913 |
| Sender submits and confirms | 10 | 170 | 1,157 | 310,252 | 311,579 | 313,387 |
| Offline recipient scans public history | 14 | 238 | 1,621 | 3,911 | 5,770 | 329,323 |
| Empty wallet recovers from seed | 14 | 238 | 1,621 | 3,911 | 5,770 | 329,323 |
| **All five functional phases** | **62** | **1,054** | **7,174** | **322,208** | **330,436** | **988,606** |

The 100-step ordinary payment sent **314,635 B** as preparation plus submission/confirmation; including past funding sync gives **318,896 B** for this sender. Within submission/confirmation the single transaction POST was **309,227 B**, comprising 17 request-line B, 119 header/blank-line B and 309,091 JSON body B. Its complete HTTP reply was 194 B. The other submission/confirmation requests and replies account for 2,352 B up and 313,193 B down. The extra diagnostic header lookup used to serialize the block was after the 62-request boundary. Its byte count was not retained in the measured phase counters. Each underlying wallet transfer produced two independent spendable ciphertexts and one zero-knowledge private proof; public-only proof checks remain separate from these communication counters. [Actual measurement and source/hash pins](evidence/measurement.json), [test log](evidence/wallet.log).

The measured `stage.py` SHA-256 was `731200353eb8bc9e95df262cc1bff61ffc59dce85eea90d25ba269c43e3164b0`. Removing one trailing space outside a string changed its SHA-256 to `6668350368659105713129eb8dd343e0eba2adac68767e401bc0af99e38024c1`. Regeneration reproduced the recorded hashes of both Rust files exactly.

The actual synthetic header was **171 B** (128 B of hashes, 4 B height and 39 B digest including its count). The transaction's one-element extrinsic vector was **154,509 B**, making the encoded fixture block **154,680 B**. The first byte after the header is `0x04`, denoting one entry in SCALE compact form. The encoded standalone payment spans bytes `[172:]` of this file; that slice has the recorded SHA-256. The byte-identical single-transaction notification is the `[171:]` slice. These are the block, extrinsic and application notification encodings for a funded real-input pair. [Full public fixture block](evidence/public/fixture-block.scale).

The release-pinned isolated verifier subsequently accepted this exact two-funded-input public extrinsic and its ordered ciphertext binding, with the same verifier ELF as the first sample. The real input count was asserted by wallet selection before proving; the public verifier sees twelve nullifier digests across six slots, including the two nullifiers of the active payment. Each nullifier is a four-field-element digest. [Fresh public-only receipt](evidence/public-process.jsonl).
