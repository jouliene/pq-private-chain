# Two private swap wallets

Each party uses its own backed-up seed and trusted local validating node. Exchange verified public address files separately. The private terms file contains both addresses, both currencies and quantities, the network, exact last eligible block height and 32 fresh random secret bytes. The public commitment is SHA-256 over the domain and the complete private encoding. The secret randomness prevents a simple public dictionary of likely exchange amounts from opening it. Each locally generated leg has a separate secret signing-key nonce. No spending seed, private funding row, path or nonce is a negotiation message.

Use the literal `native` for the native currency and a canonical 32-byte hexadecimal ID for a token. The native sender pays the fee by default. For token-for-token trades side A pays by default. The offer can specify `--payer a` or `--payer b`. Each wallet independently confirms its own fee when it prepares its leg. Give the counterparty only the files it needs over an authenticated, confidential channel. The prototype uses local files and does not supply a network negotiation transport. Consenting through the CLI requires an independently trusted address file and independently entered amounts, asset IDs, expiry and local native fee.

```sh
./pqd swap --home "$LAB" terms alice "@$BOB_ADDR" "$FIXED" 7 "$MANAGED" 30 "$EXPIRY" "$TERMS"
./pqd swap --home "$LAB" leg alice a "$TERMS" "$FIXED" 7 "$MANAGED" 30 "$LEG_A" --counterparty "@$BOB_ADDR" --expiry "$EXPIRY" --fee 3
./pqd swap --home "$LAB" leg bob b "$TERMS" "$MANAGED" 30 "$FIXED" 7 "$LEG_B" --counterparty "@$ALICE_ADDR" --expiry "$EXPIRY" --fee 0
./pqd swap --home "$LAB" authorize alice a "$TERMS" "$LEG_A" "$LEG_B" "$SIG_A"
./pqd swap --home "$LAB" authorize bob b "$TERMS" "$LEG_A" "$LEG_B" "$SIG_B"
./pqd swap --home "$LAB" combine "$TERMS" "$LEG_A" "$LEG_B" "$SIG_A" "$SIG_B" "$PACKET"
```

For a first native balance, Alice can sell 20 of her 100 managed units to Bob for 8 native. With 25 native in one eligible note, Bob pays 8 to Alice, pays 3 to the miner and keeps 14. Alice can fund her leg entirely from the managed note and keeps 80 managed. Both `authorize` calls and `combine` use the same syntax as above. Submit the completed packet to a validating peer.

```sh
./pqd swap --home "$LAB" terms alice "@$BOB_ADDR" "$MANAGED" 20 native 8 "$EXPIRY" "$TERMS" --payer b
./pqd swap --home "$LAB" leg alice a "$TERMS" "$MANAGED" 20 native 8 "$LEG_A" --counterparty "@$BOB_ADDR" --expiry "$EXPIRY" --fee 0
./pqd swap --home "$LAB" leg bob b "$TERMS" native 8 "$MANAGED" 20 "$LEG_B" --counterparty "@$ALICE_ADDR" --expiry "$EXPIRY" --fee 3
./pqd swap --home "$LAB" authorize alice a "$TERMS" "$LEG_A" "$LEG_B" "$SIG_A"
./pqd swap --home "$LAB" authorize bob b "$TERMS" "$LEG_A" "$LEG_B" "$SIG_B"
./pqd swap --home "$LAB" combine "$TERMS" "$LEG_A" "$LEG_B" "$SIG_A" "$SIG_B" "$PACKET"
./pqd swap --home "$LAB" submit "$PACKET" --node c
```

Native exchanges and token exchanges with payer B use the 3,361-byte private `SWPTER02` encoding. Relative to the original header it adds one fee-payer byte after the expiry and a currency byte before each party's address. Native has tag 0 and a zero ID, while tokens have tag 1 and a nonzero ID. Version 2 hashes the full private encoding under `SWP1/private-terms/v2` followed by NUL. Historical token-for-token agreements with payer A retain the 3,358-byte `SWPTER01` encoding and original commitment. Both use the same registered SLG1 verifier, encrypted receipt format and joint public bundle. A wallet running the current checkout can negotiate against its existing approved SWP1 deployment.

Before offering, a wallet verifies its own leg, its ordered real nullifiers, the proof-bound per-swap authorization key, fee and exact private change opening. Its SQLite wallet journal atomically stores the complete offer and exclusive real input reservations before exporting it. The ordinary payment outbox sees these reservations too. The primary native output carries the full native price, zero token quantity and a zero ID. A token output carries zero native and the full negotiated quantity under its exact tag. For native offers the wallet selects up to two unreserved native-only notes. Token offers use notes of the agreed asset and can include native-only funding. Fees are deducted separately from the sender’s available native value. The native buyer’s payment can therefore fund the seller’s later ordinary fee after seed recovery.

Before initially signing, each wallet re-verifies both complete proofs and the ordered ciphertexts under its local registered verifier. It checks distinct effect sets and signing keys, both fees, its immutable original offer and full terms commitment, exact own change, and the expected incoming commitment/ciphertext for both native and token values, including the currency ID. Its isolated spending-key role decrypts the incoming note, rebuilds the commitment under its own spend public key and derives its nullifier. It then checks both branch anchors and the expiry against its synchronized selected header, and checks its own reserved inputs are still available. The counterparty can race its funding. Atomic consensus admission checks current spentness, distinct outputs and both signatures before changing any ledger state. Both parties sign the same digest of network, blinded terms, expiry, fee side and both ordered complete leg hashes.

Each wallet persists the digest and signature before returning signature bytes. Retrying with the same bytes returns the same signature, including after a lost reply. Changed legs cannot trigger a different authorization. Before release, `abort WALLET SIDE TERMS` irreversibly closes the local session and frees its reservations. A disconnect after releasing the final signature can leave a counterparty able to broadcast the exact swap. After the currently selected chain has reached the deadline, `abort WALLET SIDE TERMS --release-after-expiry` explicitly unlocks funding for new local intents while retaining the old authorization. An alternative shorter branch may still be eligible for the original signature. Nodes enforce single consumption on each branch. Seed-only reconstruction recovers on-chain notes, while the negotiation journal and original private terms file are required to resume these off-chain authorizations.

`python3 -IB experiments/atomic-swap/wallet/check.py` tests both private encodings, both payer orientations, legacy hash compatibility, exact amounts, currency substitutions, bounded native/token funding selection, shared reservations and staging. After producing genuine legs, `python3 -IB experiments/atomic-swap/wallet/check_receipts.py HOME TERMS LEG_A LEG_B WALLET_A WALLET_B` exercises both spend-key roles and complete provers' outputs, including ciphertext substitution, ownership, asset and quantity negatives. Keep private terms, output files containing those terms, signing nonces, coin selections and private SQLite stores outside public evidence.
