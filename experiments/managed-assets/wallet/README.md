# Managed wallet operations

An MNG1 lab uses the ordinary mined-reward wallet, privately named asset inventory and seed backup flow. Its own SQLite files are `mng1-wallet-state.sqlite` and `mng1-intents.sqlite`. MNG1 stages its client from AST1 and uses a dedicated registered verifier. The original AST1 devnet runs separately. On MNG1 the ordinary `issue` creates a fixed-supply asset, and `send` supports native value and either asset policy.

With distinct funded wallet names, a live network and exported addresses, an operator can run:

```sh
./pqd managed --home "$LAB" register treasury 1000 --intent registration --wait 180
./pqd managed --home "$LAB" mint treasury "@$CUSTOMER_ADDRESS" "$ASSET" 50 --intent order-1 --wait 180
./pqd managed --home "$LAB" send customer "@$TREASURY_ADDRESS" 0 "$ASSET" 7 --intent return-1 --wait 180
./pqd managed --home "$LAB" burn treasury "$ASSET" 7 "$RETURN_TX" --intent redeem-1 --wait 180
./pqd managed --home "$LAB" balance treasury
```

Set `ASSET` to the registration result's `asset_id` and `RETURN_TX` to the confirmed customer return's `tx`. Each operation costs three native units. The initial registration credits the treasury itself. A subsequent mint can use an unrelated native fee input and pay a recipient directly. Supply events disclose the asset and quantity. Ordinary payments keep the AST1 private asset note. A fresh restore uses the seed to recover funds and rederive the issuer signing key. Recovery of pending, off-chain intent context also requires the sender's local journal.

For redemption, the treasury selects the one unspent incoming output with the specified return transaction, ID and exact amount. The wallet excludes local change and rejects a return transaction that also consumed the treasury's own funding. It pins the returned note first. If that note lacks the native fee, the second input must be native-only. A complete burn can leave zero asset units. Note selection and the return reference stay in the treasury's journal. Public nodes verify owner-authorized destruction for the right asset. Matching a particular external service or request to a returned payment is the operator's private responsibility. Store the request reference as the local `--intent`, and obtain the return transaction ID through the agreed customer channel.

A mint intent persists the prior selected supply event and sequence ahead of proving. Its retries, including after an ambiguous RPC reply or a detached inclusion, retain that authorization parent and any previously reserved inputs. If a different supply event makes the signed parent stale, a new intent authorizes the updated state. Previously reserved inputs remain associated with the original intent. The journal deliberately prevents assigning them to a different outstanding request. A wrong issuer can produce a valid signature under its own wallet key; public nodes check it against the registered key.

The CLI reports `minted`, `burned`, `asset_id`, native fee/change and token input/change. The compatibility field `issue_supply` carries the unsigned wire delta; for burns this is `2**62 + burned`. The selected public supply and a wallet's private asset balance can be read separately with `list` and `balance`.

Run `python3 -IB experiments/managed-assets/wallet/check.py` for command staging, durable request semantics, arithmetic, exact external return selection and selection failures. These local checks execute no cryptographic proof. The live managed walkthrough handles proving, mining, public verification and seed restoration.
