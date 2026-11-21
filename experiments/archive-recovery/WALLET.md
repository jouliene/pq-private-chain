# Restore and spend from the original backup

The backup is the 32-byte seed exported before the first funding payment. The
recipient supplies the seed and the local node endpoint. The node independently
validates the public PoW history and selects its tip. The wallet receives that
tip and requests common history from the node. The reproduction mounts the
approved public deployment read-only, gives the wallet a private directory and
exposes its local endpoint as a Unix socket. During restore, only the named
backup is mounted. A spend additionally needs the destination's public address.
The restored wallet has no archive connection or original wallet database.

## Funded amounts

| Event | Native | Managed asset | Selected branch |
|---|---:|---:|---|
| A payment to the offline address at H12 | 20 | 12 | Common |
| B payment to the same address at H13 | 14 | 16 | Common |
| Signed two-owner B swap at H14 | 3 fee | 7 fixed for 9 managed | Common |
| Issuer-signed mint to the onward recipient at H15 | 3 fee | 7 newly issued | First branch |
| Newly recovered owner's B payment to the onward recipient | 28 | 25 | Must be verified on inclusion |
| Change to the recovered owner | 3 | 3 | Same inclusion |
| Fee credited to that block's miner | 3 | 0 | Same inclusion |

The H8 registration binds the managed issuer. The separate H15 mint advances
its sequence and raises supply from 100 to 107. Reorganizing across H15 must
restore the common registration and supply. Before the first spend the offline
wallet holds exactly two positive notes. Both their token values and their
native values are individually insufficient. The 28-native, 25-managed output
and 3-native fee require both genuine input notes.

## Commands inside the isolated wallet role

```sh
python3 -IB /code/wallet.py /deployment /wallet /endpoint.sock "$tip" restore --seed /backup
python3 -IB /code/wallet.py /deployment /wallet /endpoint.sock "$tip" balance
python3 -IB /code/wallet.py /deployment /wallet /endpoint.sock "$tip" spend \
  --address /address --asset "$managed_id" --intent restored
python3 -IB /code/wallet.py /deployment /wallet /endpoint.sock "$confirmed_tip" confirm --intent restored
python3 -IB /code/wallet.py /deployment /wallet /endpoint.sock "$winning_tip" reconcile
```

The restore installs the seed into the private wallet and reconstructs spendable
notes and membership paths locally. An incomplete recovery result has
`complete=false`. It gives the requested and verified tips and omits holdings.
The spend command synchronizes before selecting inputs or creating an outbox
attempt. It checks the selected endpoint again immediately before submitting
the completed packet. The confirm command requires a saved attempt and its
actual presence in locally verified selected history.

On rollback, reconciliation scans the newly selected branch, restoring the
common inputs when their old spend detaches. Using the same intent on the new
branch preserves the original input reservations across retry. The registered
wallet can then replace an ineligible old attempt. Each confirmed payment
must be tied to its selected block and observed successor blocks.

## What the wallet discloses

The history request digest hashes only the framed outgoing `history_head`,
`history_range` and `history_check` requests in order. The locator, target,
start, limit and base identify public chain positions. The roles exclude seed
material, output decryption results and submitted packets from this digest.
Independent cold wallets at the same target must have identical digests and
request sizes. A fresh scan of the author's H24 prefix used two head requests,
two common range requests and one endpoint check. Wallet upload still exposes
the complete public transaction to the local node. The timing and size of a
scan can disclose a recovery or catch-up event.

`wallet_compare.py` reconciles miner-a, miner-b, alice, bob, forward, conflict
and offline. Each owner uses its own backup in a separate wallet directory.
At a common selected tip the full and pruned nodes must agree on the PoW and
monetary state, both registry descriptors and each controlled wallet's native
units, per-asset balances and note count. The totals must equal native issuance
and the individual asset supplies. Where all seven begin at genesis, the check
also compares the outgoing public query transcript across owners. These are
disclosed synthetic fixture aggregates. Wallet seeds, outboxes, membership
paths and owned-note databases stay private.
