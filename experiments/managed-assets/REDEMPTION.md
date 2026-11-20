# Local redemption and simulated bank

The redemption coordinator is a separate process from the network nodes and treasury wallet. The operator designates one specific customer return, asset, amount and payout destination. The treasury must have received that exact amount in a uniquely identifiable incoming output of the named selected-chain transaction. The treasury wallet opens it locally. A positive holding from an earlier treasury transaction, a treasury self-transfer, a spent note or an ambiguous return cannot establish a request. Enrollment pins the spending nullifier privately. One network/return transaction and one network/returned funding identity can each back only one request.

```sh
./pqd managed --home "$LAB" redeem enroll order1 treasury "$ASSET" 200 "$RETURN_TX" customer-a --node c
./pqd managed --home "$LAB" burn treasury "$ASSET" 200 "$RETURN_TX" --intent burn-order1 --wait 180
./pqd managed --home "$LAB" redeem settle order1 "$BURN_TX" --node a
./pqd managed --home "$LAB" redeem status order1 --node b
```

The service uses one simulated bank unit per returned asset unit. Accepting a request creates the service's obligation for its full amount. The purchased goods, promised rate, customer identity and off-chain details belong to the trusted operator. A return alone creates no bank payment. The selected node must report a genuine burn of the matching asset and amount that consumes the exact returned funding. Each request can track multiple competing burn transactions. The service stores a candidate after its first selected observation, even before it becomes eligible for payout. Three confirmations, counting the inclusion block, authorize settlement in this research scenario. The depth is a service choice. PoW can reorganize beyond it.

A first-time candidate that the node cannot currently see on the selected chain is refused. Prior verified candidates remain in the private journal when detached. `status` observes all recorded attempts and never initiates payment. If an observation spans more than one eight-transaction RPC, every page must identify the same selected head. The read is tied to the chosen validating node's snapshot. A reorganization between observation and external payment is possible. The bank ledger is durable and independent of later chain state.

The result fields support per-request synthetic public fixture accounting:

| Field | Meaning |
| --- | --- |
| `amount`, `owed` | Accepted request amount, and its unpaid portion. Enrollment with no payout for 200 yields 200 owed, regardless of burn depth. |
| `paid`, `payout_count`, `bank_receipt` | Amount actually paid, number of committed bank rows for the request (0 or 1), and its random immutable receipt when paid. |
| `selected_burn`, `confirmations`, `tip`, `height` | Matching burn and depth under the one observed selected head. An orphaned burn gives zero confirmations. |
| `exposure` | Already paid amount with no matching burn on the selected chain. A replacement burn removes this exposure on inclusion. Its depth can be inspected separately. |
| `attempts` | Number of distinct verified burn candidates recorded for the request. |

An orphaned paid burn of 200 therefore yields paid 200, owed 0, exposure 200 and one payout. A later matching selected replacement burn yields paid 200, owed 0 and exposure 0 with the same one bank receipt. Total outstanding token supply comes from the selected-chain registry, not the bank. The public fixture should retain only these approved service aggregates, the public chain evidence, and the intentionally disclosed demonstration labels. Never publish the service databases.

## Persistence and failure handling

The service uses two separate SQLite databases, both mode 0600 in the lab's mode 0700 `redemptions/` directory. SQLite runs with full synchronous commits.

- `requests.sqlite` has `requests` for request identity, network, treasury, asset, amount, return transaction, payee, private funding nullifier and optional acknowledged receipt. Constraints reject aliases of a prior return. `attempts` stores a candidate transaction, request and its first observed block/height.
- `bank.sqlite` has `payments`, keyed by the domain-separated hash of the network and canonical ASCII request ID, with separate uniqueness on `(network, request)`. A row contains immutable payout terms and a unique opaque receipt. A serialized insert on this business key can create only one payout. Every retry compares the terms and reads the same durable receipt.

The candidate is committed before asking the bank to pay. `redeem settle ... --crash-after-bank` exits with code 75 immediately after a fresh bank commit, before writing a local acknowledgment. Retry or run `status` to reconcile the bank's committed receipt, including after the burn has detached. An interrupted coordinator loses no bank history. A reviewer with the private lab can independently query `SELECT request,amount,receipt FROM payments` in the bank database and compare `requests.acknowledged` in the coordinator. The bank's operational state must survive service restarts.

Run `python3 -IB experiments/managed-assets/check_redeem_service.py` for the deterministic event-sequence accounting tests. They include an actual child-process exit between commits and concurrent independent SQLite writers. The integrated managed walkthrough supplies real proof-verified node events.
