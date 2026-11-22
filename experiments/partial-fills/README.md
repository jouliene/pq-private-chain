# Buy part of a standing private offer

On Linux x86-64, install Python 3.10 or later, OpenSSL, curl, xz-utils and bubblewrap with working unprivileged user namespaces. From the repository root, run the following command with a new directory. It downloads three SHA-256-pinned public inputs, including the funded C verifier deployment and the original H33 history. It runs the CLI with fresh wallets and exits after stopping its local services.

~~~sh
./pqd market --home "$(mktemp -d)/partial" partial-walkthrough
~~~

The final step independently parses the local selected and detached blocks and checks both owners’ signing journals against their exact on-chain frames. You can repeat only this step with `python3 -IB experiments/partial-fills/review/verify.py YOUR_DIRECTORY`. The result is `result.json` in the chosen directory. Only that summary is intended for publication. The network directory contains live test funds, wallet seeds, signing journals, private negotiations and per-wallet service identities. The executable walkthrough runs on one physical machine using separate wallet homes, real TCP connections, three validating node processes and CPU-mined blocks. The operator controls when nodes mine and how the peers connect. [Walkthrough](walkthrough.py) · [Public input checksums](reproduce.sh)

## Use the commands on a running C deployment

Each wallet has its own private home, its own spend key, the funded deployment, and a connection to its selected validating node. Configure two public relay endpoints under `market_relays` in each participant's `network.json`. Start the existing directory service at each endpoint with `./pqd market relay --listen HOST:PORT`. Set `STRANGER_NODE` to the pinned Node.js 24.22.1 Linux x64 executable installed by the walkthrough. TLS terminates at the wallets.

In these examples A is the seller's asset and B is the consideration. **Both commands use the maker's orientation**: `--give "$A" --take "$B"`. Quantities are unsigned integer base units. The buyer pays one native fee of 3 for every confirmed fill. The maker's first command stays running and prints a ready record.

~~~sh
./pqd market --home "$SELLER_HOME" offer seller \
  --give "$A" --take "$B" --total 100 --lot 10 --price 1 --fee 3 --endpoint "$ENDPOINT"
~~~

A buyer retrieves service advertisements, then inspects a chosen service over an authenticated encrypted channel. Use the advert handle returned by `discover` and the offer handle returned by `inspect-offer`. Advertisements contain no order ID. Each buyer obtains its own quote, authorization and expiry. On successful `fill`, the buyer submits the complete signed pair to its validating node.

~~~sh
./pqd market --home "$BUYER_HOME" discover buyer-one --partial
./pqd market --home "$BUYER_HOME" inspect-offer buyer-one "$ADVERT"
./pqd market --home "$BUYER_HOME" reserve buyer-one "$ADVERT" --offer "$OFFER" \
  --give "$A" --take "$B" --quantity 50 --lot 10 --price 1 --fee 3
./pqd market --home "$BUYER_HOME" fill buyer-one "$QUOTE" --offer "$OFFER" \
  --give "$A" --take "$B" --quantity 50 --lot 10 --price 1 --fee 3 --expiry "$HEIGHT"
./pqd market --home "$BUYER_HOME" fill-status buyer-one "$QUOTE"
./pqd market --home "$SELLER_HOME" offer-status seller "$OFFER"
~~~

The second buyer uses its own home and wallet name and chooses the same offer. After the first 50 A purchase confirms, the order has 50 A remaining. After both confirm, it has zero. For a particular quote, `fill --prepare-only` constructs the funded buyer leg without releasing authorization. `fill --sign-only` signs both sides without node submission. A firm reservation requires inputs eligible now; a positive arithmetic order balance does not guarantee an immediately available combination of wallet notes.

`cancel-fill WALLET QUOTE` releases an unsigned reservation. `cancel-offer WALLET OFFER` closes the order to new consent. After an uncertain or released signature, capacity remains encumbered across close, process restart and reorg. To restart the maker use `serve-offer WALLET OFFER`. For a previously signed pair, `recover-fill WALLET OFFER QUOTE --submit` submits the recoverable exact bytes from maker storage. A buyer can inspect durable handles with `list-fills WALLET --offer OFFER`; an explicit `--request-id` on reserve enables idempotent retries. The off-chain journals must survive. A wallet seed recovers funded holdings; it does not restore unpublished agreements, private capabilities, or outstanding off-chain authorizations. [Implementation and privacy boundaries](PROTOCOL.md)
