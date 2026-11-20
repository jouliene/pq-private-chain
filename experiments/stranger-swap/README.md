# Discover a private swap counterparty

A taker who owns only managed test dollars can find a maker, obtain a funded quote and acquire the native coins for their next fee. The taker starts with its wallet, its validating node connection and the devnet's public relay bootstrap. Makers and relays run independently of that user. The two wallets exchange every private message over an authenticated encrypted connection.

## Run the mined exchange

From the release checkout on x86-64 Linux, use Python 3.10+, OpenSSL, Rust 1.93.0, a C compiler, Git, working unprivileged bubblewrap, and the pinned Node 24.22.1 Linux x64 binary. Obtain it using the Node installation steps in [BUILD.md](../../BUILD.md). The walkthrough uses a fresh mode-0700 directory. The source build uses pinned inputs and verifies the pre-registered MNG1 and SLG1 keys.

~~~sh
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
./pqd market --home "$lab/net" walkthrough
~~~

To put one relay and the selected maker on a second physical Linux x86-64 host, add `--remote-ssh HOST` with an existing SSH configuration entry. An optional `--ssh-config FILE` selects a private SSH configuration. The operator needs key-based login with a verified host key, rsync, Python, OpenSSL, working unprivileged bubblewrap, and permission for loopback TCP forwarding. The walkthrough provisions only public source and pinned executables into a new private remote directory. The maker creates its own keys on that machine. SSH forwarding lets the loopback-only PoW network and services communicate across hosts. Wallet-to-wallet TLS ends inside the wallets. The lab's SSH operator can observe the endpoints. SSH and network packet overhead are outside the recorded TCP payloads.

## Use an ordinary taker wallet

On a running SWP1 deployment, `$HOME_TAKER` names the taker's existing private wallet home. Its selected validating node supplies history and verifies settlement. The operator provides the two public relay endpoints in `network.json` as `market_relays`, or runs the default loopback devnet relays on ports 24871 and 24872. Only network bootstrap is required before discovery. A wallet can use its balance output to identify a token it already owns.

~~~sh
./pqd swap --home "$HOME_TAKER" balance alice
./pqd market --home "$HOME_TAKER" discover alice
./pqd market --home "$HOME_TAKER" quote alice "$ADVERT_1" --asset "$DOLLAR_ID" --quantity 20
./pqd market --home "$HOME_TAKER" quote alice "$ADVERT_2" --asset "$DOLLAR_ID" --quantity 20
./pqd market --home "$HOME_TAKER" settle alice "$SELECTED_QUOTE" \
  --asset "$DOLLAR_ID" --quantity 20 --native 8 --expiry "$QUOTED_HEIGHT"
~~~

Use the two IDs returned by discovery and the quote handle and height returned by the chosen maker. The quote displays the input currency, output currency, price, fee payer and expiry. The settle command checks that the selected local economics match, completes the two authorizations, and submits the complete SWP1 bundle to the taker's node. No exchange account, peer address supplied by the taker, manual message copying or taker-operated directory is involved. An unsigned quote can be cancelled, including locally with `cancel alice HANDLE --offline`. Once authorization has been released, a peer holding both signatures may submit the exact swap until consensus expiry. [Private terms, reservations and recovery](wallet_protocol.md)

A relay operator runs `./pqd market relay --listen HOST:PORT`. A maker with a funded wallet can publish its temporary service with the following command. Use a reachable IPv4 endpoint and a valid asset ID. The relay directory is bounded and in memory. Registrations expire within ten minutes. The maker process serves the selected identity until expiry. Starting a new instance generates a fresh identity. Outstanding unsigned reservations are eligible for cleanup when the maker next processes a quote. Existing private sessions are associated with their original advertised identity.

~~~sh
./pqd market --home "$HOME_MAKER" maker maker --endpoint "$ENDPOINT" \
  --asset "$DOLLAR_ID" --quantity 20 --native 8 --quote-ttl 120
~~~

## What the parties learn

| Observer | Accessible information |
| --- | --- |
| Public relay | Temporary ML-DSA key, certificate fingerprint, service endpoint, network, registration/expiry, client connections and request timing. Both relays can correlate the same advertisement. Every discovery request lists the entire broad service. |
| Each requested maker | Taker's private request, receiving address, token ID, amount, its own price and quote lifetime. Contacting two makers can reveal the same wallet to collaborating makers. The selected maker also sees the counterparty's prepared proof and final authorization. |
| Taker | Each requested maker's address, exact offer and complete native leg. Knowledge of a quoted leg's nullifiers can link subsequent reuse even for a losing quote. |
| Network or tunnel operator | Endpoints, timing, direction and lengths. Sizes distinguish quote preparation and final authorization in this prototype. Reused routes, IPs and timing may link discovery to payment. |
| Public validating peers | A recognizable SWP1 pair with two ordered legs, fee payer, blinded commitment, expiry, anchors, nullifiers, commitments, signatures and ciphertexts. A later ordinary payment has its own public effects. Selected synthetic economics are disclosed in the report. |

The TLS key exchange combines X25519 and ML-KEM-768. The leaf certificate uses classical ECDSA. The application additionally verifies an ML-DSA-65 signature on a connection-specific TLS exporter, under the ephemeral key authenticated by the selected advertisement. A party can create many signed identities, and relays may suppress honest makers. There is no human identity, reputation, traffic-analysis resistance, guaranteed liquidity or proven end-to-end quantum bound. The wallet still relies on the registered SWP1 proofs, receipt checks, uncorrupted endpoints and its own validating source. [Channel protocol, cryptographic assumptions and tests](transport.md)

## Verification

~~~sh
python3 -IB experiments/stranger-swap/transport_check.py
python3 -IB experiments/stranger-swap/wallet_check.py
~~~

The walkthrough uses separate wallet homes, fresh funds and actual PoW. A transparent forwarding observer counts encrypted TCP payloads. A second observer counts the wallet-to-node RPCs, including every submission. The release capture contains only public blocks, packets, signed advertisements and disclosed counters. Seeds, private quote handles and messages, individual wallet databases and private negotiation artifacts belong to the wallet operators.
