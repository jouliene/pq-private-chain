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

## Two-host result

Three local PoW nodes validated the original SWP1 rules. One physical host ran the taker, the competing 7-unit maker and the relay that was taken offline. A second physical host ran the winning 8-unit maker and the surviving relay. They had separate wallet stores and temporary identities. Both hosts were controlled by the research operator. Two service instances and two independently funded wallets simulate separate operators; this demonstration makes no claim about unrelated real-world operators or anonymous routing. A second check on the remote machine matched the actual mined leg and signature to that maker's private journal and found its 20 managed units and 14 native change. The remote validator reconstructed the winning monetary state from the public capture. [Host and public replay evidence](evidence/TWO-HOST.json)

| Author capture, one swap | Sent bytes | Received bytes |
| --- | ---: | ---: |
| Both makers register with both relays, combined | 29,480 | 348 |
| Taker discovers both makers with one relay down | 123 | 14,711 |
| Private TLS traffic across all scenarios, measured at the taker | 235,927 | 647,075 |
| Public SWP1 submission to the validating node | 320,928 | 120 |
| Subsequent fetch of both confirmed frames, combined | 182 | 320,954 |

The two current quotes plus the selected private settlement used 669,380 TCP payload bytes in both directions combined. The 883,002-byte private traffic total also includes the deliberately expired quote, the disconnected maker and the substituted endpoint. These counts include TLS handshakes and record framing. They exclude TCP/IP headers, acknowledgements and the lab SSH wrapper. The independent forwarding counters matched on every authenticated exchange. During the deliberate certificate mismatch the forwarder read 5,390 bytes from the wrong server, while only 1,873 reached the taker before it closed the connection. Neither side received a private quote request in this case. The two measurements describe distinct endpoints of a failing connection.

The complete public settlement bundle was 320,905 bytes. Its two frames increased the mined block by 320,900 bytes over an empty block, to 321,122 bytes. Settlement traffic in the table describes the submit and the observed reads. Other gossip fanout and wallet history sync depend on the topology. The author capture records the wallet-node RPC sizes separately. With one real nonce search triggered every 12 seconds independent of the mempool, the operator observed inclusion 7.75 s after submission and 26.85 s after the taker selected the quote. These are one-run timings. They do not set a confirmation or throughput target.

At heights 7 and 9, before and after the abandoned negotiations, the chain showed the same spent set and 12 setup fees. Both intervening blocks had empty payment vectors. All three peers had empty mempools, and there were zero submissions in the 39 observed wallet RPCs preceding settlement. The winning swap was in block 11 and the onward ordinary payment in block 12. The two user fees brought the total to 18; 1,200 native units were issued. The recovered wallet's only input to the onward payment was the newly acquired 8-unit output.

The first remote launch stopped before wallet trading because the SSH child was already a process-group leader. The operator wrapper now uses the existing group or creates its own. The next funded run exposed an overly strict comparison of counts across a terminated TLS connection. The retained run instruments each operation at both boundaries and enforces equality for authenticated exchanges. Both refusal paths must send zero private application bytes.

The [release](https://github.com/jouliene/pq-private-chain/releases/tag/private-stranger-swap-2026-11-20) provides author and non-author public captures. To replay the author evidence from an empty ledger, start in the release checkout with the `$lab/net/deployment` created above.

~~~sh
out=$(mktemp -d)
gh release download private-stranger-swap-2026-11-20 -R jouliene/pq-private-chain \
  -p author-public.tar.gz --dir "$out"
(cd "$out" && echo '051eebb355848186f9d2870bd5926a450ad155ca1a5f0581b627b5e27776deff  author-public.tar.gz' | sha256sum -c - \
  && tar -xzf author-public.tar.gz && sha256sum --quiet -c SHA256SUMS)
python3 -IB experiments/stranger-swap/replay.py "$lab/net/deployment" "$out/public"
~~~

Public replay uses the registered node verifiers and the captured blocks. The mapping of the 8-unit private receipt to the onward payment requires a holder's independently restored wallet. The raw private opening and spending key stay on that holder's host.

A non-author fetched the implementation at `9bb62eab924bf85b35ad04884eb85b5548ffea9a` and exercised independent wallets, fresh notes, two new identities, two relays and a different 12-block history. The independent taker saw inclusion 12.55 seconds after submission. It privately reopened each funded quote, verified the onward recipient and seller after a fresh restore, and matched the final public block graph. [Clean reproduction and limitations](review/REVIEW.md)
