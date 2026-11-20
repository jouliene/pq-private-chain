# Ephemeral private maker channel

A taker verifies the chosen advertisement, connects to its IPv4 endpoint and authenticates the selected maker before sending the quote request or continuation. The two public discovery relays can store and forward the same signed advertisement. The private endpoint serves its own temporary identity. Each client operation opens a separate TLS connection and has no dependence on a TLS session cache. The Node executable and its embedded OpenSSL are pinned to the Linux x64 build in the [repository build instructions](../../BUILD.md).

## Public identity and channel binding

The advertisement carries exactly the version, network, service, issue and expiry timestamps, IPv4 endpoint, ML-DSA-65 public identity, TLS leaf certificate fingerprint and signature. The identity is canonical standard base64 of 1,974-byte DER SubjectPublicKeyInfo. The fingerprint is lowercase SHA-256 of the complete DER certificate. The signature is canonical base64 of 3,309 bytes. Sort object keys, use ASCII-escaped JSON with commas and colons as separators and no whitespace. The maker signs the following bytes with its disposable ML-DSA-65 key. The selected advert ID is the lowercase SHA-256 of the complete canonical signed object.

```text
ASCII("PQD/stranger-advert/v1") || NUL || canonical_JSON(object_without_signature)
```

Both endpoints require TLS 1.3, the sole named group X25519MLKEM768, TLS_AES_256_GCM_SHA384 and ALPN pqd-stranger/1. The taker checks the negotiated group, negotiated version, cipher, ALPN, fresh handshake and exact leaf certificate fingerprint. The maker generates its own short-lived self-signed P-256 certificate. The private trust decision uses the signed advertisement and a second live ML-DSA-65 signature. Public CA and DNS hostname validation are outside this pinned protocol. The first encrypted frame from the maker is its signature over the following bytes. Only after verification does the taker send the private application frame.

```text
id = from_hex(advert_id)
binding = TLS-Exporter("EXPORTER-pqd-stranger-v1", context=id, length=48)
signed = ASCII("PQD/stranger-server-auth/v1") || NUL || id || binding
```

The exporter ties the signature to this TLS handshake and the selected immutable advertisement. The cipher suite supplies authenticated record encryption. ML-KEM-768 contributes a post-quantum component to hybrid key establishment and ML-DSA-65 authenticates the ephemeral advert and channel. The TLS certificate signature is classical ECDSA. These are composition claims for the implemented protocol. A proof of the full application composition, traffic-analysis resistance, human identity, reputation, uptime and secure delivery of bootstrap configuration remain open. Discovery and endpoints expose IPv4 addresses, timing, public advert fields and traffic sizes. An untrusted relay can suppress an advert or advertise a different service identity under its own key. Takers trust their selected verified ephemeral identity. The maker sees private requests addressed to it. Takers use the wallet's per-request random capability and wallet-specific receiving address; the server does not require a public taker identity. [Node TLS API](https://nodejs.org/download/release/v24.22.1/docs/api/tls.html) · [OpenSSL named groups](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/) · [TLS 1.3 exporters](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5) · [IANA supported groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8) · [Node crypto API](https://nodejs.org/download/release/v24.22.1/docs/api/crypto.html) · [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

## Runtime, frames and accounting

`market_transport.py` locates the repo-local Node or accepts an absolute `STRANGER_NODE` override. Each Python process checks the executable's approved SHA-256 before first launch and checks again if the file metadata changes. Each helper requires Node 24.22.1 with embedded OpenSSL 3.5.9. Certificate creation uses the host OpenSSL CLI for a fresh P-256 key and certificate. The maintained Node crypto and TLS APIs perform all advertisement signatures, live signatures and transport encryption. The node role inherits a minimal environment. There are no npm dependencies. Use a 0700 identity directory and a fresh `transport-identity` subdirectory per advert. Keep the private key files in the operator home. The service enforces advert expiry during requests. Local key retention follows the operator's private-home lifecycle.

The taker sends one bounded 4-byte big-endian length and a UTF-8 JSON object. It receives a similarly framed JSON reply with either a result or a short generic failure. Each body is at most 1,048,576 bytes including its JSON envelope. The earlier signature frame uses the same prefix. The client starts one small Node process per transport operation; the maker keeps one Node acceptor and one serialized Python wallet handler, caps live sockets at eight and replies busy while a maker operation runs. The handshake and pre-dispatch application frame have 8-second bounds. The TCP connection has a 150-second overall bound; the taker supervisor allows 160 seconds including helper exit. A disconnected request may already be running on the maker and may have committed private wallet state. The wallet uses durable request IDs, pinned final bytes and capabilities for retries; its own native-role execution has separate time bounds.

`request(ad, body, meter=m)` fills `request_B` and `reply_B` with encoded JSON body lengths. `wire_request_B` and `wire_reply_B` count the actual socket payload below TLS, including the handshake, live signature frame, application prefixes, encrypted records and orderly shutdown seen by that endpoint. TCP/IP headers, packet retransmissions, process pipes, public discovery and downstream chain RPC have separate accounting. Failed calls retain observed traffic and authentication stage when available. Do not publish per-session payloads, private quote capabilities, addresses or key directories.

## Reproduce

```sh
python3 -IB experiments/stranger-swap/transport_check.py
```

The check starts two processes and a separate counting TCP proxy. It verifies negotiated group 0x11ec from the raw ServerHello, checks both observed byte totals against the client counters and exercises a real classical-only listener. A newly signed advert with an independently generated identity pins the genuine server's exact TLS certificate to isolate rejection of the live ML-DSA signature. Other cases cover a different certificate, an edited signed endpoint, oversize input and a generic authenticated maker rejection. None requires a payment address or a funded wallet.
