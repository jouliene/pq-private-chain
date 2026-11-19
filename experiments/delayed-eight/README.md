# Reproduce the eight-payment historical certificate

Use Linux x86-64, Python 3.10+, Git, a C toolchain, rustup, bubblewrap with unprivileged namespaces and working loopback sockets. Allow at least 9 GiB of available RAM, several GiB of disk and HTTPS for the pinned Rust dependencies and Qnero upstream. The normal APV2 operator path and the original DLF1 network remain separately executable.

~~~sh
git clone https://github.com/jouliene/pq-private-chain.git
cd pq-private-chain
git checkout --detach delayed-dlf1-eight-2026-11-19
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
python3 -IB experiments/delayed-eight/reproduce.py "$lab/fresh"
~~~

The command compiles the pinned DLF1 and D8C1 programs, derives both public verifiers, creates new wallet seeds, mines at the real 22-bit devnet difficulty, builds two fresh certificates, compacts a disposable replica, and starts an empty peer validator. It checks rollback, missing authorizations, resume, forks and the restored recipient's new spend. The final public-only replay starts from the retained interchange and checks the new payment after its wallet has stopped. PoW nonces, heights, keys, proof randomness and timings vary. The two certificates share one warm builder. The first eight genuine transactions have eight different wallet owners; a separate ninth payer on the competing branch exercises an uncovered transaction and an underfilled certificate.

To verify the author's committed public history from a clean checkout, run the lighter command below. It needs no wallet or original eight proof packets.

~~~sh
python3 -IB experiments/delayed-eight/reproduce.py "$lab/public" --public-only
~~~

The fresh run's public numeric results are in `live/CAPTURE.json`, `live/BRANCH.json`, `live/RELAY.json`, `cert/CERTIFICATES.json`, `accept/ACCEPT.json`, `replay/PUBLIC.json` and `COSTS.json`. The portable retained file is `accept/retained.d8`. Full original PoW bodies for direct audit are in `live/blocks`, the public post-recovery payment and its mined suffix in `accept/successor`. The private sender/recipient homes, seeds, databases and outboxes remain inside the private work directory. Publish only explicitly selected public records.

[Decision and costs](DECISION.md) · [Certificate profile and negative controls](crypto/README.md) · [Assurance](assurance/ASSURANCE.md) · [Independent checks](review/REGISTER.md) · [Clean result and public assets](https://github.com/jouliene/pq-private-chain/releases/tag/delayed-dlf1-eight-2026-11-19)
