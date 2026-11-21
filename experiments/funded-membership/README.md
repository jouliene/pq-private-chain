# Verify funded membership under three proof registrations

Use Linux x86-64, Python 3.10 or newer, Rust 1.93.0 with rustup, Cargo, a C build toolchain, Git, curl, patch, tar/xz and bubblewrap with working user namespaces. The script obtains the checksummed Node 24 signature verifier, pinned upstream sources and locked Cargo packages. It creates an isolated private directory and uses local CPU proof-of-work. The public genesis and historical funding rules are unchanged.

```sh
bash experiments/funded-membership/reproduce.sh /tmp/funded-membership-fresh
```

Supply a new directory for each run. Its wallets, seeds, negotiations and databases are private. The run first funds two receipts at H12 and H13, preserves the A/B installation, and stages C over the funded H24 stores. The ordinary CLI is `./pqd upgrade --home HOME --node a --suite auto`; its actions include send, restore, balance, issue, register, mint, burn and the existing two-wallet negotiation. The H25 activation is a research network rule. Existing A/B peers can mine a different chain beyond it. Operators require the same scheduled software to agree on validation.

**Independent checks.** The pure-Python model needs no Rust build. The public replay checks every original proof, both owner approvals and the fork-relative ledger. The separate owner test can attribute inputs by possession of one backup per isolated trial. The following commands use the private result directory generated above.

```sh
python3 -IB experiments/funded-membership/vectors.py
o=/tmp/funded-membership-fresh
p="$o/network/public/membership"
d="$o/network/deployment"
python3 -IB experiments/funded-membership/conformance.py "$p"
python3 -IB experiments/funded-membership/review/replay.py "$p" "$d" "$o/helpers" "$o/node-v24.22.1-linux-x64/bin/node"
python3 -IB experiments/funded-membership/controls.py "$p" "$d"
python3 -IB experiments/funded-membership/review/owners.py "$p" "$d" "$o/network/owner-backups/offline" "$o/network/membership-negotiation/receiver.backup"
```

The published block graph, signed bundle, legacy-B comparison and synthetic economic observations can be checked in place of the newly mined graph in both public readers. Run the owner check only with matching backup material from one's own fresh experiment. [Decision](DECISION.md) · [Reference predicate](REFERENCE.md) · [C proof and role pins](HARDENING.md) · [Independent assurance](review/ASSURANCE.md) · [Measurements](MEASUREMENTS.md)

To obtain the author's public graph, use an empty directory and verify the release checksum before extraction. The archive contains raw blocks and packets, two legitimate B retirement controls, the signed C swap and disclosed fixture measurements. Do not publish the local run directory.

```sh
base=https://github.com/jouliene/pq-private-chain/releases/download/funded-membership-2026-11-21
mkdir /tmp/funded-membership-public-check
curl -fLsS "$base/funded-membership-public.tar.gz" -o /tmp/funded-membership-public-check/funded-membership-public.tar.gz
(cd /tmp/funded-membership-public-check && sha256sum -c -) < experiments/funded-membership/RELEASE.sha256
tar -xzf /tmp/funded-membership-public-check/funded-membership-public.tar.gz -C /tmp/funded-membership-public-check
python3 -IB experiments/funded-membership/review/replay.py /tmp/funded-membership-public-check/public "$d" "$o/helpers" "$o/node-v24.22.1-linux-x64/bin/node" | cmp - experiments/funded-membership/evidence/REPLAY.json
```

The independently funded graph is `funded-membership-independent.tar.gz` at the same release URL. Use [its checksum](review/INDEPENDENT.sha256), extract in another empty directory and run the same public readers. Its tips, key-dependent identities and roots are recorded in [the fresh result](review/FRESH.json). All three CI jobs tested the [executable revision](https://github.com/jouliene/pq-private-chain/commit/0842fc21fa77291e382282da103b9154ac0ff50f). [Public review](review/CLEAN.md) · [CI](review/CI.json)
