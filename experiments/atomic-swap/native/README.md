# Registered SLG1 roles and local receipt test

A fresh two-wallet run generated two 143,251-byte legs, each carrying a 139,658-byte proof and two encrypted receipts. The two wallet processes opened their incoming payments and their own change. The established MNG1 implementation independently opened the same four notes. A new MNG1 proof consumed the first participant's payment to the second, using the exact real nullifier derived when the second participant checked the incoming receipt. The old public verifier rejected the prepared SLG1 packet both verbatim and relabelled as AST1 or MNG1. Both separate authorization signatures verified; substituting the other participant's key or changing expiry failed. [Role results](ROLE.json)

The test uses disposable wallet seeds on private tmpfs and synthetic authenticated Merkle roots. The network walkthrough supplies mined inclusion, fork choice, rollback and post-restore branch spending. The registered relation had 499 gates before blinding, degree bits 12 and 34 public inputs. Two valid funded witnesses paid fees zero and three. The full prover/registered verifier rejected witnesses with another authorization key against the same committed outputs, with a fee of one, with inflated quantities or with a different output token ID. [Statement and private opening](PROFILE.md) · [Registration](REGISTER.json) · [Relation results](CHECK.json)

## Reproduce

Run from the repository root with the pristine Qnero checkout at `f04c91307837c0231668383bec76ba98d89d2652`, Rust 1.93.0 and an empty output directory. Use a fresh build target for independent reproduction. The last command also uses the already registered compatible MNG1 installation. Supply only installations built against the published source and key pins. The build adds the role example and its small public/issuer-authentication adapters in a disposable copy of upstream. It leaves every existing AST1 and MNG1 source and registration intact.

```sh
python3 -IB experiments/atomic-swap/native/build.py "$lab/slg" "$upstream" "$lab/target"
RAYON_NUM_THREADS=2 "$lab/slg/native" register "$lab/slg/registered"
cmp "$lab/slg/registered/swap.vk" experiments/atomic-swap/native/registry/swap.vk
RAYON_NUM_THREADS=2 "$lab/slg/native" check-relation "$lab/slg/registered" | cmp - experiments/atomic-swap/native/CHECK.json
python3 -IB experiments/atomic-swap/native/check_roles.py "$lab/slg" "$mng_build" | cmp - experiments/atomic-swap/native/ROLE.json
```

The profile binds the public key to both normal, spendable typed notes at the wallet boundary. The sender chooses an ephemeral authority during construction. The circuit does not prove the private software's nonce-generation policy or honest approval of a displayed trade. Reusing a nonce with the same seed repeats the public key. A process with access to the private signing IPC can sign a digest. The participant's trusted local wallet therefore validates and persists its decision before issuing S. An arbitrary relay has only the proved leg, its public receipts and any final signature expressly released to it. The approving parties' signatures cover the two ordered packet digests, network, terms commitment, fee payer and expiry; the node verifies both signatures and both proofs. [Joint packet encoder](../swap_wire.py)

## Public pair measurements

Use the deployed operator code, its read-only verifier inputs and a complete public SWB1 bundle. Neither program takes a wallet home, seed, private negotiation file or node database. Each native verification process runs inside the same mount/network namespace isolation as the live node. The Python caller imports the deployed chain, pair verifier, envelope parser and transport codecs. The pair check runs at the transaction's expiry height, so it measures both proofs and both signatures under the actual rules independently of the machine's current tip. Selected block membership, conflict checks, disk transactions, publication, and network laps are measured by the walkthrough.

```sh
python3 -IB experiments/atomic-swap/measure.py "$deployment" "$public_bundle"
python3 -IB experiments/atomic-swap/controls.py "$deployment" "$public_bundle"
```

The cold trial starts a new pinned verifier, checks one pair and shuts down. Its end-to-end wall time to approval includes binary pin validation, process startup, key initialization, framing, IPC and both proof/signature checks. CPU to the final verdict includes the Python caller, completed setup helpers and live Linux process CPU of the sandbox supervisors and native worker. The worker is sampled before shutdown because the namespace does not propagate its CPU usage into the parent’s reaped-child counter. Linux process ticks have the reported resolution. High-resolution native stage meters and launcher/parent shutdown counters are recorded separately. The warmed process records its first call as warm-up and the next five as measurements. Each pair's CPU total combines host process CPU with the four native verification meters; warm call wall time includes decoding and IPC. The native RSS value is Linux process high-water RSS including worker threads. The host process has a separate high-water value. Both are process maxima and shared pages may overlap. Role traffic counts four framed requests and replies per accepted pair. Cold shutdown and setup costs are reported separately from warm pair samples.

Wire accounting separates the two receipts in each leg, proof bytes, inner and outer framing, and both final authorization signatures. Per-block bytes include the two u32 packet lengths and the header/reward/nonce shared by the block. The one-copy negotiation-file sum assumes each party exchanges each required artifact once; the private terms byte count comes from the public codec schema. The submit RPC size includes its request metadata and length prefix. These are application-layer bytes, without application retries, gossip duplication or IP link-layer overhead. Negative controls independently check each owner's signature against changes to the network, private terms commitment, expiry, payer and both leg digests.
