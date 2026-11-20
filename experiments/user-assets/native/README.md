# Choice of note representation

AST1 uses one native amount plus one private (asset ID, quantity) per note. A transaction can fund a recipient and return both kinds of change in the existing two-output shape. Both token-only and mixed gifts work. All notes live in the same tree and use one registered verifier. [Exact relation and receipt format](PROFILE.md)

Consider a sender with a token-only A note of 20 and a native-only note of 10. She sends 7 A and pays a fee of 3 native. Partial change in each holding is essential to this example.

| Receiver gets | Single-asset notes needed | AST1 tagged notes needed |
|---|---|---|
| 7 A, zero native | Receiver 7 A, sender 13 A, sender 7 native. Three outputs. | Receiver (0, 7 A), sender (7 native, 13 A). Two outputs. |
| 7 A and 2 native | Receiver 7 A, receiver 2 native, sender 13 A, sender 5 native. Four outputs. | Receiver (2 native, 7 A), sender (5 native, 13 A). Two outputs. |

A single-asset note would privately commit one ID, one quantity and one owner, with zero ID denoting native. It can also keep asset identity private in a common tree. It would need conditional per-ID conservation, a distinct native fee equation and padding or a larger proof shape to serve both example payments atomically. Exact funding that leaves no native change can produce a token-only payment and token change in two single-asset outputs. Exact funding in both lanes can also fit a mixed gift. Those exceptions depend on the note amounts in the wallet. Applying two or more payments instead adds outputs, fees, intermediate spending and public timing observations. There is no claim of a measured proof cost for that alternative.

A mixed AST1 gift provides one-time native fee funding. A recipient of a token-only output may need a separate native funding note before spending. A note that holds A cannot also hold B and the wallet cannot combine two *different positive* IDs into one payment, even when it only wants to spend native. One prover knows all real input openings. This prototype supplies neither multi-owner authorization nor atomic swaps.

## Proof and state boundary

The common hidden ID and its conditional placement in **each authenticated note opening** prevent clearing A on an input and allocating the same quantity of B on an output. A proof of equality of aggregate amounts without the authenticated IDs would be insufficient. A dummy contributes zero in both lanes. An issuance must spend a real position-zero note with authorization, create exactly its published fixed cap and consume zero incoming tokens. Presence of a network-bound ID descriptor, uniqueness on the selected branch, spentness, reward rules and rollback are node obligations. One ID can have many outputs with different owners and randomized commitments. There is no subsequent mint authorization or token fee lane. Any pre-existing protocol receiving or PQ assumption continues to apply to the matching component. [Proof source](profile.rs) · [Negative controls](checks.rs) · [Reference assurance](../../token-profile/ASSURANCE.md)

A validator sees all ordinary slots, anchor and height, fee, two nullifiers, two commitments, complete ciphertexts, and the proof with five zero issuance words. Repeated broadcast of an identical packet is trivially linkable. Rebuilding a transaction with the same real input preserves that real nullifier. Fresh outputs/randomness and hidden IDs do not undo these observations. Spending a fresh private output generally produces a different nullifier. Issuance discloses network, ID, cap, first spending nullifier, block/time information and any published application metadata. IP-level observation, an issuer or recipient disclosing mappings, low-entropy activity and a compromised wallet can reduce privacy.

## Reproduction and measurement

Run from the repository root with Rust 1.93.0, the pinned pristine Qnero checkout and an unused output directory. No pre-generated witness material is needed. The shared target is an optional local build cache. A clean reproduction uses a fresh target. The encrypted receipt implementation is inherited from the pinned implementation and TKN1 adapter. The new wallet places the full private ID in the encrypted memo.

```sh
lab=$(mktemp -d)
git clone https://github.com/DigitalGuards/qnero.git "$lab/upstream"
git -C "$lab/upstream" checkout --detach f04c91307837c0231668383bec76ba98d89d2652
python3 -IB experiments/user-assets/native/build.py "$lab/build" "$lab/upstream" "$lab/target"
RAYON_NUM_THREADS=2 "$lab/build/native" register "$lab/build/registered" > "$lab/REGISTER.json"
cmp "$lab/build/registered/asset.vk" experiments/user-assets/native/registry/asset.vk
RAYON_NUM_THREADS=2 "$lab/build/native" check-relation "$lab/build/registered" > "$lab/CHECK.json"
cmp "$lab/CHECK.json" experiments/user-assets/native/CHECK.json
```

The relation checks construct fresh private witnesses directly against the registered circuit. They include a genuine transfer, genuine maximum-cap issuance, and five invalid cases. The independent node, address opening, receipt binding, fee settlement, wallet recovery and competing-branch behavior require the live operator walkthrough. The generated BUILD manifest records the pristine revision, lock digest, generated source digests and this installation's binary digest. Path-dependent build identity can differ across machines. Compare the source pins and registration independently and approve the local binary.

The prover writes a `compact_prove` meter for constructing a *complete* payment with two receipts and a `wallet_setup` meter for cold setup. A fresh `native verify registered` process writes `verifier_setup` and `public_verify` meters. Each reports elapsed seconds, process CPU seconds across worker threads, and Linux process high-water RSS in KiB. The peak is cumulative for that process. Record complete frame bytes as 9 + proof bytes + 3,584, and record block, sync, storage and inclusion clocks separately where used. Verifier IPC receives one little-endian u32 length and that many bytes, and returns one length-delimited record (or the single byte 0 for rejection). Fresh independent verification needs only the approved binary, public key and public packet. Never retain private wallet IPC or per-note openings. [Live walkthrough](../README.md)

The registered AST1 circuit has 488 gates before blinding, 31 public inputs, degree bits 12 and FRI reduction schedule [2,2,2,2,2]. TKN1 had 468 preblinding gates and 26 public inputs at the same padded degree. A gate count alone does not determine proof latency, proof length or end-to-end throughput. [AST1 registration](REGISTER.json) · [TKN1 registration](../../token-profile/candidate/evidence/REGISTER.json)
