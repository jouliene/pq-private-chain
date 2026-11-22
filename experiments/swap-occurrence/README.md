# Phase 1E — occurrence conservation across a funded atomic swap

**Decision. Retain the deployed profile-C swap rules for monetary conservation.** A selected branch can include an SWB3 exchange and then continue under the ordinary C payment, registration, mint, burn and reward rules. The proof needs a consistent interpretation of the inherited prefix once. It derives the next state after each complete block, including blocks with a swap. No consensus, wallet or wire-format change was made. [History theorem](Swap.lean) · [Specialization to the registered protocol](Bridge.lean)

## What is established

* **For the same packet.** `packet_refines` starts with an accepted byte string, its selected parent, the two registered worker results and local satisfying witnesses for those statements. Both signers authorize the same ordered digest. The checked public NFs and output CMs match the occurrence transition in order (spent rows as a set). The entire registry event list stays fixed. Each asset keeps its total unconsumed face value. The native decrease for both legs together is exactly 3. Either leg may pay. [Packet decoder and two-signature check](Wire.lean) · [Ledger refinement](Bridge.lean)
* **For each real input.** A leg's verified height, header and depth bind its Merkle membership to its own eligible prefix. Selected CM uniqueness gives one funded occurrence. Commitment, typed opening and owner binding make the real NF stable across openings. Public freshness therefore rules out a previous debit, including one by the other leg. Dummies never debit an occurrence. A swap output incorporates the ephemeral signing key into its effective raw opening; a later spender uses that effective opening and needs no signing secret from the creation. [Opening and membership derivation](Bridge.lean)
* **Across blocks.** The physical limit is four frames. A swap occupies two, with one logical fee. Global uniqueness checks include all other frames and nonzero supply events. The ordered fold carries freshness through the block and credits the miner once with 100 plus the sum of the logical fees. With all outputs and fees accounted for, aggregate native face value grows by exactly 100 per covered block. Ordinary C transfers and all four supply operations reuse their earlier arithmetic and registry refinement. [Mixed-block and branch induction](Swap.lean)

The pure state transition commits two legs together or keeps the starting rows. Database atomicity is a separate implementation claim. The experiment compares selected SQLite rows and pools before and after failed admissions, then checks the complete accepted exchange on three real nodes. The Lean development does not model SQLite locking, process crashes or PoW selection. [Source mapping, assumptions and scope](MAPPING.md)

## Funded result

The walkthrough reuses the published partial-fill funding recipe. Two fresh buyers independently purchase 50 A for 5 B each from the same seller. Two physical frames and both fresh signatures are included in each accepted exchange. The observation checks private funding links locally and exports the following test amounts. [Measured amounts and controls](observed.json) · [Observation program](observe.py) · [Prior scenario](../partial-fills/README.md)

| | First fill | Second fill |
|---|---:|---:|
| Seller's funded A inputs | 90 | 40 change from the first fill + an older 10 |
| A received by this buyer / A change to seller | 50 / 40 | 50 / 0 |
| B received by seller | 5 | 5 |
| Native fee from buyer / seller | 3 / 0 | 3 / 0 |
| Native reward in the single-swap block | 103 | 103 |

For the second fill the funded run observed a 400,165-byte SWB3 packet, four new spent marks, four user outputs, one reward and zero registry writes. The three nodes confirmed the same ordered public effects. The live node rejected an incomplete pool submission, a PoW-sealed block with a missing leg, a block with a repeated pair and a previously spent pair. Rejections left the observed durable state and pools unchanged. Separate synthetic relation controls ran the registered prove-and-verify pipeline. It succeeded for fees of zero and three and failed as expected for a changed signer key, a fee of one, token inflation and an inconsistent asset. The control reports a combined verdict, without attributing each failure to a particular stage. [Runnable controls](source.py)

## Reproduce

On x86-64 Linux use Bash, Git, curl, GNU tar, zstd, xz, OpenSSL, Python 3.10+ and working unprivileged bubblewrap namespaces. Allow several GB for the private working directory. From the pinned checkout run:

```bash
bash experiments/swap-occurrence/reproduce.sh "$(mktemp -d)/case"
```

The command verifies the pinned Lean toolchain, Node.js and public history/deployment downloads, regenerates the SLG3 source from pinned Qnero, checks the registered role, compiles the Lean modules with warnings as errors, and makes fresh funded swaps. A public-only native worker re-verifies both proofs and signatures. Lean then recomputes the byte framing and common authorization digest from the observed packet and compares the admitted effects to the selected store. Additional replay controls change the order, omit a leg, remove one signature verdict and introduce a spent NF. [Reproducer](reproduce.sh) · [Kernel audit](kernel.py) · [Wire readback](Replay.lean)

A non-author repeated the default command from an anonymous public clone. A separate byte parser and SQL readback confirmed the exact 40 A plus 10 A spend, both owner journals per exchange and the two miner rewards. Submitting the second frame alone over live RPC also left every persistent table unchanged. All three public summaries matched the tested CI artifact byte for byte. [Independent review and checksums](review/PUBLIC.md)

Only `case/observed.json`, `kernel-result.json` and `source-result.json` are public results. The case directory contains actual keys, negotiations and input links. Keep the directory private. The proof's deployment assumptions include a faithful A/B prefix, soundness for the exact registered statements and the scoped hash and signature assumptions listed in the source mapping. Quantitative post-quantum security, privacy jointly with receipts, and universal wallet recoverability remain open.
