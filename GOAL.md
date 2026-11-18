# Independent-node payment validation decision

Start from published `7c2d0fc8b68c566d13e3e341c1f49bacaad527f4`. CP03 is the executable reference. Its 15.39% transport experiment and the wallet synchronization milestone are closed.

Decide how independent nodes should validate complete private payments at the owner's 100M offered payments/year sizing input. Evaluate one primary design, masked outer sumcheck with hiding WHIR-style linear-form openings, and one fallback, transparent block aggregation of public wallet-generated CP03 proofs. Preserve private ownership, funded occurrence membership, nullifiers, bounded conservation and fees, and statement/receipt binding. Separate wallets, builders, pruned and archival nodes and cold recovery. Tenfold reduction is a research screen. Quantify the complete before- and after-inclusion obligation.

A selection requires three fresh complete payments, public verification, receipt and subsequent spending. An independently reviewed decision to defer both routes requires an executed discriminator for each, precise barriers and the next test that could change the decision. Publish reviewed source, measurements, projections and reproduction commands to the existing repository. The global blockchain objective stays **ACTIVE**.

**Bounded decision reached.** Defer both tested configurations. Independent reproduction confirmed a verifier bottleneck for the masked proof and the accelerator workload for transparent block aggregation. CP03 remains the running reference. The [architecture decision](experiments/node-validation/DECISION.md) identifies the next discriminating experiment.
