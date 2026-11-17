# Complete-payment size experiment

The bounded implementation and evaluation passed independent review. Global
blockchain development remains **ACTIVE**. The tenfold size screen was missed.

The published synchronization baseline is `8f9bae9b96248e6c147acf9664fd34bb727cb756`.
The independently reproduced executable revision is
`9dce9420fa4fa96a01b63c70fdbea8e6dde08012`. The candidate uses the reference
CP03 proof with new versioned public encoding. The reference protocol, backup
and spending path, ledger, CI workflow, parameters and fees are preserved.

| Sample | Complete 2x2 proofs | Mean compact body B | Matched reduction |
|---|---:|---:|---:|
| Primary | 3 | 1,488,346 | 15.182% |
| Independent clean execution | 3 | 1,477,063 | 15.599% |

Both executions used fresh processes and independent public inputs. The prover,
statement, ciphertext and actual cryptographic proof controls passed. The
[results](experiments/payment-size/RESULTS.md) specify exactly which failures
reached the crypto verifier. The initial namespace-launcher resource readings
were corrected by measuring the verifier child. The final evidence charges both
public registry preparations, body framing, the optional 528-byte named
statement, complete packing overhead, runtime libraries and native executable.

The decision is to retain this as an experimental transport and defer ledger
integration. A qualifying smaller payment construction and affordable storage
model remain open. A masked R1CS reduction to hiding WHIR with verifier-owned
parameters is the next proposed discriminator. Full recursive verification and
source-to-construction obligations are documented in the three-route screen.
No follow-on project, consensus integration or wallet tuning is running.

[Reproduction instructions](experiments/payment-size/README.md) ·
[Independent disposition](experiments/payment-size/review/CLEAN_REPRODUCTION.md) ·
[Public sample bodies](experiments/payment-size/evidence/three-payments/).
