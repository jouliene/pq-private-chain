# Independent reference check

Reviewed source revision `8f9bae9b96248e6c147acf9664fd34bb727cb756`.
This check concerns the retained public fixture and the code for producing and
checking it. Fresh execution of a candidate is a separate result.

## Complete body accounting

From the repository root run `python3 -I experiments/payment-size/review/cp03_bytes.py`.
The program checks the immutable fixture identity, reads the body and proof
lengths, then partitions the inner proof using the trusted CP03 codec dimensions.
All counts below are bytes of the released 2x2 payer fixture.

| Component | Bytes |
| --- | ---: |
| Body header, canonical statement, both receiving envelopes | 4,876 |
| Proof envelope header | 206 |
| Degree, roots, opening claims, helpers and initial fold commitments | 60,364 |
| Randomizer opening batch | 81,796 |
| Trace opening batch | 816,516 |
| Quotient opening batch | 243,076 |
| Public preprocessing opening batch | 214,916 |
| Ten FRI fold opening batches | 325,672 |
| Terminal element and remaining zero grinding fields | 56 |
| **Complete proof** | **1,742,602** |
| **Complete body** | **1,747,478** |

The trace batch sends 160 openings of 584 eight-byte field elements, 747,520
bytes before salts, path counts and sibling hashes. Sending the 579 ordinary
columns alone under this encoding costs 741,120 bytes. Changing headers or
removing public preprocessing from the wire cannot by itself reach the
175,126-byte complete-body screen. These counts describe one actual CP03 body.
The 1,751,265.75-byte historical mean measures a different sample.

## Public and private check boundaries

- The installed registry builds the AIR, its 512-by-114 fixed table and the
  public verifier key locally. It checks the fixed-table digest, equal prover
  and verifier roots, 579 main columns, 966 assertions per 2x2 row, eight
  quotient chunks and 49 projected public fields. See
  `source/experiments/compact-all-payments-v3/src/registry.rs`.
- The 528-byte canonical statement carries two nullifiers and two commitments.
  The parser enforces zero ordinary credit and debit, fee and count bounds,
  canonical elements and distinct nullifiers. The AIR constrains ownership and
  note openings, occurrence-index reconstruction, both membership paths,
  input/output range, and exact value conservation. The deployed ledger adds the
  arity-specific minimum fee and spentness/anchor policy. Read
  `compact-arities-v3/src/{air,program,statement}.rs` and
  `source/crates/ledger-cp03/src/admission.rs`.
- Receipt digests and nonce are absent from the 49-field AIR projection.
  `compact-all-payments-v3/src/frame.rs` absorbs the entire canonical statement,
  projection, selected identities, preprocessing digest and commitment before
  challenges. The ledger reconstructs each receipt digest from its actual
  encrypted envelope, core, chain and slot. Thus a candidate needs both the
  full statement binding and a public body-level envelope check. Neither
  establishes decryptability for an arbitrary malicious sender.
- `compact-all-payments-v3/src/engine.rs::prove_owned` generates a trace from the
  supplied witness and checks all constraints before creating a proof.
  A direct negative test can flip an in-range private value, key or path element
  while holding public bytes constant. Record which stage rejects it. To isolate
  conservation from note commitment binding, regenerate dependent public
  commitments after changing a bounded output amount, preserving an imbalance.
  A wallet rejecting an unexpected packet length tests another boundary.
- The baseline public campaign rebinds a changed canonical statement to an outer
  header consistent with the changed statement before requiring rejection by
  cryptographic verification. It also changes a decodable commitment or opening.
  Keep these controls distinguishable from stale header, malformed encoding
  and decryption failures. A fresh public-verifier process needs only public
  statement, envelopes, proof, exact approved code and public setup.

## Hiding boundary in a direct multilinear port

A literal switch from the baseline to the bundled multilinear AIR prover and a
hiding WHIR PCS would disclose witness-dependent data. The CP03 trace generator
fills each key-word column from its corresponding secret in each 174-row input
block; other rows contain zero for that column. At a publicly known multilinear
evaluation point, the column therefore gives a publicly weighted combination of
the two private words. Private index-bit columns have the same structure.

The bundled `multi-stark/src/prover.rs` explicitly passes per-column local/next
terminal values into the proof opening. The hiding WHIR adapter assumes requested
evaluations may be revealed, and its guarantees concern its inner PCS transcript.
A viable replacement needs an outer hiding argument covering these terminal
values and the outer constraint-sumcheck round messages together. The source
observation applies to the direct unmasked composition only; the retained CP03
uses separate trace and quotient randomization.
