# Security of the compact complete ordinary proof

The candidate prover takes a CP03 ordinary statement and its private witness,
runs the complete randomized CP03 prover, then canonically encodes the resulting
public proof and transaction. The new file carries the 528-byte statement, both
2164-byte receipt envelopes and the compact proof in one body. The verifier starts
with that file and its installed program. It reconstructs the public fixed table
from the local program, recomputes its commitment, derives the query coordinates
from the Fiat–Shamir transcript, reconstructs the CP03 proof and calls the
existing complete cryptographic verifier. The unchanged mask, field, hash and
query parameters control security. A fresh encoding of an old proof is useful
for testing this map. The measured samples start with newly generated private
payments.

| Obligation | Mechanism and scope |
|---|---|
| Verifier owns the relation | An ordinary transaction selects only the allowed 2x2 grammar. The verifier builds the AIR, public table and registry from compiled code, checks the fixed commitment, and frames the exact statement with local profile, program and preprocessing identities. |
| Spend authority and single consumption | Each input links a secret key to the owner in its note, its opening and its canonical occurrence-based nullifier. The public statement enforces distinct nullifiers. The ledger checks current spentness, replay and admissible anchors. |
| Funded occurrences | Each of the two inputs binds its origin and commitment through 40 ordered levels to the declared root. The relation constrains index bits and each index against the public leaf count. The ledger selects eligible root/count pairs. |
| Output and conservation | Both note commitments, asset type, bounded amounts and integer conservation including the fee are checked. The ordinary grammar requires zero credit and debit. The standalone candidate checks the existing ordinary minimum fee. |
| Receipt binding | The full ciphertext envelopes, their ordinals, chain identity and canonical transaction core determine the public receipt digests. The verifier checks both. The full statement, including nonce and digests outside the 49-field AIR projection, enters Fiat–Shamir. Receiver decryptability and recipient anonymity have separate assumptions. |
| Public-only compression | Fixed openings are computed from verifier-owned deterministic preprocessing. For all other omitted words a transcript-derived row occurrence selects identical bytes already in this proof. The producer compares every elided value before emission. The verifier takes no prover-selected dictionary, query indices, table, external proof or database. |
| Byte identity and new identifiers | The new body and proof have distinct magic bytes. The reference ledger retains CP03 objects and IDs. A future protocol must choose a single consensus identity or deliberately define a transport encoding that expands to the canonical ledger object. |
| Soundness, knowledge and privacy | An accepted candidate maps efficiently to a complete CP03 proof for the same statement. A claimed knowledge guarantee requires the corresponding CP03 knowledge guarantee. An honest candidate transcript is deterministic public post-processing of a CP03 transcript. Compression lengths and repeated-query patterns are computable from that public transcript. This inherits the existing research assumptions for joint masking, Fiat–Shamir in the QROM, adaptive multi-payment privacy, Poseidon2 and receiving. |
| Availability, resources and DoS | Cold verification reconstructs the entire public table and full proof in memory, then performs complete verification. Reads, fixed arity, query counts, tree depths and body size are bounded. Resource measurements cover finite samples on Linux x86-64. Further consensus integration would need its own service and admission boundary. |

The logical correspondence relies on the original verifier accepting only the
registered program and on both implementations agreeing on the byte grammar.
An incorrect compact transcript replay can cause an honest proof to be rejected.
Exact roundtrips, independent verification of the expanded proof, rejection
tests and independent execution directly exercise that implementation risk.
Formal cryptographic qualifications for CP03 are in [SECURITY.md](../../docs/SECURITY.md).
