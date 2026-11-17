# Cryptographic roles and research obligations

The code executes genuine cryptographic proofs and native post-quantum primitives.
A successful finite test does not prove the complete protocol's quantum security,
zero knowledge, recipient anonymity or authorization theorem. This repository is
not a production-security certification. No whole-system numerical PQ strength
is assigned.

| Role | Current exact mechanism | Qualification still required |
|---|---|---|
|Receiving secret|Final ML-KEM-1024; Node24.22.1/OpenSSL3.5.9|IND-CCA premises do not by themselves establish recipient anonymity; multi-user/adaptive and QROM composition remain separate.|
|Receipt payload and binding|Labelled HKDF-SHA384, AES-256-GCM nonce12/tag16/plaintext512; SHAKE25648-byte key confirmation; descriptor1672/envelope2164/context174|Joint KEM/DEM/KC/context and payment-proof privacy, correlated simulation and query bounds. Static receiving-key compromise exposes old receipts; no forward secrecy.|
|Laboratory source authority|Pure ML-DSA-87, context PQCHAIN-CP3-SOURCE;314-byte message,4627-byte signature,2592-byte public key|Native provider/runtime and one-time current-state checks; this is not implemented permissionless issuance or a spend-knowledge substitute.|
|Commitments, authority, nullifiers and tree|Framed Poseidon2 over Goldilocks, width16/exponent7/RF8/RP24/rate8/capacity8/output8;152constants|Binding, randomized hiding, secret-derived unpredictability and domain/role composition have distinct assumptions; no inherited SHAKE guarantee or numerical quantum claim.|
|Complete payment proof|Hiding uni-STARK/direct FRI over Goldilocks^5 (X^5−3), N512/H1024,579main/114fixed, B16/q160,8quotient chunks,10binary folds, SHA3-512|Actual hiding-IOP correspondence, correlated masks/joint FRI, adaptive multiple-proof privacy, soundness/knowledge and Fiat-Shamir/QROM remain qualified research obligations.|
|Randomness and challenges|Three separate fallible32-byte OS seeds, StdRng/ChaCha forks, one-use opening state, fresh transcripts; Fixed(2) outside base field|PRG entropy/fork/output-volume, conditioning and multi-target analysis. A32-byte seed alone is neither a defect nor a full security argument.|
|Recovery|Private key inventory plus common public history/inventory and independently supplied endpoint; current wallet constructs membership paths locally with a fixed native frontier and bounded joint journal|Endpoint validity, consensus, freshness and availability cannot be inferred from hash linkage. No remote owned-index queries. Current refresh rereads the whole prefix; a fresh backup still needs every retained random receiving key.|

The verifier owns the allowed programs/profile. Public verification does not
accept an arbitrary prover-chosen program or read wallet secrets. Complete same-
witness ownership/membership/nullifier/value constraints are necessary but not
sufficient: canonical encoding, checked integer bounds, accepted anchors,
source authorization/entitlement, duplicate rejection, fees and atomic commit
are separately enforced in the ledger.

Ledger privacy is separate from network metadata. The current code does not hide
sender IP, relay timing/volume, archive access patterns or provide a deployed
anonymous relay. Small synthetic examples do not measure an anonymity set.

## Classical plus PQ hybrids

No elliptic-curve component is added by default. An EC+PQ KEM can hedge shared-
secret confidentiality only under its exact combiner assumptions; recipient
identification by either branch can still break anonymity. AND authorization can
retain unforgeability if one independent branch survives, but pays both key,
signature and verification costs. OR/downgrade acceptance inherits a broken
branch. Quantum-broken EC value commitments can break supply binding despite a
PQ transport/signature. A hybrid cannot repair proof hiding or nullifier errors.
No anonymous-receiving/full-relation hybrid is established by these smoke tests.

## Installation and testing boundary

The explicit runtime installation process binds actual Node/native/config bytes
at this operator's selected paths. It changes installation identity, not the
payment algorithm/profile. Equal version strings alone do not attest binary
provenance. Preserve source/runtime/ELF checks, held-descriptor invocation,
process cleanup and typed failure handling; failures are not permission to bypass
them. The trusted local host is outside the adversary model of these tests.

Private fixture inputs/backups travel through bounded local memory/pipes and are
not committed, logged or hashed by the publication smoke. This is not a memory-
erasure proof or protection against a privileged host. Public synthetic fixtures
include only intended public protocol data and are not live funds.

Functional reproduction, resource viability, formal PQ/privacy assurance and
production readiness remain separate. Native fault behavior, constant-time/FFI
review, portable/optimized agreement, cross-platform reproducibility and economic
consensus security require additional evidence. Rust memory safety alone proves
none of those properties.
