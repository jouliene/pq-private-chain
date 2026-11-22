# Native verification of the packed terminal

The C++20 backend consumes the registered 4,096-leaf, width-91, 60-opening, 75-row encoding. Its inputs are the public transcript, circuit-derived binary and trace coefficient vectors, and their expected wide affine value. Each invocation reads the complete proof. The construction and its existing security qualifications are in the [ring specification](../../structured-keccak/ring/README.md).

The wire uses little-endian GF(2^16) and GF(2^256) encodings. Wide multiplication uses 64-bit PCLMUL products and two levels of Karatsuba composition, then reduction modulo X^256 + X^10 + X^5 + X² + 1. The base field uses the registered polynomial 0x1100b. The implementation derives the embedded subfield, inverse tower basis, absolute trace and dual basis locally. Those fixed algebra tables are the only reused data. The width and challenge counts used in a given verification are independent of packet-controlled dimensions.

The transcript length-prefixes each SHAKE input with the registered framing and absorbs all challenge bytes, including discarded lanes in base-field draws. The native ring opening checks all 256 trace bits, combines the two square identities with the affine projections, checks the public sum of Q, reconstructs all 60 distinct column choices, verifies every ordered Merkle path and checks Q at every opening. An opening computes an equivalent double sum: first weight each row by its opened base symbol, then apply each of the 91 packing-point interpolation weights. The final degree check reconstructs the original R evaluations from 60 authenticated plus 91 additional columns and hashes the exact base-field serialization. The parent verifier checks the complete transcript extent.

The independent component test consumes the existing public 83,866-byte projection fixture. It compares the wide multiplier against a shift-and-reduce implementation, checks inverses, exhausts the 65,536 embedded symbols under multiplication by the basis generator, and rejects eight altered or incorrectly framed proofs. It requires a little-endian x86-64 host with PCLMULQDQ/SSE4.1, C++20 and OpenSSL libcrypto for SHAKE256.

```bash
cd experiments/sgm1-admission/native
scratch=$(mktemp -d)
c++ -std=c++20 -O3 -Wall -Wextra -mpclmul -msse4.1 backend.cpp backend_check.cpp -lcrypto -o "$scratch/backend-check"
"$scratch/backend-check" ../../structured-keccak/ring/evidence/projection.proof
```
