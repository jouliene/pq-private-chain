# Native registered SGM1 public verifier

The C++20 verifier recompiles the 99-permutation public monetary wiring from the canonical FS01 statement, reconstructs the transcript and checks the packed proof in the same call. Its C ABI takes a verifier-owned 32-byte genesis pin, a 526-byte encoded statement and the proof. All binary inputs have explicit lengths. The public statement includes the chain, funded root and count, fee, two nullifiers, two output commitments, intent and authorization. The enclosing ledger authenticates the eligible ancestor, reconstructs the intent from the role, envelope and receipts, performs signature and state checks and supplies this statement. The same monetary proof relation checks ordinary transactions and the two separately bound swap legs. [C ABI](sgm1_verify.h) · [Python wrapper](verify.py) · [Ledger integration](../ledger.py)

## Build and run

From the project root on Linux x86-64 with SSE4.1/PCLMULQDQ, a C++20 compiler and OpenSSL development headers:

```bash
native=experiments/sgm1-admission/native
out=$(mktemp -d)
"$native/build.sh" "$out"
SGM1_NATIVE_LIB="$out/libsgm1_verify.so" python3 "$native/replay.py" PUBLIC_PAYMENT_RUN GENESIS_SHA256
"$out/sgm1-verify" GENESIS_SHA256 STATEMENT_FILE PROOF_FILE
```

The replay tool takes an output directory produced by the previous structured-payment harness, containing the ordinary packet and signed public prefix. Use the same pinned Node binary as the original funding replay via FS_RECEIPT_NODE. The tool checks both signatures, derives the expected funded root, parses the SGM1 envelope, then measures five real proof checks and tries fifteen mutations. It reports process CPU/wall time for each proof call and peak RSS of the Python process. Prefix replay and intent parsing occur before the proof-call timer. The first call includes loading the native library and initializing its process-wide field tables. Each subsequent call also recompiles fresh statement-specific wiring, derives fresh challenges and evaluates all constraints and authenticated openings. Byte bounds are enforced before copying the proof in the C ABI. The backend requires 23.92 MiB for the main 783,808-element challenge-field coefficient vector on the measured count-13 transaction. [Replay program](replay.py)

The shared library returns 1 on success, otherwise 0 and an optional error message. The Python wrapper exposes `verify(pin, statement, proof)` with three byte strings, returns True on acceptance and raises ValueError for invalid proof data. It loads the library selected by SGM1_NATIVE_LIB, defaulting to `libsgm1_verify.so` beside the wrapper. The standalone verifier takes a lowercase or uppercase hex genesis pin and public binary statement/proof files.

## Registered computation

The setup mirrors the arithmetic and allocation order of the public Python payment relation. Count-dependent comparator branches change wire indices and sometimes proof length, including the exact capacity case at 2^40. The 66-bit carry chains, inactive-input equality, real/dummy nullifier selection, asset/quantity logic, auth, both outputs, hidden child ordering, header/padding and capacity bits are all compiled into fixed public constraints. Each intermediate sponge rate block uses the preceding permutation's output and retains its capacity; wire identifiers are shared wherever the reference reuses them. The first two witness coordinates are explicitly constrained to 0 and 1. [Native wiring](wiring.cpp) · [Reference relation](../../structured-keccak/payment/monetary.py)

The upper verifier reconstructs the exact labeled transcript from the pin, statement and K=4 suite. It runs six GKR reductions, their five 11-variable map reductions and the ordered-child and scalar sum-checks. All product and public wiring checks are aggregated to the same committed witness. Three terminal transposed map checks share coefficients on the same input boundaries; the verifier combines their linear projections before a single scatter across the 99×4 groups. The native ring/AS and LCS/DECS backend authenticates the result. The parser must consume the complete proof. Each call owns its statement, transcript and commitments. Only immutable field and Keccak tables can persist across calls. [Upper verifier](upper.cpp) · [Ring and commitment backend](backend.cpp)

## Checks

`wiring_check.py` reconstructs independent Python and native public wire maps for counts 1, 2, 3, 13, 2^39−1, 2^39, 2^40−1 and 2^40. It compares canonical hashes of every address in every permutation boundary, private selector, product and linear check, including all public target bits and their order. The test needs the earlier wide-field module because the Python wiring imports the existing proof runtime. Build that dependency with `experiments/hidden-membership/smallwood/build-wide.sh OLD_NATIVE_DIRECTORY` and run:

```bash
PYTHONPATH=OLD_NATIVE_DIRECTORY python3 experiments/sgm1-admission/native/wiring_check.py
```

The historical ordinary packet digest `7d824013f097fa234c51bd1343f20034845a2ae6fadf9bfdb4a957f21832a6d7` was replayed from its signed prefix. A second frozen reproduction, digest `25330c52bad41a36a11ff844e54b1086e739a8b647d6980f2164e1b46d5f928b`, also passed. These checks concern wire compatibility and actual verification costs. The underlying quantum knowledge and privacy assumptions and the ledger-admission results are reported separately. [Prior published digest](../../structured-keccak/evidence/PAYMENT.json) · [Measured replay and controls](public-replay.json)
