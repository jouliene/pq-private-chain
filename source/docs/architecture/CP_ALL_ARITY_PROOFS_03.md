# CP all-arity genuine proof caller 03

Root source allocation, 2026-11-16. Implement in
`experiments/compact-all-payments-v3/`; do not alter the closed bounded caller,
arity frontend or historical proof/support evidence. This is the next genuine
complete-payment discriminator, not permission for ledger admission or a claim
that source authorization and encrypted receiving have already been integrated.
Root owns integration and any shared edits. Essential shared extraction must be
delivered as an unapplied exact patch and reviewed before root applies it.

## Exact inputs and decision

Use the executed arity frontend source03-locked manifest
`f78d079650a9606157bf77ca1be2785fbfe1da187b432a9cf082a6f2025270b1`,
archive `38c0c71bb3822f5c4b90616273cb0abccfcc652b4fbc9b94e3e528cb68ed3685`,
actual controls receipt `41cd8b9ff4dc203c553284cbe1389633e2cce382f44db1a9c8c7723c56fd4201`.
Independent actual review follows; source review17b2f463 and runner reviewd603e080
already passed. Root read actual constraints, symbolic degree and raw cases.

| Arity | Statement bytes | Public fields | Assertions per row | Real permutations |
|---:|---:|---:|---:|---:|
| 0 | 448 | 33 | 965 | 8 |
| 1 | 464 | 41 | 966 | 182 |
| 2 | 528 | 49 | 966 | 356 |

All have N512, 579 main and 114 fixed columns, both current/next, and actual
symbolic degree3. The largest monetary side is at most3*MAX<2^53<p.
The real Rust AIR controls passed61 relation cases,26 internal trace mutations,
45 parser cases, three host identity groups and the old/new differential and
credit-to-transfer opening/origin linkage. Those controls are not proofs.

Use the actual bounded proof source03d9338c and component source07
13f3a7fd as the cryptographic baseline. Its nine production postimages and
all transitive P3 dependencies must resolve to the same regular bounded view.
The component's Forced sampler is not a production dependency. Root's latest
genuine bounded2x2 proof4ef687f7 and reviewf588973e are prior evidence, not a
proof under this new frontend or new statement grammar.

The new question is whether all three complete relations produce actual bounded
proofs, verify with public artifacts alone, and support immutable preparation
reuse without program/arity confusion or changed security geometry.

## Trusted registry and versioned framing

Compile one sealed registry with exactly three approved programs. Canonical
kind/arity selects one enum member; a transaction cannot supply new program code,
manifest bytes, constraints, parameters, table or verification keys. One common
profile identity binds the full ordered three-program shape policy and shared
cryptographic parameters. Each program has a distinct program identity binding
its actual source, arity, layout, canonical fixed table and complete relation.
Canonical embedded JSON and SHA3-512 identity rules remain as reviewed.

Prepare each program from trusted source/table and recompute its exact degree,
assertion count, widths, next-row closure and preprocessing commitment. Refuse
any mismatch. Prepared objects are immutable and include their exact approved
arity/IDs; only a parsed matching statement can use them. The public verifier
must call the canonical CP_ARITIES_03 parser before obtaining the projection.
The frontend's shape-only bytes/projection APIs intentionally used for malicious
AIR fixtures cannot become public intake bypasses.

Define a new frame with literal ASCII tag `PQPC/CP-FRI/03/FRAME`:

```
u16(tag_length) || tag || u16(3) || profile_id64 || program_id64 ||
SHA3-512(ASCII("PQPC/CP-P2-03/RESEARCH-PAYMENT")) ||
preprocessing_id64 || preprocessing_commitment64 ||
u32(statement_length) || canonical_statement ||
u32(public_value_count) || ordered_public_values_as_canonical_u64le
```

The whole frame is absorbed before any challenge. Exact source/nonce/receipt
bytes remain bound even where they are outside the AIR projection. The public
projection is derived from the parsed statement and has exactly33/41/49 entries,
never padded with ignored public values. A new challenger is created for every
proof or verification; no statement, decoded proof, transcript or verdict cache.

The complete proof envelope is
`ASCII("CPFRI003")[8] || u16(3) || profile64 || program64 || frame_digest64 ||
u32(payload_length) || unchanged canonical inner proof payload`.
Its header remains206 bytes. Old magic/version/identity rejects. Reuse the actual
reviewed codec/hash/PCS/FRI implementation, not a witness-as-proof or signature
substitution. New framing is deliberately incompatible protocol code; avoid
blind copies of the fixed2x2 campaign. Small shared generic operations may be
extracted while preserving old callers' exact behavior and archived evidence.

## Parameters, entropy and limits

Retain Goldilocks and its exact degree5 basis, N512/H1024, B16/q160, five helper
columns, eight quotient chunks if recomputed, all salts/correlated masks, SHA3-512
proof roles, binary folds and zero PoW. All P3 type edges must use the reviewed
bounded zeta/PCS-alpha Fixed2 selection, typed abort and no retry/partial proof
publication. Genuine producer randomness remains fallible fresh OS entropy;
no test sampler, deterministic masks or size-based retries. The existing internal
32-byte StdRng/ChaCha12 qualification remains; no PRG upgrade is implied.

The old904-constraint combination bound does not cover the new965/966 counts.
Recompute the affected combination terms from exact source/formulas before a
genuine-proof allocation. Keep unchanged FRI/observation terms distinct and
retain all hash/knowledge/Fiat-Shamir/QROM/adaptive-receipt qualifications.
Do not present a numeric algebraic union bound as whole-protocol PQ assurance.

Enforce2,097,152 complete proof bytes at producer publication, bounded file/IPC
intake and public verification API before decoding or large allocation. Keep
the separately bounded inner codec. Statement intake is at most528 bytes and
must have the exact arity length. Witness shape is exactly n actual inputs and
two outputs. No dummy note/NF or extra unbound witness. Any private producer
interface must not log/commit/hash secret witness/backup bytes or print field
values on failure. Public diagnostic fixtures remain explicitly separate.

The existing layout-based honest byte ceiling may be reused only after checking
the actual inner geometry and its unchanged assumptions. Lower public arity or
real hash-row count does not authorize smaller masks/N. Increased assertions
do not automatically imply more serialized fields, but actual proof bytes and
measured times must decide. Preserve old measurements as their own results.

## Next bounded evidence

First deliver actual source/graph/manifests, a public byte-level reference frame/
envelope decoder, source/parameter correspondence and bounded runner. No Cargo,
archive, timing, proof or private cycle is allocated by this document. Root
reviews and allocates those stages separately, stopping on each real failure.

Then create one genuine PUBLIC proof for each0x2/1x2/2x2 relation. The initial
existing61-case fixture may supply semantic vectors, but its tiny-value credit
and fee2 examples are not admissible under CP_INTEGRATION_03's tariff. Provide
a deterministic PUBLIC linked three-payment fixture with sufficient registered-
credit-sized value and the exact fixed reservation minimum fees, ordinary
credit/debit zero, real depth40 funded membership and real output openings.
Source registration/signature and receipt encryption remain unverified in this
standalone proof fixture and must be labeled; no funding/admission claim follows.
Do not claim an invented witness path establishes canonical history.

Fresh public-only verification must genuinely accept every generated proof and
reject corrupted payloads, coherent statement mutations (chain, nonce, fee,
credit/debit where legal, NFs, CMs, root/count, receipts and credit source),
unapproved profile/program/context, malformed/trailing/noncanonical encodings,
program/arity confusion and exact/over-cap controls. Separate parser/identity
rejections from decoded cryptographic rejections. A changed credit source can
leave AIR values identical; the exact transcript and later authorization still
must bind it. Exercise each authentic proof with a wrong prepared program.

After genuine public artifacts exist, prepare all three trusted programs once
in a fresh public-only process and verify distinct proof/statement pairs in
mixed and repeated order with a fresh transcript every time. Measure total
registry preparation, each complete call including parse/bind/decode/cleanup,
peak/current memory and cold startup separately. Final call after negatives
must still succeed. Every call executes real verification. No verdict/program
from the producer or proof-derived preparation may be reused. The FP2 whole
admission/state/receiving/recovery requirements remain outside this experiment.

Keep source/runtime snapshots and actual exit/signal/wrapper/raw outcomes.
Independent review follows exact executed code; final acceptance still requires
private receiving, source signatures/current consumption, atomic ledger, backup-
only restoration/new spend, three fresh cycles and same-revision independent
rebuild/public replay. This caller is the next implementation, not completion.
