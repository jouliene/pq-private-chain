# CP complete arity frontend contract 03

Root source allocation, 2026-11-16. Implement the exact 0x2, 1x2 and 2x2
relations below in `experiments/compact-arities-v3/`, with independent reference
vectors and adversarial AIR checks. This does not authorize a private proof or
ledger admission. Root owns semantics; historical CP frontends stay unchanged.
Reuse their hash/permutation code and the context layout wherever coherent.

The decision is executable complete value/authority/membership behavior for all
three required arities. The old 2x2 proof is not a credit or 1x2 implementation.
No dummy public input/nullifier, ignored zero-valued note, signature-only proof
or unbound existential may substitute for a missing input.

## Shared field, notes and hashes

Inherit CP_P2_FRONTEND_01 and CP_CONTEXT_AIR_02 for canonical Goldilocks fields,
Poseidon2 constants/sponge/domains, note `(asset,amount,owner[8],rho[5],r[5])`,
40-byte spending key, depth40 membership, funded `(origin,CM)` identity, NF and
context equality. Keep MAX=1,840,960,000,000,000. All amounts/assets and every
use of an input opening remain tied to the same witness. Output owners are
arbitrary canonical F^8; the payer need not know output spending secrets.

Use one distinct approved program/preprocessing identity for each arity. Program
choice is reconstructed from the canonical kind/arity and a fixed trusted set,
never supplied code. Keep N512 for all three programs in this first discriminator:
small credit traces must not silently reduce the hiding-mask dimension below the
reviewed query/observation budget. No proof geometry or security change is
authorized by a smaller number of real hash rows. Expose actual counts/degrees.

## Exact public statement

Use eight-byte ASCII `CP-P2-03`, u16le version3; input arity n in {0,1,2}, output
arity2; kind3 for n=0 (credit) and kind1 for n=1 or2 (transfer); three zero
reserved bytes. Chain32 and nonce32 follow, retaining offsets16 and48. Then:

```
n ordered NF64 || two ordered output CM64 || fee_u64 || anchor_root64 ||
count_u64 || credit_u64 || debit_u64 || two ordered opaque receipt_digest48 ||
[source_id48 only for credit]
```

Total lengths are448/464/528 bytes for n=0/1/2. Reject suffixes, noncanonical
field limbs, inconsistent headers/lengths, nonzero debit, out-of-range fee or
credit, and duplicate NFs where n=2. Transfers require credit=0 and count in
1..2^40. Credit requires credit in1..MAX and count in0..2^40; its anchor still
requires later ledger authentication. `source_id48` is an opaque identifier of
a registered parent-state entitlement, not a producer-selected verification key.

The ordered AIR projection is
`chunks(chain)[5] || n*NF[8] || 2*CM[8] || fee || root[8] || count || credit || debit`,
with33/41/49 field values. Source, nonce, receipts, kind and exact bytes remain
transcript-bound context. Public projection is derived once from parsed bytes.
They are not falsely credited as private AIR claims. All three programs must
explicitly constrain their fee/credit/debit semantics even in direct AIR tests.

## Relation and exact accounting

For n=1 or2, every actual input proves AUTH(key)=owner, NOTE(note)=CM,
NF(key,origin,CM)=the corresponding public NF, and LEAF(origin,CM) membership
below the same authenticated root/count with a40-bit index and count-1-index.
Use the existing first/last/transition and per-hash context constraints. No
additional inactive input opening may appear in the witness interface.

Every output proves its NOTE hash and zero asset. Every actual private amount,
fee and (for credit) public credit has Boolean51-bit decompositions for v and
MAX-v. Ordinary credit and all debit are zero. Require exactly:

```
sum(actual input amounts) + credit = out_amount0 + out_amount1 + fee.
```

All sides are below3*MAX<p, so field equality with these ranges is integer
conservation. Credit additionally constrains credit-1 to an unsigned51-bit
decomposition, so direct AIR use also rejects zero credit. A 0x2 relation has no
membership/authority input to ignore: it
proves output openings and exact distribution of the public authorized credit.
Authorization itself remains mandatory in the protocol: registry lookup/current
source consumption and genuine ML-DSA-87 verification bind this exact statement.
A frontend proof with an arbitrary credit does not authorize issuance. The
synthetic genesis/source/signature/body contract is a separate root integration
gate and cannot be replaced by a public fixture or successful relation check.

The real permutation schedule is174*n+8: each input uses AUTH2, NOTE4, NF4,
LEAF4 and40*NODE4 rows, then each output NOTE4. All remaining rows to512 are
fully constrained padding as before. Specify deterministic, nonoverlapping
range/index-check selectors. Padding/inactive scratch columns are internal
constrained state, not ignored public inputs or extra witness notes. Carry only
the actual live context; all selected values must be tied on every use.

## Immutable core and receipt compatibility

For ordinary transfers retain the inherited core payload, generalized only to
the actual NF count:
`[1,n,2] || n*NFs || outCM0 || outCM1 || [fee] || chunks(nonce) || [1]`.
For credit use
`[3,0,2] || outCM0 || outCM1 || [fee] || chunks(nonce) || [1] || source_chunks || [credit]`.
`source_chunks` injectively splits the opaque48 bytes into six7-byte little-endian
integers and one6-byte integer, with no field reduction. Thus source identity
and credit amount bind the funded core. CORE=H_CORE(chain,payload), and each
origin=H_ORIGIN(chain,CORE||[ordinal]) exactly as before. Exclude anchor/count,
receipts, proof bytes/randomness and source signature from the immutable core.
Changing/reproving/reanchoring cannot create a new occurrence; changing source
does. Receipt context and later ledger must recompute this exact core/origin.

This is a fresh CP chain/codec, not a bridge accepting old-chain proofs. All
arities share the same NOTE/AUTH/NF/LEAF hashes so genuine credit outputs can
later be spent as1x2 and then2x2. ML-KEM/AES receipt encryption is not implemented
or qualified by the frontend; preserve the receiving obligations in MIGRATION01.

## Source delivery and discriminating controls

Deliver actual Rust AIR/witness/program/parser code plus an independent Python
reference, not only a schedule. Preserve a complete positive2x2 differential
case against the old relation, genuine1x2 funded membership, and credit exact
distribution with two real outputs. Include zero/boundary values and rebuilt
malicious openings for wrong authority/NF/path/index/count, wrong output CM,
overflow/modular-only balance, forged public credit/debit, wrongkind/arity/source
framing and source/core identity changes. Distinguish parser, AIR, public host
identity and future cryptographic outcomes; source/signature rejection is not
claimed by these AIR tests.

No Cargo, timed sizing or proof is allocated by this source task. First deliver
exact source/shape/constraint reasoning for root and independent review, then
root allocates bounded compile/controls. No current shared source mutations;
propose any indispensable extraction as an unapplied minimal patch. No mock,
witness-as-proof, reduced queries/masks or missing constraints to fit a count.
After this gate the bounded genuine-proof caller must instantiate all three
approved programs and execute real private integration/recovery; it cannot
inherit completion from these public frontend controls.
