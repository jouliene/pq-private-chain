# CP integration contract 03: source, body and receiving

Root source contract, 2026-11-16. The reviewed revision02 is preserved at commit
659a319f9f12fc6f5fc867148f0e22adac111ce1 (SHA256 fb76e30a12a14d65b39ea941ccf5ec4b60bb06fe0f9a2b5b26177afc21291d36).
The receiving-failure clarification below is a new narrowly scoped review input;
it changes no bytes, primitive, fee or mathematical payment rule. This is the next concrete
integration boundary for the fresh CP research chain, not approval for ledger
admission or a claim that this code already exists. PAYMENT_CONTRACT.md supplies
the implementation-independent semantics. CP_ARITIES_03.md fixes the complete
0x2/1x2/2x2 relation. The bounded challenge caller is still a separately reviewed
and measured prerequisite. Preserve the historical R2 ledger, receipts and keys;
do not reinterpret their funded outputs or proofs as CP objects.

This document resolves fee/proof-length circularity, exact source authorization
and the envelope-to-statement boundary. The final approved program/profile IDs
must come from the genuine all-arity backend. A placeholder or producer-supplied
ID can never authorize a genesis or payment. Atomic storage, scan-stream
implementation and final private cycles remain separate execution gates below.

## Typed bytes and domain separation

All integer encodings are unsigned little endian with the stated width. All
length arithmetic uses checked integers before allocation; reject truncation,
suffixes and nonzero reserved fields. `blob(x)=u32(len(x))||x`.
`Tag(L)=u16(len(ASCII("PQPC/CP3/"+L)))||ASCII("PQPC/CP3/"+L)`.
Labels are the literal uppercase names below, with hyphens where shown.

`H48(L,x)=SHAKE256(Tag(L)||x,48 bytes)` is used only for receiving/KC/descriptor
roles. `H64(L,x)=SHA3-512(Tag(L)||x)` is used for transport/history/signature
context IDs. These are opaque bytes. They are not CP field digests, are never
reduced modulo p, and do not change the separately approved proof-frame hashes.

CORE, ORIGIN, AUTH, NOTE, NF, LEAF and NODE remain the exact arity frontend's
domain-separated Poseidon2 operations. Their 64-byte outputs are eight canonical
Goldilocks limbs; each limb must be less than p before use. Spending keys and
note rho/r each contain five canonical limbs. Chain and transaction nonce are
32 opaque bytes. Receipt digests are 48 opaque bytes. The sole asset is zero.
No general 48-to-64-byte replacement or old-key padding is allowed.

## Complete canonical body and fee rule

The body is exactly:

```
ASCII("CPBODY03")[8] || version_u16=3 || statement_length_u16 ||
proof_length_u32 || authorization_length_u16 || reserved_u16=0 ||
statement || envelope0[2164] || envelope1[2164] || authorization || proof
```

The header is 20 bytes. The statement is the exact CP_ARITIES_03 grammar;
kind/arity and all lengths must agree. Proof means the entire approved proof
envelope, including its header and all authentication/opening data. It is neither
a witness nor a bare inner payload. A fixed trusted profile sets
`PROOF_CAP=2,097,152` for each of the three first integration programs. This is
a proposed enforcement budget; credit/1x2 fit and costs require actual evidence.
If an honest complete program cannot fit, revise the version and reviewed
resource analysis before proceeding; never reduce masks, queries or constraints
or retry proof randomness to fit. A nonempty bounded proof must still verify.

| Inputs / kind | Statement | Envelopes | Authorization | Nonproof body | Body cap |
|---|---:|---:|---:|---:|---:|
| 0 / credit | 448 | 4,328 | 4,627 | 9,423 | 2,106,575 |
| 1 / transfer | 464 | 4,328 | 0 | 4,812 | 2,101,964 |
| 2 / transfer | 528 | 4,328 | 0 | 4,876 | 2,102,028 |

Body intake enforces the absolute maximum before reading/allocating and the
arity-specific bound after the bounded header/statement parse. The proof API
independently enforces its complete-envelope cap. Exactly two fixed envelopes
are present; their public headers are checked. No descriptor, recipient address,
view tag or spending key is added to the public body. Reconstruct CORE from the
parsed statement, recompute each actual envelope digest below and require exact
equality to its ordered statement slot before proof verification. The verifier
chooses its program from the trusted kind/arity table; body bytes cannot select
new code, parameters or an unapproved identity.
Require statement.chain to equal the configured canonical genesis chain before
any source lookup, signature acceptance, proof acceptance or state transition.
The standalone statement parser's acceptance is not this ledger equality check.

Define `reserved_body_bytes(n)=PROOF_CAP+nonproof_body_bytes(n)` and
`minimum_fee(n)=10,000+10*n+100*2+reserved_body_bytes(n)` atoms. The minimums are
2,116,775 / 2,112,174 / 2,112,248 atoms for n=0/1/2. The stated tariff is a local
research policy, not an owner-approved economic launch policy or a currency
price. The sender may pay a larger fee up to MAX; the full chosen fee enters the
proof equation and public escrow. Credit must cover its own fee, too.

The reservation is fixed before CORE, receipts, statement and Fiat-Shamir
challenges. Actual proof length is checked against the cap but does not change
the fee; unused reservation is not refunded. This avoids a fixed-point search
where a fee changes the transcript and hence the proof length used to price that
fee. No size-based proof retry or omitted proof-byte charge is permitted. The
full arity-specific cap is charged even if the realized proof is shorter.

FP2's 8,192-byte ordinary nonproof allowance contains the 4,876-byte actual
2x2 framing above. It does not contain the 9,423-byte credit framing. Preserve
FP2's conservative ordinary cap/traffic scenario and separately report actual
body lengths and the finite synthetic credit overhead. Signature bytes are not
silently dropped to fit the ordinary allowance.

## Registered source and genuine authorization

A synthetic genesis registers 1..16 unique 48-byte source IDs, each with an
exact credit in minimum_fee(0)..MAX and a 2,592-byte raw ML-DSA-87 public key. This
ensures every registered source can at least fund a zero/zero output claim under
the frozen tariff. The standalone credit relation's broader positive range does
not bypass this genesis policy. Zero outputs remain real value-zero notes; they
alone cannot fund a later positive fee. Entries are
sorted lexicographically by source bytes. The exact checked sum equals declared
G<=MAX. All G initially exists as unconsumed public liabilities, with no private
leaves and zero fee escrow. This is test funding, not a permissionless issuance
or consensus mechanism. No later source registration, reward, burn or bridge is
part of this integration version.

The proposed genesis bytes are:

```
ASCII("CPGEN003")[8] || version_u16=3 || reserved_u16=0 || chain32 ||
G_u64 || source_count_u16 || receipt_suite_u16=1 || protocol_id64 ||
proof_profile_id64 || program_id64[0,1,2] ||
repeated(source_id48 || credit_u64 || authority_public_key2592)
```

Its fixed prefix is 376 bytes; every source adds 2,648. All IDs are equality
checked against the trusted installed specification/manifests, not accepted as
genesis-selected algorithms. The protocol ID is H64(PROTOCOL,blob(canonical
protocol manifest)); root will freeze that manifest with the approved codecs,
tariff, source rules and all-arity proof identities before any admission. A
genesis for an unknown profile or incomplete manifest rejects.

For credit, registry lookup must find the exact source in the canonical parent
state. Reconstruct the public credit from that registry and require equality to
the statement; require zero debit and asset zero. Verify a genuine pure
ML-DSA-87 signature (exactly 4,627 bytes) using that registered key and context
ASCII("PQCHAIN-CP3-SOURCE"). No producer key or alternate signature mode exists.
Let `statement_id=H64(STATEMENT,blob(exact_statement))`. The signed message is:

```
Tag(CLAIM-AUTH) || chain32 || kind_u8=3 || source_id48 || sequence_u64=0 ||
registered_credit_u64 || asset_u32=0 || proof_profile_id64 ||
approved_credit_program_id64 || statement_id64
```

This message has 314 bytes. The exact statement binds both actual receipt
digests, outputs, fee, nonce, anchor/count and public credit. The signature does
not replace the full credit proof. Changing anchor or receipts requires a new
authorization, even when CORE stays the same. Receipt encryption precedes the
signature; neither signature nor proof enters CORE or receipt derivation, so
this ordering introduces no circularity. Transfers have empty authorization.

Consume the **source_id** once in current tentative state, independently of
CORE and body identity. A signer can authorize two distinct statements for one
source; at most one can be admitted. A changed nonce, fee, outputs, receipts,
anchor, proof or randomized signature cannot recreate the entitlement. After
rollback the liability and all related effects must return together. The
credit CORE still includes source and credit under CP_ARITIES_03; this binding
does not replace the source-consumption set. Current nullifiers and CORE replay
sets are also mandatory. All deltas remain tentative until the whole block
passes genuine verification.

## Receiving codec: retained primitive suite, new CP context

Use the existing genuine ML-KEM-1024, HKDF-SHA384 and AES-256-GCM primitive path
and its retained vector coverage, with new CP bytes. This is a source/algorithm
choice, not an assertion that the new adapter has been executed. Descriptors
are off-chain addresses; they are never appended to public receipts.

Descriptor = ASCII("CPD3")[4] || format_u16=3 || suite_u16=1 || chain32 ||
owner64 || raw_ML-KEM-1024_public_key1568, exactly 1,672 bytes. Apply the existing
encapsulation-key modulus check before encapsulation and exact native import/
export round trip. A receiving private key must correspond to the descriptor's
public key. Require descriptor.chain == context.chain == the wallet's configured
CP chain before sealing or opening, including the prepared-recipient path.
Canonical syntax alone does not prove honest key generation.

The envelope header is ASCII("CPR3") || format_u8=3 || suite_u8=1 || u16(0).
Envelope = header8 || KEM_ciphertext1568 || encryption_nonce12 ||
encrypted_note512 || GCM_tag16 || KC48, exactly 2,164 bytes. The independently
random 12-byte encryption nonce is not the 32-byte transaction nonce.

The 512-byte plaintext is:

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII("CPNOTE03") |
| 8 | 160 | Canonical note: asset, amount, owner[8], rho[5], r[5], all u64 limbs |
| 168 | 64 | Canonical commitment CM[8] |
| 232 | 2 | Memo byte length <=128 |
| 234 | 128 | Memo followed by zero padding |
| 362 | 150 | Zero reserved tail |

Use fresh uniform canonical field sampling for the spending key and note rho/r;
reject out-of-field u64 candidates instead of reducing them. Retain fresh KEM
encapsulation entropy and mandatory native primitive errors. No deterministic
test key, seed or forced challenge enters a private acceptance cycle.

Let `D=H48(DESCRIPTOR,blob(descriptor))`, and
`C=chain32||u16(3)||u16(1)||CORE64||ordinal_u16||CM64||header8` (174 bytes).
Ordinal is exactly 0 or 1. Let ct and nonce be the actual envelope's KEM
ciphertext and encryption nonce, and ss the 32-byte KEM shared secret:

```
salt = H48(RECEIPT-SALT, C || ct || nonce)
prk = HKDF-Extract-SHA384(salt, ss)
enc = HKDF-Expand-SHA384(prk, Tag(RECEIPT-ENC) || D || C, 32)
com = HKDF-Expand-SHA384(prk, Tag(RECEIPT-COM) || D || C, 48)
aad = Tag(RECEIPT-AAD) || C || D || ct || nonce
(encrypted_note, auth) = AES-256-GCM(enc, nonce, plaintext512, aad)
KC = H48(RECEIPT-KC, com || D || C || ct || nonce || encrypted_note || auth)
receipt_digest[j] = H48(RECEIPT, chain || CORE || u16(j) || blob(envelope[j]))
```

This retains the exact previous hybrid's structure with explicitly new typed
inputs. Use constant-time equality for KC. Malformed candidate receipts,
failed ciphertext authentication and invalid decrypted note contents are local
misses, with no key-specific callback, logging or network request. This does
not include unavailable/changed helper code, failed helper transport or exit,
timeout, invalid wallet configuration, or unexpected native-provider failures.
Those are operational failures: propagate a typed error, discard/wipe tentative
batch candidates and abort the scan batch without advancing its completeness
checkpoint. A blanket catch-to-null or error-message comparison must not hide
an operational failure. Successful authentication and canonical note parsing do
not excuse a later failed NOTE/NF computation. No failed batch receives partial
funding, balance or recovery credit. After
authentication, enforce every canonical limb/range/padding rule, asset zero,
owner equality to the descriptor and the wallet's AUTH(key), embedded CM equal
to the authenticated funded CM, and NOTE recomputation. A genuine proof binds
the public receipt digest; it does not prove encryption correctness. A malicious
payer can strand its own value, which remains outstanding and is not refunded.

No-expiry/all-key retention and additive `(origin,CM)` accounting remain
mandatory. Later receiving-key compromise exposes old receipts; no forward
secrecy is asserted. ML-KEM IND-CCA, a good GCM test or a working wallet does not
prove recipient anonymity. The joint commitment/receipt/proof simulation,
KDF/KC assumptions, malicious-key scope and network metadata remain explicitly
qualified in the security-obligation map. Do not introduce EC-only fallback.

## Atomic state and complete recovery gates

Retain depth40 and the last256 canonical ancestor root/count pairs, including
genesis while retained. Credit must also use an authenticated retained pair;
its proof does not make an arbitrary root/count canonical. Multiple blocks may
have the same pair: membership binds the pair, not a producer-supplied block ID.
No same-block output spending. Current tentative spent/source/CORE sets include
earlier bodies in the proposed block, while anchor eligibility uses the parent
history. Reject before tree overflow; two real outputs are appended even if zero.

Store tree/frontier and leaf count, funded occurrences, current nullifiers,
CORE IDs, source liabilities, fee escrow, authenticated canonical history,
wallet scan records and undo information as one logical atomic transition.
Use checked integer accounting. Public outstanding value is
G-unconsumed_source_liabilities-fee_escrow; private conservation relies on the
genuine full proofs, not this public identity alone. The original growing JSON
snapshot clone is a regression reference, not a scalable storage solution.
Specify and measure a bounded incremental store and actual crash/reorg protocol
before claiming FP2's remaining 10ms whole-admission budget.

A reduced wallet scan must authenticate every ordered statement, receipt, funded
occurrence and nullifier from genesis to an independently held expected endpoint.
Single inclusion paths do not establish completeness. Its concrete block/range
commitment and validator-produced scan record format must be frozen and
implemented before proof omission receives recovery/resource credit. Full
validators still verify every proof; a reduced scanner explicitly trusts
validation of the authenticated endpoint. The server cannot select that endpoint
or silently substitute a stale one. Rebuild paths and current spentness before
creating the restored wallet's fresh proof.

Backups must carry the new CP key/descriptor associations and all advertised
receiving keys, chain/version and inventory. Reject legacy backups. Check the
backup inventory against an independently retained current inventory checkpoint;
an old backup alone cannot prove that no later key was ever advertised. No old
wallet, cached note, witness or producer verdict may enter a backup-only restore.
The final recovery operation must generate and admit a new genuine spend.

Required implementation controls include double-authorized distinct COREs for
one source, cross-chain body/descriptor/prepared-recipient substitution, a
genesis source below its fee minimum, changed receipt plus recomputed digest
with old proof, changed
signature context/profile/statement, fee below the fixed reservation, actual
over-cap proof/body, exact-cap malformed input, late-invalid block, crash on both
sides of commit, rollback/reinclusion, equal CMs at distinct origins, old retained
keys, omitted scan ranges, server-selected stale endpoint and missing newer
inventory. Parser/host/reference successes stay separate from cryptographic and
integrated outcomes. Three final fresh cycles and an independent same-revision
rebuild/public replay remain required; this specification is not completion.
