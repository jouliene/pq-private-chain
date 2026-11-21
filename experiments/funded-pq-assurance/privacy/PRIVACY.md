# Privacy and robustness of funded payments

## Decision summary

The funded release has a **demonstrated funding-equality leak across retries and
forks**.  The released MNG2 comparison and the two competing MNG3 payments at
height 25 have different packet IDs, proof profiles, output commitments and
receipts, but publish the same two nullifiers.  An observer with the three
packets links all three authorizations to the same two funded inputs without
breaking any cryptography.  The two MNG3 packets also occur in different blocks
at the same height.  This is intentional double-spend prevention, but it means
that neither proof rerandomization nor receipt rerandomization provides
retry/fork unlinkability.

The same public corpus gives no comparable equality link from the paid output
to the labelled onward spend, or from that spend's change to the labelled final
spend.  This is only a negative search over one finite trace.  The public
`RUN.json` labels disclose the fixture lineage; an ordinary chain observer does
not obtain that lineage from byte inequality.  Later-spend unlinkability remains
a **conditional claim**, requiring a joint argument for commitments,
nullifiers, proofs, receipts, wallet behavior and auxiliary information.

All 40 selected/alternate graph-packet receipt envelopes and both additional
legacy-control envelopes were distinct, as were their ML-KEM, note and memo
ciphertext components.  This is an observed freshness result over 42 public
envelopes, not an anonymity or robustness bound.  The release exposes one
common receipt header `(version=1, suite=1, diversifier=0)`, fixed component
lengths, proof version and length, operation class, public fee, anchor,
commitments, nullifiers and supply fields.  Each signed swap additionally
exposes its two sides, fee payer, expiry, network, shared blinded-terms
commitment, two authorization keys/signatures and fixed output roles
(counterparty payment first, change second).

No reviewed source establishes a formal privacy theorem for the whole funded
view.  In particular, FIPS 203 specifies ML-KEM confidentiality properties; it
does not by itself establish recipient/key anonymity, cross-key robustness, a
wallet reaction model or composition with the payment proof.  The proof system
also lacks an established adaptive, multi-proof quantum zero-knowledge theorem
for the exact receipt-correlated transcript.  The appropriate status is
**functional receiving plus measured public leakage; joint PQ privacy remains
unqualified**.

[Machine-readable observations](RESULTS.json) · [public-only analyzer](analyze.py)

## Reproduction and input boundary

The analyzer accepts only the extracted `public/` directory from the exact
pinned author archive.  It rejects another archive digest, unsafe/non-regular
archive members, duplicate paths, symlinks and every missing, added or changed
file at any depth.  It then checks the exact `RUN.json` top-level schema, every
graph-packet filename/hash, proof and receipt framing, the legacy comparison
packet and the duplicated nullifier projection in `RUN.json`.  It does not
import a deployment and has no code path for a seed, backup, wallet database,
witness, opening or negotiation file.

```sh
work=/tmp/funded-pq-privacy
mkdir -p "$work"
curl -fLsS \
  https://github.com/jouliene/pq-private-chain/releases/download/funded-membership-2026-11-21/funded-membership-public.tar.gz \
  -o "$work/funded-membership-public.tar.gz"
(cd "$work" && sha256sum -c -) < experiments/funded-membership/RELEASE.sha256
tar -xzf "$work/funded-membership-public.tar.gz" -C "$work"
python3 -IB experiments/funded-pq-assurance/privacy/analyze.py \
  "$work/public" --archive "$work/funded-membership-public.tar.gz" \
  | cmp - experiments/funded-pq-assurance/privacy/RESULTS.json
```

The analyzed archive SHA-256 is
`24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87`.
The analyzer matched 20 unique graph packet files, 40 graph receipts, two
legacy-control receipts and zero secret inputs.
The release schema itself intentionally includes fixture operation labels and
wallet-balance disclosures.  Results based on labels are therefore described as
release-fixture observations, not deductions available from an unlabelled
ledger.

## Observer views and permitted leakage

Privacy claims must name the view.  These views are not interchangeable:

| Observer | View |
| --- | --- |
| Selected-chain reader | The winning blocks and ordered packet bytes: proof profile/length, operation wrapper, anchor/height/depth, fee, public supply fields, nullifiers, commitments, fixed receipt headers/lengths and ciphertexts. |
| Public archive or gossip observer | The selected view plus valid orphaned, rejected, superseded and exact retransmitted packets that reach it.  It can compare nullifiers across proof versions and forks. |
| Connected peer/validator | The archive view plus arrival order, source connection, timing, retries, refusal reason and possibly IP/transport metadata.  Ledger privacy does not hide these fields. |
| Counterparty or payer | Its destination address, chosen amounts/assets, funding policy, plaintext outputs and local randomness; a swap party additionally knows the complete private agreement and both offers.  There is no privacy claim against a participant for facts it already knows. |
| Wallet/history provider | Common range queries in the incremental protocol plus connection and timing.  Identical ranges hide owned indices only within the stated cursor/target policy; a malicious provider can still delay or omit data and observe network metadata. |
| Post-compromise observer | A prior public view plus the particular secret exposed at a stated time.  A bare phrase such as “later compromise” is insufficient. |

Permitted ledger leakage for an ordinary transfer includes network and proof
suite, operation class, packet size, anchor and public depth, two nullifiers,
two commitments, fee, receipt framing and the existence/time of later public
spends.  Supply operations expose their public asset and quantity fields.
Swap leakage additionally includes the public fields listed in the summary.
Traffic origin, peer access patterns and off-chain address presentation are
outside ledger privacy and must be assessed separately.

## Observer games

### P1: proof-only witness privacy

Fix a canonical public statement `x`, verifier registration and corruption
state.  The challenger chooses `b`, proves one of two valid same-public-statement
witnesses `w_b` with fresh independent prover coins, and gives the adversary the
proof plus adaptively selected other proofs and allowed auxiliary input.  The
adversary must guess `b`.  The game must cover common funded inputs across proof
versions, chosen statements, related receipts, multiple users and quantum random
oracle queries.

Passing finite differential tests or configuring row/leaf hiding does not bound
this advantage.  A proof simulator also does not by itself simulate the changed
commitments and ciphertexts of two complete payment histories.  Current status:
**formal guarantee not established for MNG1/2/3 or SLG1/2/3**.

### P2: complete payment-history privacy

The challenger builds two histories with the same permitted leakage, schedule,
operation classes, proof profiles, fees, retry/fork equality pattern, corruption
events and later-spend pattern, but swaps the hidden sender/input assignment,
recipient assignment or equal-shaped amount/asset assignment.  The adversary
sees the complete public history and allowed auxiliary inputs and guesses the
world.  Corrupted senders and recipients are excluded only for the facts they
necessarily know.  Network metadata is either held fixed or explicitly included
as leakage.

A proof hybrid must remain consistent with the commitments, receipt digest and
later nullifiers.  A ciphertext hybrid must preserve the correlated commitment,
proof and later-spend distribution.  Independent marginal claims for the proof,
KEM and AEAD do not supply this joint simulation.  Current status: **target game;
no reduction or quantitative advantage bound**.

### R1: recipient/key privacy

Generate two honest, independently random receiving keys and equal-length valid
note messages.  The challenge receipt encrypts to key `b`.  The adversary sees
both public addresses, the correlated output commitment/proof, other adaptively
chosen receipts and every non-challenge secret permitted by the corruption
schedule, then guesses `b`.  Any externally visible trial-decryption result,
error, response time or subsequent wallet action belongs in the view.  Revealing
the challenged receiving secret or asking for the challenged plaintext makes
the game trivial and must be excluded or treated as compromise.

This game is stronger than ML-KEM shared-secret confidentiality.  *Post-Quantum
Anonymity of Kyber* gives relevant QROM results for the analyzed Kyber KEM and
hybrid PKE construction.  Application here requires a written correspondence to
final FIPS 203 ML-KEM-1024 (including current errata), the pinned wrapper,
deterministic seed derivation, two labelled ChaCha20-Poly1305 invocations, the
actual decryption interface, chosen-key policy and multi-user query bounds.
That correspondence has not been supplied.  Current status: **conditional
research direction, not an inherited theorem**.

### R2: receipt robustness and ciphertext integrity

Give an adversary chosen public keys and receipt-construction access.  It wins if
one envelope is accepted as an owned, commitment-matching positive note under
two distinct honest keys, under a key other than the intended key, or with an
ambiguous semantic opening.  A second game lets the adversary choose malformed
keys/ciphertexts and observe every wallet response, testing whether validity or
key identity becomes an oracle.

The wallet maps decryption failure to `NotOurs`, then checks its expected spend
public key, typed opening and public commitment.  These checks are useful local
defenses.  The public proof binds the ordered ciphertext bytes, but does not prove
that an ordinary payer encrypted a usable note for the intended recipient.  A
malicious payer may strand its own value.  Swap wallets mitigate this for honest
participants by opening the incoming payment and own change before signing both
legs.  None of these code paths proves cross-key robustness or constant external
behavior.  Current status: **functional checks observed; formal robustness and
reaction analysis open**.

### F1: retry and fork privacy

Two questions must be separated:

1. `funding-equality`: did two packets consume the same funded note(s)?
2. `commercial-intent-equality`: were they attempts to satisfy the same invoice,
   recipient and amount?

For the first game the funded construction deliberately loses: equal real inputs
publish equal nullifiers.  The release demonstrates two shared nullifiers across
all three B/C authorizations.  An exact retransmission is even more directly
linkable by complete packet identity.  For the second game, nullifier equality is
strong auxiliary evidence but does not alone identify recipient, amount or
business intent.  Timing, peer source, off-chain address reuse and later behavior
can supply that missing evidence.  Current status: **funding equality is observed
leakage; commercial-intent privacy has no bound**.

A selected-chain-only observer may see only `paid_C`.  The published release or a
well-positioned gossip observer sees the losing `alternate_C`; the separately
released legacy control adds `legacy_B`.  Reorganization does not erase packets
already observed.

### L1: later-spend unlinkability

Construct two equal-leakage histories in which two challenge outputs are swapped
between recipients and one is later spent.  Give the adversary the earlier
commitments/receipts and later proof/nullifiers, while holding timing, fee, input
arity, retry pattern and corruption schedule fixed.  The adversary guesses which
earlier output funded the later spend.

In this release the labelled `paid -> onward` and `onward -> final` comparisons
have zero equality between source commitments and later nullifiers, and zero
reused receipts.  This refutes only an accidental direct byte-equality link in
those two samples.  The released fixture labels and private owner review reveal
the true lineage through separate disclosure.  A proof requires commitment
hiding/binding, nullifier pseudorandomness for unknown keys, proof zero knowledge,
receipt key privacy and control of side information.  Current status:
**experimental non-equality; formal guarantee open**.

## Receipt construction and robustness assessment

The funded address is 1,601 bytes: version, a 32-byte spend public commitment and
a reusable 1,568-byte ML-KEM-1024 encapsulation key.  Each 1,792-byte receipt has
the following public shape:

| Field | Bytes | Public consequence |
| --- | ---: | --- |
| version, suite, diversifier | 7 | All released values are `(1,1,0)`. |
| three length prefixes | 12 | Component lengths are explicit. |
| ML-KEM-1024 ciphertext | 1,568 | Freshness was observed, recipient identity was not tested. |
| encrypted note + tag | 128 | Fixed plaintext shape hides length, subject to AEAD/KDF assumptions. |
| encrypted memo + tag | 77 | Fixed memo shape hides length, subject to the same qualifications. |

The adapter builds a plaintext containing two `u64` values, `rho`, opening,
fixed-width memo and the recipient spend identifier.  The pinned implementation
derives separate ChaCha20-Poly1305 key/nonce pairs from the same KEM secret using
the labels `note-aead` and `memo-aead`; the seven-byte header is AEAD associated
data.  Consensus binds the ordered receipt bytes through a public digest.  The
receiver decrypts, checks its spend identifier and recomputes the typed output
commitment.

Security therefore depends on fresh encapsulation randomness and the exact KDF
separation.  Repeating the KEM secret for the same recipient would repeat the
derived AEAD key/nonce pair; RFC 8439 requires nonce uniqueness for a fixed key.
Forty distinct KEM ciphertexts are reassuring for this trace but do not test a
faulty or adversarial randomness source.  There is no explicit independent key-
confirmation field; successful AEAD authentication plus the owned commitment
check acts as application acceptance.  Whether this is anonymous and robust for
maliciously chosen keys is precisely the R1/R2 obligation.

Grubbs, Maram and Paterson show that anonymous/IND-CCA KEM properties do not
generically make arbitrary KEM-DEM composition anonymous; their positive QROM
results require particular transform and authenticated-DEM premises.  Maram and
Xagawa later establish positive anonymity results for Kyber and derived hybrid
PKE in their model.  Neither paper analyzes these two correlated DEM messages,
the funded commitment/proof, retained static backup, wallet error surface or
later spend.  NIST currently flags potential updates to FIPS 203; an exact
correspondence must use the final standard plus applicable errata, not the name
“Kyber” alone.

## Compromise epochs

| Compromise | Before receipt | After receipt, before spend | After spend/key rotation | Consequence |
| --- | --- | --- | --- | --- |
| Counterparty/payer state | Knows destination, values, selected inputs and plaintext it creates. | Retained intent/journal links packet and business intent. | Erasure can reduce later endpoint evidence, but cannot erase public nullifier or packet equality. | No privacy from the payer for its own payment. |
| ML-KEM decapsulation key only | Opens receipts under that key. | Retrospectively trial-decrypts recorded receipts and learns note/memo contents. | Still opens all archived receipts for the same retained static key; no receiver forward secrecy. | Does not alone prove possession of the separate spend credential, but identifies incoming notes and values. |
| Complete 32-byte wallet backup | Derives both spend and receiving material. | Opens historical receipts, derives owned nullifiers and can authorize unspent notes. | Retrospectively links archived receipts and spends; deterministic recovery defeats deletion of a child key if the master survives. | Confidentiality, recipient privacy and spend authorization for that wallet are lost. |
| Spend/prover witness or live prover state | Reveals owned openings, paths and input/output assignment. | Can link proof and possibly authorize spend depending on exposed keys. | Exposure of prover masks/coins is not analyzed; some ZK constructions lose hiding if randomness is disclosed. | Must be treated as sensitive even if the public proof is hiding. |
| Swap signing nonce/key | Can authorize a joint digest under the proof-bound public key. | Before expiry, theft can forge owner approval for a different joint digest compatible with the fixed proved leg. | Historical signatures remain verifiable; expiry/spentness limits new admission, not disclosure. | Does not decrypt receipts, but breaks the affected swap authorization boundary. |
| Validator or history provider | Sees public packets, peer source and timing; can censor or reorder within consensus power. | Reorgs reveal competing attempts and may trigger retries. | Archived observations survive reorg.  Omission can harm recovery. | Consensus control does not reveal KEM plaintext by itself; it materially expands traffic/fork leakage. |
| Proof/receipt cryptographic break | Depends on broken component and game. | A proof-ZK break may expose witness; KEM/DEM break may expose recipient/value; binding break may enable ambiguity. | Recorded history enables harvest-now/decrypt-later attacks. | Component failure must not be summarized as a single uniform “privacy break.” |

Independent per-address receiving keys can limit a decapsulation-key compromise
to their use epochs only if those keys are actually independent, old keys are no
longer needed, and the master backup is not compromised.  The current 32-byte
backup intentionally regenerates historical keys for recovery, so backup-only
recovery and forward secrecy are in tension.  Key rotation does not protect old
receipts while the recovery secret can reconstruct their keys.

## Evidence classification

| Class | Supported statement |
| --- | --- |
| Observed public leakage | Three authorizations share two nullifiers; all pairwise commitments/receipts differ; swap header and slot roles are visible; packet/profile lengths distinguish eras and operations. |
| Finite experiment | Forty released receipt components are distinct; two labelled later-spend transitions have no direct commitment/nullifier equality. |
| Functional guarantee in tested code path | Honest restored wallets opened receipts, recomputed commitments and spent; honest swap wallets verify both proofs and open expected incoming/change outputs before signing. |
| Protocol rule, not privacy theorem | Consensus binds ordered receipt bytes, enforces nullifier uniqueness and applies/reverts both swap legs atomically. |
| Conditional cryptographic claim | Receipt confidentiality for uncompromised honest keys under ML-KEM/KDF/ChaCha assumptions; later-spend unlinkability under commitment/nullifier/proof/receipt assumptions. |
| Formal guarantee established here | None for whole-payment anonymity, adaptive multi-proof ZK, final-ML-KEM recipient anonymity, cross-key robustness or post-compromise privacy. |

## Required next assurance work

1. Specify the exact final-ML-KEM receipt algorithms as a single PKE scheme,
   including key validation, seed derivation, KDF inputs, both DEM calls,
   decryption failure normalization and commitment acceptance.  Map it line by
   line to a stated anonymity/robustness theorem or prove the missing variant.
2. Test malicious and cross-key cases with two or more independently generated
   keys: malformed encapsulation keys/ciphertexts, key/ciphertext substitution,
   dual acceptance, correlated DEM modification and externally observable scan
   timing/errors.  Functional honest decryption is not the acceptance criterion.
3. Give a simulator/reduction for the complete P2/L1 view across adaptive
   MNG/SLG proofs, receipt-correlated commitments and later spends.  Quantify
   multi-user and lifetime losses in the intended classical/PQ model.
4. State wallet key epochs and compromise claims explicitly.  If retrospective
   privacy is required, redesign recovery/key evolution rather than claiming it
   from rotation of deterministically recoverable static keys.
5. Treat shared nullifiers as permitted funding-equality leakage.  If product
   requirements demand retry/fork unlinkability, that conflicts with the current
   public single-consumption identity and requires a different construction, not
   more proof randomness.

## Primary sources and inspected implementation

- [FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), including the NIST planning note and linked potential errata.
- Varun Maram and Keita Xagawa, [*Post-Quantum Anonymity of Kyber*](https://eprint.iacr.org/2022/1696), PKC 2023.
- Paul Grubbs, Varun Maram and Kenneth G. Paterson, [*Anonymous, Robust Post-Quantum Public Key Encryption*](https://eprint.iacr.org/2021/708), EUROCRYPT 2022.
- Mihir Bellare et al., [*Key-Privacy in Public-Key Encryption*](https://doi.org/10.1007/3-540-45682-1_33), ASIACRYPT 2001.
- Michel Abdalla et al., [*Robust Encryption*](https://iacr.org/archive/tcc2010/59780477/59780477.pdf), TCC 2010.
- [RFC 8439, ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html).
- Local exact sources inspected: `spend-proof-decision/RECEIVING.md`,
  `token-profile/candidate/pair_codec.rs`, `atomic-swap/swap_wire.py`,
  `atomic-swap/wallet/swap_wallet.py`, `atomic-swap/wallet/terms.py`,
  `funded-upgrade/swap_wire.py`, `funded-upgrade/wallet_stage.py`,
  `funded-membership/scenario.py`, `funded-membership/package.py` and
  `funded-membership/review/owners.py`.
- The full KEM/AEAD bodies are pinned upstream at Qnero commit
  `f04c91307837c0231668383bec76ba98d89d2652`; this task inspected the local
  adapter and existing exact construction map, not a newly fetched full upstream
  source checkout.  Therefore implementation-to-paper correspondence remains an
  explicit open obligation.
