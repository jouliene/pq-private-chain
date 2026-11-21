# Independent assurance review

## Review disposition

**Not qualified for a 128-bit post-quantum monetary-security or privacy
claim.** The committed artifacts do reproducibly establish several narrower
facts: the exact C verifier-key geometry and serialization sizes, the stated
ideal-function arithmetic, the S64 structural size model, and public-byte
observations over the pinned funded-membership release. None of those facts is
an end-to-end reduction for unauthorized spend, inflation, proof knowledge,
proof zero knowledge, recipient anonymity, or later-spend unlinkability.

The frozen binding, proof and privacy prose now states those boundaries
accurately. The binding calculator now makes its success convention, time,
memory, oracle and qRAM/non-qRAM assumptions explicit, and the monetary games
separate a chosen cross-value claw from fixed-victim search. The genuine
C-to-N7 run also has valid public proofs and internally coherent prototype
state semantics. Its 412,886-byte bridge bundle is not admissible under the
current 262,144-byte chain packet limit; the decision must retain the explicit
out-of-band qualification and require a versioned migration frame/block design.

This review is independent of the author calculators. The scripts in this
directory do not import them:

- [`independent_check.py`](independent_check.py) parses the two verifier keys
  and independently recomputes proof geometry, serialization, the OPlonky
  arithmetic analogy, and ideal attack resource annotations.
- [`archive_audit.py`](archive_audit.py) reads only the pinned author archive,
  rejects non-regular or unexpected members, and independently counts public
  packets and receipt components.
- [`INDEPENDENT.json`](INDEPENDENT.json) and [`ARCHIVE.json`](ARCHIVE.json) are
  the checked results.
- [`migration_public_audit.py`](migration_public_audit.py) independently
  parses and verifies the frozen migration release, while
  [`MIGRATION_PUBLIC.json`](MIGRATION_PUBLIC.json) is its public-only receipt.

Anonymous HTTPS-clone reproduction remains a separate post-publication gate.

## Reproduced results

All Python checks below were run with a clean environment equivalent to
`env -i PATH=/usr/bin:/bin LC_ALL=C python3 -IB ...`.

| Surface | Independent result | Disposition |
| --- | --- | --- |
| Binding calculator | The committed JSON and seven unit tests reproduce. For the researcher-defined 4.4-billion-target scenario, the four-word ideal multi-target search exponent is `111.982572`; the ideal BHT collision exponent is `85.333333`. | Arithmetic and explicit resource annotations accepted; security interpretation remains conditional. |
| C verifier keys | Both keys are 1,481 bytes. MNG3 SHA-256 is `6cb89745c94ec7b2ff97173ec0819b8567ae5672991b2fdbbe3cbe5810ebadf2`; SLG3 SHA-256 is `7acd892eb041260a90efe30fc19771922da2be083707dec4116f8b3af9765c4a`. | Exact artifact identity accepted. |
| Registered C geometry | 135 wires, 60 routed wires, two PLONK repetitions, 32 FRI queries, 8,192 trace rows, 262,144 LDE positions, five arity-four folds, seven partial products per repetition, quotient factor eight, maximum constraint-vector length 123, and filtered declared gate degrees eight and nine. | Key decoding accepted; theorem mapping not implied. |
| Registered C sizes | MNG3 proof/frame `179264/182863` bytes; SLG3 proof/leg-frame `179288/200076` bytes. | Exact serialization model reproduced. |
| S64 model | 64 FRI queries and three PLONK repetitions force 16,384 trace rows in the modeled builder, 524,288 LDE positions, 2,880 FRI masks per polynomial, and 8,650 total blinding rows. MNG3 proof/frame is `387952/391551`; SLG3 is `387976/408764`. | Structural model reproduced; S64 was not built or benchmarked. |
| Privacy archive | Author archive SHA-256 `24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87` contains exactly 59 regular files, including 20 graph packets, 34 blocks, 40 graph receipts, and two legacy-control receipts. All 42 complete/KEM/note/memo components are distinct. | Finite public-byte observations accepted. |
| Privacy boundary v3 | Fresh analyzer output is byte-for-byte equal to `privacy/RESULTS.json`. A copy with nested `public/blocks/extra.bin` fails with `extracted public tree differs from pinned archive`. | Exact archive/tree binding and public-only input boundary accepted. |
| C-to-N7 public migration | The 13 Python migration tests pass. Fresh public processes verify MNG3, the bridge equality proof and onward N7P2 proof. The selected H1--H26 branch, context, N7 root/count and artifact hashes were independently reconstructed; all seven public mutations were rejected. | Accepted as bounded out-of-band prototype evidence, not integrated consensus or proof-system qualification. |
| Migration release boundary | The exact 59-file migration membership archive is 7,701,082 bytes with SHA-256 `50008712589106a8a934040dd4fa8465d1eb269f0ca7232f18ffbb2999662b6d`; its extracted tree matches exactly. | Resolves the initial mismatch with the earlier privacy/author archive, subject to publication and anonymous HTTPS-clone reproduction. |

## Reviewed corrections and claim boundaries

### 1. The ideal-query figures are not total attack costs

The binding output now encodes the success envelope, illustrative serial time,
memory and membership-oracle assumptions that were missing in the first
review. The decisive resource facts are:

- The 4.4-billion-target table alone is 140.8 GB when each target is 32 bytes.
- A textbook BHT table at the reported four-word exponent has about
  `2^85.33` entries, or about `2^90.33` raw bytes before indexing and error
  correction.
- Unit-cost coherent lookup assumes an appropriate qRAM/coherent-memory
  model. Without that model, lookup/circuit time can dominate the stated
  query count.
- A multi-target Grover query requires a reversible target-membership oracle;
  its construction and access cost are not priced.

The calculator correctly labels the qRAM-like BHT/Grover models, a conservative
sampled-list trade-off, and a separate CNS no-qRAM random-function screen. It
also labels the `10^12` queries/s conversion as a researcher illustration and
does not equate an oracle query with a CPU instruction. These corrections are
accepted; none turns the ideal exponents into a Poseidon2 attack or total
physical cost.

### 2. Seven limbs are conditional on a monetary collision reduction

Five Goldilocks limbs clear 128 ideal quantum query bits in all checked
multi-target preimage scenarios; seven are the first whole-limb width strictly
above 128 in the stated arbitrary-collision benchmark. It does not follow that
seven is unconditionally the smallest monetary-safe profile.

Game US includes a fixed uncorrupted victim occurrence. A fixed-victim second
preimage/preimage problem is not the same as freely choosing both sides of a
collision. The corrected Game IN now specifies a cross-value claw between
canonical native-value-four and native-value-five domains: fund the first
opening, then debit through the second. This is a coherent conditional monetary
experiment, while the application of ideal BHT to the constrained encodings
remains an explicit hypothesis rather than a Poseidon2 attack. The frozen
decision correctly presents seven limbs as an engineering screen for that
selected obligation, not an unconditional minimum.

The lifetime traffic assumptions are otherwise labelled correctly: 20 years,
acceptance fractions, transaction mix, output multiplicity, and usable-target
fractions are researcher scenarios. Only 100 million offered payments per year
is owner input.

### 3. The inflation audit now fixes creation-side opening semantics

Game IN now follows the opening used by the honest creation transition, or the
opening extracted from that accepted creation proof. It does not select the
colliding opening that makes later equations balance. It separately classifies
changed value as IN, changed authority as US, and a changed lifetime identity
enabling retained debits as XV. This resolves the earlier ambiguity, still
conditioned on the missing extractor/cross-proof-consistency theorem.

The code map supports the narrower structural claims: candidate-height C
dispatch applies to debit routes, spentness is common, and the reviewed
ordinary/supply/swap transitions stage effects atomically. Those source facts
do not replace extraction, binding, signature, database-failure, or replay
reductions.

### 4. OPlonky is a diagnostic substitution, not an applicable bound

The three substitutions reproduce exactly. For registered C their negative
log2 values are `86.655149`, `113.700506`, and `111.830075`; for S64 they are
`126.982724`, `170.256217`, and `110.830075`. The third denominator is correctly
`|K \\ D| = p^2 - n`, not `p^2` or `p - n`.

The proposed source values are plausible implementation observations:

- `k=123`: verifier-key maximum constraint-vector length;
- `d=9`: maximum filtered declared gate degree;
- `u=s=8`: quotient/degree-related implementation values; and
- `r'=60`: routed permutation-wire count.

But no proved index map shows that those implementation fields are the exact
objects denoted by OPlonky Lemma 4.9. In particular, qp-plonky2's two or three
beta/gamma permutation repetitions, selector filtering, batched two-point
openings, quotient chunks, and copy index have not been shown to instantiate
the lemma's repeated protocol. FRI/list soundness and Fiat--Shamir/QROM losses
also remain outside the substitution.

The corrected proof prose now draws the valid conclusion: this route does not
certify 128-bit security. The roughly 110.83-bit S64 term is not an upper bound
on actual S64 security and is not an attack. S64 is excluded by the current
262,144-byte physical-frame discriminator and warned on resources, not
cryptographically disproved.

### 5. Source identity is attributed, not checked by the proof calculator

The inspected qp-plonky2 1.5.5 crate metadata attributes the source to revision
`632f23ca07712bfa5bc8ed082bc05c41c5929dfb`. The author calculator hard-codes
that version/revision and checks the verifier keys plus four project source
files; it does not hash the crate bodies or `.cargo_vcs_info.json`.

`proof/ASSURANCE.md` now says this accurately. Publication must retain that
narrow language, or the checker must be extended to verify a complete pinned
crate-source manifest. “Calculator-verified upstream source” would be false in
the current artifact.

### 6. Privacy v3 fixes the input-boundary defects; its conclusions remain finite

The v3 analyzer fixes the earlier archive-boundary defects. It pins the author
archive, rejects unsafe/non-regular/duplicate archive entries and extracted
symlinks, builds a full size/SHA-256 manifest, and requires exact equality with
the extracted tree before parsing. It accesses no wallet backup, seed,
database, witness, receipt key, negotiation file, or other secret input.

The conclusions that follow are limited but sound:

- the legacy B, alternate C, and paid C packets share both public nullifiers;
  their commitments and receipts differ;
- all 42 released receipt envelopes and each component are byte-distinct; and
- two labelled later-spend comparisons have no direct
  commitment-to-nullifier or receipt equality.

These observations establish funding-equality leakage in the released
retry/fork fixture and the absence of two simple byte-equality links. They do
not establish proof zero knowledge, ML-KEM recipient/key privacy, cross-key
robustness, wallet reaction privacy, complete-history P2 privacy, or L1
unlinkability. The current privacy report states those limitations correctly.

### 7. Frozen C-to-N7 public migration evidence

The two-proof composition is functionally coherent. A fresh MNG3 packet proves
authorization, membership, the original input nullifiers, conservation and the
three-unit fee. Its two output commitments are transient. The equality circuit
opens those exact commitments, recomputes two N7 commitments, and connects the
native amount, token amount and exact little-endian asset mapping for each
slot. The node-side statement checks bind the MNG3 input nullifiers and outputs
to the C verifier result and recompute a version-3 context over the C network,
exact H26 parent, candidate height, complete C packet, parsed effects and all
four receipt hashes.

The independent public audit established all of the following without a seed,
wallet database, opening, note plaintext or witness:

- the MNG3, equality and onward N7P2 proofs verify in fresh public processes;
- the exact H1--H25 selected lineage and empty H26 parent replay to anchor
  `9b00806d...9928`, count 47 and derived depth three;
- the authenticated H26 spent page has 22 entries and excludes both MNG3 input
  nullifiers;
- the context, N7 network/scope, activation ID, two-leaf depth-40 root, onward
  root/count/fee and all retained artifact hashes recompute;
- bridge context/C-output/N7-output mutations, both corrupted proofs, and
  onward root/output mutations are rejected; and
- the actual prototype ledger, using genuine public-verifier callbacks,
  inserts the two original C nullifiers and only two N7 commitments, charges
  the fee once, rejects replay and both C/bridge orderings, and restores the
  same state after rollback/reinclusion.

The canonical byte accounting is exact:

```text
28 framing + 847 statement + 182863 MNG3 packet
+ 225660 equality proof + 3488 N7 receipts = 412886 bytes
```

The optional 16-byte C-receipt index is derived metadata and is not added to
the canonical bundle. The onward N7P2 packet is `3837 + 4 + 230805 = 234646`
bytes and already contains its 3,488 receipt bytes; the separately released
proof and receipts are copies, not additional consensus bytes.

The bundle exceeds current `devnet/chain.py` `MAX_PACKET=262144` by 150,742
bytes. Admission occurred in the separate prototype ledger, not the PoW block
codec. The corrected decision/design now state that a versioned migration
frame/block rule plus relay, validation, memory and denial-of-service
measurements remain mandatory.

The first proposed reproduction path incorrectly referred to the earlier
author privacy archive (`24fc6206...`), which has a different randomized H25
tip and does not contain the migration-selected block. The resolution is a
separate exact 59-file migration membership archive: 7,701,082 bytes, SHA-256
`50008712589106a8a934040dd4fa8465d1eb269f0ca7232f18ffbb2999662b6d`.
The independent audit requires this digest and exact archive/extracted-tree
equality. It also requires the exact secret-free C deployment archive:
7,557,294 bytes, SHA-256
`682ed92c510c0b73ddf21ed7c50c048c4430bb8b06c5e6fc28db1e63e8c5d942`,
with exact equality to its 63-file extracted tree. These are distinct migration
release assets, not substitutes for the earlier privacy archive.

`RUN.json`'s `private_dependency: false` is accepted only as “public
verification has no private dependency.” Recreating the exact MNG3, bridge and
onward proof bytes requires the original seed and private witnesses. The
public release can verify the backup-recovery output but cannot independently
prove that the author recovery child received no undisclosed private sidecar.
The source contract and process boundary are supporting evidence, not a
publicly reproducible negative fact.

Fresh verifier executable SHA-256 values are deliberately excluded from the
checked receipt: Rust binaries may differ with build path/tooling while
embedding identical registrations. The public audit regenerates the bridge
and N7 verifier keys, requires byte identity with the registered keys, checks
their exact digests, and requires successful public proof verification. The
three executable hashes copied from frozen `RUN.json` are labelled as author
run provenance only and are never compared with a rebuilt executable.

The portability control used two legitimate builds with different executable
hashes: bridge `7a46b374...` versus `39687cb8...`, and N7 `ae2a29c9...`
versus `8ff6cbc7...`. Both builds regenerated the registered keys byte for byte,
verified the public proofs, rejected the mutations, and matched the same
`MIGRATION_PUBLIC.json` receipt.

## End-to-end blockers

No reviewed artifact supplies all premises needed for a quantitative monetary
claim. The unresolved composition includes:

1. extraction or direct monetary soundness for the exact registered
   PLONK/FRI transcript under adaptive, many-proof quantum attack;
2. an applicable FRI/list and Fiat--Shamir/QROM theorem with concrete losses;
3. instantiated Poseidon/Poseidon2 commitment, sponge, tree, and nullifier
   assumptions for the exact encodings and domains;
4. a reduction from the chosen binding/collision game to US, XV, or IN;
5. issuer-signature, state-transition, rollback, and historical-admission
   composition; and
6. an HVZK/full-payment privacy simulation correlated with receipts and later
   spends.

Finite passing tests and exact serialization arithmetic cannot fill these
gaps. The frozen decision is supportable as a conditional research/devnet and
out-of-band migration result, not production qualification.

## Reproduction commands

From the worktree root:

```sh
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB experiments/funded-pq-assurance/binding/lifetime_security.py \
  --check experiments/funded-pq-assurance/binding/RESULTS.json
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB -m unittest discover \
  -s experiments/funded-pq-assurance/binding -p 'test_lifetime_security.py'
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB -m unittest discover \
  -s experiments/funded-pq-assurance/binding/migration -p 'test_*.py'
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB experiments/funded-pq-assurance/proof/check.py
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB experiments/funded-pq-assurance/review/independent_check.py \
  --check experiments/funded-pq-assurance/review/INDEPENDENT.json
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB experiments/funded-pq-assurance/review/archive_audit.py \
  /tmp/funded-membership-public.tar.gz \
  --check experiments/funded-pq-assurance/review/ARCHIVE.json
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 -IB experiments/funded-pq-assurance/privacy/analyze.py \
  /tmp/funded-membership-public-inspect/public \
  --archive /tmp/funded-membership-public.tar.gz \
  | cmp - experiments/funded-pq-assurance/privacy/RESULTS.json
```

The privacy commands require the exact earlier author archive and matching
extracted tree. The complete post-publication command, including the distinct
migration lineage and deployment release assets, clean bridge/N7 builds,
registered-VK comparison, public proof verification, selected-branch replay
and `MIGRATION_PUBLIC.json` check, is:

```sh
bash experiments/funded-pq-assurance/reproduce.sh /tmp/funded-pq-assurance-reproduction
```

The destination must be absent or empty. The local devnet replay uses Unix
sockets and may require the normal sandbox approval. The optional
`FUNDED_PQ_MEMBERSHIP_ARCHIVE`, `FUNDED_PQ_MIGRATION_ARCHIVE` and
`FUNDED_PQ_C_DEPLOYMENT_ARCHIVE` variables may point to already downloaded
checksum-matching public assets; they are not private dependencies.
The replay also requires `bubblewrap` (`bwrap`) to enforce the same isolated
wallet-role execution used when the evidence was created. The reproduction
script fails closed before building if the executable or required user
namespaces are unavailable. The Ubuntu 22.04 CI job pins the official amd64
package `0.6.1-1ubuntu0.3`, records its version and exercises the namespace
capability before the full release audit. The verifier does not fall back to
an unsandboxed role.
