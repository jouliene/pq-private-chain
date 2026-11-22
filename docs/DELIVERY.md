# Commit-based development and review delivery

## Authority and source history

The initial public tree is a selected new-history import of research revision
360fc54e6b76dc864131f5c17b80c93b02c8bc67. IMPORT_MAP.json records selected source
paths, byte identities and explicit installation adaptations. The research Git
history and its internal logs/private workspaces are preserved separately and
are not imported here.

After verified publication this public development checkout is the authoritative
implementation tree. Edit its canonical source and setup inputs, then create new
installation workspaces for checks. Do not edit generated .work copies or manually
maintain a diverging implementation in the old research workspace. Research
journals may reference public immutable commits without becoming dependencies.

## Publication and completion for every milestone

The owner authorizes the orchestrator to commit and publish reviewed work to
[jouliene/pq-private-chain](https://github.com/jouliene/pq-private-chain) on a
standing basis. This rule covers implementations, research-only decisions and
rejected candidates. Subagents may implement or review. The orchestrator owns
Git integration and publication.

1. **LOCAL.** Pin the exact tested commit. Include the reviewed source, relevant
   tests or calculators, dependency revisions, checksums and licenses, a concise decision,
   exact reproduction commands and the minimum public evidence needed to check
   the result. For a rejected design, include the decisive calculation or
   component test and say which later experiments were omitted.
2. Fetch `origin`, confirm the push destination, check the ancestry against
   `origin/main` and inspect every outgoing commit, including intermediate
   blobs. Preserve unrelated local changes. Keep spending seeds, private
   witnesses, credentials, wallet databases and internal audit logs private.
   Place large required public fixtures in a versioned GitHub Release with
   a checksum and a pinned download command. If a local commit contains private
   material, preserve it locally and prepare a clean equivalent from public
   history. Document the SHA mapping and repeat affected checks before publishing.
3. **PUBLISHED, VERIFICATION PENDING.** Publish through the permitted branch
   path and confirm that the exact intended commits are reachable from public
   `main`. Respect branch protection and required PR checks. Use an ordinary
   fast-forward when allowed. Never force-push or move an existing milestone
   tag. Publish corrections as new commits.
4. **Public verification.** Have a non-author clone the public HTTPS URL into
   an empty directory without credentials, Git object alternates or local-source
   fallback. Record the clone's `origin/main`, check each reported SHA with
   `git merge-base --is-ancestor`, and check out the named revision. Run the
   decisive published checks there with their pinned public inputs. Compare
   regenerated outputs to the stated evidence and decision. Inspect applicable
   GitHub Actions and record the run URL, conclusion and actual head SHA for
   each. If the handoff adds a later evidence or documentation commit, verify
   its public reachability and what changed from the tested commit.
5. **VERIFIED.** Update `STATUS.md` with the observed public result. The native
   Goal can be marked COMPLETE once the decisive checks succeed from the public
   revision and applicable CI has passed. Provide the full tested and final
   SHAs, commit/compare/decision and CI links, one copy-paste reproduction
   command and the reviewer's actual scope. If delivery stalls, keep the
   milestone incomplete and report the exact blocker and last publicly verified
   SHA.

## Funded C occurrence-indexed supply

The [Phase 1D reproduction](../experiments/occurrence-supply/README.md) uses the public Phase 1C history, a fresh offline receipt and a newly proved spend. Publish only the three [workflow summaries](../.github/workflows/occurrence-supply.yml). The example used by the Lean path checker contains a private input link and stays inside the private reproduction directory.

## Funded C supply packet refinement

The Phase 1C [walkthrough](../experiments/supply-refinement/README.md) checks fresh private openings, original public block replay and Lean against selected SQLite rows. The versioned fixture contains only nine public blocks. The output directory also holds private funding links and true output nullifiers. Only the explicitly named aggregate JSON files in the [workflow](../.github/workflows/supply-refinement.yml) are deliverable.

## Funded C snapshot bootstrap

The fresh-wallet and fixed-fixture [reproduction commands](../experiments/snapshot-bootstrap/README.md) cover distinct obligations. The [versioned release](https://github.com/jouliene/pq-private-chain/releases/tag/snapshot-bootstrap-c-v1) carries only public originals, compact wallet records, checkpoint state, manifest and test branch identities. The checkout pins its archive digest and independently obtained base registration. Record provisional and fully verified measurements separately. [Decision](../experiments/snapshot-bootstrap/DECISION.md)

## Online partial fills on funded C

The [CLI walkthrough](../experiments/partial-fills/README.md) downloads public pinned inputs, extends the funded chain, negotiates two purchases against one private order, detaches and re-includes a signed fill, and mines an equal-notional full swap. Its final independent parser checks all three selected chains, both owners’ signing journals and the source of the second fill’s change. The published evidence contains public block identities and synthetic accounting totals. Keep the runtime directories and off-chain order capabilities private. [Measured decision](../experiments/partial-fills/RESULTS.md)

## SGM1 monetary-security decision

The [funded security walkthrough](../experiments/sgm1-security/README.md) verifies
the prior public proof, the explicit degree-table variant, the conditional query
calculations and the pre-draft wallet endpoint checks. The optional EAR1 public
archive contains just the verified transaction and funded prefix. Preserve the
distinction between a complete public verifier run and a quantum extraction
claim. [Architecture decision](../experiments/sgm1-security/DECISION.md)

## SGM1 two-core admission

The [capacity walkthrough](../experiments/sgm1-admission/README.md) regenerates
funding and payment proofs, compares the registered reference with the native
verifier, and measures independently submitted transfers and swaps on a durable
isolated ledger. Preserve the exact code SHA, public packet hashes, raw
arrival/commit traces, aggregate RSS sampling convention, catch-up costs and
independent reproduction beside the decision. The non-author reproduced the measurements on exact executable
`823cdcc43e6e47a4e58e83ba78aefef237f4f04e`, including fresh independent wallets,
the release's 110 proof-bearing legs, actual arrival backlogs and twelve historical
replays. All three applicable workflows passed on the executable. Subsequent
decision, evidence and review commits contain documentation and public JSON only.
[Independent record](../experiments/sgm1-admission/review/PUBLIC.md)

## Structured private Keccak spending

The public executable revision `9502266c7e976f16af47cb23a7104257dacf6968`
passed four push workflows. An independent anonymous clone rebuilt the field code,
proved both complete hidden paths from freshly signed funding, constructed the
183,224-byte ordinary payment and opened both encrypted outputs. The proof fits
the signed-leg allowance. Warm verification and the exact quantum-security
argument remain integration gates. [Decision and command](../experiments/structured-keccak/DECISION.md) · [Public reproduction and CI](../experiments/structured-keccak/review/PUBLIC.md)

## Hidden funded membership

An anonymous clean clone of `9dc3ca8ad63a47efe8982942296cc34debc527cd`
rebuilt every dependency, produced fresh signed funding and verified two distinct
hidden openings against one public depth-40 root. It reproduced both full path
profiles, the table-lookup component, size models and branch controls. All four
push workflows passed on the same executable revision. Keep the funded tree and
change the proof of its private hash transitions before integrating a payment.
[Decision](../experiments/hidden-membership/DECISION.md) · [Independent measurements, commands and CI](../experiments/hidden-membership/review/PUBLIC.md)

## Fresh-genesis private spend selection

A non-author rebuilt both pinned proof components and exercised fresh
signed issuance, offline receipt and onward witness construction from an
anonymous public clone of `13989d9448216f2573b0b2faf349da80d854392b`.
Both full payment geometries failed the preintegration screen. The public
review records the exact byte counts, source-matched limitations, fresh
component costs and three successful CI runs on the tested revision.
[Decision and command](../experiments/fresh-spend/DECISION.md) · [Independent receipt](../experiments/fresh-spend/review/PUBLIC.md)

## Funded profile C assurance

Starting public baseline:
`e55b35e04cf353bb1e1c6e51c07a33b81ddd937c`. The architecture decision and
measured C-to-N7 migration were introduced by
`4b7b798d3fc3e9bd8bcde9119811708282972618`; the exact tested and publicly
reproduced source is `c4bc9411751728660ae14af509f0b3eb35187530`.

The result retains C only as an executable research/devnet reference and
conditional legacy migration authorization. It does not establish 128-bit
post-quantum monetary security, complete-payment privacy, production readiness
or an integrated PoW migration. The 412,886-byte out-of-band bridge exceeds the
current ordinary packet limit by 150,742 bytes. The binding and proof changes
required before mainnet are recorded in the
[decision](../experiments/funded-pq-assurance/DECISION.md).

The public release pins the distinct migration branch and secret-free C
deployment with checksums. A non-author reproduced the literal command below
from an anonymous HTTPS clone with public downloads only; the exact
[receipt](../experiments/funded-pq-assurance/review/PUBLIC_CLONE.json) records
the checkout, asset identities, regenerated verifier keys, tests and claim
boundary. Both the [push CI](https://github.com/jouliene/pq-private-chain/actions/runs/44915102891)
and [full release audit](https://github.com/jouliene/pq-private-chain/actions/runs/44915116674)
passed on the tested SHA. An earlier dispatch failed closed because the hosted
runner lacked `bwrap`; the published correction pins and capability-checks the
runtime rather than bypassing wallet-role isolation.

```sh
bash experiments/funded-pq-assurance/reproduce.sh /tmp/funded-pq-assurance-reproduction
```

[Release assets](https://github.com/jouliene/pq-private-chain/releases/tag/funded-pq-assurance-2026-11-21)

## Lattice spend architecture decision

The anonymous public checkout of research revision `ebb732a94640c5be3a9d60ea4b14bb0e2580dd10` reproduced the two architecture screens, the public and newly generated membership proofs, the four funded reference roles, and the cost and migration checks. The existing payment and PoW workflows passed on that revision. The later handoff carries only reports and measurements. [Decision](../experiments/lattice-spend/DECISION.md) · [Commands](../experiments/lattice-spend/README.md) · [Independent receipt](../experiments/lattice-spend/review/CLEAN.md) · [Smoke CI](https://github.com/jouliene/pq-private-chain/actions/runs/44853578935) · [PoW CI](https://github.com/jouliene/pq-private-chain/actions/runs/44853579029)

## Initial delivery record (historical)

This was the first public milestone; no earlier public milestone SHA/compare URL
existed. The prior research source revision is provenance, not an invented public
ancestor. The initial code commit is
`b3121208b47484917a887041c376f4a5840a81b4`; subsequent release-preparation commits
change only delivery documentation/evidence. Exact public verification and any
CI outcome are retained in `delivery-result.json` on the immutable
[publication-2026-11-17 release](https://github.com/jouliene/pq-private-chain/releases/tag/publication-2026-11-17).
The handoff must use that record's tested public revision, not assume the branch
name still denotes the tested bytes. That first milestone used manual CI. The
network milestone adds automatic push/PR smoke coverage and the isolated wallet
cycle. Its actual run URL/conclusion must be checked; the presence of
`.github/workflows/smoke.yml` is not a PASS.

## Network-feasibility delivery

The next milestone retains the initial public revision
`d8f800037b5efbb76a5a1d6d4d3100e55f676a00` as its comparison baseline. Its tested
implementation/experiment source revision is
`a9357c27d7458277b80b78ac887696a9ea9a99a8`. Later reviewed CI changes add public
startup diagnostics, correct smoke ordering, and run the unchanged payment tests
in a verified Noble userland on an Ubuntu22 host. Those are executable environment
changes, not merely documentation. Core payment/wallet source manifests remain
unchanged. The final record identifies the exact automatically tested checkout,
its CI wrapper/workflow identities, and any subsequent documentation/evidence-only
revision. Source correspondence is checked explicitly; it is not inferred from
the branch name or from an earlier installation's binary hashes.

The `network-feasibility-2026-11-17` release's `delivery-result.json` is the final
publication readback: exact public revision, actual automatic push-CI run/result,
source approvals, acceptance scopes and public replay archive identity. Until that
record and successful CI exist, publication is pending even if local checks pass.
The optional462551040-byte public archive contains genesis,264 full payment bodies
and a comparison manifest only. Its source build and replay commands are in
`experiments/network-feasibility/wallet-integration/README.md`. It is not a private
fixture or database backup. No full-private264 independent rerun, production
security or completion of the global blockchain follows from this release.

## Source manifests after a deliberate source change

`CORE_MANIFEST.json` is the explicit selected build/test-source inventory; each
entry has bytes and SHA256. `SOURCE.json` files separately bind the experiment
entry points. They are developer review inputs, not transaction-selected programs.
After an authorized change, review the exact diff and consciously add/remove
required inputs in these lists, recompute their hashes from the public checkout,
then commit the code and manifests together and use a new clean installation.
The existing Python standard-library hashing functions in scripts/common.py are
sufficient; no original research export script or archive is a maintenance
prerequisite. Never sweep `.work`, secrets, generated databases or binaries into
a new manifest. The historical IMPORT_MAP remains the initial-import record;
do not rewrite it to conceal later development. Preserve algorithm/profile IDs
unless the protocol change itself explicitly requires a coherent version change.

## Incremental synchronization delivery

Baseline: `2b87d1e5fcb9090390c476138bbd174d6034a6a9`. Non-implementing clean
reproduction tested implementation `17dd4e73f4fbde9fee2129d0fd761b864eefe42f`.
Published candidate `78ef14fd25f00b8f9c0b37db83e969192e6e2bb1` passed actual automatic
[CI44146325047](https://github.com/jouliene/pq-private-chain/actions/runs/44146325047), including the new incremental
nine-proof cycle and the existing relevant checks. The final handoff commit is
documentation/evidence only relative to that CI revision; its `[skip ci]` marker
avoids a duplicate heavy job for unchanged executable source. No CI success is
attributed to an unexecuted later commit. Final public SHA is reported in the
owner handoff and is recoverable from the containing Git history.

See [PUBLICATION.json](../experiments/incremental-sync/PUBLICATION.json),
[results](../experiments/incremental-sync/RESULTS.md),
[reproduction commands](../experiments/incremental-sync/README.md) and the
[non-implementing review](../experiments/incremental-sync/review/CLEAN_REPRODUCTION01.md).
This completes wallet synchronization only. Global blockchain development,
complete-payment storage costs and formal PQ/privacy obligations remain open.

## Funded fixed-parent TCitH evaluation

The reviewed delivery includes the complete native proof, two-owner wallet harness, isolated PoW registration, branch and spent-state controls, costed security alternatives and a checksum-pinned release of public signed bundles and funding blocks. Reproduce the full decision with `bash experiments/funded-tcith/reproduce.sh`. The live proof registration and public history are preserved. [Decision](../experiments/funded-tcith/DECISION.md) · [Reproduction](../experiments/funded-tcith/README.md)

The non-author independently rebuilt the proof and both released verifiers, reproduced the first signed leg and produced a fresh funded leg on another branch. The second signed pair and its public funding prefix are separately checksummed assets on the same release. [Independent report](../experiments/funded-tcith/review/CLEAN.md) · [Second archive checksum](../experiments/funded-tcith/review/INDEPENDENT.sha256)
