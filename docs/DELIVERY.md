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
