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

## Every completed development milestone

1. Make coherent source/specification changes with the relevant tests. Preserve
   invariants, failures, dependency pins/licenses and any changed assurance limits.
2. Execute the appropriate focused checks against the exact candidate. Record
   actual outcome and scope; an unexecuted CI job or source review is not a pass.
3. Commit and push the reviewed revision without force-pushing, rewriting public
   history or moving old milestone tags. A later correction is a new commit.
4. Verify the public SHA and compare it with the tested revision. For dependency/
   build/installation changes repeat a clean public-URL clone with no research
   fallback. Do not silently test one revision and hand off another.
5. Give the owner the repository URL, full immutable commit SHA and commit URL,
   previous milestone SHA/compare URL, exact setup/build/test commands, outcomes,
   limits and changes in unverified claims. Update brief STATUS.md.

An external reviewer reads the specified revision when the owner supplies the
handoff. Public read access suffices; no write access or automatic monitoring/
approval is assumed. Publication or AI review does not confer an audit/security/
production designation.

Large optional public artifacts may be generated from included code or attached
to an immutable versioned release with hashes and a fetch command. A hash or
review summary never replaces a required runnable source, fixture or test oracle.
Private material, credentials, wallet databases and old secret-bearing history
must never be staged. Inspect the complete history before an initial publication.

## Current delivery record

This is the first public milestone; no earlier public milestone SHA/compare URL
exists. The prior research source revision is provenance, not an invented public
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
