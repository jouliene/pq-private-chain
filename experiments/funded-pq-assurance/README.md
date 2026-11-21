# Funded profile C monetary-assurance decision

## Decision

Do not claim 128-bit post-quantum monetary security or complete-payment privacy
for funded profile C.  Keep C executable as the devnet reference and a
conditional legacy migration authority.  For a mainnet-target profile, replace
the four-word binding-critical note/tree/owner/nullifier construction and replace
or externally qualify the exact noninteractive proof backend.  The complete
argument, assumptions and retain/change matrix are in [DECISION.md](DECISION.md).

This milestone did not implement a practical attack.  It separated the actual
money games from generic collisions, calculated conditional ideal-function
screens, mapped the registered transcript to the missing proof results, measured
public retry/receipt observations, and exercised the smallest coherent wider
successor on funded money.

## One-command public reproduction

From an anonymous HTTPS clone of the published revision, run:

```bash
bash experiments/funded-pq-assurance/reproduce.sh /tmp/funded-pq-assurance-reproduction
```

The destination must not already contain files. The script uses Python 3,
`curl`, `tar`, `sha256sum`, Rustup, the pinned Rust 1.93.0 toolchain and a
working `bubblewrap` (`bwrap`) user-namespace runtime. The accepted Ubuntu
22.04 CI pins package `0.6.1-1ubuntu0.3`. The script tests the namespace
capability before building and has no unsandboxed wallet-role fallback. It:

1. regenerates the binding and proof calculations and runs the light state
   tests;
2. downloads the checksum-pinned prior funded-membership author archive and
   reproduces the privacy observations;
3. rebuilds the registered bridge and N7 verifier from locked source;
4. verifies the released bridge and onward proof from public artifacts and
   rejects public mutations; and
5. downloads the exact clean-reproducer H1--H25 migration lineage and matching
   secret-free C deployment release assets, then runs the independent
   branch/C/bridge/N7 audit without any seed, note opening, wallet database or
   witness.

`FUNDED_PQ_MEMBERSHIP_ARCHIVE`, `FUNDED_PQ_MIGRATION_ARCHIVE` and
`FUNDED_PQ_C_DEPLOYMENT_ARCHIVE` may name already downloaded checksum-matching
archives. `FUNDED_PQ_CARGO_HOME` may name a reusable public Cargo cache.  They
are convenience inputs, not private or untracked dependencies.

The privacy fixture and migration lineage are intentionally distinct.  The
bridge used the prior milestone's independently generated clean-reproduction
branch, whose paid H25 tip is `0000028c...`, not the older author branch whose
paid H25 tip is `0000019c...`.  The initial handoff incorrectly pointed the
migration verifier at the older archive; independent review caught that the
selected block was absent.  The exact H1--H25 migration lineage is therefore a
separate checksum-pinned release input rather than a silent substitution.

The author migration proof is not regenerated because doing so requires the
historical owner's private backup.  Public reproduction instead rebuilds the
registered public verifiers, checks every released byte, replays the selected C
branch, verifies the fresh C authorization and both new proofs, recomputes the
bridge context and N7 root, and exercises changed statements/proofs.  The
backup-only recovery claim is an author-run functional result; the public
release contains no backup and cannot independently repeat that private action.

## Evidence map

- [Architecture decision](DECISION.md)
- [Monetary games](binding/GAMES.md) and [code map](binding/CODE_MAP.md)
- [Reproducible lifetime calculator](binding/lifetime_security.py) and
  [frozen output](binding/RESULTS.json)
- [Exact proof/transcript analysis](proof/ASSURANCE.md) and
  [frozen parameters](proof/PARAMETERS.json)
- [Joint-view privacy analysis](privacy/PRIVACY.md) and
  [public observations](privacy/RESULTS.json)
- [Wider profile](binding/WIDER_PROFILE.md),
  [migration design](binding/migration/DESIGN.md) and
  [measured result](binding/migration/RESULTS.md)
- [Independent challenge](review/REVIEW.md)
- [Anonymous public-clone and CI receipt](review/PUBLIC_CLONE.json)

The migration evidence is under
`binding/migration/evidence-author05/` and is below 1 MiB.  Large prior public
history, the exact migration lineage and the secret-free C deployment are
checksum-pinned release assets.
No seed, private witness, note plaintext, wallet database or internal audit log
is a public reproduction input.
