# Dependency provenance and notices

`IMPORT_MAP.json` identifies the imported research boundary, exact before/after
file identities, direct Git objects versus retained public archive members, and
all68registry crate versions/checksums/licenses. Files are copied as selected
source, not as research Git history. Public build/run paths do not read the
research tree, retained archives or package caches.

The modified Plonky3 workspace is under
`source/experiments/compact-challenge-v1/view01/`, based on upstream commit
`0d803737b681774186cd283b1fd2d8e493655c82`. Its original `LICENSE-MIT` and
`LICENSE-APACHE`, per-package license metadata and upstream notices are retained.
The bounded extension challenge/transcript changes are the existing selected
research implementation, not a new publication-time cryptographic change.
The complete existing workspace is retained to preserve path/dev-target resolution.

`vendor/` holds the full checksum-verified source of each pinned crates.io package,
including its original Cargo metadata, license/copyright notices and
`.cargo-checksum.json`. The `.crate` archive checksum is recorded in that file and
the import map. Duplicate source `.crate` archives are not needed or shipped.
Bundled native SQLite sources/notices remain in their original crate. Third-party
code keeps its own license terms; no new blanket license is applied to it.

The project-authored packages retain their existing metadata. This publication
does not invent a new license grant for material whose owner has not selected one.
The Node/Rust/native toolchain are separately provisioned infrastructure under
their upstream terms; their binaries are not vendored or committed. Runtime
approval pins are generated locally and ignored, never shipped as another
machine's private configuration.

`fixtures/cp03-reference/` contains genuine **public synthetic research vectors**:
proof-bearing bodies, headers/genesis and public signature requests. These are
test inputs, not production issuance or private wallets. No secret key, note
witness or backup is included. New private material is generated only in RAM by
the fresh smoke; see `BUILD.md`.
