# Persistent public Ledger/archive role

The five Rust modules are byte-identical to the actually executed research
Source01 role. No payment/proof/fee or archive rule was rewritten. The public
Cargo manifest/lock and wrapper now consume the independently prepared public
core installation, without any research-tree or old installation fallback.

After root setup/build and the genuine distinct producer, review `SOURCE.json`
and use the actual approved installation/workload identities:

```sh
python3 -I experiments/architecture-feasibility/role-pipeline/public-role/ops.py build \
  --label build01 --installation .work/reviewer/fresh/installation.json \
  --approve-installation APPROVED_INSTALLATION_SHA256 \
  --approve-source REVIEWED_PUBLIC_ROLE_SOURCE_JSON_SHA256
python3 -I experiments/architecture-feasibility/role-pipeline/public-role/ops.py run \
  --label run01 --build-label build01 \
  --installation .work/reviewer/fresh/installation.json \
  --approve-installation APPROVED_INSTALLATION_SHA256 \
  --approve-source REVIEWED_PUBLIC_ROLE_SOURCE_JSON_SHA256 \
  --workload /absolute/path/to/producer/.work/distinct01.public/workload.json \
  --approve-workload ACTUAL_PUBLIC_WORKLOAD_SHA256
```

Build uses a fresh target/Cargo home and the approved finite offline vendor,
toolchain and installed source. It keeps the pinned lockfile, validates actual
compiler manifests/features/depfile closure/ELF/native linkage and rechecks the
installation. The local dependency is explicitly rebound to the approved
workspace's source, where installation-only native/provider identities live.
The published source dependency path remains independently inspectable.
Build child budget180s/run120s,one CPU/4GiB AS are bounded experiment watchdogs;
source/runtime hash checks additionally need an outer supervisor if desired.

The runner prepares a persistent immutable registry, then reads/SHA-checks and
genuinely admits16 signed credits, archives and evicts them, tests a late-invalid
final ordinary proof without partial SQL state, genuinely admits the original16
ordinary payments and publishes/evicts those bodies. The mutation changes an
opaque proof commitment; append_local_block avoids an expected-header mismatch
shortcut, and Error::Proof plus all14-table/schema/version equality is mandatory.

Cached full_block must fail before actual archive fetch. Every fetched original
body byte is compared, then a newly prepared independent Ledger replays both
blocks with genuine proof/source/state checks. Canonical state matches while
random catalog identities/cache placement are checked against separate local
obligations. A complete reduced scan is checked too; no cached verifier verdict,
untrusted program or wallet secret enters public verification.

The source quota16*BODY_MAX has watermark0; credits are archived before ordinary
admission. Destination quota32*BODY_MAX and archive allowance128MiB fit this tiny
fixture, not a deployment. All32 original public bodies are retained as RAM
oracles. Page cache is uncontrolled/warm and the negative control precedes the
ordinary positive span. Per-stage CPU/RSS/Linux self I/O are scoped explicitly;
waited-child peaks are not summed into simultaneous process-tree memory.

Inclusive spans contain nested APIs **and full SQL snapshots/assertions/oracle
allocation/copy/metadata observations**. They overlap exclusive stage rows and
must not be added, or subtracted from admission to infer archive time. Local
file fetch is not WAN delivery. This finite sequential test establishes neither
sustainable TPS,annual catch-up,large-state storage,private recovery nor a
composed PQ/privacy theorem. Historical observations are in the parent summary;
any new public smoke result must be identified separately.
