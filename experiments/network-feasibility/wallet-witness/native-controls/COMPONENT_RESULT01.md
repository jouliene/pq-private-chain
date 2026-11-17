# Native selective-frontier component result

Actual public component controls passed on the new `gate3a` installation:
installation SHA256`c025a573103f652004cfe7400ef7fff3db0ef32c1458b0103fa753b477a2546b`,
helper SHA256`830abcd29b8cdec9aa8d2b76a1fb5c78ff365aba203da58b247ac4e46e23b1bb`.
`COMPONENT_RESULT01.json` pins the frozen source and unchanged raw public receipts
preserved in `evidence/native01/` with `FILE_MANIFEST.json`.
The three installed core source copies match the reviewed canonical files.
This readback made no native/build/proof rerun or dependency/ELF hash sweep.

| Actual controls | Result | Outer wall / peak RSS |
|---|---|---|
| JS native/API/production-parser controls |13passed, exit0, no stderr/timeout |0.196963s /72,544KiB |
| Rust selective-frontier controls |5passed,0failed |1.245351s /172,968KiB including test compilation |

Both receipts preserve first wait4 and CPU0. Rust reports0.71s compilation and
0.52s test execution, rounded by Cargo/test output. Those times/peaks are not
isolated production-helper latency or RSS. Nonfatal dependency/style/deprecation
warnings remain in raw Rust stderr; they did not hide failed controls.

The actual positive JS case with **K64 and256incoming leaves in one block**
completed under the fixed5s child timeout. The whole13-check process took0.197s;
there is no separate maximum-case timer and no benchmark of every mature
maximum-state shape. State173248B, whole-request213249B and response338716B are
conservative fixed caps below1MiB, not measured RSS. Legacy caps135723/82434 stay
unchanged; AUTH/NOTE/NF were exercised, without claiming this suite is a broad
statement/batch/payment regression run.

Controls cover the padded-sibling continuation trap, next real nonpadding-sibling update,
forget/discovery, canonical geometry/masks/fields, caps and malformed/truncated/
trailing input/output. Rust compares roots and paths with a small test-only
full-tree oracle. Its structural count2^40 shape does not execute trillion leaves.
Runtime state retains only the unpadded frontier and live completed siblings;
temporary padding is not serialized. No Python runtime or all-history vector
was added to the helper.

This is a public helper component PASS. It does not establish wallet receipt
ownership, a genuine new spend, anchor expiry, rewind/recovery, endpoint authority,
network anonymity or joint PQ/privacy security. Node still owns private capability
bindings for chain/genesis/profile/cursor/inventory/revision and checks exact
selected root/count. No selection/state bytes or digests, tokens, paths or raw
private streams appear in this result. Wiping remains best effort. Integrated
wallet acceptance is separate work owned and allocated by Root.
