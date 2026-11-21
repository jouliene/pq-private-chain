# Genuine migration attempt record

The successful public evidence is `evidence-author05`.  Four earlier attempts
were deliberately kept outside the repository as private diagnostic workspaces;
none produced a bridge proof or a publishable partial success.

| Attempt | Last completed boundary | Failure and correction |
| --- | --- | --- |
| Offline exporter build 1 | Source patching | A new empty Cargo cache lacked pinned `blake3`; offline resolution stopped. The successful build reused the cache from the retained reproducible funded-C run. No network fallback or dependency substitution was used. |
| Author 01 | Public metadata preflight | The sandbox denied loopback socket creation before wallet-secret use. The local devnet was rerun under the existing authorized loopback permission. |
| Author 02 | C history replay and backup restoration | The wallet API returns `balance`, not `native`. The harness was corrected without changing protocol checks. |
| Author 03 | Fresh MNG3 packet and proof | The selected spent-set comparison referenced the unimported public `packed` codec. Static global-name checking was added after importing the exact ledger helper. |
| Author 04 | Fresh MNG3 packet, branch split and receipt opening | The private exporter appends diagnostic receipt kind `2`/`3`; the strict bridge witness correctly rejects that non-cryptographic field. The harness now validates and removes it before canonical witness serialization. |
| Author 05 | Complete | Fresh MNG3 authorization, empty/conflicting H26 branches, H27 bridge, public verification, atomic controls, seed-only recovery and ordinary N7P2 onward spend all passed. |

The failed attempts are integration diagnoses, not negative cryptographic
results.  Their correction history is retained so the final run is not
misrepresented as succeeding on its first execution.
