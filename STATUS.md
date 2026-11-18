# Wallet-created private payment

**Bounded architecture decision delivered. Global blockchain development remains ACTIVE.** The baseline is `a131ee5881e89e02f721fcfc3b5d01225437366e`. Defer both candidates for network activation and keep CP03 as the executable reference. The proofs are complete research payments under the stated constructions. The measured implementations have no system-wide quantitative PQ/privacy assurance.

| Deliverable | Evidence |
|---|---|
| Three new complete WHIR 2×2 payments, recipient spending, public replay, negatives and durable accounting | [Wallet and public bodies](experiments/wallet-created/wallet/README.md), [structured source and oracle](experiments/wallet-created/structured/README.md), [joint-transcript analysis](experiments/wallet-created/structured/ASSURANCE.md) |
| Qnero at one occupied wallet slot, full bytes, receiving/recovery, native FRAME settlement | [Default comparison](experiments/wallet-created/qnero/README.md), [wire capture](experiments/wallet-created/qnero/http/README.md), [pallet](experiments/wallet-created/qnero/pallet/README.md) |
| Two distinct wallet processes, public-only native aggregation, four received notes, new recipient spend | [Native source, inputs and reproduction](experiments/wallet-created/native/README.md) |
| Independent fresh cryptographic runs, public verification, correct retained state; actual compute and state limits | [Independent core review](experiments/wallet-created/review/CLEAN_CORE.md), [independent native review](experiments/wallet-created/review/CLEAN_NATIVE.md) |
| Integrated default-network decision, priced participation, future token and swap semantics | [Decision and next experiment](experiments/wallet-created/DECISION.md), [role calculator and tables](experiments/wallet-created/ROLES.md), [future versions](experiments/wallet-created/EXTENSIONS.md) |

The publishable complete wallet path was built at `1e5956364b2a39117f80d00d41923b6b92422439`, durable replay at `abbca400862233bba0c9a7f7f9e468c7b19c58c4`, and native aggregation at `4ab7e6fa4699b94821c7978c37d98fe9c600ea08`. Each has its own independent evidence; the pinned external comparator source is `DigitalGuards/qnero@f04c91307837c0231668383bec76ba98d89d2652`.

To reproduce from a new checkout, follow BUILD.md, then the wallet, native and Qnero commands linked above. Run `python3 -IB experiments/wallet-created/roles.py | diff -u experiments/wallet-created/ROLES.json -` for the 95%/100% projections. To look up the automatic baseline smoke for the published checkout, run `gh run list --repo jouliene/pq-private-chain --workflow smoke.yml --commit "$(git rev-parse HEAD)"`. The hosted smoke exercises the preserved reference. Independent release evidence above covers the new payment paths.

Next decision-changing work would test four genuinely independent origins with a security-qualified profile, eligible retained anchors and incremental verification state. The two-origin saving carries no credit for that future occupancy. Neither 1 nor 5 TB/archive-year represents owner approval. The global protocol still needs quantified PQ/privacy composition, data availability and viable participation; no consensus activation or new protocol milestone has started.
