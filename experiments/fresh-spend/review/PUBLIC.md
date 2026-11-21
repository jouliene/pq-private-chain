# Anonymous public reproduction

A non-author completed the decisive checks at 2026-11-21 18:30:54 UTC
on public source `13989d9448216f2573b0b2faf349da80d854392b`. The review
started in an empty directory with a clean environment, HTTPS as the sole
Git transport, no credential helper, interactive prompts disabled, no system
or user Git configuration and no object alternates. The reviewer observed
this SHA as `origin/main`, checked ancestry from
`7d5887842ba513c254128bbb5818bbd6617ce3fc`, detached at the tested revision
and downloaded all four pinned archives. The checkout stayed clean.

```sh
work=$(mktemp -d)
cd "$work"
env -i PATH=/usr/bin:/bin LANG=C GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_ASKPASS=/bin/false GIT_ALLOW_PROTOCOL=https \
  git -c credential.helper= -c http.extraHeader= -c core.askPass=/bin/false \
  clone --no-local --single-branch --branch main https://github.com/jouliene/pq-private-chain.git checkout
cd checkout
git merge-base --is-ancestor 13989d9448216f2573b0b2faf349da80d854392b origin/main
git checkout --detach 13989d9448216f2573b0b2faf349da80d854392b
env -i PATH=/usr/bin:/bin LANG=C bash experiments/fresh-spend/reproduce.sh "$work/result"
```

| Reproduced independently | Outcome |
|---|---|
| Fresh signed asset funding and six relation/wallet tests | Passed in 6.251 s. Fresh receipt process opened the provided public row with the original seed. The host's onward witness used that note. Re-encryption changed both ciphertexts and the intent authorization while the same two input nullifiers recurred. |
| SHAKE256 funded-leaf component, VOLE-256s | 119,056 B. Prove 0.37 s / 67,456 KiB. Public verification 0.34 s / 53,368 KiB. |
| Same component, VOLE-256f | 170,468 B. Prove 0.09 s / 20,992 KiB. Public verification 0.08 s / 14,564 KiB. |
| Public negative controls | For each VOLE setting the new verifier process rejected a changed statement, changed domain and corrupted proof. |
| Stock Picnic L5-UR | Three fresh 209,506 B signatures. Sign CPU 214.861–220.402 ms, verify CPU 145.445–146.724 ms. Changed message and hidden commitment rejected. Upstream known-answer tests passed. |
| Regenerated geometry | Both price reports matched the checked-in bytes. Full ordinary projections were 10,751,268 B and 424,891,726 B. |

The reviewer separately read the upstream degree-two VOLE and Picnic
serializers and recomputed the costs from their layouts. The 80 parent
permutations alone need 3,072,000 binary ANDs. Charging just the corresponding
packed vectors gives 8,448,000 B for small VOLE and 336,384,000 B for Picnic
with 438 rounds. Substituting the reviewer's measured kernels into the Picnic
payment model gave 9.283–9.574 s prover CPU and 5.059–5.166 s verifier CPU.
These latter values are projections, separate from the measured signatures.

The review also checked the scope of FAEST theorem 9.42 and Picnic lemma
5.9. The latter single-event bound is vacuous at the stated query budget.
The tested relation models both owners and a signed issue. Full FS01 proof
generation, a complete authenticated history scan, swap settlement and full
node admission have no implementation or timings. The account, note typing
and selected-row recovery claims were narrowed during review to the exact
components exercised. [Decision and sources](../DECISION.md)

All three automatic push runs reported success on the exact tested SHA
`13989d9448216f2573b0b2faf349da80d854392b`. The fresh-spend job ran the
public qualification script. The other two exercised the existing payment
and PoW wallet regressions. The later handoff adds only Markdown evidence.
[Fresh spend qualification](https://github.com/jouliene/pq-private-chain/actions/runs/44935786763) · [Local PoW devnet](https://github.com/jouliene/pq-private-chain/actions/runs/44935786772) · [Research payment smoke](https://github.com/jouliene/pq-private-chain/actions/runs/44935786798)
