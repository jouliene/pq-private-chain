# Genuine distinct-payment workload generator

This imports the real32-proof mechanism, with only public installation/path
relocation. Sixteen disposable payers/destinations and sixteen distinct source
entitlements are created in RAM. A fresh ML-DSA-87 laboratory authority authorizes
the credits. Sixteen genuine credit proofs form one16-body block; actual checked
history recovers the funded notes; sixteen genuine2x2 proofs consume disjoint
pairs at the same parent anchor and form another16-body block. All proofs,
signatures,fees,transcripts and state checks remain genuine and unchanged.

After root setup and build, review `SOURCE.json` and the explicit installation
approval. Then, with the machine's one heavy slot available:

```sh
python3 -I experiments/architecture-feasibility/role-pipeline/producer/run.py \
  --label distinct01 --installation .work/reviewer/fresh/installation.json \
  --approve-installation APPROVED_INSTALLATION_SHA256 \
  --approve-source REVIEWED_PRODUCER_SOURCE_JSON_SHA256
```

The approved installation supplies Node, immutable source/runtime pins, the
operator/private-parent approvals and helper identity. Only that operator-selected
workspace supplies wallet/crypto modules; a transaction cannot select code. All
existing private prover/program/source/runtime verification stays active.
`scripts/common.py` captures the private worker in bounded RAM, retains first
wait4/cleanup status, and never writes or hashes raw private output. Only an exact
fixed success schema or known fixed failure stage is persisted. One CPU/4GiB AS
and480s are watchdogs, not deployment targets or measured performance promises.

Public output is `.work/distinct01.public/workload.json` beside this README,
plus its genuinely generated bodies/headers/genesis. The normalized manifest
has chain/genesis/two block rows/endpoint; each row lists16 body path/hash entries.
No opening,key,backup,private input index or credit/payment mapping is exported.
The producer's membership calls are to its local trusted laboratory Ledger and
do not demonstrate the separate private witness-stream integration.

Labels,source approvals and output directories are exclusive. Failed attempts
remain local evidence; no automatic retry or historical ELF/proof fallback exists.
Generated public proof receipts remain inside the approved disposable workspace.
The32-proof campaign need not be repeated by the short publication smoke; its
historical outcome is explicitly separate from any new clean-public-clone checks.
