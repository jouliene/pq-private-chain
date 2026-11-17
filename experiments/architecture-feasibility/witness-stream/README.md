# Local selective witnesses

This is the real fixed-endpoint append-frontier mechanism, with the original
Frontier class unchanged. A public entry point now consumes a freshly generated
common workload instead of machine-pinned historical files. All cryptographic
hashes/empty subtrees/depth40/occurrence identities are unchanged. The approved
core installation supplies the independent Python arity/hash reference and its
constants; no private key/witness file is read.

After the root private payment/recovery smoke, use its reported public
`workload.json` and approved installation. The smoke's three genuine bodies are
sufficient; running the full32-proof distinct generator is optional here.

```sh
python3 -I experiments/architecture-feasibility/witness-stream/probe.py \
  --installation .work/reviewer/fresh/installation.json \
  --approve-installation APPROVED_INSTALLATION_SHA256 \
  --approve-source REVIEWED_WITNESS_SOURCE_JSON_SHA256 \
  --workload /absolute/path/reported/by/private-smoke/workload.json \
  --approve-workload ACTUAL_PUBLIC_WORKLOAD_SHA256 \
  --output /absolute/new/witness-result.json
```

`SOURCE.json` binds this entry point and README; inspect its files and SHA256
before using that source approval. The installation loader checks the explicit
installation identity and all source/runtime pins before and after the run.
Runtime relocation is approved by core setup; no historical machine identity
is silently accepted or verification check disabled.

At each generated checkpoint, the probe derives every funded leaf in order,
constructs public diagnostic target paths, matches the authentic header root and
independent sparse-tree paths, then rejects omission/reorder/mutation/unfunded
targets. It does not itself establish payment-proof validity or consensus; the
operator must authenticate the workload/endpoint and separately run the genuine
Ledger verification. A hash-bound stale prefix is not latest recovery.

For N leaves,k selected indices,D=40, the mechanism uses O(D+kD) retained state
and O(N+D+kD) work. The test harness additionally retains every leaf and a full
sparse oracle, so reported RSS is not a streaming bound. Public diagnostic targets
are not real owned indices. No remote owned-index request occurs. Actual private
target composition, network metadata and host compromise remain separate.

`finish()` pads and consumes the frontier; this is fixed-endpoint restoration,
not live witness maintenance or rollback. An old anchor can expire during a long
restore. A restored spender still needs authenticated live catch-up and local
witness refresh to a currently eligible anchor, without leaking owned indices.
No annual recovery, throughput or PQ-security claim follows from this probe.
