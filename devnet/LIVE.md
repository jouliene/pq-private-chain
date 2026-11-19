# Payment under continuous proof of work

The normal `pqd start` configuration starts two independent miners and a third validating peer. In this run both miners searched continuously before, during and after wallet proving. The sender waited for its own mined reward, then authorized one 17-unit payment to a newly created recipient. No client-triggered blocks, miner pauses, tips chosen by the driver or precomputed transfers were used.

| Proposal | Wallet anchor | C tip before submit | Solved during wallet preparation | Client preparation wall | Admission | Return frame |
|---|---:|---:|---:|---:|---|---:|
| First | H2 | H11 | 9 | 13.843 s including cold setup | Rejected for anchor age | 41 B |
| Replacement | H11 | H16 | 5 | 9.034 s | Acknowledged, included at H18 | 120 B |

After the first explicit refusal, the client freshly checked the selected public spent set for both verified nullifiers and scanned for the two expected outputs with the same recipient key. Neither nullifier nor recipient output had appeared. The wallet rescanned the current branch and made a fresh proof for the same intent. Each packet was 230,206 B, or 230,229 B on the submitting socket. Both attempts thus consumed 460,458 B outgoing and 161 B in replies. The occupied block was 230,432 B.

All three nodes selected the same H18 block, the recipient opened the expected 17-unit unspent note, and node C saw a successor. That observation occurred 3.675 s after the successful acknowledgement and 26.633 s after the original intent began proving. Startup, acquisition of a genuine reward, both proofs, observation and shutdown took 39.542 s. The cold prover setup took 7.487 CPU-s. The two proofs took 17.924 and 17.566 CPU-s with 1,090,784 KiB process high-water RSS. A and B each reported ten solved candidates. Their successful nonce jobs accounted for 50,181,876 hashes and 35.766 CPU-s. Interrupted jobs are outside that counter.

From the repository root, prepare the runtime using the [native build instructions](crypto/README.md). The first command creates fresh private wallet and node data; use separate new home and evidence directories. The second independently verifies both published proofs, checks PoW and replays admission and all 19 selected blocks from empty genesis using only the public artifacts. Opening the recipient note was observed by its wallet during the live run. [Public timings, receipts and rejected attempt](evidence/live/LIVE.json) · [Public replay](evidence/live/PUBLIC_REPLAY.json)

```sh
python3 -IB devnet/live.py --runtime "$runtime" --home "$lab/live-home" \
  --evidence "$lab/live-evidence" --amount 17
python3 -IB devnet/live.py --check --runtime "$runtime" --evidence devnet/evidence/live
```

A new run accepts a single intent of 1–97 units and makes at most four fresh proposals. Only an explicit stale-anchor rejection with a clean selected-state check allows a replacement. Acknowledged transactions are observed through inclusion or expiry. An ambiguous submission response stops the run. Fresh PoW timing, the number of stale proposals and the observed receipt delay will vary.
