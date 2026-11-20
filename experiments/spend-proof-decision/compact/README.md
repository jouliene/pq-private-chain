# Can canonical multiproofs recover the fixed frame budget?

K384 changes the argument hash and query schedule. Its complete canonical proofs exceed the current per-frame limit. The qp-plonky2 1.5.5 compressed format derives positions from Fiat–Shamir, merges repeated Merkle paths and infers redundant fold values. The experiment uses that existing format on every complete proof. The compact KCP1/KCB1 research carriers keep both receipts per proof, all authorization bytes, the common context and original companion digests. Each offline decoder has only the compact bytes and registered local public verifier. It recovers exactly the original K3M1/K3L1 bytes, verifies the expanded proof, re-encodes canonically and reconstructs the original authorization preimage. A bare substitution of new bytes into an old signed swap would change that preimage. The codec measures an alternative to enlarging the devnet packet limit. It has no peer-facing deployment or general untrusted-input acceptance. [Codec](codec.rs) · [Complete transport comparison](compare.py) · [Upstream proof methods](https://github.com/Quantus-Network/qp-plonky2/blob/632f23ca07712bfa5bc8ed082bc05c41c5929dfb/plonky2/src/plonk/proof.rs)

From the repository root, with the pinned Qnero checkout and a fresh output directory, run the following after creating the candidate specimens. The candidate README documents the pinned compiler, verifier and wallet build. GNU time meters each short-lived process. The codec's decode timings include full proof checking and the canonical re-encoding check. The native public role measures the independent spend and signature verification in the ordinary and swap measurements.

~~~sh
p=experiments/spend-proof-decision
python3 -IB "$p/candidate/build_compact.py" "$work/compact-build" "$upstream" "$work/target"
RAYON_NUM_THREADS=2 python3 -IB "$p/compact/compare.py" "$work/compact-build/compact" "$public" "$work/compact-result"
~~~
