# Funded C proof assurance

This directory maps the registered MNG3/SLG3 proof transcript to the
project-declared `qp-plonky2` 1.5.5 pin and calculates one proof-only stronger
profile over the same arithmetic relations. The calculator checks committed
keys and selected project sources; it does not authenticate the crate bodies
or their VCS metadata. It does not register or activate a new verifier.

From the repository root:

```sh
python3 -IB experiments/funded-pq-assurance/proof/calculate.py \
  > /tmp/funded-pq-proof-parameters.json
cmp /tmp/funded-pq-proof-parameters.json \
  experiments/funded-pq-assurance/proof/PARAMETERS.json
python3 -IB experiments/funded-pq-assurance/proof/check.py
```

`PARAMETERS.json` reproduces both registered verifier hashes, the exact C proof
sizes, blinding fixed point, FRI geometry and conditional numerical screens. It
also sizes `S64`: three PLONK repetitions and 64 FRI queries with the same
MNG3/SLG3 relation, field, rate, cap, folds strategy and Poseidon transcript.
S64 is calculated, not built or benchmarked. Its conditional terms are not a
soundness or post-quantum knowledge theorem.

The analysis and exact claim boundary are in [ASSURANCE.md](ASSURANCE.md).
