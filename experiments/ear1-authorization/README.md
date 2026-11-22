# Reproduce the EAR1 adaptive-authorization decision

From a clean checkout on Ubuntu 24.04 x86-64 with SSE4.1 and PCLMULQDQ, use the distribution CPython 3.12, NumPy 1.26.4, python3-dev, python3-psutil, gcc, libssl-dev, curl and xz-utils. The scratch path must be new. Both HTTPS inputs (the public EAR1 funding archive and x86-64 Node 24.22.1 for the existing receipt code) are SHA-256 pinned in the script.

~~~sh
PATH=/usr/bin:/bin bash experiments/ear1-authorization/reproduce.sh "/tmp/ear1-review-$(date +%s)-$$"
~~~

The command builds the local wide-field kernel, replays the published funded proof in a public process, compares the entire ordered round-width census, and regenerates all four evidence JSONs. The funded decoding step uses a separate, fresh private fixture and publishes only lengths, counts and verdicts. The compiler transport step uses deterministic public symbols. Its wire hash is reproducible; it exercises the commitments, prefix coins and static I/O table only. Neither probe produces a new EC01 payment. The complete EC01 resources are derived for the count-13 funded geometry. No capacity, mining or deployment run is part of this experiment.

To check only the arithmetic on a standard-library Python 3.12 installation, run `python3 -B experiments/ear1-authorization/loss.py` and `python3 -B experiments/ear1-authorization/alternative.py`. See the primary manuscript pin and extraction argument in [THEOREM.md](THEOREM.md), the compiler registration in [ALTERNATIVE.md](ALTERNATIVE.md), and the [architecture decision](DECISION.md).
