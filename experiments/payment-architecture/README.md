# Reproduce the payment architecture comparison

Start with Linux x86-64, 4 GiB or more available memory for concurrent wallets, several GiB of disk, Python 3.10+, Git, rustup, C build tools, bubblewrap with working unprivileged namespaces, and outbound HTTPS for pinned source and the Cargo lockfile. Use the commit identified in the [release](https://github.com/jouliene/pq-private-chain/releases/tag/payment-proof-architecture-2026-11-19). The public checkout supplies the complete experimental adaptation; upstream versions and digests are pinned.

~~~sh
git clone https://github.com/jouliene/pq-private-chain.git
cd pq-private-chain
git checkout --detach payment-proof-architecture-2026-11-19
rustup toolchain install 1.93.0 --profile minimal
lab=$(mktemp -d)
python3 -IB experiments/payment-architecture/reproduce.py "$lab/direct"
~~~

The command compiles upstream revision `f04c91307837c0231668383bec76ba98d89d2652` with locked dependencies, checks a newly derived verifier against the 1,481-byte registered verifier, prepares an isolated alternate-network deployment and runs both PoW experiments. Each runtime checks the locally built executable and the registered verifier. The 22-bit difficulty, nonce search, branch selection, rewards, fees, receipt generation and private wallet state follow the checked-in devnet. The staged network accepts only DLF1. The root command `./pqd start` runs the APV2 reference.

`$lab/direct/public`, `$lab/direct/PUBLIC-REPLAY.json` and `$lab/direct/busy-public` contain the ordinary and full-block public evidence. Each run creates new private wallet homes inside the chosen directory. Limit publication to the JSON measurements and public block bytes. The public captures and final clean run are linked from the release.

~~~sh
d=experiments/payment-architecture
python3 -IB "$d/direct/replay.py" "$lab/direct/network" "$lab/direct/public"
python3 -IB "$d/direct/busy.py" --replay "$lab/direct/network" "$lab/direct/busy-public"
python3 -IB "$d/direct/costs.py" "$lab/direct/public/RUN.json" "$lab/direct/PUBLIC-REPLAY.json"
python3 -IB "$d/budget.py"
~~~

For the compact lattice gate install a C compiler, the OpenSSL development package, and the CPU support listed in its report. It fetches and hashes the authors' pinned archive, invokes their prover three times and verifies the new public artifacts in separate processes. The shared-proof gate accepts a registered APV2 devnet runtime. The commands below prepare one. On a prepared installation use its existing runtime directory.

~~~sh
python3 -IB "$d/compact/probe.py"
python3 -IB - "$lab/apv2" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, str(Path("devnet").resolve()))
from runtime import prepare
prepare(Path(sys.argv[1]))
PY
python3 -IB "$d/shared/replay.py" --runtime "$lab/apv2" --certificate "$d/shared/evidence/certificate.bin"
python3 -IB "$d/shared/costs.py"
~~~

To regenerate the detached certificate, use the builder command in the [shared construction record](shared/RESULTS.md). The 8-bit proof of work in the alternate shared-core representation is deliberately small. Direct DLF1 tests and their public replays use ordinary 22-bit devnet work. [Costs, security and decision](DECISION.md) · [Independent review](review/REVIEW.md) · [Hybrid receipt assessment](review/RECEIVING.md)
