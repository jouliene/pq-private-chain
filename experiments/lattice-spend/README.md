# Reproduce the lattice spend architecture decision

The [decision](DECISION.md) covers two lattice proof routes and an executable test of the fixed-arity parent. Funding and consensus continue to use the released MNG1/SLG1 registrations.

From the repository root on Linux with Bash, Python 3, NumPy/SciPy, curl, tar and sha256sum, run:

~~~sh
bash experiments/lattice-spend/reproduce.sh
~~~

This fetches the checksum-pinned Poseidon2 constants and public funded PoW archive, regenerates the literal SIS costs, checks the complete Goldilocks conversion census, recomputes candidate frames and memory bounds, and checks the new root and common nullifiers on the selected branch, including the funded swap. It runs neither AVX-512 code nor a private wallet. [Code and funding pins](../packed-tcith/encoding/README.md) · [SIS review](sis/README.md) · [Fixed-arity root experiment](pivot/README.md)

To rebuild LaZer and independently check the membership evidence from public bytes, use GCC 13.2+, make, CMake, Python 3.12 development tools/pip, GMP/MPFR development files and the CPU requirements in the [toolkit instructions](lazer/README.md). The last optional argument in the parameter probe and the optional `--sde` argument to the benchmark select the pinned Intel emulator on processors lacking the Tiger Lake instructions.

~~~sh
scratch=$(mktemp -d)
bash experiments/lattice-spend/lazer/build.sh "$scratch/build"
python3 -IB experiments/lattice-spend/lazer/run.py "$scratch/build" "$scratch/public" --replay experiments/lattice-spend/lazer/public --positive-only
bash experiments/lattice-spend/funded/price.sh "$scratch/build" | cmp - experiments/lattice-spend/funded/PLAN.txt
python3 -IB experiments/lattice-spend/lazer/run.py "$scratch/build" "$scratch/fresh"
~~~

The last command makes fresh membership proofs, verifies them in separate processes and tests changed roots and changed proof coefficients. Those proofs are synthetic public membership fixtures. Sizes may vary with private proving randomness. Scripts use a verifier-selected, versioned profile; local pins, a complete public root and the proof supply every input to the public verification role. The published non-native parameter probe only selects a shape. To run the full integer oracle on an actual transfer, both independently controlled swap legs and a seed-restored onward spend, follow the [funded role instructions](funded/README.md#reproduction).

Third-party works are referenced at their pinned public sources. The small unified diff is a research change to the external LaBRADOR implementation. The pinned LaZer frontend is distributed under the MIT license and the modified backend under Apache-2.0. [Frontend license](https://github.com/lazer-crypto/lazer/blob/b958e247a2fdb9593b3c25c9603c6c5305c19420/LICENSE) · [Backend license](https://github.com/lazer-crypto/labrador/blob/c1ae0e612d5accd9e7d9d1c264951c1afe949c83/LICENSE)

The two binary fixtures contain framed public messages for synthetic membership statements. Private wallet workspaces stay with their respective owners.
