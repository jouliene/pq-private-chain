# Funded post-quantum binding assurance

## Decision

MNG3/SLG3 closes the concrete variable-depth membership gap for new debits,
provided the exact proof yields an authorized witness and the four-word funded
hash is binding for every note, owner, nullifier, header and tree use. The
current evidence does not supply those end-to-end premises or a 128-bit
adaptive quantum bound. It therefore supports a conditional research-devnet
decision, not launch qualification.

The security questions are separated in [GAMES.md](GAMES.md): unauthorized
spend, cross-version double spend and accepted inflation. [CODE_MAP.md](CODE_MAP.md)
maps each premise to the producer, verifier, candidate-height dispatch and
atomic state transition. [WIDER_PROFILE.md](WIDER_PROFILE.md) prices the
smallest coherent wider alternative and its migration.

The deterministic ideal-function calculator shows why one number is
insufficient. Under the researcher-defined 20-year, 100% inclusion, 90/10
ordinary/swap output scenario, 4.4 billion usable targets reduce the
four-word ideal quantum target-search exponent to about 111.98 bits. The
four-word arbitrary-collision benchmark is about 85.33 query bits regardless
of that lifetime count. Seven Goldilocks words are the first whole-limb width
strictly above a 128-bit ideal arbitrary-collision exponent; five suffice only
for the checked target-search scenarios. This arithmetic does **not** make
seven limbs an unconditional monetary-security minimum: which hash game is
necessary, and how it composes with knowledge soundness and state admission,
must first be proved for Games US/XV/IN. These are ideal generic benchmarks,
not Poseidon2 or whole-payment security claims.

## Query probability, memory and time model

For the 4.4-billion-target scenario, the explicit ideal-model comparison is:

| Profile | One-target Grover scale | `T`-target Grover/Boyer scale | BHT collision query/time | Raw `T` table | BHT list lower-level bytes | Serial ideal-oracle years at `10^12` q/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 limbs | 128.00 bits | 111.98 bits | 85.33 bits | 140.8 GB | `1.5597e27` B | target `1.63e14`; collision `1.54e6` |
| 7 limbs | 224.00 bits | 207.98 bits | 149.33 bits | 246.4 GB | `5.0350e46` B | target `1.29e43`; collision `2.85e25` |

The probability rows in `RESULTS.json` evaluate
`min(1, (2q+1)^2 T / |range|)`, the standard ideal Grover success envelope,
at `q = 2^64, 2^96, 2^112, 2^128`. The same expression is labelled as a
small-angle estimate only while it is at most `0.01`; after that the output
reports only the capped bound, not an oscillatory exact Grover probability.
For example, four limbs and 4.4 billion targets give bounds about `5.17e-29`
at `2^64`, `9.54e-10` at `2^96`, and the envelope is already saturated at
`2^112`. Seven limbs and the same targets give about `2.80e-48` even at
`2^128`. The single-target rows are separate.

The multi-target exponent assumes a coherent, unit-cost membership oracle over
every target, equivalently an ideal qRAM-like table. The raw table byte counts
exclude load time, address logic, reversible comparison, error correction and
fault tolerance. Original BHT uses a sampled list of roughly
`|range|^(1/3)` outputs plus Grover search, hence both query/time exponent and
at-least-list memory are reported. The low-memory row retains a list
`M=|range|^s`, costing `max(M, sqrt(|range|/M))` ideal queries/time; it is the
parameterized original construction, not a claim that a physical low-memory
machine reaches that rate. The `10^12` queries/s conversion is an intentionally
optimistic researcher illustration. One coherent Poseidon2/target-membership
query is not one CPU instruction, so these years are not runtime forecasts.

As a separate no-qRAM ideal screen, Chailloux, Naya-Plasencia and
Schrottenloher (CNS) give soft-`O(2^(2n/5))` collision query/time on one
processor, `O(n)` quantum memory and soft-`O(2^(n/5))` classical memory.
Substituting `n = log2(p^k)` gives about `2^102.4` query/time, a nominal linear
256-qubit scale (with an unspecified constant) and `2^51.2` classical-memory
exponent for four limbs; seven limbs give `2^179.2`, nominal 448-qubit scale
and `2^89.6`. These are inferred ideal random-function resource exponents,
not a circuit, hardware estimate, Poseidon2 attack or monetary reduction.

Finally, `R` adaptive attempts with conditional per-attempt failure at most
`2^-128` have union bound `R*2^-128`: 2 billion attempts leave about 97.10
negative-log2 bits, and 4.4 billion leave about 95.97. This statement requires
the bound to hold after every prior transcript; it is not derived from the
generic query exponents and assumes no independence.

N7P2 is sufficient as the implemented seven-word comparator, not as a funded
successor. Selecting a wide profile while preserving existing money requires a
new atomic C-to-wide bridge and a backup-only successor spend. The minimal
experiment is specified in [WIDER_PROFILE.md](WIDER_PROFILE.md). The corrected
two-proof light gate, version schedule, artifact retention and recovery
criteria are in [migration/DESIGN.md](migration/DESIGN.md); the creator-packet
nullifier mistake stopped before proving is preserved in
[migration/DIAGNOSIS.md](migration/DIAGNOSIS.md).

## Reproduce

Run from the checkout root:

```sh
python3 -IB experiments/funded-pq-assurance/binding/lifetime_security.py \
  --check experiments/funded-pq-assurance/binding/RESULTS.json
python3 -IB -m unittest discover \
  -s experiments/funded-pq-assurance/binding \
  -p 'test_*.py'
python3 -IB -m unittest discover \
  -s experiments/funded-pq-assurance/binding/migration \
  -p 'test_*.py'
```

To inspect a fresh result without changing the repository:

```sh
python3 -IB experiments/funded-pq-assurance/binding/lifetime_security.py
```

The owner input is only 100 million **offered** payments/year. Twenty years,
acceptance fractions, transaction mix, output multiplicity, zero reward
targets and the assumption that every occurrence is a usable attack target are
explicit researcher scenarios in the JSON. They are not traffic limits or
owner requirements.

## Primary sources

- Boyer, Brassard, Hoyer and Tapp, *Tight bounds on quantum searching*,
  [arXiv:quant-ph/9605034](https://arxiv.org/abs/quant-ph/9605034).
- Brassard, Hoyer and Tapp, *Quantum Algorithm for the Collision Problem*,
  [arXiv:quant-ph/9705002](https://arxiv.org/abs/quant-ph/9705002). The BHT
  sampled-list size and its parameterized list/Grover trade-off are the source
  for the reported original and conservative low-memory rows.
- Chailloux, Naya-Plasencia and Schrottenloher, *An Efficient Quantum
  Collision Search Algorithm and Implications on Symmetric Cryptography*,
  [IACR ePrint 2017/847](https://eprint.iacr.org/2017/847), for the separate
  polynomial-quantum-memory/no-qRAM collision screen.
- Grassi et al., *Poseidon2*,
  [IACR ePrint 2023/323](https://eprint.iacr.org/2023/323).
- Don et al., *Security of the Fiat-Shamir Transformation in the Quantum
  Random-Oracle Model*,
  [IACR ePrint 2020/282](https://eprint.iacr.org/2020/282). This is a general
  transformation theorem, not an instantiation proof for the registered
  payment transcript.
- The pinned Qnero implementation at
  [`f04c91307837c0231668383bec76ba98d89d2652`](https://github.com/DigitalGuards/qnero/tree/f04c91307837c0231668383bec76ba98d89d2652)
  and the checked-in source/manifests linked in [CODE_MAP.md](CODE_MAP.md).
