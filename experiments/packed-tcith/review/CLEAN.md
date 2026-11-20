# Independent public reproduction

I cloned `https://github.com/jouliene/pq-private-chain.git` over anonymous HTTPS into an empty directory. The advertised `HEAD` and `refs/heads/main` both named `f198a4dce12ac27d1d6215e612fa68825d0cd694`. I detached at that revision and verified that it descends from `d92de79fe1fce97a33d88f706996e6cdd8ec188f`. Git used an empty home, no system or user configuration, disabled credential helpers and prompts, HTTPS-only transport and no alternate object store.

## Inputs and commands

I downloaded the Poseidon crate and the earlier funded public archive from their published URLs. The crate SHA-256 was `5872607e25ea4ee5fb37e64bf1462168e1a36a4e719cdc8a105533c708253918`, the extracted constants file was `54604af022354364c45fbdde106be3f223775992d6fa5685e77c75e66fd970f6`, and the archive was `06c6e392a7896aa8670c365e3895e3d673f676e75919b143be36c823851d4673`. All 25 archive manifest entries matched. For the four private assignments I used my own previously mined funding home and previously rebuilt capture binary, independent of the author's home. Each worker reconstructed its assigned wallet and generated a fresh released proof. [Input URLs and private fixture setup](../encoding/README.md)

These are the commands I ran from the detached repository. The public output of each deterministic JSON producer was compared byte-for-byte with the adjacent checked-in report. The component comparison accepted variable timings and required the exact public bytes and both rejection verdicts.

```sh
d=experiments/packed-tcith
for f in model/results model/calibrate model/certify review/audit resources/network; do
    python3 -B "$d/$f.py"
done
python3 -B "$d/model/miniature.py"
python3 -B experiments/amplified-spend/traffic.py "$public_archive"
python3 -IB "$d/encoding/encoding.py" "$constants"
python3 -IB "$d/encoding/check.py" "$constants" --events "$public"
python3 -IB "$d/encoding/funded.py" "$funding_home" "$capture" "$constants"
python3 -B "$d/resources/measure.py" --check
```

## Funded paths and resource decisions

The historical PoW replay independently rebuilt 12 blocks and the common tip `000002199e08d8eed9254dc699686679ddf074a1f053e25696db67d652bdc3b5`. All historical roots and four ordered public vectors (31, 34, 34, 31 words) matched. Each of four one-seed workers verified a new MNG1 or SLG1 proof with the existing verifier, compared all full assignments and packed maps in both encodings at width 101, and rejected a changed receipt, coherent port substitution and nonzero padding. The fourth recovered the selected historical 8-unit receipt from backup and used it as its sole input to a payment of 5 with fee 3. The public-only synthetic suite included ten semantic negative controls per profile. The separate 1,712-byte miniature accepted the genuine transcript and rejected all four alterations.

The degree-seven model gives 237,945 complete ordinary bytes and 259,964 bytes for each signed leg at the shared geometry. Ordinary fixed fields occupy 3,841 bytes. Retaining the live six-byte outer MSP1 envelope would raise that modeled ordinary figure to 237,951. The live signed-frame parity target leaves 139,386 proof bytes. I separately enumerated widths, opened-party counts and powers of two using an optimistic integer bound and applied the independent exact binomial and bit-reversal-tree calculator to every survivor. Fourteen tuples survived the inexpensive bound through height 40, and none met that target. At height 41, `s=65, ℓ=8` gives 137,776 proof bytes, 158,836 framed bytes, 304 worst-case sibling hashes and 19,668,063,997,657,088 raw field bytes in one commitment. At height 16, `s=140, ℓ=45`, removing the two path bodies and terminal links leaves 149 witness columns and 207,408 proof bytes. This leaves 33,676 bytes for both replacement paths and their binding; this arithmetic gives no construction of those replacements. [Independent pricing](audit.py) · [Exhaustive certificate](../model/CERTIFICATE.json)

I also regenerated the live traffic baseline from the downloaded archive. At 100 million operations with 10% swaps, the one-copy packed archive projects to 16,106,435,000,000 B for the released baseline, 26,620,875,000,000 B for the modeled direct degree-seven worst-case geometry at height 20, and 36,058,715,000,000 B for the over-cap height-16 geometry. [Network assumptions and totals](../resources/NETWORK.json)

## Full-size commitment and degree-check component

The native prover processed 1,048,576 leaves of 744 field words each (6,241,124,352 B). The 206,672-byte component was byte-identical under SHA-256 `ac94fc61e0e9f3041edd474d68258351391ec53bb297d03e36c4c810f988286a`. The native and Python verifiers checked all 825 masked-degree openings and the 371-hash frontier and both rejected independently modified shares and frontier data.

| Process | Wall (s) | User CPU (s) | System CPU (s) | Peak RSS (KiB) |
|---|---:|---:|---:|---:|
| Component prover | 117.14 | 117.07 | 0.06 | 173,624 |
| Native verifier process, five warm checks | 0.12 | 0.11 | 0.00 | 8,064 |
| Python verifier process, one check | 0.12 | 0.11 | 0.00 | 17,812 |

Warm native wall times in milliseconds were 19.371, 19.328, 19.387, 19.325, 19.581 (median 19.371). The share-table and Merkle internal timer read 116.845 seconds. The host used Linux-6.8.0-149-generic-x86_64-with-glibc2.39, 13.3.0, OpenSSL 3.0.13 and Python 3.12.3. These measurements cover synthetic complete-size commitments and public degree opening verification only. TCitH full funded proof generation, quantum extraction and multi-user receipt privacy remain unverified. The four funded proof calls above ran the released protocol.

The final detached revision was clean. Public and four-role summaries had SHA-256 `799a167954125d98d0f8ec12775cc3d121a345dc34a0e9759749d0e7025234c9` and `352cf8106fccbc8a74a540ba69a32a82c43323d10e57e4eeea3bcfcc587a3bdd` respectively.
