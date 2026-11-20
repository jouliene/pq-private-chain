# K384 matched author result

K384 verified the funded fixed-for-managed exchange, both independent final authorizations, and the ordinary post-restore transfer. The 495,975-byte ordinary envelope exceeds the live physical frame bound by 233,831 bytes. Each signed swap frame is 513,188 bytes, exceeding it by 251,044 bytes. A complete signed bundle is 1,026,389 bytes. Both registered proofs use degree 16,384, compared with 4,096 for their corresponding live configurations. The K384 profile is an executable comparison and cannot be activated within the existing frame capacity. [Complete measurements and public identities](evidence/MATCHED.json) · [Concrete assurance limits](BOUNDS.md)

| Artifact | K384 author bytes | Existing live framing bytes |
|---|---:|---:|
| Ordinary proof | 492,376 | 139,634 |
| Ordinary full transfer envelope | 495,975 | 143,233 |
| One swap leg, including both receipts | 495,993 | 143,251 |
| Signed swap physical frame (each) | 513,188 | 160,446 |
| Two-owner signed bundle | 1,026,389 | 320,905 |

A fresh author run exercised one ordinary proof and two separately constructed swap-leg proofs. The native prove intervals include the two real ciphertexts; setup is shown separately. Native CPU includes both worker threads and process peak resident sizes are in KiB.

| Operation | Setup wall s | Prove or sign wall s | Prove or sign CPU s | Peak KiB |
|---|---:|---:|---:|---:|
| Ordinary, managed 30 and independent native input | 2.417 | 5.304 | 10.131 | 1,837,020 |
| Alice's leg, mixed note with 15 fixed and 20 native | 2.445 | 5.193 | 9.909 | 1,837,008 |
| Bob's leg, mixed note with 80 managed and 18 native | 2.509 | 5.368 | 10.241 | 1,836,664 |
| Alice's final SLH signature | — | 0.092 | 0.092 | 3,236 |
| Bob's final SLH signature | — | 0.091 | 0.091 | 3,232 |

Across three public verification calls with the same ordinary packet, median native verification CPU was 8.42 ms. Native ordinary verifier setup took 2.590 s wall and 4.238 s CPU; process peak was 684,972 KiB. Three public pair validations each ran both full leg proofs and both signatures, with median summed native verification CPU 28.75 ms. The pair verifier setup took 2.666 s wall and 4.353 s CPU, peak 684,868 KiB. The independent public-only comparison uses separate processes and reports its own end-to-end measurements.

Separate original MNG1-funded identities started with a fixed cap of 70 and a managed issuer registration of 300. The genuine subsequent +40 mint and −10 holder burn left managed supply 330. Signed envelopes, old proof verification, and the original registry state transitions were exercised on fixture roots. Alice paid 7 fixed and received 30 managed. Bob paid 30 managed and received 7 fixed. Change was 17 native + 8 fixed and 18 native + 50 managed, respectively. Starting from independent backups, Alice's two-input K3M1 ordinary proof forwarded her exact 30 managed, Bob's MNG1 proof forwarded his exact 7 fixed, and the forward recipient's MNG1 proof consumed Alice's new 30 managed output. These are checked note openings and genuine proofs in an isolated inventory. The corresponding funded public commitments for swap slots zero are recorded in MATCHED.json. The full candidate cycle has no independent PoW admission, production activation, or new post-quantum security theorem.

An earlier successful circuit exercise used two fixed assets (7/11) and two real inputs per leg. It provided the first complete size observation only. The first attempt at the matched checker stopped after the fixed issuance because a registry helper used an incorrect method name. The corrected run used the existing deployed `SupplyRegistry.record_event` and completed the signed managed event sequence. [Exploratory record](evidence/FIRST.json) · [Fresh reproduction](README.md)
