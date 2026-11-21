# Cost of funded membership

## Reproduction

After the funded-membership walkthrough, use the installed public deployment
and its public capture. The measurement process creates and discards its own
SQLite database. The three arguments identify the installation, directory of
public block bodies and selected block ID.

```sh
capture="$run_home/public/membership"
tip=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tips"]["final"]["tip"])' "$capture/RUN.json")
python3 -IB experiments/funded-membership/costs.py "$run_home/deployment" \
  "$capture/blocks" "$tip" --wallet-report "$capture/RUN.json" > "$result_directory/costs.json"
```

The wallet timings in the capture come from the actual clients that built the
transactions. The public measurement replays the named ancestry from empty
genesis. It checks each singleton or indivisible swap at its real candidate
height. Proof and signature verification use the installation's approved native
roles. The verifier measures a first call followed by three more checks of each
same public operation. Every warm check reruns the verifier and any issuer or
joint approval checks. The first call may share a role that a previous block
already started.

Each selected block is then separately admitted once through `Chain.accept`,
including PoW, historical anchor matching, signatures, spentness, issuance,
tree append, fee/reward accounting, SQLite writes and the synchronous commit.
Each durable sample must execute the expected number of fresh native checks.
For an issuer-signed operation this is two. For the swap it is four. Timing
excludes file reads that load the block into the controller and excludes a
miner searching for the nonce. The public replay needs no spending key.

Wall time includes subprocess and SQLite latency. CPU measurements separately
cover the controller and native public verification. The unmetered native
hash service is included in wall time. Reported verifier RSS is the role's
process-lifetime high-water mark. SQLite file growth measures logical database
length after each real commit and can use pages previously reserved. It does
not measure physical drive writes. Proving and wallet authorization times
are local to each participant. An authorization command includes its wallet
policy and receipt checks as well as signing.

## Wire sizes

The two registrations add one public field word per proof. A C ordinary transfer
is 182,863 bytes, eight more than B. The complete signed C swap is 400,165 bytes,
sixteen more than B. The signed managed C supply envelope is 200,023 bytes.
For a workload of 100 million included ordinary transfers the eight extra
bytes are 0.8 GB per complete copy, before framing or replication. The owner's
100 million offered payments/year is a separate workload input. [Decoded
registrations](PROFILE.json)

## Author measurement on the funded branches

The author used Linux 6.8.0-151-generic, Python 3.12.3 and an i7-8700K
with 12 logical CPUs visible. Each native role was configured for two Rayon
threads. The public replay selected H33 with 3,300 native units issued, 51
fees, 71 appended notes and 38 published nullifiers. Its 4,096-byte-page
SQLite file ended at 3,674,112 bytes. It used DELETE journaling and FULL
synchronous commits.

The released B comparison and the new C payment each consumed the original
two positive notes and paid 28 native plus 25 managed units, with a 3-native
fee. Each used a freshly constructed proof. These individual timings lack
the repetitions needed to separate a small parameter-change effect from
ordinary variation.

| Wallet role | Measured proving wall, s | Native CPU, core-s | Native peak RSS, KiB |
|---|---:|---:|---:|
| B transfer of both recovered notes | 9.804 | 19.01 | 886,648 |
| C transfer of both recovered notes | 9.761 | 18.90 | 886,988 |
| C onward transfer | 9.721 | 18.85 | 886,984 |
| C swap, first participant | 9.911 | 19.22 | 887,024 |
| C swap, second participant | 9.934 | 19.24 | 887,232 |
| C managed mint | 9.985 | 19.18 | 887,112 |
| C managed registration | 9.895 | 18.98 | 887,244 |

The two C swap offer commands took 12.949 and 13.002 s. Their separate
authorization commands took another 3.093 and 3.028 s. Each participant
released a 182,881-byte offer and a 17,088-byte authorization. Those
commands ran sequentially in this walkthrough. The H25 C payment's complete
wallet command, including submission, took 12.766 s.

| Selected operation | Height | Complete submission, B | Warm public verification median, ms | Native verification CPU median, ms | Full durable block, ms |
|---|---:|---:|---:|---:|---:|
| A transfer to offline address | 12 | 143,233 | 12.276 | 11.460 | 19.473 |
| B transfer to same address | 13 | 182,855 | 8.810 | 8.117 | 18.882 |
| B signed swap | 14 | 400,149 | 30.805 | 27.814 | 39.509 |
| C two-input restored transfer | 25 | 182,863 | 8.826 | 8.131 | 19.309 |
| C onward transfer | 26 | 182,863 | 8.778 | 8.132 | 14.567 |
| C signed swap | 27 | 400,165 | 29.707 | 26.840 | 47.215 |
| C issuer-signed mint | 28 | 200,023 | 14.320 | 13.209 | 21.357 |
| C fixed issue | 29 | 182,863 | 8.753 | 8.091 | 14.997 |
| C issuer-signed registration | 30 | 200,023 | 14.392 | 13.226 | 20.922 |
| C authorized burn | 32 | 182,863 | 8.780 | 8.103 | 14.448 |
| C transfer at depth four | 33 | 182,863 | 8.766 | 8.101 | 14.905 |

The first C ordinary verification, including startup of its role, took
2.691 s. The first C signed pair took 2.697 s including its separate swap
role startup. The C verifier roles each recorded a 351,576 KiB high-water
RSS. The public Python replay controller peaked at 31,656 KiB. The warm
figures are per-transaction samples from registered roles that remain alive.
The durable figures are single observations for different blocks, with all
checks repeated and committed. The decoded statement sizes are deterministic.
The timing observations establish neither sustained admission capacity nor a
statistical throughput improvement from the change. [C registration sizes](PROFILE.json)
