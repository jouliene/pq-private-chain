# Independent public reproduction

Both published commands exited 0 at `1237ed898eda343c10d3518ae588ac46e84c607b`. I cloned the public HTTPS origin into an empty directory with the credential helper, terminal prompt and system/global Git configuration disabled. The clone used no object alternates. The tested commit descended from `7e8a687`; public `main` and release tag `snapshot-bootstrap-c-v1` both resolved to it at the time of the test. Each command used a new runtime directory and downloaded its default inputs. [Tested source](https://github.com/jouliene/pq-private-chain/tree/1237ed898eda343c10d3518ae588ac46e84c607b/experiments/snapshot-bootstrap) · [Release](https://github.com/jouliene/pq-private-chain/releases/tag/snapshot-bootstrap-c-v1)

```sh
bash experiments/snapshot-bootstrap/reproduce.sh "$(mktemp -d)/run"
bash experiments/snapshot-bootstrap/public-fixture.sh "$(mktemp -d)/public"
```

## Measured startup at H39

| Endpoint | Elapsed | Requests | Replies | Total application traffic | Peak allocated node storage |
|---|---:|---:|---:|---:|---:|
| Genesis replay, fully verified | 13.029 s | 3,783 B | 3,711,422 B | 3,715,205 B | 4,173,824 B |
| Snapshot, provisional | 3.404 s | 3,934 B | 3,749,093 B | 3,753,027 B | 434,176 B |
| Snapshot, fully verified, cumulative | 15.418 s | 7,529 B | 7,277,078 B | 7,284,607 B | 8,491,008 B |

Each path retrieved the same 3,708,923 B of original blocks before first use. The provisional node checked their work and the separately registered 37,586 B checkpoint. Its source operator supplied a 460 B registration outside the measured channel. The provisional node downloaded 3,525,612 B of original blocks again for full verification. Both fully verified stores occupied 4,083,712 allocated bytes at completion. Frame counts and byte totals matched the author run at all three endpoints. Timings include cold process startup. The ordinary path ran first on the same host with a shared OS cache. Disk peaks are sampled in the node directory and include temporary replay files and SQLite journals. [Independent measurements](observations.json) · [Author measurements](../MEASURED.json)

## Wallet origins and branch selection

My fresh H37 state had SHA-256 `84fde87cfcdcbdfd029a02a6b8b902418b4aa028ed30bff8c5cbe7fcc3e43ca7`. With the funded H36 receipt missing, the restored wallet returned an incomplete result and withheld its balance and submission. The incomplete attempt received 80,121 B of history replies. After the authentic record arrived, the same wallet completed its scan with another 11,759 B and identified one 17-native note. It spent 11, paid 3 and retained 3. When a heavier branch diverged after H36, both validators and their restored wallets observed balances of 17 and 0. The new proof spent the old note on the winning branch, restoring balances of 3 and 11. These amounts are disclosures from the test wallets. The public frames independently show one shared nullifier, anchors at H38 and H40, and a single selected fee of 3.

The read-only checker reconstructed every receipt from its originating physical frame and checked the block work, original reward record, counted public transitions and registry revisions. It compared 44 compact records, 44 recipient ciphertexts and 44 reward origins in each fixture. Both final H41 databases agreed on 4,100 native subsidy units, 57 cumulative fees, 83 ordered outputs, 42 spent identifiers and seven registry events. Fixed asset supplies were 13 and 80. Managed supplies were 15 and 97. Corrupt state, work or receipt data failed their respective checks. A gap in shared original bodies left the live node provisional. A separately registered conflicting history commitment led to quarantine that survived restart. [Checker](check.py) · [Independent branch and control observations](observations.json)

The separate fixed capture contained 92 allowlisted members in 3,948,506 B. Its downloaded SHA-256 was `c20e7c5d6985d6f0f81683de1720bce5eb45820a35d45e5721da959a01c2e3ed`. The checkout registration matched its H37 state. With the losing H37 original withheld, the provisional node adopted a heavier branch after replay from genesis through H41. The fixed winning tip and the independently funded winning tip were different. Each matched its own genesis-only reference. [Registered fixture](../FIXTURE.json)

The result supports earlier use under the operator's checkpoint assumption. At this sample size full corroboration took longer and transferred more bytes than genesis replay. Separate validating processes on one loopback host exercise the data paths. Operator independence, production availability and population-wide performance remain open.
