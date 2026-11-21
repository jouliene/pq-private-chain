# Independent public reproduction

A non-author cloned the public HTTPS repository into an empty directory with
credential prompts, system and global Git configuration, the SSH agent and
local Git object sources disabled. The first public `origin/main` resolved to
`d761ee1e70fb585b90757da809c3a8abcfa3d5c8`. The ancestry check succeeded.
The detached checkout contained no object alternates and its tracked files
remained clean. [Tested revision](https://github.com/jouliene/pq-private-chain/commit/d761ee1e70fb585b90757da809c3a8abcfa3d5c8)

From that checkout, `bash experiments/archive-recovery/reproduce.sh NEW_PRIVATE_DIRECTORY`
built the registered A/B roles in a fresh Cargo home, funded previously unused
wallets and exited successfully in 498.01 seconds. The genesis and protocol
network matched the published experiment. The two initial A/B funding
transactions, both restored-wallet spends and both independently mined branches
had different identities from the author's. [Measured public results](FRESH.json)

| Observation | Fresh result |
| --- | --- |
| Both archives refuse H12 | The home retained the verified H11 prefix. The wallet returned incomplete and its attempted payment submitted nothing. |
| Only archive 2 restores H12 | The home requested the 13 remaining H12–24 bodies. Seven fresh wallets on each of the pruned and full endpoints requested the same common history. |
| A/B backup recovery | The 32-byte backup recovered 20 native and 12 managed units from A, and 14 native and 16 managed units from B. The H24 common wallet payload was 45,188 bytes. |
| First payment | The recipient observed 28 native and 25 managed units from the H25 transaction. H26 confirmed it. The losing branch also held a seven-unit managed mint. |
| Restart and competing work | After reopening, the H26 home selected a heavier H28 branch with a common ancestor at H14. It fetched 28 original bodies totaling 1,465,801 bytes. The earlier payment and mint disappeared, restoring the two original inputs. |
| Replacement payment | The winning B packet consumed those same two nullifiers at H29. H30 confirmed it. The restored sender had 3 native and 3 managed units left. |
| Public monetary replay | Across 42 original blocks, the reader checked 7 MNG1 proofs, 3 MNG2 proofs, 2 SLG2 proofs and 4 distinct issuer/swap signatures. The selected history had 3,000 issued native units, 80 fixed units, 100 managed units, 27 cumulative fees and 20 spent identifiers. |
| Final physical state | The home directory held 442,368 bytes, with three retained full bodies totaling 183,525 bytes. All 30 common receipt records matched full replay. Eleven old proof samples were absent from the home files. |
| Interrupted recovery and equal work | The separate released-graph check resumed the prefix from H5 and a competing branch from H10. It chose the lower H19 tip ID at equal work and refused the damaged local state. |

The same clean deployment and independently rebuilt reference helpers verified
the author's release bundle, SHA-256
`bd71e2bdad0f3144c562df8f70d2c31e2a8f3dcb6f94e048be0b5c7da459510f`.
Its regenerated JSON compared byte-for-byte equal to the committed
`experiments/archive-recovery/PUBLIC.json`. The fresh fixture's projected
100M-operation scenario reproduced the committed calculation. Its measured
wallet proof times were 9.604 and 9.538 seconds. Housing both archives on one
machine exercises the logical roles and wire traffic. Independent operators,
WAN availability and production privacy require separate evidence.
[Public reproduction commands](../README.md)

The fresh allowlisted bundle contains 42 public block bodies and two files
of disclosed fixture observations. The release checksum for this separate
bundle is recorded alongside the review. [Independent bundle checksum](INDEPENDENT.sha256)
