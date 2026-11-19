# APV2 traffic, storage and service costs

The author used four independent wallet processes. Every measured transfer spent two funded notes and created two encrypted receipts. Uploads are framed messages to a Unix-domain intake endpoint. The measured block relay is a separate framed local stream. Counts below include those application encodings. IP, TCP, TLS, consensus gossip, retransmission below the application and client polling are outside this transport.

## One complete block

| Payers | Standalone wallet uploads B | ACKs B | Final proof B | Receipts B | Packet B | Archive block B | One peer stream B | Archive B/payer |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 230,210 | 32 | 226,613 | 3,584 | 230,206 | 230,358 | 230,362 | 230,358 |
| 2 | 460,420 | 64 | 226,477 | 7,168 | 233,654 | 233,806 | 233,810 | 116,903 |
| 3 | 690,630 | 96 | 236,445 | 10,752 | 247,206 | 247,358 | 247,362 | 82,453 |
| 4 | 920,840 | 128 | 236,653 | 14,336 | 250,998 | 251,150 | 251,154 | 62,788 |

Each final packet adds 9 bytes to proof and receipts; each block adds 152 bytes, including its 132-byte header. An empty block takes 152 bytes to archive and 156 bytes to relay. Each submitted wallet proof has its own 4-byte frame. At widths 2–4 the producer sends the same framed wallet packets into the builder's local pipe and receives one packet plus a 4-byte frame. This intra-host copy contributes CPU and memory traffic separately from wallet ingress. Two, three and four separate singleton blocks use 460,716, 691,074 and 921,432 archive bytes. Their respective combined blocks use 233,806, 247,358 and 251,150 bytes. A direct singleton can confirm immediately at its next eligible opportunity without waiting for peers.

## Annual role model

The 100 million offers per 365 days average 3.171 offers/s. Every offer produces one fresh proof and reaches the intake with one 32-byte acknowledgement; 95% or 100% reach the selected history. The 5% case assumes losses after acknowledgement. 1 and 5 decimal TB per archive-year are comparison scenarios. The owner set no annual traffic limit. Missing submissions, transport fanout, reorg downloads and duplicate delivery change costs separately. The two researcher-selected mixes specify percentages of **nonempty blocks**, not of payments.

| Mix | Inclusion | Included M | Mean paid width | Archive TB | One framed relay edge TB | Days of 1 / 5 TB archive | Eight eligible blocks at uniform demand |
|---|---:|---:|---:|---:|---:|---:|---:|
| low | 95% | 95 | 1.21 | 18.1947 | 18.1953 | 20.1 / 100.3 | 1.607 s |
| low | 100% | 100 | 1.21 | 19.1523 | 19.1530 | 19.1 / 95.3 | 1.526 s |
| busy | 95% | 95 | 3.50 | 6.7267 | 6.7268 | 54.3 / 271.3 | 8.365 s |
| busy | 100% | 100 | 3.50 | 7.0807 | 7.0808 | 51.5 / 257.7 | 7.947 s |

The low mix is 85/10/4/1% at widths 1/2/3/4 with one empty block per paid block. The busy mix is 5/10/15/70% with one empty per nine paid blocks. Including the empty opportunities, one included payment represents 191,522.91 archive bytes in the low mix and 70,806.88 in the busy mix. At full inclusion, even four payments in every block and zero empty blocks would consume 6.279 TB/year. One archival copy also needs the initial 3,084-byte genesis and implementation storage. An extra fully relayed edge, a second archival replica and an archive returning a cold full history each add their respective full stream or body copy. A pruned validator still receives every selected block. At full inclusion one continuously relayed copy costs 4.859 Mbit/s for the low mix and 1.796 Mbit/s for the busy mix.

Each offered wallet uploads 230,210 B. Collectively this is 23.021 TB/year, or 5.840 Mbit/s continuously on one receiving edge, plus 0.0032 TB/year of acknowledgements in the opposite direction. The measured topology opens one successful intake edge; a policy forwarding every singleton to another independent endpoint adds a second copy. If 5 million offers each resend after a full upload with lost acknowledgement, the extra uploads alone add 1.15105 TB. The measured unavailable endpoint failed before any application bytes; the separate duplicate-delivery control retransmitted the full packet and received another ACK. Receipts are already present in all packet sizes.

A wallet can retry the same authorized bytes while their anchor stays eligible. If it expires, replacing the anchor requires a fresh wallet proof, refreshed commitment data and another submission. This implementation admits eight successive selected heights for each anchor. The table converts that discrete interval using uniform block spacing at the required mix and inclusion rate. A real stochastic chain has no corresponding deterministic elapsed-time bound. Deliberately orphaned authorizations and an authorization one block past expiry were rejected in the public trace.

## Storage and recovery

Each accepted payment adds two 32-byte nullifiers and two 32-byte commitments to durable admission data. Storing those values once gives 12.16/12.80 GB of new values at 95/100% inclusion. The implementation also retains header and ID (164 bytes/height), amounting to 25.75/27.11 GB per low year or 4.95/5.21 GB per busy year. SQL row encoding, duplicate unique indexes, height lookup, counts/fees and recent bodies/frontiers add to this lower bound. Deduplicating physical disk pages or compacting SQLite does not recreate historical ciphertexts.

Common receipt recovery scans two ordered 1,824-byte rows (32-byte commitment plus 1,792-byte ciphertext) and up to two 32-byte public spent nullifiers per included payment. A year at full inclusion gives 364.8 GB of receipt rows, 6.4 GB of nullifiers and 6.4 GB plus the genesis leaves for the commitment history. The implementation streams whole-record pages into the wallet, materializes them and rebuilds the full tree for the next spend. At 100M inclusions this baseline entails gigabytes for a year-end payer. A light wallet needing independent authentication must obtain source blocks to validate or receive a separately authenticated index; an untrusted server returning only filtered hits does not provide that guarantee. A pruned node with no surviving archive cannot serve older encrypted notes for a restored key.

## Live direct service

One sender created four payments in response to intents 12 s apart on a continuously advancing 2 s local block clock. The preferred endpoint was stopped. The direct endpoint received 920,840 B and returned 128 B of acknowledgements; 19 empty and four occupied blocks used 924,412 B on a single framed stream. The sender's cold setup cost 4.417 s wall / 7.118 CPU-s, with 591,648 KiB peak RSS. Warm payment preparation took 8.649–8.762 s wall and 16.806–17.055 CPU-s, with up to 1,089,724 KiB process-peak RSS. Intent-to-inclusion was 10.044–10.083 s, with 1.274–1.384 s after upload. The four inclusion heights were 5/6/6/6 blocks after their respective anchors. The last confirmation occurred at 46.044 s for an offered rate of 0.0833/s. The measured direct clock is slower than the average opportunity rate implied by either 100M/year mix.

## Measured author campaign

The first lone offer committed 0.241 s after intake, including the 0.200 s underfill grace. With all aggregation workers offline, the direct authorization committed in 0.036 s after intake; the restored wallet's direct authorization took 0.033 s. These measurements start **after** the wallet proof. Across 25 completed uploads including the duplicate, the endpoints received 5,755,250 B and returned 800 B. Three attempts failed before sending application data. The actual extension relay carried 2,869,364 B and the competing branch delivery another 230,518 B.

| Width | Builder cold wall / CPU s | Builder warm wall / CPU s | Builder peak KiB | Peer proof CPU ms | Producer state admission ms | Peer receive + validate ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | bypass | bypass | — | 11.94 | 16.37 | 17.39 |
| 2 | 4.07 / 6.54 | 8.53 / 16.55 | 1,106,660 | 10.90 | 19.63 | 15.79 |
| 3 | 8.41 / 13.36 | 17.18 / 33.42 | 2,105,896 | 11.90 | 23.38 | 17.01 |
| 4 | 8.44 / 13.43 | 17.19 / 33.35 | 2,155,104 | 25.59 | 22.68 | 33.04 |

Times are means by measured width. The two- and three-payer groups took 12.687 and 25.689 s from oldest intake through cold builder setup and inclusion. The builder's warm sample counts are 1/1/4 for 2/3/4, including genuine singleton verification inside every aggregation. The independently receiving node verified 7/1/1/4 final proofs at the four widths, including selected branch replacements. Contention and short samples affect means. A separate isolated verifier performed eight fresh checks per width on the same approved public history; median CPU was 10.16/10.16/10.79/11.11 ms, peak RSS 5,700 KiB. Cold verifier registration loading averaged 0.325 ms across the two author node processes. Process high-water RSS includes earlier work in that process.

Wallet cold setup averaged 4.360 s wall / 7.005 CPU-s across four new wallets and one restored wallet. Twenty-eight warm payments averaged 8.680 s wall / 16.876 CPU-s, ranging from 8.559 to 8.932 s wall with peak RSS 1,090,884 KiB. Distinct fee-paying users can prove independently. At 100M offers/year this implies 53.51 CPU-s/s distributed over the senders, or 27.52 simultaneously busy copies at the measured mean elapsed time and available hardware. Even the fastest observed 8.559 s proof exceeded the uniformly spaced eight-block interval in all four tabled scenarios (1.526–8.365 s), before any queue or confirmation delay. Parallel senders improve aggregate work throughput without shortening an individual authorization.

| Mix and inclusion | Aggregator CPU-s/s | Serial builder wall-s/s | Receiver verifier CPU-s/s | Queue intake verification CPU-s/s |
|---|---:|---:|---:|---:|
| Low, 95% / 100% | 8.28 / 8.71 | 4.26 / 4.49 | 0.030 / 0.031 | 0.036 / 0.038 |
| Busy, 95% / 100% | 25.83 / 27.19 | 13.31 / 14.01 | 0.018 / 0.019 | 0.036 / 0.038 |

Those are linear work estimates on this host: the selected builder's elapsed work exceeds one worker-year in every row. The public node checks a final block proof once; the producer also checks each chosen singleton before dispatch and repeats final verification at block admission. Invalid/expired queue entries, conflicts, database IO, hashing, peer transport, and initialization add work beyond the proof-only rates. A 10× ten-minute burst at the full-inclusion scenario would leave about 18,602/18,890 equivalent payments backlogged for one serial builder in the low/busy mixes, even with unlimited buffering and fixed service times. At these settings the modeled backlogs continue growing after arrivals return to baseline. The actual intake queue has a 64-entry limit.

The prepared busy test offered twelve *already-proved* payments in three groups of four at 26.677 s intervals (0.14994 payments/s; 4.73% of 100M/year demand). The groups committed 17.144–17.319 s after the oldest intake. All three met their local deadlines, the queue drained and the last group finished at 70.584 s. The first staged four-payer opportunity with a cold builder took 25.997 s from intake. The single worker's busy result and the 0.0833/s direct clock are finite hardware measurements; none demonstrate sustained 3.171/s or continuous wallet arrival and aggregation at that rate.

At selected height six, the seed-only restore required a 32-byte private backup. It obtained six unspent notes using 43,776 B of common receipt rows and 768 B of common spent nullifiers. The framed S exchange consumed 44,565 B into the wallet and an 8-byte count reply; scanning took 2.42 ms CPU. A full independent download at that point comprised the 3,084-byte genesis and 1,423,388 B of archived blocks. The subsequent local P request included 3,840 B of ordered commitments, costing 5,592 B into the wallet and 230,210 B out. Together with the public restore startup and exit, those transfers exactly account for 50,161 B in and 231,827 B out on the isolated actor's public pipe. This wallet had previously sent payments as well as received them; its recovered inventory can include change. Its synthetic genesis openings were absent after restore. In the separate incoming-only control the receiver had zero genesis notes, received two payments, restored its 32-byte seed, opened 0/1/1/2 notes when scanning empty/first/second/both histories and spent both received notes at height four. Those controls and the follow-up unspent scan used 28,993 B into the restored process and 231,859 B out.

On the independently advancing 2 s clock, four already-proved genesis submissions totaling 920,840 B entered a warm builder. Its 250,998-byte aggregate was ready after 17.421 s (33.76 CPU-s). At its next opportunity the prospective height was nine; all four anchors were stale. The producer rejected the package atomically. Publishing lone transactions or reproving against newer anchors would change both delay and billed data. Running builders in parallel can increase throughput across groups, but cannot shorten this measured single group's proof and confirmation path.

At the final selected height 20, both node databases kept 21 header rows, 140 commitments and 44 spent nullifiers. A fresh full public replay confirmed all 31 events in 0.328/0.325 s on archive/pruned nodes. The archive kept 2,387,924 B of complete bodies in 2,457,600 B of database file. The pruned node retained nine 152-byte empty blocks, their nine frontiers and all current admission indexes. It held 69,632 B of live SQLite pages in a 2,220,032-byte file with 2,150,400 B on the freelist; logically identical copy-compaction used 61,440 B. Compaction temporarily requires room for a separate copy. The unusual suffix of nine empty blocks makes this small retained-body measurement unsuitable as an annual growth rate.

The independent clean build and four freshly funded wallets reproduced all four exact packet sizes. Its 28 warm wallet operations averaged 8.578 s / 16.678 CPU-s (1,090,916 KiB peak). Warm builders at widths 2/3/4 averaged 8.454/17.121/16.989 s and 16.365/33.267/32.943 CPU-s. All three prepared four-payer groups met the independent run’s 0.15365 payments/s schedule and the last group completed at 69.051 s. The same calculator verified every serialized packet, block and recovery frame against the independent RESULT and TRACE. [Independent review](../review/REVIEW.md)

The byte and resource model reevaluates all main packet and block identities, validates actor framing, and reports individual opportunity and projection values in the [calculated results](COSTS.json). The public verifier calibration has its own [32 raw timed checks](VERIFY_COST.json). From the experiment directory, regenerate both with the approved deployment binary and local registry from the [reproduction instructions](../REPRODUCE.md).

```sh
python3 costs/roles.py evidence/main --replay evidence/PUBLIC_REPLAY.json \
  --storage evidence/STORAGE.json --direct evidence/direct/DIRECT.json --clock evidence/clock/CLOCK.json
python3 costs/verify_cost.py "$lab/crypto" "$lab/keys" evidence/main/packets "$exesha" "$profile"
```
