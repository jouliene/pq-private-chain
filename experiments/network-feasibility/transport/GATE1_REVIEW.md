# Gate1 actual cost review and next discriminator

Actual full96 receipt: `.work/gate1-96/RESULT.json`, SHA256
`732f1c969b4e18f03f5a7d70ccbae17279c13147c5b99e1f5e100c081c89a098`.
`GATE1_96.json` retains the exact per-candidate stages, individual sender CPU,
all11 archive RPC byte records (including interrupted/crash rows), conservation
checks, directory bytes and native lifetime scope. SOURCE02 is unchanged.

## What ran

Separate loopback TCP processes used two nominal100Mbit/s application-byte paced
links, one40ms response latency per RPC, CPU0/1/2,4GiB address-space limits and
sampled tree/disk watchdogs. This is not WAN or cold-cache evidence. Real96credit
and96ordinary bodies passed complete destination verification and atomic commit.
A coherent corrupted final proof reached `Proof` after96 real attempts; all14 SQL
tables stayed unchanged. The valid followup committed; exact canonical retry,
archive publication-before-lostACK/reupload, namespace denial and fresh reopening
passed. Total physical attempts were288proof/96source-signature. Destination
all14 tables matched producer except the random local catalog ID.

| Actual scope | Wall seconds | CPU seconds | Memory scope |
|---|---:|---:|---|
| Valid ordinary96 producer PUT process |13.949979|0.917469|18,304KiB direct process peak |
| Ordinary96 destination complete command |20.837566|7.348455|Native lifetime peaks below cover entire campaign |
| Included destination receive/identity |14.462289|1.017865|Overlaps archive GET; do not add GET again |
| Included destination parse/API copy |0.824124|0.824068|Real full-frame/body copies |
| Included genuine admit/durable RETAIN |5.534562|5.489926|No source-signature work for ordinary2x2 |
| Funding96 destination complete command |25.194076|11.628090|Funding priced separately |
| All six sender transfer/control processes |56.815060 summed serial process wall|4.078312|Max18,328KiB; not sum of peaks |
| Two archive incarnations, all controls/GETs |14.503084 and128.392373 process lifetimes|11.961805 total|Max18,688KiB; opaque bytes,0proofs |
| Native validator whole lifecycle |85.923052 including oracle idle|24.898233 self +3.869699 waited helpers|405,336KiB self /227,760KiB helper separate maxima; sampled simultaneous tree463,940KiB |
| Fresh native reopen |1.206745|1.207688|64,880KiB native peak |

The measured topology has **one producer, one archive, one destination (fanout1)**.
Each declared producer→archive and archive→destination link has its own100Mbit/s
application budget with reverse request/ACK bytes counted. Archive GET overlaps
destination receive; the two are one transfer. This gives no free replica or
relay fanout: k destinations require k complete egress copies, and a single
shared100Mbit/s archive egress would share its budget across them. Current archive
source permits only one GET, so simultaneous k-way fanout is not implemented.

The ordinary producer PUT plus destination service is
13.949979421+20.837565988=**34.787545409s**, a serialized **stage-cost sum**.
It is not observed end-to-end sojourn or steady throughput: this campaign archived
all candidates before starting destination work. It exceeds the mean96-offer
interval30.27456s at100M/365days. The optimistic isolated-stage maximum20.837566s
is below that interval, but actual bounded overlap under the archive's shared
CPU/queues remains unmeasured. That is the next discriminating question.

Native absolute counters include startup/completed commands until sampling after
Ledger/provider drop; final receipt serialization/exit follows. bwrap wait4 is
wrapper-only (0.002926CPU for the first wrapper), never native cost. Inclusive
spans overlap their nested stages. Cumulative memory peaks are not summed;
sampling can miss short simultaneous peaks. Source generation separately took
1439.136s for192genuine proofs, including producer orchestration and local
validation; sender timing is not proof generation or live wallet throughput.

## Exact bytes and retention

| Actual link | Forward application bytes | Reverse application bytes |
|---|---:|---:|
| Producer → archive, all six calls incl interruption/crash/retry |673,856,896|208 |
| Archive → validator, all five GETs incl negative/retry |673,344,044|260 |

Every endpoint byte count matches its peer. The interrupted PUT received65,588B;
the crash-beforeACK row received168,607,800B and sent0, independently of its
unfinished cumulative counter. These failed/control bytes are included above.
TCP/IP headers and retransmissions are outside the application-byte model.
A normal ordinary PUT or GET alone transfers168,160,588B in both directions
combined: frame168,160,484 +52B request +52B ACK.

Destination keeps192 full bodies totaling336,754,720B, including separate funding;
ordinary96 bodies alone are168,153,728B. Required publication pending/unexported
are both0 because explicit local RETAIN prohibits eviction/export. Final DB is
340,254,720B logical (340,258,816 allocated); sampled DB/journal peak340,448,848B
logical (340,455,424 allocated). This local finite policy does not provide a
pruned-node model.

Archive final four objects total505,183,300B logical /505,204,736 allocated:
254,584B genesis +168,607,748B funding +168,160,484B invalid candidate
+168,160,484B ordinary. Its extra invalid candidate is charged laboratory control
storage, not accepted history. The prepared producer frames occupy the same
505,183,300B; original producer public output/DB/scans occupy682,051,742B logical,
and Parent public proof/statement/manifest copies separately occupy336,480,280B.
These copies are not collapsed into a fictitious single-copy disk cost.

At the measured ordinary body mean,100M payments imply about175.160TB/year of raw
bodies per retained copy, before metadata/replicas. The bounded storage success
does not imply ordinary-node affordability. Wallet scan/recovery, pruned archive
availability and permissionless issuance remain separate. A miner inherits
validation/relay obligations plus unimplemented PoW work; that missing work is
not zero. Archive storage performs no payment verification and its ACK is not
admission. No architecture-wide participation or annual capacity PASS is made.

**Gate1 finite functional path passes.** Root accepted actual receipts. Gate2
requires a newly declared source/profile and allocation; no larger workload or
pipeline implementation is authorized by this document.
