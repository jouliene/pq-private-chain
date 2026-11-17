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

## Paired full Gate2 result

The predeclared eight96ordinary blocks +96separate funding completed under the
same proof profile. Actual full receipt SHA256
`8343cfd3ddb63520555a43e1b8b318a3ddb816c1454b6094f6c1e6ff96765964`;
`GATE2_FULL01.json` contains author read-only arithmetic replay, source/build/
profile/workload pins, all individual process costs and exact copy/byte counts.
No native/build/proof run or source change was made for this readback.

| Question | Gate1 observation | Full Gate2 observation |
|---|---|---|
| Ordinary block service |96 complete receive→verify→durable RETAIN20.837566s |Eight genuine96 blocks20.615336–21.047986s, mean20.781193s |
| Upload/service serialization |13.949979s PUT +20.837566s destination =34.787545s arithmetic, not sojourn |Six distinct, newly unadmitted ordinary body-transfer overlaps13.379003–13.442527s each;80.444821s total; archive connections2 |
| Offered queue |No finite offered-load schedule |768payments at fixed[0,0,T,2T,3T,4T,5T,6T],T30.27456s; last ACK287.618316s before fixed363.29472s |
| Backlog/restart |Failure/rollback, publication lostACK, retry/reopen controls |Pending peak4batch IDs/672,640,976B frame work on disk; credits2;159.457134s explicit credit backpressure; validator down90.824782s; fresh open and full current-tip retry add0proofs |
| Fixed-end obligations |Explicit RETAIN/pending0 |All8batches accepted, no future/pending/uploading/ready/validating work, credits0, missed offers0, late transitions0;75.676404s drain margin |
| Complete cryptographic work |96funding +96invalid attempts +96validordinary |96funding +768newordinary =864physical destination proof attempts/96source signatures; no new-body cached verdict |
| Durable state |All14tables equal except local catalog ID |All14tables equal; height9/1728leaves/1536NFs/864cores,fees1,825,416,864,liabilities0;864full bodies1,513,556,768B/pending0 |

There are21 complete archive RPCs:10PUT and11GET, including the priced full
current-tip retry GET. Producer→archive sent1,513,872,676B and received520B;
archive→validator sent1,682,007,932B and received572B. Each endpoint's independent
per-call arithmetic matches its peer. All13 role process incarnations exit0.
Two actual PID namespaces each deny5known producer/DB/proof/frame/blob files.
All40 offer-state transitions precede the cutoff. Postdeadline records contain
only stop/terminal events, no late payment ACK used to repair the drain.

The receiver's two native lifetimes cost67.819430self CPU seconds plus3.604015
already-waited helper CPU seconds. Direct sender processes cost5.121601CPU s;
archive costs11.572017CPU s and performs0payment proofs. bwrap wrappers together
cost0.005333CPU s; they are not the receiver. Native self RSS max407,936KiB,
waited helper max227,780KiB and sampled simultaneous role-tree max411,572KiB are
separate, not a sum. Linux native physical read_bytes total815,104B while logical
rchar is much larger: page cache was uncontrolled/warm, not cold-storage evidence.

**Controller/oracle cost is material and separate:**155.098410user +63.687373
system =218.785783CPU s; measured wall431.700683s. Its deltas start after source/
installation/build pin preflight and include preparation, monitoring/scheduling
and postdeadline SQL/identity checks; no per-phase CPU split exists. Its allowed
affinity is0..11, unlike roleCPUs0/1/2. Cumulative controller peak933,504KiB includes
earlier process history/preflight. Do not call this complete controller startup
cost, a validator RSS peak, or a whole experiment using only three CPUs. Final
receipt serialization follows the last samples. The source alone does not permit
charging all218.8CPU s to protocol service or dropping it from experiment cost.

Fresh genuine864-proof generation separately took6639.207363s/6619.042769CPU s,
with248,668KiB wait4 peak. It includes private bridge/local verification and is
not live wallet throughput or a sum of simultaneous process-tree RSS.

All producer output copies are now charged: source public bodies/DB/scans
3,048,188,982B +Parent public copies1,513,875,869B +Parent JSON/claim provenance
1,650,975,430B +supervisor2091B +prepared frames1,513,872,156B =7,726,914,528B
logical. Allocated7,744,724,992B leaves845,209,600B under the declared8GiB output
watchdog. Provenance is laboratory overhead, not protocol archive data. Gate1's
older producer-copy listing did not include/enforce Parent JSON/claim provenance
under the same combined watchdog; no retroactive complete-copy claim is made.
Reusable installation/vendor/build targets are outside this output-disk budget.

Archive final10objects occupy1,513,872,156B logical/1,513,926,656B allocated.
Destination final DB occupies1,523,658,752B logical/1,523,662,848B allocated;
sampled DB/journal peak1,524,398,760B logical/1,524,404,224B allocated. The explicit
2GiB RETAIN quota is local finite provisioning. Actual ordinary bodies average
1,751,265.75B: an analytic all-valid100M ordinary-payment year still implies
175.126575TB of raw bodies per retained copy, before metadata/replicas. No owner
traffic cap, pruned-node success or annual affordability approval follows.

The finite uncertainty from Gate1 was resolved by actual bounded overlap, drain,
backpressure and restart, without dropping proof validation or reducing payment
parameters. This establishes the declared finite local full-duplex/fanout1
retained-node slice. It does not establish stationary queue stability, WAN TCP,
PoW cost/propagation, arbitrary larger-state service, archive availability or
formal joint PQ/privacy assurance. Root owns that participation decision and
has provisionally retained CP03 under the explicit finite full-RETAIN validator
plus separate opaque archive research model, authorizing Gate3. Annual owner
budget acceptance remains separate; the global blockchain Goal remains ACTIVE.
