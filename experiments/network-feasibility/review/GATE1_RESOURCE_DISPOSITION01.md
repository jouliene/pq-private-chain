# Independent Gate1 resource disposition

The actual96-body result supports proceeding to a finite queue experiment under
an explicit provisioned-role model. It does not establish that ordinary users
can operate an annual full-history node. The complete body obligation remains
approximately175TB/year per copy at100M offered ordinary payments; additional
archive copies, traffic/fan-out, indexes, undo, bootstrap and wallet history remain
costs. No owner acceptance of that model is implied.

The measured ordinary destination command took20.837565988s, including receive,
identity checks, parse/copy, genuine validation, atomic durable commit, RETAIN and
head readback. The declared96-payment interval is30.27456s. Producer PUT took
13.949979421s. Their serial sum34.787545409s exceeds the interval by4.512985409s.
The experiment did not overlap these stages. A theoretical maximum-of-stages
calculation cannot replace the next actual run.

There is no observed correctness or isolated-stage resource blocker prohibiting
a bounded pipeline test. Archive one-PUT/one-GET slots and separate CPUs provide
a concrete hypothesis: upload the next frame while validating the current one.
Actual concurrent archive I/O, bandwidth pacing, backpressure, CPU contention,
retention and restart must determine whether that hypothesis holds.

The next experiment must make the following boundaries concrete before running:

- Fix all offered timestamps independently of completed uploads/admissions. A
  blocked sender cannot silently reset the offered clock. Count offered, locally
  queued, rejected/deferred, uploading, archive-durable, downloading, accepted and
  unfinished payments/bytes at the common observation end.
- Declare each bounded queue, simultaneous frame/spool copies, raw and physical
  disk quotas, CPUs, link pacing and burst/restart interval. Use actual distinct
  genuine payments. Pre-generation and funding are separately priced; this is
  not live wallet throughput.
- Actually overlap separate producer/archive/validator roles. Preserve one
  writer per ledger and exact per-role admission order. An archive durable-byte
  ACK authorizes availability only; the validator's canonical commit remains
  separate. No cached proof verdict authorizes a new block.
- Exercise bounded stopped/restarted-role recovery while the offered clock
  continues. Acknowledged objects must survive, unacknowledged requests remain
  counted, retry identity must be exact, and accepted payments cannot be lost or
  double-applied. Preserve failures and all terminal evidence.
- Observe queue peaks and complete drain, or report all remaining backlog and
  retention obligations. Include interrupted/retried traffic and redundant
  physical writes. Final RETAIN growth is completed durable responsibility, not
  a free pruning result or an implicit export queue.
- Compare final canonical state independently. Price native cumulative SELF and
  waited CHILDREN separately from bwrap. Do not sum inclusive/nested spans or
  cumulative RSS maxima. Whole process wall contains oracle idle time.

A finite pass may provisionally retain this backend for the stated measured
profile. It cannot answer the separate participation question by silently
increasing hardware or assigning175TB/year to every ordinary validator. The
result should explicitly retain that unresolved architectural decision. No
proof/security parameter change, cryptographic pivot or larger campaign is
justified solely by the present wrapper-metric defect or serial scheduling gap.

Evidence: GATE1_96_READBACK01.json. This disposition is independent readback of
the actual run, not a duplicate native verification or the final clean-checkout
reproduction required by the owner Goal.
