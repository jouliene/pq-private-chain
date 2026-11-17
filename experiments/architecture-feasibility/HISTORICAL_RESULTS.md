# Historical mechanism results

Recorded before publication at research revision
`360fc54e6b76dc864131f5c17b80c93b02c8bc67`; these are **historical observations**,
not outcomes of a new public-clone run. The repository supplies real source and
local public fixture generation rather than requiring an old private installation
or presenting hashes as a substitute for runnable mechanisms.

The original fixed-endpoint witness probe matched authentic roots and selected
depth40 paths at eight checkpoints across two genuine public payment histories,
each containing2,4,6,8 leaves. Eight omission/order/mutation/unfunded-target controls
rejected. This supported O(D+kD) selective frontier/path state by source analysis.
The diagnostic driver retained all leaves and a full sparse oracle, so its
25,100KiB process peak was not a streaming-memory bound. Its finish operation is
terminal; private target integration/live append/reorg updates remain open.

The distinct campaign generated16 fresh authorized credit proofs followed by16
fresh2x2 proofs spending32 disjoint funded notes, in two16-body blocks. Their
56,106,288 public body bytes passed persistent Ledger admission. A changed opaque
digest in the final ordinary proof produced Error::Proof without partial state;
all14 SQL tables/schema/version matched before/after. All32 bodies were durably
published and evicted, then fetched from archive and freshly verified/admitted
by another public Ledger. Canonical final state matched: height2,64 leaves,32
nullifiers,fee escrow67,664,368 and zero remaining source liabilities.

For the ordinary16 block, nonoverlapping local intake/admission/archive append/
publication spans totaled2.474226449s wall; admission alone was0.849105804s. Their
per-body arithmetic means154.639ms/53.069ms were not latency distributions or
measured sustainable TPS. The whole public-role child was15.480441s/272,396KiB.
Page cache was warm/uncontrolled, all32 originals were retained as RAM oracles,
and self physical read_bytes was0. Inclusive diagnostic spans contained SQL
snapshots/assertions and must not be added to exclusive stages or interpreted as
archive-only time. These numbers establish neither WAN performance, annual
catch-up, long-state storage, private recovery nor production security.
