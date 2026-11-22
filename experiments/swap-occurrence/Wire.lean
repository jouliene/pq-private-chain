import Occurrence

/- The driver supplies a registered public worker on the *exact* bytes queried.
   The worker is a trust boundary. No worker verdict is built into this decoder. -/
namespace SwapWire
open FundedRefinement FundedOccurrence

structure Frame where
  side : Nat
  payer : Nat
  expiry : Nat
  network : Bytes
  terms : Bytes
  other : Bytes
  sig : Bytes
  leg : Bytes

def magic (s : String) := s.toUTF8.push 1

def readFrame (raw : Bytes) : Option Frame := do
  guard (17195 < raw.size && raw.size ≤ 262144 && cut raw 0 5 == magic "SWF3")
  let leg := raw.extract 17195 raw.size
  guard (3593 < leg.size && cut leg 0 5 == magic "SLG3" && leg.size == 3593 + atLE leg 5 4)
  let side := atLE raw 5 1
  let payer := atLE raw 6 1
  let expiry := atLE raw 7 4
  let terms := cut raw 43 32
  guard (side ≤ 1 && payer ≤ 1 && 0 < expiry && uLE terms != 0)
  return ⟨side,payer,expiry,cut raw 11 32,terms,cut raw 75 32,cut raw 107 17088,leg⟩

structure Frames where
  left : Frame
  right : Frame

def framed (raw : Bytes) : Option (Bytes × Bytes) := do
  guard (13 ≤ raw.size && raw.size ≤ 13+2*262144 && cut raw 0 5 == magic "SWB3")
  let n := atLE raw 5 4
  let offset := 9+n
  guard (0 < n && n ≤ 262144 && offset+4 ≤ raw.size)
  let m := atLE raw offset 4
  guard (0 < m && m ≤ 262144 && raw.size == offset+4+m)
  return (cut raw 9 n, cut raw (offset+4) m)

def pair (raw : Bytes) : Option Frames := do
  let (x,y) ← framed raw
  let a ← readFrame x
  let b ← readFrame y
  guard (a.side==0 && b.side==1 && a.payer==b.payer && a.expiry==b.expiry &&
    a.network==b.network && a.terms==b.terms && a.other==sha256 b.leg && b.other==sha256 a.leg)
  return ⟨a,b⟩

def joint (f : Frames) : Bytes :=
  sha256 (domain "SWP3/joint-authorization/v1" ++ f.left.network ++ f.left.terms ++
          putLE f.left.expiry 4 ++ putLE f.left.payer 1 ++ sha256 f.left.leg ++ sha256 f.right.leg)

structure Effects where
  pi : FundingPI
  keyBytes : Bytes
  receipts : Bytes

def Effects.key (x : Effects) := uLE x.keyBytes
def Effects.nfs (x : Effects) := [x.pi.nf0,x.pi.nf1]
def Effects.cms (x : Effects) := [x.pi.cm0,x.pi.cm1]

def readEffects (leg reply : Bytes) : Option Effects := do
  guard (reply.size==3790 && reply[0]?==some 49)
  let anchor := cut reply 1 32
  let n0 := cut reply 37 32
  let n1 := cut reply 69 32
  let c0 := cut reply 101 32
  let c1 := cut reply 133 32
  let fee := atLE reply 165 8
  let depth := atLE reply 3789 1
  let cts := cut reply 173 3584
  guard ([anchor,n0,n1,c0,c1].all canonical && uLE c0 != 0 && uLE c1 != 0 &&
    (fee==0 || fee==3) && 1≤depth && depth≤20 && cts==leg.extract (leg.size-3584) leg.size)
  return ⟨⟨atLE reply 33 4,depth,uLE anchor,fee,uLE n0,uLE n1,uLE c0,uLE c1⟩,
           cut reply 3757 32,cts⟩

def sigRequest (f : Frames) (e : Effects) (slot : Frame) :=
  bytes [86] ++ e.keyBytes ++ joint f ++ slot.sig

def expectedFee (payer side : Nat) := if payer=side then 3 else 0

/-- Concrete guards in MembershipSupport.check_funding and the parent chain check.
    Includes the distinct public effects of a leg independent of its partner. -/
def parentGuard (p : PublicState) (u : FundingPI) (a : Anchor) : Bool :=
  decide (25≤p.height+1 ∧ p.height+1<2^32 ∧ u.height<p.height+1 ∧ p.height+1-u.height≤8 ∧
    a.ap=u.anchor ∧ 1≤a.count ∧ a.count≤4^20 ∧ depthOf a.count=u.depth ∧
    u.nf0≠u.nf1 ∧ u.cm0≠u.cm1 ∧ u.nf0∉p.spent ∧ u.nf1∉p.spent ∧ u.cm0∉p.cms ∧ u.cm1∉p.cms)

structure LegOK (p : PublicState) (w : Worker) (f : Frames) (slot : Frame) (side : Nat) where
  row : Effects
  anchor : Anchor
  fromWorker : readEffects slot.leg (w slot.leg)=some row
  selected : p.anchors row.pi.height=some anchor
  funded : parentGuard p row.pi anchor=true
  fee : row.pi.fee=expectedFee f.left.payer side
  signed : w (sigRequest f row slot)=success

def verifyLeg (p : PublicState) (w : Worker) (f : Frames) (slot : Frame) (side : Nat) :
    Option (LegOK p w f slot side) :=
  match he : readEffects slot.leg (w slot.leg) with
  | none => none
  | some e =>
    match ha : p.anchors e.pi.height with
    | none => none
    | some a =>
      if h : parentGuard p e.pi a=true ∧ e.pi.fee=expectedFee f.left.payer side ∧
          w (sigRequest f e slot)=success then
        some ⟨e,a,he,ha,h.1,h.2.1,h.2.2⟩
      else none

structure Accepted (network : Bytes) (p : PublicState) (w : Worker) (raw : Bytes) where
  frames : Frames
  original : pair raw=some frames
  chain : frames.left.network=network
  height : p.height+1≤frames.left.expiry
  payer : frames.left.payer≤1
  a : LegOK p w frames frames.left 0
  b : LegOK p w frames frames.right 1
  authorities : a.row.keyBytes≠b.row.keyBytes
  nfs : (a.row.nfs++b.row.nfs).Nodup
  cms : (a.row.cms++b.row.cms).Nodup

def admit (network : Bytes) (p : PublicState) (w : Worker) (raw : Bytes) :
    Option (Accepted network p w raw) :=
  match hf : pair raw with
  | none => none
  | some f => do
    if hn : f.left.network=network ∧ p.height+1≤f.left.expiry ∧ f.left.payer≤1 then
      let a ← verifyLeg p w f f.left 0
      let b ← verifyLeg p w f f.right 1
      if h : a.row.keyBytes≠b.row.keyBytes ∧ (a.row.nfs++b.row.nfs).Nodup ∧
          (a.row.cms++b.row.cms).Nodup then
        return ⟨f,hf,hn.1,hn.2.1,hn.2.2,a,b,h.1,h.2.1,h.2.2⟩
      else none
    else none

theorem both_authorized {network p w raw} (ok : Accepted network p w raw) :
    w (bytes [86] ++ ok.a.row.keyBytes ++ joint ok.frames ++ ok.frames.left.sig) = success ∧
    w (bytes [86] ++ ok.b.row.keyBytes ++ joint ok.frames ++ ok.frames.right.sig) = success ∧
    ok.a.row.keyBytes ≠ ok.b.row.keyBytes := ⟨ok.a.signed,ok.b.signed,ok.authorities⟩

theorem one_fee {network p w raw} (ok : Accepted network p w raw) :
    ok.a.row.pi.fee+ok.b.row.pi.fee=3 := by
  have bound := ok.payer
  rw [ok.a.fee, ok.b.fee]
  rcases (show ok.frames.left.payer=0 ∨ ok.frames.left.payer=1 by omega) with zero | one <;>
    simp_all [expectedFee]

theorem rejected_without_frames {network p w raw} (bad : pair raw=none) :
    admit network p w raw=none := by
  unfold admit
  split <;> simp_all

/-- Public accounting columns written by _attach. Output rows are chronological;
    nullifier rows are represented in insertion order (SQLite keys them by NF). -/
structure Rows where
  outputs : List (Nat × Bytes)
  marks : List Nat
  supply : List FundedRefinement.SqlEvent

def Effects.outputRows (e : Effects) :=
  [(e.pi.cm0,cut e.receipts 0 1792),(e.pi.cm1,cut e.receipts 1792 1792)]

def insertSlot (old : Rows) (outs : List (Nat × Bytes)) (nf : List Nat)
    (event : Option FundedRefinement.SqlEvent) : Rows :=
  ⟨old.outputs++outs,old.marks++nf,event.toList++old.supply⟩

/-- Both physical ManagedSlots returned by verify_pair have zero supply. The
    candidate is checked in full before the transactional writes are committed. -/
def commitBoth (old : Rows) {network p w raw} (ok : Accepted network p w raw) : Rows :=
  let first := insertSlot old ok.a.row.outputRows ok.a.row.nfs none
  insertSlot first ok.b.row.outputRows ok.b.row.nfs none

def settle (network : Bytes) (p : PublicState) (w : Worker) (raw : Bytes) (old : Rows) : Rows :=
  match admit network p w raw with
  | none => old
  | some ok => commitBoth old ok

theorem rejected_keeps_rows {net p w raw old} (no : admit net p w raw=none) :
    settle net p w raw old=old := by simp [settle,no]

theorem accepted_writes {net p w raw old} {ok : Accepted net p w raw} (yes : admit net p w raw=some ok) :
    let final := settle net p w raw old
    final.outputs=old.outputs++(ok.a.row.outputRows++ok.b.row.outputRows) ∧
    final.marks=old.marks++(ok.a.row.nfs++ok.b.row.nfs) ∧ final.supply=old.supply ∧
    FundedRefinement.latest final.supply=FundedRefinement.latest old.supply := by
  simp [settle,yes,commitBoth,insertSlot,List.append_assoc]

end SwapWire
