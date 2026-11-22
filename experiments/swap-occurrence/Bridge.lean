import Swap
import Wire

/-! Join the physical SLG3 effect rows to the private relation for those same proofs.
    No historical position, solvent post-state, or cross-leg pairing is a premise. -/
namespace SwapBridge
open FundedOccurrence FundedAnchor FundedSwap SwapWire
open FundedC hiding State holdings
open FundedRefinement (PublicState Worker Bytes)

structure PublicFields (h : Hashes) (t : Tx) (e : Effects) : Prop where
  n0 : e.pi.nf0=published h t.i
  n1 : e.pi.nf1=published h t.j
  c0 : e.pi.cm0=commit h t.u
  c1 : e.pi.cm1=commit h t.v

theorem leg_guards {h t e p f slot side w st} (a : LegOK p w f slot side)
    (eq : a.row=e) (pub : PublicProjection st p) (v : PublicFields h t e) : PublicGuards h st t := by
  subst e
  have g := a.funded
  simp only [parentGuard,decide_eq_true_eq] at g
  obtain ⟨_,_,_,_,_,_,_,_,dn,dc,f0,f1,c0,c1⟩ := g
  rw [v.n0,v.n1] at dn
  rw [v.c0,v.c1] at dc
  rw [v.n0] at f0
  rw [v.n1] at f1
  rw [v.c0,pub.cms] at c0
  rw [v.c1,pub.cms] at c1
  exact ⟨dn,dc,fun mem => f0 (pub.spent.mem_iff.mpr mem),
               fun mem => f1 (pub.spent.mem_iff.mpr mem),c0,c1⟩

theorem pair_guards {h st net p w raw a z} (ok : Accepted net p w raw)
    (pub : PublicProjection st p) (x : PublicFields h a ok.a.row) (y : PublicFields h z ok.b.row) :
    PairGuards h st a z := by
  refine ⟨leg_guards ok.a rfl pub x,leg_guards ok.b rfl pub y,?_,?_⟩
  · simpa [Effects.nfs,marks,x.n0,x.n1,y.n0,y.n1] using ok.nfs
  · simpa [Effects.cms,leaves,x.c0,x.c1,y.c0,y.c1] using ok.cms

/-- One actual selected header and the normalized header exhibited by this leg.
    The displayed chronological tree is supplied by the selected ledger. -/
structure Headers (hash : Hash) (le : Digest → Digest → Bool)
    (headerHash : OccurrenceMember.Header → Digest) (st : State)
    {p w f slot side} (a : LegOK p w f slot side) where
  selected : OccurrenceMember.Header
  proved : OccurrenceMember.Header
  selectedHeight : selected.height=a.row.pi.height
  provedHeight : proved.height=a.row.pi.height
  selectedAP : headerHash selected=a.anchor.ap
  provedAP : headerHash proved=a.row.pi.anchor
  headerBinding : headerHash selected=headerHash proved → selected=proved
  countBound : a.anchor.count≤st.births.length
  top : levels hash le ((st.births.map Occurrence.cm).take a.anchor.count) a.row.pi.depth=[selected.root]
  occupied : proved.root≠0

structure RealPath {hash le headerHash st p w f slot side} {a : LegOK p w f slot side}
    (head : Headers hash le headerHash st a) (leaf : Nat) where
  quads : List Quad
  depth : quads.length=a.row.pi.depth
  links : Path hash leaf quads head.proved.root
  binding : Binds hash le ((st.births.map Occurrence.cm).take a.anchor.count) quads

def RealPath.selected {hash le headerHash st p w f slot side} {a : LegOK p w f slot side}
    {head : Headers hash le headerHash st a} {leaf} (v : RealPath head leaf) :
    OccurrenceMember.Selected hash le st a.anchor.count leaf := by
  have guards := a.funded
  simp only [parentGuard,decide_eq_true_eq] at guards
  obtain ⟨era,bound,old,age,ap,lo,hi,depth,_⟩ := guards
  exact OccurrenceMember.fromEligibleHeader headerHash p.height head.selected head.proved
    ⟨a.row.pi.anchor,a.row.pi.height,a.row.pi.depth⟩ v.quads ⟨era,bound⟩ ⟨old,age⟩
    head.selectedHeight head.provedHeight (head.selectedAP.trans ap) head.provedAP
    head.headerBinding ⟨lo,head.countBound,hi⟩ depth.symm v.depth head.top head.occupied v.links v.binding

/-- Witness-level interfaces of the registered statement. This records only local
    wire equations and hash/security premises. The two real paths, if present, end
    at the common private header of this leg. The two legs may use different anchors. -/
structure Witness (h : Hashes) (b : Binding h) (hash : Hash) (le : Digest → Digest → Bool)
    (headerHash : OccurrenceMember.Header → Digest) (openRaw : Nat → Nat → Nat) (st : State)
    {p w f slot side} (a : LegOK p w f slot side) (t : Tx) where
  fields : PublicFields h t a.row
  gates : LegGates h t a.row.pi.fee
  head : Headers hash le headerHash st a
  paths : ∀ i∈[t.i,t.j], i.real=true → Nonempty (RealPath head (commit h i.w.body))
  seedU : Nat
  seedV : Nat
  rawU : t.u.raw=openRaw a.row.key seedU
  rawV : t.v.raw=openRaw a.row.key seedV
  allowedU : b.bodyAllowed t.u
  allowedV : b.bodyAllowed t.v
  rhoU : t.u.rho=h.rho (published h t.i) (published h t.j) 0
  rhoV : t.v.rho=h.rho (published h t.i) (published h t.j) 1
  scopes : ∀ i∈[t.i,t.j], b.spendAllowed i.w ∧ b.bodyAllowed i.w.body
  owners : ∀ i∈[t.i,t.j], i.real=true → owner h i.w=i.w.body.pk

def Witness.opening {h b hash le headerHash openRaw st p w f slot side}
    {a : LegOK p w f slot side} {t} (x : Witness h b hash le headerHash openRaw st a t) :
    LegOpening h b hash le openRaw st a.anchor.count t a.row.key a.row.pi.fee :=
  ⟨x.gates,x.seedU,x.seedV,x.rawU,x.rawV,x.allowedU,x.allowedV,x.rhoU,x.rhoV,x.scopes,x.owners,
   fun i mem real => (x.paths i mem real).elim (fun path => ⟨path.selected⟩)⟩

theorem unique_funded_input {h b hash le headerHash openRaw st p w f slot side}
    {a : LegOK p w f slot side} {t} (x : Witness h b hash le headerHash openRaw st a t)
    (hist : HistoryOK h b st) (proj : PublicProjection st p) {i}
    (mem : i∈[t.i,t.j]) (real : i.real=true) :
    ∃ o, st.births[pos h st i]?=some o ∧ i.w.body=o.body ∧ pos h st i<a.anchor.count ∧
      pos h st i∉st.debits.map Debit.pos ∧
      ∀ j birth, st.births[j]?=some birth → birth.cm=commit h i.w.body → j=pos h st i := by
  obtain ⟨path⟩ := x.paths i mem real
  have guard := leg_guards a rfl proj x.fields
  have fresh : published h i∉st.spent := by
    rcases List.mem_cons.mp mem with e | e
    · exact e ▸ guard.i
    · exact (List.mem_singleton.mp e) ▸ guard.j
  exact OccurrenceMember.matched_real hist real (x.scopes i mem).2 (x.scopes i mem).1
    (x.owners i mem real) fresh path.selected

/-- Any later ordinary or swap real opening of this CM has the same effective raw
    (as well as the same private amounts). It need not know the ephemeral signing key
    or the creator's salt. Only the equality of the public commitments is required. -/
theorem later_effective_raw {h b hash le headerHash openRaw st p w f slot side}
    {a : LegOK p w f slot side} {t} (x : Witness h b hash le headerHash openRaw st a t)
    (v : Body) (allowed : b.bodyAllowed v)
    (hit : commit h v=commit h t.u ∨ commit h v=commit h t.v) :
    (v=t.u ∧ v.raw=openRaw a.row.key x.seedU) ∨ (v=t.v ∧ v.raw=openRaw a.row.key x.seedV) := by
  rcases hit with u | z
  · have eq := commitment_body b allowed x.allowedU u
    exact Or.inl ⟨eq,eq ▸ x.rawU⟩
  · have eq := commitment_body b allowed x.allowedV z
    exact Or.inr ⟨eq,eq ▸ x.rawV⟩

def payer {net p w raw} (ok : Accepted net p w raw) := decide (ok.frames.left.payer=1)

theorem fees {net p w raw} (ok : Accepted net p w raw) :
    ok.a.row.pi.fee=feeFor (payer ok) false ∧ ok.b.row.pi.fee=feeFor (payer ok) true := by
  have bound := ok.payer
  rw [ok.a.fee,ok.b.fee]
  rcases (show ok.frames.left.payer=0 ∨ ok.frames.left.payer=1 by omega) with z | o <;>
    simp_all [payer,expectedFee,feeFor]

/-- A successful public pair and two local, same-statement witness interpretations
    account for exactly the same two physical slot writes, as one atomic transition. -/
theorem authorized_settlement {h b hash le headerHash openRaw st net p w raw a z}
    (ok : Accepted net p w raw) (proj : PublicProjection st p) (hist : HistoryOK h b st)
    (x : Witness h b hash le headerHash openRaw st ok.a a)
    (y : Witness h b hash le headerHash openRaw st ok.b z) :
    (w (sigRequest ok.frames ok.a.row ok.frames.left)=FundedRefinement.success ∧
     w (sigRequest ok.frames ok.b.row ok.frames.right)=FundedRefinement.success) ∧
    HistoryOK h b (applyPair h st a z) ∧ (∀ c, holdings (applyPair h st a z) c+charge c=holdings st c) := by
  have left := x.opening
  have right := y.opening
  rw [(fees ok).1] at left
  rw [(fees ok).2] at right
  have both := pair_conservation left right (pair_guards ok proj x.fields y.fields) ⟨[],by simp⟩ hist
  exact ⟨⟨ok.a.signed,ok.b.signed⟩,both.1,both.2.1⟩

/-- Instantiate the history admission predicate by the order and exact keys,
    effects and counts from a successfully decoded original packet for this parent.
    Supply and swap workers are separately registered binaries. -/
def registered (h : Hashes) (network : Bytes) (publicAt : State → PublicState)
    (worker : Worker) : FundedSwap.Admit := fun st na l ka nz r kz paid =>
  ∃ (raw : Bytes) (ok : Accepted network (publicAt st) worker raw),
    SwapWire.admit network (publicAt st) worker raw=some ok ∧
    ok.a.anchor.count=na ∧ ok.b.anchor.count=nz ∧ ok.a.row.key=ka ∧ ok.b.row.key=kz ∧
    payer ok=paid ∧ PublicFields h l ok.a.row ∧ PublicFields h r ok.b.row

def packetItem {h b hash le headerHash openRaw st net w raw l r}
    (publicAt : State → PublicState) (managed : Worker) (reg : FundedSupply.Registry)
    (ok : Accepted net (publicAt st) w raw) (passed : SwapWire.admit net (publicAt st) w raw=some ok)
    (x : Witness h b hash le headerHash openRaw st ok.a l)
    (y : Witness h b hash le headerHash openRaw st ok.b r) :
    Item h b hash le openRaw (registered h net publicAt w) st (FundedRefinement.uLE net) managed reg :=
  .swap (payer:=payer ok)
    ⟨raw,ok,passed,rfl,rfl,rfl,rfl,rfl,x.fields,y.fields⟩
    ((fees ok).1 ▸ x.opening) ((fees ok).2 ▸ y.opening)

theorem packetItem_checked {h b hash le headerHash openRaw st net w raw l r}
    (publicAt : State → PublicState) (managed : Worker) (reg : FundedSupply.Registry)
    (ok : Accepted net (publicAt st) w raw) (passed : SwapWire.admit net (publicAt st) w raw=some ok)
    (x : Witness h b hash le headerHash openRaw st ok.a l)
    (y : Witness h b hash le headerHash openRaw st ok.b r) (proj : PublicProjection st (publicAt st)) :
    (packetItem publicAt managed reg ok passed x y).checked (publicAt st) :=
  pair_guards ok proj x.fields y.fields

def emittedSwapRow (e : Effects) : EmittedSlot :=
  ⟨e.pi.nf0,e.pi.nf1,e.pi.cm0,e.pi.cm1,FundedC.zeroId,0⟩

/-- Furnishes the ordered-vector premise of checked_block_guards directly from the
    same two worker replies. SWB3 has no registry field controlled by the spender. -/
theorem packetItem_emitted {h b hash le headerHash openRaw st net w raw l r}
    (publicAt : State → PublicState) (managed : Worker) (reg : FundedSupply.Registry)
    (ok : Accepted net (publicAt st) w raw) (passed : SwapWire.admit net (publicAt st) w raw=some ok)
    (x : Witness h b hash le headerHash openRaw st ok.a l)
    (y : Witness h b hash le headerHash openRaw st ok.b r) :
    (packetItem publicAt managed reg ok passed x y).emitted =
      [emittedSwapRow ok.a.row,emittedSwapRow ok.b.row] := by
  change [EmittedSlot.ofTx h l FundedC.zeroId 0,EmittedSlot.ofTx h r FundedC.zeroId 0]=_
  simp [EmittedSlot.ofTx,emittedSwapRow,x.fields.n0,x.fields.n1,x.fields.c0,x.fields.c1,
    y.fields.n0,y.fields.n1,y.fields.c0,y.fields.c1]

/-- The actual four output CMs and the spent set of both physical writes are the
    public projection of the *same* ghost transition used for monetary accounting. -/
theorem packet_projection {h st net p w raw l r} (ok : Accepted net p w raw)
    (pub : PublicProjection st p) (x : PublicFields h l ok.a.row) (y : PublicFields h r ok.b.row) :
    (applyPair h st l r).births.map Occurrence.cm = p.cms++(ok.a.row.cms++ok.b.row.cms) ∧
    ((ok.a.row.nfs++ok.b.row.nfs)++p.spent).Perm (applyPair h st l r).spent := by
  constructor
  · simp [applyPair,extendBirths,Effects.cms,x.c0,x.c1,y.c0,y.c1,pub.cms,List.append_assoc]
  · simp only [Effects.nfs,x.n0,x.n1,y.n0,y.n1,List.cons_append,List.nil_append]
    exact (List.Perm.append (List.reverse_perm
      [published h l.i,published h l.j,published h r.i,published h r.j]).symm pub.spent)

/-- Same starting rows, same SWB3 bytes, same registered worker queries. The
    committed four public outputs/marks agree with the hidden occurrence transition
    and the unchanged registry describes its resulting holdings. -/
theorem packet_refines {h b hash le headerHash openRaw st net p w raw l r}
    (old : SwapWire.Rows) (ok : Accepted net p w raw) (pass : SwapWire.admit net p w raw=some ok)
    (proj : PublicProjection st p) (hist : HistoryOK h b st)
    (cols : old.outputs.map Prod.fst=p.cms) (spent : old.marks.Perm p.spent)
    (initial : Consistent st (FundedRefinement.latest old.supply))
    (x : Witness h b hash le headerHash openRaw st ok.a l)
    (y : Witness h b hash le headerHash openRaw st ok.b r) :
    let rows := SwapWire.settle net p w raw old
    let money := applyPair h st l r
    rows.supply=old.supply ∧ rows.outputs.map Prod.fst=money.births.map Occurrence.cm ∧
    rows.marks.Perm money.spent ∧ Consistent money (FundedRefinement.latest rows.supply) ∧
    holdings money .native+3=holdings st .native := by
  obtain ⟨outputs,marks,rows,reg⟩ := accepted_writes (old:=old) pass
  obtain ⟨cms,nfs⟩ := packet_projection ok proj x.fields y.fields
  obtain ⟨_,_,flow⟩ := authorized_settlement ok proj hist x y
  refine ⟨rows,?_,?_,?_,flow .native⟩
  · rw [outputs,List.map_append,List.map_append,cols,cms]
    rfl
  · rw [marks]
    exact ((spent.append_right _).trans List.perm_append_comm).trans nfs
  · rw [reg]
    intro q
    have same := flow (.asset q)
    simp only [charge,Nat.add_zero] at same
    exact ⟨same.trans (initial q).1,(initial q).2⟩

/-- The output opening uses eight unsigned LE32 words of the 32-byte authority
    and four canonical Goldilocks limbs of the new raw digest, after the domain.
    Inputs type the already-effective raw directly with OPEN. -/
def swapRaw (sponge : List Nat → Nat) (key salt : Nat) :=
  sponge (0x534c47310001 ::
    ((List.range 8).map (fun i => (key >>> (32*i)) % 2^32)) ++
    ((List.range 4).map (fun i => (salt >>> (64*i)) % 2^64)))

/-- The deployed admission specialization. Only the imported prefix must be
    consistent. The history constructors carry registered packet/local witness
    checks for all later swaps; they do not supply intermediate balances. -/
theorem registered_history {h b hash le sponge net worker managed publicAt start initialRows final rows count}
    (path : FundedSwap.History h b hash le (swapRaw sponge) (registered h net publicAt worker)
      (FundedRefinement.uLE net) managed publicAt start initialRows final rows count)
    (hist : HistoryOK h b start) (initial : Consistent start (FundedRefinement.latest initialRows))
    (distinct : start.spent.Nodup) :
    HistoryOK h b final ∧ Consistent final (FundedRefinement.latest rows) ∧ final.spent.Nodup ∧
    holdings final .native=holdings start .native+100*count :=
  selected_history path hist initial distinct

end SwapBridge
