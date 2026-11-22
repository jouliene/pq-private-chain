import Member

/-! Occurrence semantics of the two SLG3 legs in one SWB3 group. The registered proof
    and byte/authority checks are interfaces. No secret for a newly funded recipient
    is needed. A chronological position is computed from the selected history. -/
namespace FundedSwap
open FundedC hiding State holdings
open FundedSupply FundedOccurrence
open FundedAnchor (Hash Digest)

def feeFor (payer side : Bool) := if payer = side then 3 else 0

def debitFor (fee : Nat) : Currency → Nat
  | .native => fee
  | .asset _ => 0

/-- Field residuals of the leg and its base SpendTargets, including the SLG3 first-real
    guard. The registered codec further restricts the emitted fee to zero or three. -/
structure LegGates (h : Hashes) (t : Tx) (fee : Nat) : Prop where
  codecFee : fee=0 ∨ fee=3
  feePolynomial : (fee * ((fee + P - 3) % P)) % P=0
  firstReal : t.i.real=true
  cash : (t.i.w.body.native.val+t.j.w.body.native.val)%P =
    (((t.u.native.val+t.v.native.val)%P)+fee)%P
  tokens : (t.i.w.body.token.val+t.j.w.body.token.val)%P = (t.u.token.val+t.v.token.val)%P
  ti : tag t.asset (inputView h t.i).note
  tj : tag t.asset (inputView h t.j).note
  tu : tag t.asset (paymentView h t).u
  tv : tag t.asset (paymentView h t).v
  zeroSelector : (t.i.w.body.token.val+t.j.w.body.token.val)%P=0 ↔ t.asset=zeroId
  dummyI : dummyGate (inputView h t.i)
  dummyJ : dummyGate (inputView h t.j)

/-- An extracted SLG3 witness of this leg with this proof-emitted authority. The input
    raw field is already the effective stored opening. Outputs hash a fresh raw wire with
    the public eight-word signing key before the ordinary typed note hash. -/
structure LegOpening (h : Hashes) (b : Binding h) (hash : Hash) (le : Digest → Digest → Bool)
    (openRaw : Nat → Nat → Nat) (parent : State) (n : Nat) (t : Tx) (key fee : Nat) where
  gates : LegGates h t fee
  rawU : Nat
  rawV : Nat
  effectiveU : t.u.raw=openRaw key rawU
  effectiveV : t.v.raw=openRaw key rawV
  scopeU : b.bodyAllowed t.u
  scopeV : b.bodyAllowed t.v
  rhoU : t.u.rho=h.rho (published h t.i) (published h t.j) 0
  rhoV : t.v.rho=h.rho (published h t.i) (published h t.j) 1
  inputScope : ∀ i∈[t.i,t.j], b.spendAllowed i.w ∧ b.bodyAllowed i.w.body
  authorized : ∀ i∈[t.i,t.j], i.real=true → owner h i.w=i.w.body.pk
  paths : ∀ i∈[t.i,t.j], i.real=true →
    Nonempty (OccurrenceMember.Selected hash le parent n (commit h i.w.body))

theorem LegOpening.countBound {h b hash le openRaw parent n t key fee}
    (o : LegOpening h b hash le openRaw parent n t key fee) : n≤parent.births.length := by
  obtain ⟨p⟩ := o.paths t.i (by simp) o.gates.firstReal
  exact p.inRange.2.1

theorem LegOpening.wires {h b hash le openRaw parent n t key fee}
    (o : LegOpening h b hash le openRaw parent n t key fee) : PrivateWires h b parent n t := by
  have slot {i} (mem : i∈[t.i,t.j]) : SlotWires h b parent n i :=
    OccurrenceMember.slot_wires (o.inputScope _ mem).1 (o.inputScope _ mem).2
      (o.authorized _ mem) (o.paths _ mem)
  exact ⟨slot (by simp),slot (by simp),o.scopeU,o.scopeV,o.rhoU,o.rhoV⟩

theorem local_amounts {h t fee} (g : LegGates h t fee) (c : Currency) :
    bodyValue t.i.w.body c + bodyValue t.j.w.body c =
      bodyValue t.u c + bodyValue t.v c + debitFor fee c := by
  cases c with
  | native =>
    have hi := (exact_intermediate_bounds t.i.w.body.native.isLt t.j.w.body.native.isLt).2.2
    have ho := (exact_intermediate_bounds t.u.native.isLt t.v.native.isLt).2.2
    have fi := g.codecFee
    have i : t.i.w.body.native.val+t.j.w.body.native.val<P := by omega
    have o : t.u.native.val+t.v.native.val<P := by omega
    have f : t.u.native.val+t.v.native.val+fee<P := by omega
    simpa [bodyValue,debitFor,Nat.mod_eq_of_lt i,Nat.mod_eq_of_lt o,Nat.mod_eq_of_lt f] using g.cash
  | asset id =>
    have hi := (exact_intermediate_bounds t.i.w.body.token.isLt t.j.w.body.token.isLt).2.2
    have ho := (exact_intermediate_bounds t.u.token.isLt t.v.token.isLt).2.2
    have i : t.i.w.body.token.val+t.j.w.body.token.val<P := by omega
    have o : t.u.token.val+t.v.token.val<P := by omega
    have tok := g.tokens
    rw [Nat.mod_eq_of_lt i,Nat.mod_eq_of_lt o] at tok
    have tagI := effective_tag _ id _ g.ti
    have tagJ := effective_tag _ id _ g.tj
    have tagU := effective_tag _ id _ g.tu
    have tagV := effective_tag _ id _ g.tv
    simp only [inputView,paymentView,value_view] at tagI tagJ tagU tagV
    simp only [tagI,tagJ,tagU,tagV,debitFor,Nat.add_zero]
    by_cases eq : t.asset=id <;> simp [eq,noteView,tok]

theorem leg_delta {h b now n t fee} (hist : HistoryOK h b now) (ev : TxEvidence h b now n t)
    (g : LegGates h t fee) (c : Currency) :
    holdings (applyTx h now t) c+debitFor fee c=holdings now c := by
  have f := selected_flow hist ev g.dummyI g.dummyJ c
  have v := local_amounts g c
  omega

structure PairGuards (h : Hashes) (now : State) (a z : Tx) : Prop where
  left : PublicGuards h now a
  right : PublicGuards h now z
  nullifiers : (marks h a ++ marks h z).Nodup
  commitments : (leaves h a ++ leaves h z).Nodup

def applyPair (h : Hashes) (now : State) (a z : Tx) := applyTx h (applyTx h now a) z

theorem extendBirths (h : Hashes) (now : State) (t : Tx) :
    (applyTx h now t).births=now.births++[⟨commit h t.u,t.u⟩,⟨commit h t.v,t.v⟩] := by
  simp [applyTx,birth,consume,List.append_assoc]

private theorem after_one {h now t u} (g : PublicGuards h now u)
    (nf : ∀ a∈marks h t, ∀ z∈marks h u, a≠z)
    (cm : ∀ a∈leaves h t, ∀ z∈leaves h u, a≠z) : PublicGuards h (applyTx h now t) u := by
  have freshNF {k} (mem : k∈marks h u) (old : k∉now.spent) : k∉(applyTx h now t).spent := by
    change k ∉ published h t.j :: published h t.i :: now.spent
    simpa [old] using And.intro (Ne.symm (nf _ (by simp [marks]) _ mem))
      (Ne.symm (nf _ (by simp [marks]) _ mem))
  have freshCM {k} (mem : k∈leaves h u) (old : k∉now.births.map Occurrence.cm) :
      k∉(applyTx h now t).births.map Occurrence.cm := by
    rw [extendBirths,List.map_append,List.mem_append,not_or]
    exact ⟨old,fun hm => cm _ hm _ mem rfl⟩
  exact ⟨g.distinctNF,g.distinctCM,freshNF (by simp [marks]) g.i,freshNF (by simp [marks]) g.j,
    freshCM (by simp [leaves]) g.u,freshCM (by simp [leaves]) g.v⟩

theorem PairGuards.afterLeft {h now a z} (g : PairGuards h now a z) :
    PublicGuards h (applyTx h now a) z :=
  after_one g.right (List.pairwise_append.mp g.nullifiers).2.2 (List.pairwise_append.mp g.commitments).2.2

private theorem longer {base now : State} (h : Hashes) (t : Tx)
    (ext : ∃ tail, now.births=base.births++tail) :
    ∃ tail, (applyTx h now t).births=base.births++tail := by
  obtain ⟨tail,eq⟩ := ext
  simp [extendBirths,eq,List.append_assoc]

theorem leg_evidence {h b hash le openRaw parent now n t key fee}
    (leg : LegOpening h b hash le openRaw parent n t key fee)
    (ext : ∃ tail, now.births=parent.births++tail) (guard : PublicGuards h now t) :
    TxEvidence h b now n t := evidence guard (lift_wires leg.wires leg.countBound ext)

private theorem spent_distinct {h b s n t} (e : TxEvidence h b s n t) (old : s.spent.Nodup) :
    (applyTx h s t).spent.Nodup := by
  change (published h t.j :: published h t.i :: s.spent).Nodup
  simpa [e.i.fresh,e.j.fresh,Ne.symm e.distinctNF] using old

/-- The two registrations can use different eligible parent counts. All four real/dummy
    selectors still publish fresh marks. No intermediate history or consistency certificate
    needs to be supplied for the left-to-right schedule. -/
theorem pair_conservation {h b hash le openRaw parent now na nz a z ka kz payer}
    (left : LegOpening h b hash le openRaw parent na a ka (feeFor payer false))
    (right : LegOpening h b hash le openRaw parent nz z kz (feeFor payer true))
    (guards : PairGuards h now a z) (ext : ∃ tail, now.births=parent.births++tail)
    (hist : HistoryOK h b now) :
    HistoryOK h b (applyPair h now a z) ∧
    (∀ c, holdings (applyPair h now a z) c+charge c=holdings now c) ∧
    (now.spent.Nodup → (applyPair h now a z).spent.Nodup) := by
  have ea := leg_evidence left ext guards.left
  have ez := leg_evidence right (longer h a ext) guards.afterLeft
  have ha := apply_ok hist ea
  refine ⟨apply_ok ha ez,?_,fun nd => spent_distinct ez (spent_distinct ea nd)⟩
  intro c
  have da := leg_delta hist ea left.gates c
  have dz := leg_delta ha ez right.gates c
  unfold applyPair
  cases payer <;> cases c <;> simp [feeFor,debitFor,charge] at * <;> omega

/-- All cross-leg real pairs refer to different chronological births. The conclusion is
    derived from the public mark guard, local binding and two selected funding paths. -/
theorem cross_leg_indices {h b hash le openRaw parent now na nz a z ka kz fa fz}
    (left : LegOpening h b hash le openRaw parent na a ka fa)
    (right : LegOpening h b hash le openRaw parent nz z kz fz) (g : PairGuards h now a z)
    (ext : ∃ tail, now.births=parent.births++tail) (hist : HistoryOK h b now)
    {i j} (mi : i∈[a.i,a.j]) (mj : j∈[z.i,z.j]) (ri : i.real=true) (rj : j.real=true) :
    pos h now i ≠ pos h now j := by
  have ea := leg_evidence left ext g.left
  have ez := leg_evidence right ext g.right
  have ei : SlotEvidence h b now na i := by
    rcases List.mem_cons.mp mi with eq | tail
    · exact eq ▸ ea.i
    · exact (List.mem_singleton.mp tail) ▸ ea.j
  have ej : SlotEvidence h b now nz j := by
    rcases List.mem_cons.mp mj with eq | tail
    · exact eq ▸ ez.i
    · exact (List.mem_singleton.mp tail) ▸ ez.j
  obtain ⟨u,atU,cu,_⟩ := funded_opening hist ei ri
  obtain ⟨v,atV,cv,_⟩ := funded_opening hist ej rj
  intro same
  rw [same,atV] at atU
  cases Option.some.inj atU
  have eq := same_spend_nf b ei.bodyScope ej.bodyScope ei.witnessScope ej.witnessScope cu cv
  have ni : published h i∈marks h a := List.mem_map_of_mem (f:=published h) mi
  have nj : published h j∈marks h z := List.mem_map_of_mem (f:=published h) mj
  exact (List.pairwise_append.mp g.nullifiers).2.2 _ ni _ nj (by simpa [published,ri,rj] using eq)

/-- Instantiated by the wire bridge with ordered, jointly authorized proof-emitted rows. -/
abbrev Admit := State → Nat → Tx → Nat → Nat → Tx → Nat → Bool → Prop

/-- Logical transactions at one fixed parent. Ordinary and all four supply routes use
    their existing registered gates. A swap has one constructor for both physical frames. -/
inductive Item (h : Hashes) (b : Binding h) (hash : Hash) (le : Digest → Digest → Bool)
    (openRaw : Nat → Nat → Nat) (admit : Admit) (base : State) (net : Nat)
    (w : FundedRefinement.Worker) (r : Registry) : Type where
  | single (entry : BlockItem h b base net w r)
  | swap {na nz a z ka kz payer} (signed : admit base na a ka nz z kz payer)
      (left : LegOpening h b hash le openRaw base na a ka (feeFor payer false))
      (right : LegOpening h b hash le openRaw base nz z kz (feeFor payer true))

namespace Item
variable {h b hash le openRaw admit base net w r}
def slots : Item h b hash le openRaw admit base net w r → List Tx
  | .single x => [x.t]
  | .swap (a:=a) (z:=z) _ _ _ => [a,z]

def fee (x : Item h b hash le openRaw admit base net w r) : Nat :=
  match x with
  | .single _ => 3
  | .swap (payer:=payer) _ _ _ => feeFor payer false + feeFor payer true

theorem fee_eq (x : Item h b hash le openRaw admit base net w r) : x.fee=3 := by
  cases x with
  | single => rfl
  | @swap _ _ _ _ _ _ payer _ _ _ => cases payer <;> rfl

def assetID (x : Item h b hash le openRaw admit base net w r) : Option AssetId :=
  match x with
  | .single e => blockID e
  | .swap .. => none

def insert (height : Nat) (rows : List FundedRefinement.SqlEvent)
    (x : Item h b hash le openRaw admit base net w r) :=
  match x with
  | .single e => insertItem height rows e
  | .swap .. => rows

/-- Both physical rows are swap slots with zero supply and no SQL registry event. -/
theorem swap_no_registry_write {admit : Admit} {na nz a z ka kz payer}
    (signed : admit base na a ka nz z kz payer)
    (left : LegOpening h b hash le openRaw base na a ka (feeFor payer false))
    (right : LegOpening h b hash le openRaw base nz z kz (feeFor payer true))
    (height : Nat) (rows : List FundedRefinement.SqlEvent) :
    (Item.swap (net:=net) (w:=w) (r:=r) signed left right).insert height rows=rows ∧
    (Item.swap (net:=net) (w:=w) (r:=r) signed left right).assetID=none := ⟨rfl,rfl⟩

def applyTo (now : State) (x : Item h b hash le openRaw admit base net w r) :=
  x.slots.foldl (applyTx h) now

end Item

private theorem after_slots {h now u} (ts : List Tx) (g : PublicGuards h now u)
    (nf : ∀ t∈ts, ∀ a∈marks h t, ∀ z∈marks h u, a≠z)
    (cm : ∀ t∈ts, ∀ a∈leaves h t, ∀ z∈leaves h u, a≠z) :
    PublicGuards h (ts.foldl (applyTx h) now) u := by
  induction ts generalizing now with
  | nil => exact g
  | cons t ts ih =>
    exact ih (after_one g (nf t (by simp)) (cm t (by simp)))
      (fun v hv => nf v (by simp [hv])) (fun v hv => cm v (by simp [hv]))

private theorem longer_slots {h} {base now : State} (ts : List Tx)
    (ext : ∃ tail, now.births=base.births++tail) :
    ∃ tail, (ts.foldl (applyTx h) now).births=base.births++tail := by
  induction ts generalizing now with
  | nil => exact ext
  | cons t ts ih => exact ih (longer h t ext)

section Schedule
variable {h : Hashes} {b : Binding h} {hash : Hash} {le : Digest → Digest → Bool}
  {openRaw : Nat → Nat → Nat} {admit : Admit} {base : State} {net : Nat}
  {w : FundedRefinement.Worker} {r : Registry}

local notation "Entry" => Item h b hash le openRaw admit base net w r

private theorem run_one (height : Nat) (x : Entry) (now : State) (rows : List FundedRefinement.SqlEvent)
    (ext : ∃ tail, now.births=base.births++tail)
    (g : ∀ t∈x.slots, PublicGuards h now t)
    (nf : (x.slots.flatMap (marks h)).Nodup) (cm : (x.slots.flatMap (leaves h)).Nodup)
    (same : ∀ id, x.assetID=some id → FundedRefinement.latest rows id=r id)
    (hist : HistoryOK h b now) (initial : Consistent now (FundedRefinement.latest rows))
    (nd : now.spent.Nodup) :
    HistoryOK h b (x.applyTo now) ∧ Consistent (x.applyTo now) (FundedRefinement.latest (x.insert height rows)) ∧
    (x.applyTo now).spent.Nodup ∧ holdings (x.applyTo now) .native+x.fee=holdings now .native := by
  cases x with
  | single e =>
    have ev := evidence (g e.t (by simp [Item.slots])) (lift_wires e.wires e.eligibleBound ext)
    have ok := apply_ok hist ev
    have unique := spent_distinct ev nd
    cases hp : e.policy with
    | ordinary gates =>
      have cash := ordinary_delta hist ev gates .native
      have tokens : Consistent (applyTx h now e.t) (FundedRefinement.latest rows) := by
        intro id
        have eq := ordinary_delta hist ev gates (.asset id)
        simp only [charge,Nat.add_zero] at eq
        exact ⟨eq.trans (initial id).1,(initial id).2⟩
      simpa [Item.applyTo,Item.slots,Item.insert,insertItem,Item.fee,hp] using
        And.intro ok (And.intro tokens (And.intro unique cash))
    | supply pkt eff res =>
      have old := same pkt.x.desc.publicId (by simp [Item.assetID,blockID,hp])
      let actual : FundedRefinement.PacketOK net w _ (FundedRefinement.latest rows) :=
        {pkt with parentGuard := old ▸ pkt.parentGuard}
      have tok := checked_packet hist actual eff ev res height initial
      have cash := supply_fee hist ev (same_payment eff ▸ FundedRefinement.residuals_gates res)
      simpa [Item.applyTo,Item.slots,Item.insert,insertItem,Item.fee,hp,actual] using
        And.intro ok (And.intro tok (And.intro unique cash))
  | @swap _ _ a z _ _ _ signed left right =>
    have pg : PairGuards h now a z := ⟨g _ (by simp [Item.slots]),g _ (by simp [Item.slots]),
      by simpa [Item.slots] using nf,by simpa [Item.slots] using cm⟩
    have ⟨ok,balance,unique⟩ := pair_conservation left right pg ext hist
    refine ⟨ok,?_,unique nd,?_⟩
    · intro id
      have eq := balance (.asset id)
      simp only [charge,Nat.add_zero] at eq
      exact ⟨eq.trans (initial id).1,(initial id).2⟩
    · rw [Item.fee_eq]
      exact balance .native

/-- Public guards are evaluated at the parent; pairwise disjoint published words
    across the entire physical block derive all intermediate guards. Distinct active
    supply IDs imply every SQL preflight still sees its parent row at its ordered write. -/
theorem schedule (height : Nat) (xs : List Entry) (now : State) (rows : List FundedRefinement.SqlEvent)
    (ext : ∃ tail, now.births=base.births++tail)
    (guards : ∀ e∈xs, ∀ t∈e.slots, PublicGuards h now t)
    (nf : (xs.flatMap (fun e => e.slots.flatMap (marks h))).Nodup)
    (cm : (xs.flatMap (fun e => e.slots.flatMap (leaves h))).Nodup)
    (ids : (xs.filterMap Item.assetID).Nodup)
    (same : ∀ id∈xs.filterMap Item.assetID, FundedRefinement.latest rows id=r id)
    (hist : HistoryOK h b now) (initial : Consistent now (FundedRefinement.latest rows))
    (nd : now.spent.Nodup) :
    let final := xs.foldl Item.applyTo now
    HistoryOK h b final ∧ Consistent final (FundedRefinement.latest (xs.foldl (Item.insert height) rows)) ∧
    final.spent.Nodup ∧ holdings final .native+(xs.map Item.fee).sum=holdings now .native := by
  induction xs generalizing now rows with
  | nil => exact ⟨hist,initial,nd,by simp⟩
  | cons x xs ih =>
    obtain ⟨hn,tn,cn⟩ := List.pairwise_append.mp nf
    obtain ⟨hc,tc,cc⟩ := List.pairwise_append.mp cm
    have next := run_one height x now rows ext (guards x (by simp)) hn hc
      (fun id mem => same id (List.mem_filterMap.mpr ⟨x,by simp,mem⟩)) hist initial nd
    have nextGuards : ∀ e∈xs, ∀ t∈e.slots, PublicGuards h (x.applyTo now) t := by
      intro e he t ht
      apply after_slots _ (guards e (by simp [he]) t ht)
      · intro a ha k hk j hj
        exact cn k (List.mem_flatMap.mpr ⟨a,ha,hk⟩) j
          (List.mem_flatMap.mpr ⟨e,he,List.mem_flatMap.mpr ⟨t,ht,hj⟩⟩)
      · intro a ha k hk j hj
        exact cc k (List.mem_flatMap.mpr ⟨a,ha,hk⟩) j
          (List.mem_flatMap.mpr ⟨e,he,List.mem_flatMap.mpr ⟨t,ht,hj⟩⟩)
    have remaining : (xs.filterMap Item.assetID).Nodup := by
      cases eq : x.assetID with
      | none => simpa only [List.filterMap_cons,eq] using ids
      | some id =>
        have nodup : (id::xs.filterMap Item.assetID).Nodup := by
          simpa only [List.filterMap_cons,eq] using ids
        exact (List.nodup_cons.mp nodup).2
    have unchanged : ∀ id∈xs.filterMap Item.assetID, FundedRefinement.latest (x.insert height rows) id=r id := by
      intro id hid
      obtain ⟨e,he,eq⟩ := List.mem_filterMap.mp hid
      have old := same id (List.mem_filterMap.mpr ⟨e,List.mem_cons_of_mem _ he,eq⟩)
      cases x with
      | swap => exact old
      | single entry =>
        cases hp : entry.policy with
        | ordinary => simpa [Item.insert,insertItem,hp] using old
        | supply pkt _ _ =>
          have skip : pkt.x.desc.publicId∉xs.filterMap Item.assetID := by
            have nodup : (pkt.x.desc.publicId::xs.filterMap Item.assetID).Nodup := by
              simpa [List.filterMap_cons,Item.assetID,blockID,hp] using ids
            exact (List.nodup_cons.mp nodup).1
          have diff : id≠pkt.x.desc.publicId := fun sameID => skip (sameID ▸ hid)
          simpa [Item.insert,insertItem,hp,FundedRefinement.latest_after_insert,write,diff] using old
    obtain ⟨hok,cons,uniq,cash⟩ := ih _ _ (longer_slots x.slots ext) nextGuards tn tc remaining
      unchanged next.1 next.2.1 next.2.2.1
    refine ⟨hok,cons,uniq,?_⟩
    have paid := next.2.2.2
    simp only [List.foldl_cons,List.map_cons,List.sum_cons]
    change holdings (xs.foldl Item.applyTo (x.applyTo now)) .native + (xs.map Item.fee).sum =
      holdings (x.applyTo now) .native at cash
    omega

end Schedule
namespace Item
variable {h b hash le openRaw admit base net w r}

def checked (p : FundedRefinement.PublicState) (x : Item h b hash le openRaw admit base net w r) : Prop :=
  match x with
  | .single e => parentChecked p e
  | .swap (a:=a) (z:=z) _ _ _ => PairGuards h base a z

theorem checked_guards {p : FundedRefinement.PublicState}
    (x : Item h b hash le openRaw admit base net w r) (proj : PublicProjection base p)
    (ok : x.checked p) : ∀ t∈x.slots, PublicGuards h base t := by
  cases x with
  | single e =>
    rintro t ht
    obtain rfl : t=e.t := List.mem_singleton.mp ht
    exact parent_guards proj ok
  | swap signed a z =>
    rintro t ht
    rcases List.mem_cons.mp ht with eq | tail
    · exact eq ▸ ok.left
    · exact (List.mem_singleton.mp tail) ▸ ok.right

end Item

/-- The public state function denotes the selected node view at the indexed occurrence
    state. Membership and SQL projection, branch choice and faithful initial interpretation
    remain explicit. The accepting logical items are checked against this common parent. -/
structure Block (h : Hashes) (b : Binding h) (hash : Hash) (le : Digest → Digest → Bool)
    (openRaw : Nat → Nat → Nat) (admit : Admit) (net : Nat) (w : FundedRefinement.Worker)
    (publicAt : State → FundedRefinement.PublicState) (base : State)
    (rows : List FundedRefinement.SqlEvent) where
  items : List (Item h b hash le openRaw admit base net w (FundedRefinement.latest rows))
  capacity : (items.flatMap Item.slots).length≤4
  projection : PublicProjection base (publicAt base)
  checked : ∀ e∈items, e.checked (publicAt base)
  nfs : (items.flatMap (fun e => e.slots.flatMap (marks h))).Nodup
  cms : (items.flatMap (fun e => e.slots.flatMap (leaves h))).Nodup
  ids : (items.filterMap Item.assetID).Nodup
  reward : Body
  rewardScope : b.bodyAllowed reward
  rewardFresh : commit h reward∉(items.foldl Item.applyTo base).births.map Occurrence.cm
  rewardToken : reward.token.val=0
  rewardNative : reward.native.val=100+(items.map Item.fee).sum

namespace Block
variable {h b hash le openRaw admit net w publicAt base rows}
variable (block : Block h b hash le openRaw admit net w publicAt base rows)

def result := birth h (block.items.foldl Item.applyTo base) block.reward
def registryRows := block.items.foldl (Item.insert ((publicAt base).height+1)) rows

/-- The fold counts the two swap fees as physically emitted. Their sum is exactly
    three for any payer side, producing one charge per logical transaction. -/
theorem fees :
    (block.items.map Item.fee).sum = 3*block.items.length ∧ block.items.length≤4 := by
  have totals (xs : List (Item h b hash le openRaw admit base net w (FundedRefinement.latest rows))) :
      (xs.map Item.fee).sum=3*xs.length ∧ xs.length≤(xs.flatMap Item.slots).length := by
    induction xs with
    | nil => simp
    | cons a xs ih =>
      have nonempty : 1≤a.slots.length := by cases a <;> simp [Item.slots]
      simp only [List.map_cons,List.sum_cons,List.length_cons,List.flatMap_cons,List.length_append,Item.fee_eq]
      omega
  have total := totals block.items
  exact ⟨total.1,Nat.le_trans total.2 block.capacity⟩

theorem invariant (hist : HistoryOK h b base) (initial : Consistent base (FundedRefinement.latest rows))
    (nd : base.spent.Nodup) :
    HistoryOK h b block.result ∧ Consistent block.result (FundedRefinement.latest block.registryRows) ∧
    block.result.spent.Nodup ∧ holdings block.result .native=holdings base .native+100 ∧
    block.reward.native.val=100+3*block.items.length ∧ block.reward.native.val≤112 := by
  obtain ⟨hok,c,u,money⟩ := schedule ((publicAt base).height+1) block.items base rows ⟨[],by simp⟩
    (fun e mem => e.checked_guards block.projection (block.checked e mem))
    block.nfs block.cms block.ids (fun _ _ => rfl) hist initial nd
  have face := block.rewardNative
  obtain ⟨sum,capacity⟩ := block.fees
  refine ⟨birth_ok hok block.rewardScope block.rewardFresh,?_,u,?_,by omega,by omega⟩
  · intro id
    simpa [result,birth_value hok,bodyValue,block.rewardToken,registryRows] using c id
  · unfold result
    rw [birth_value hok]
    change _+block.reward.native.val=_
    omega

end Block

/-- Induction over complete selected blocks from an arbitrary imported, faithful prefix.
    The start index can be H25 or later. A block requires only its local public/private
    evidence. A detached suffix and its competitor are separate derivations from the
    common state and rows. No intermediate consistency or native-supply invariant is a
    premise of the block constructor. -/
inductive History (h : Hashes) (b : Binding h) (hash : Hash) (le : Digest → Digest → Bool)
    (openRaw : Nat → Nat → Nat) (admit : Admit) (net : Nat) (w : FundedRefinement.Worker)
    (publicAt : State → FundedRefinement.PublicState) (start : State)
    (initialRows : List FundedRefinement.SqlEvent) : State → List FundedRefinement.SqlEvent → Nat → Prop
  | start : History h b hash le openRaw admit net w publicAt start initialRows start initialRows 0
  | next {now rows count} : History h b hash le openRaw admit net w publicAt start initialRows now rows count →
      (block : Block h b hash le openRaw admit net w publicAt now rows) →
      (publicAt now).height=(publicAt start).height+count →
      History h b hash le openRaw admit net w publicAt start initialRows block.result block.registryRows (count+1)

theorem selected_history {h b hash le openRaw admit net w publicAt start initialRows final rows count}
    (selected : History h b hash le openRaw admit net w publicAt start initialRows final rows count)
    (hist : HistoryOK h b start) (initial : Consistent start (FundedRefinement.latest initialRows))
    (nd : start.spent.Nodup) :
    HistoryOK h b final ∧ Consistent final (FundedRefinement.latest rows) ∧
    final.spent.Nodup ∧ holdings final .native=holdings start .native+100*count := by
  induction selected with
  | start => exact ⟨hist,initial,nd,by simp⟩
  | next _ block _ ih =>
    obtain ⟨hok,c,u,cash⟩ := ih
    obtain ⟨next,aligned,unique,delta,_⟩ := block.invariant hok c u
    exact ⟨next,aligned,unique,by omega⟩

#print axioms local_amounts
#print axioms cross_leg_indices
#print axioms pair_conservation
#print axioms schedule
#print axioms Block.invariant
#print axioms selected_history
end FundedSwap

namespace FundedSwap
open FundedC hiding State holdings
open FundedSupply FundedOccurrence
open FundedAnchor (Hash Digest)

/-- Cardinality of a finite set represented by a list, counting the last occurrence
    of each element. This agrees with Python's len(set(...)) for decoded canonical words. -/
def distinctCount [DecidableEq α] : List α → Nat
  | [] => 0
  | a::xs => if a∈xs then distinctCount xs else distinctCount xs+1

theorem distinctCount_le [DecidableEq α] (xs : List α) : distinctCount xs≤xs.length := by
  induction xs with
  | nil => simp [distinctCount]
  | cons a xs ih =>
    by_cases mem : a∈xs <;> simp [distinctCount,mem] <;> omega

theorem distinctCount_eq_iff [DecidableEq α] (xs : List α) : distinctCount xs=xs.length ↔ xs.Nodup := by
  induction xs with
  | nil => simp [distinctCount]
  | cons a xs ih =>
    by_cases mem : a∈xs
    · have upper := distinctCount_le xs
      simp [distinctCount,mem]
      omega
    · simp [distinctCount,mem,ih]

/-- A normalized physical ManagedSlot row at the ordered group_effects boundary. -/
structure EmittedSlot where
  nf0 : Nat
  nf1 : Nat
  cm0 : Nat
  cm1 : Nat
  issueID : AssetId
  supply : Nat
  deriving DecidableEq

namespace EmittedSlot

def nfs (s : EmittedSlot) := [s.nf0,s.nf1]
def cms (s : EmittedSlot) := [s.cm0,s.cm1]
def activeID (s : EmittedSlot) := if s.supply=0 then none else some s.issueID

def ofTx (h : Hashes) (t : Tx) (id : AssetId) (word : Nat) : EmittedSlot :=
  ⟨published h t.i,published h t.j,commit h t.u,commit h t.v,id,word⟩

/-- The deployed three set-size checks, after the packet vector capacity check.
    The count is the number of physical packets in the parsed block vector. -/
def checked (physicalCount : Nat) (rows : List EmittedSlot) : Bool :=
  decide (physicalCount≤4 ∧ distinctCount (rows.flatMap nfs)=(rows.flatMap nfs).length ∧
    distinctCount (rows.flatMap cms)=(rows.flatMap cms).length ∧
    distinctCount (rows.filterMap activeID)=(rows.filterMap activeID).length)

end EmittedSlot

namespace Item
variable {h b hash le openRaw admit base net w r}

/-- Per-item expected public projection. Ordering, including the two sides and
    the two NF and CM positions inside each side, is preserved. For supply events
    use the decoded public descriptor, including the high burn bit in the word. -/
def emitted (x : Item h b hash le openRaw admit base net w r) : List EmittedSlot :=
  match x with
  | .single e =>
    match e.policy with
    | .ordinary _ => [EmittedSlot.ofTx h e.t zeroId 0]
    | .supply pkt _ _ => [EmittedSlot.ofTx h e.t pkt.x.desc.publicId pkt.x.desc.word]
  | .swap (a:=a) (z:=z) _ _ _ => [EmittedSlot.ofTx h a zeroId 0,EmittedSlot.ofTx h z zeroId 0]

theorem emitted_projection (x : Item h b hash le openRaw admit base net w r) :
    x.emitted.length=x.slots.length ∧ x.emitted.flatMap EmittedSlot.nfs=x.slots.flatMap (marks h) ∧
    x.emitted.flatMap EmittedSlot.cms=x.slots.flatMap (leaves h) ∧
    x.emitted.filterMap EmittedSlot.activeID=x.assetID.toList := by
  cases x with
  | swap => exact ⟨rfl,rfl,rfl,rfl⟩
  | single e =>
    cases hp : e.policy with
    | ordinary => simp [emitted,slots,assetID,blockID,hp,EmittedSlot.activeID,EmittedSlot.ofTx,
        EmittedSlot.nfs,EmittedSlot.cms,marks,leaves]
    | supply pkt eff res =>
      have pos := pkt.x.nonzero
      have wd := pkt.x.signedWord
      have nonzero : pkt.x.desc.word≠0 := by omega
      simp [emitted,slots,assetID,blockID,hp,EmittedSlot.activeID,EmittedSlot.ofTx,nonzero,
        EmittedSlot.nfs,EmittedSlot.cms,marks,leaves]

end Item

/-- A successful check of the ordered public vector supplies all four block guards.
    The alignment premise is componentwise equality of the ordered emitted rows with
    the exact two-NF/two-CM projections of these admitted items. Neither it nor the
    physical frame/row correspondence asserts uniqueness within or across items. -/
theorem checked_block_guards {h b hash le openRaw admit base net w r}
    (xs : List (Item h b hash le openRaw admit base net w r))
    (physicalCount : Nat) (raw : List EmittedSlot) (onePerFrame : physicalCount=raw.length)
    (ordered : ∀ i : Nat, raw[i]?=(xs.flatMap Item.emitted)[i]?)
    (ok : EmittedSlot.checked physicalCount raw=true) :
    (xs.flatMap Item.slots).length≤4 ∧
    (xs.flatMap (fun e => e.slots.flatMap (marks h))).Nodup ∧
    (xs.flatMap (fun e => e.slots.flatMap (leaves h))).Nodup ∧
    (xs.filterMap Item.assetID).Nodup := by
  have projections (xs : List (Item h b hash le openRaw admit base net w r)) :
      (xs.flatMap Item.emitted).length=(xs.flatMap Item.slots).length ∧
      (xs.flatMap Item.emitted).flatMap EmittedSlot.nfs =
        xs.flatMap (fun e => e.slots.flatMap (marks h)) ∧
      (xs.flatMap Item.emitted).flatMap EmittedSlot.cms =
        xs.flatMap (fun e => e.slots.flatMap (leaves h)) ∧
      (xs.flatMap Item.emitted).filterMap EmittedSlot.activeID=xs.filterMap Item.assetID := by
    induction xs with
    | nil => exact ⟨rfl,rfl,rfl,rfl⟩
    | cons x xs ih =>
      have proj := x.emitted_projection
      simp only [List.flatMap_cons,List.length_append,List.flatMap_append,List.filterMap_append,
        proj.1,proj.2.1,proj.2.2.1,proj.2.2.2,ih.1,ih.2.1,ih.2.2.1,ih.2.2.2,List.filterMap_cons]
      cases x.assetID <;> simp
  have exactRows : raw=xs.flatMap Item.emitted := List.ext_getElem? ordered
  obtain ⟨len,nf,cm,ids⟩ := projections xs
  simp only [EmittedSlot.checked,decide_eq_true_eq,distinctCount_eq_iff] at ok
  rw [onePerFrame,exactRows,len,nf,cm,ids] at ok
  exact ok

#print axioms distinctCount_eq_iff
#print axioms checked_block_guards
end FundedSwap

namespace FundedSwap
open FundedC

/-- Finite public-vector control. A leading supply row and the two physically adjacent
    swap rows are internally distinct. Changing either swap row to reuse a leading
    public effect fails the full vector guard. Zero-word rows may repeat the zero ID. -/
theorem cross_item_set_checks :
    let single : EmittedSlot := ⟨1,2,21,22,FundedSupply.testId,8⟩
    let left : EmittedSlot := ⟨3,4,23,24,zeroId,0⟩
    let right : EmittedSlot := ⟨5,6,25,26,zeroId,0⟩
    let other : EmittedSlot := ⟨7,8,27,28,FundedSupply.testId,1⟩
    EmittedSlot.checked 3 [single,left,right]=true ∧
    EmittedSlot.checked 2 [left,{right with nf0:=2,cm1:=21}]=true ∧
    EmittedSlot.checked 3 [single,left,{right with nf0:=2}]=false ∧
    EmittedSlot.checked 3 [single,{left with cm1:=21},right]=false ∧
    EmittedSlot.checked 4 [single,left,right,other]=false ∧
    EmittedSlot.checked 5 [single,left,right,{other with issueID:=zeroId,supply:=0},
      ⟨9,10,29,30,zeroId,0⟩]=false := by decide

#print axioms cross_item_set_checks
end FundedSwap
