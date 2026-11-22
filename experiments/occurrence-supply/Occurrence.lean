import Refinement

/-! Selected chronological occurrences. No spending credential or future real nullifier is
    stored in a birth. A debit records an opening only when an actual real spend occurs. -/
namespace FundedOccurrence
open FundedC
open FundedSupply

structure Body where
  pk : Nat
  rho : Nat
  raw : Nat
  native : Fin B
  token : Fin B
  asset : AssetId
  deriving DecidableEq
structure Occurrence where
  cm : Nat
  body : Body
  deriving DecidableEq
structure Spend where
  ask : Nat
  nk : Nat
  body : Body
  deriving DecidableEq
structure Debit where
  pos : Nat
  nf : Nat
  witness : Spend
  deriving DecidableEq
structure State where
  births : List Occurrence
  spent : List Nat
  debits : List Debit

def bodyValue (b : Body) : Currency → Nat
  | .native => b.native.val
  | .asset id => if b.asset=id then b.token.val else 0

def liveSum (c : Currency) (used : List Nat) (base : Nat) : List Occurrence → Nat
  | [] => 0
  | x::xs => (if base ∈ used then 0 else bodyValue x.body c) + liveSum c used (base+1) xs

def holdings (s : State) (c : Currency) := liveSum c (s.debits.map Debit.pos) 0 s.births

structure Hashes where
  typed : AssetId → Nat → Nat → Nat
  ak : Nat → Nat
  pk : Nat → Nat → Nat
  inner : Nat → Nat → Nat → Nat
  cm : Nat → Nat → Nat
  realNF : Nat → Nat → Nat → Nat
  dummyNF : Nat → Nat → Nat → Nat
  rho : Nat → Nat → Nat → Nat

def typed (h : Hashes) (b : Body) := h.typed b.asset b.token.val b.raw
def inner (h : Hashes) (b : Body) := h.inner b.pk b.rho (typed h b)
def commit (h : Hashes) (b : Body) := h.cm (inner h b) b.native.val
def trueNF (h : Hashes) (w : Spend) := h.realNF w.nk w.body.rho (typed h w.body)
def owner (h : Hashes) (w : Spend) := h.pk (h.ak w.ask) w.nk

def Compatible (h : Hashes) (w : Spend) (o : Occurrence) : Prop :=
  owner h w=w.body.pk ∧ commit h w.body=o.cm

/-- These are local collision exclusions on the actual domain-separated primitive
    preimages encountered in the considered history/openings. There is no injectivity
    assumption for NF, no global injectivity over an infinite domain and no owner
    preimage assumption for a new output. -/
structure Binding (h : Hashes) where
  bodyAllowed : Body → Prop
  spendAllowed : Spend → Prop
  cmBinding : ∀ a b, bodyAllowed a → bodyAllowed b → commit h a=commit h b →
    (inner h a,a.native.val)=(inner h b,b.native.val)
  innerBinding : ∀ a b, bodyAllowed a → bodyAllowed b → inner h a=inner h b →
    (a.pk,a.rho,typed h a)=(b.pk,b.rho,typed h b)
  typedBinding : ∀ a b, bodyAllowed a → bodyAllowed b → typed h a=typed h b →
    (a.asset,a.token.val,a.raw)=(b.asset,b.token.val,b.raw)
  pkBinding : ∀ u v, spendAllowed u → spendAllowed v → owner h u=owner h v →
    (h.ak u.ask,u.nk)=(h.ak v.ask,v.nk)

theorem commitment_body {h} (bind : Binding h) {a b}
    (qa : bind.bodyAllowed a) (qb : bind.bodyAllowed b) (eq : commit h a=commit h b) : a=b := by
  have hc := bind.cmBinding a b qa qb eq
  have hi := bind.innerBinding a b qa qb (congrArg Prod.fst hc)
  have ht := bind.typedBinding a b qa qb (congrArg (fun p => p.2.2) hi)
  have hn : a.native=b.native := Fin.ext (congrArg Prod.snd hc)
  have hq : a.token=b.token := Fin.ext (congrArg (fun p => p.2.1) ht)
  cases a; cases b
  simp_all

theorem same_spend_nf {h} (bind : Binding h) {u v : Spend} {o : Occurrence}
    (bu : bind.bodyAllowed u.body) (bv : bind.bodyAllowed v.body)
    (su : bind.spendAllowed u) (sv : bind.spendAllowed v)
    (hu : Compatible h u o) (hv : Compatible h v o) : trueNF h u=trueNF h v := by
  have same := commitment_body bind bu bv (hu.2.trans hv.2.symm)
  have pub : owner h u=owner h v := hu.1.trans ((congrArg Body.pk same).trans hv.1.symm)
  have keys := congrArg Prod.snd (bind.pkBinding u v su sv pub)
  change u.nk=v.nk at keys
  simp [trueNF,same,keys]

def prefixHit (s : State) (count cm : Nat) := cm ∈ (s.births.take count).map Occurrence.cm
def lookupPosition (s : State) (cm : Nat) := (s.births.map Occurrence.cm).idxOf cm

private theorem idx_unique (xs : List Occurrence) (nd : (xs.map Occurrence.cm).Nodup) {k x}
    (hit : xs[k]?=some x) : (xs.map Occurrence.cm).idxOf x.cm=k := by
  induction xs generalizing k with
  | nil => simp at hit
  | cons a xs ih =>
    obtain ⟨no,rest⟩ := List.nodup_cons.mp nd
    cases k with
    | zero => simp at hit; subst a; simp
    | succ k =>
      simp only [List.getElem?_cons_succ] at hit
      have ne : a.cm≠x.cm := by
        intro eq
        exact no (List.mem_map.mpr ⟨x,List.mem_of_getElem? hit,eq.symm⟩)
      have be : (a.cm == x.cm)=false := beq_eq_false_iff_ne.mpr ne
      simp [List.idxOf_cons,be,ih rest hit]

theorem selected_position (s : State) (count cm : Nat) (nd : (s.births.map Occurrence.cm).Nodup)
    (member : prefixHit s count cm) :
    ∃ o, s.births[lookupPosition s cm]?=some o ∧ o.cm=cm ∧ lookupPosition s cm<count ∧
      ∀ k y, s.births[k]?=some y → y.cm=cm → k=lookupPosition s cm := by
  obtain ⟨o,mem,eq⟩ := List.mem_map.mp member
  obtain ⟨k,atK⟩ := List.mem_iff_getElem?.mp mem
  have bound := (List.getElem?_eq_some_iff.mp atK).choose
  have small : k<count := by simp [List.length_take] at bound; omega
  rw [List.getElem?_take_of_lt small] at atK
  have idx : lookupPosition s cm=k := by rw [← eq]; exact idx_unique _ nd atK
  exact ⟨o,idx ▸ atK,eq,idx ▸ small,fun j y atJ matchCM => by
    change j=(s.births.map Occurrence.cm).idxOf cm
    rw [← matchCM]; exact (idx_unique _ nd atJ).symm⟩

structure HistoryOK (h : Hashes) (b : Binding h) (s : State) : Prop where
  distinctCM : (s.births.map Occurrence.cm).Nodup
  distinctDebit : (s.debits.map Debit.pos).Nodup
  bodies : ∀ o∈s.births, o.cm=commit h o.body ∧ b.bodyAllowed o.body
  debitOrigin : ∀ d∈s.debits, ∃ o, s.births[d.pos]?=some o ∧
    Compatible h d.witness o ∧ b.bodyAllowed d.witness.body ∧ b.spendAllowed d.witness ∧
    d.nf=trueNF h d.witness ∧ d.nf∈s.spent

/-- The node checks NF freshness. This theorem derives the unused position needed for
    accounting from that check and the *earlier real spend*, if such a debit existed. -/
theorem fresh_nf_implies_unused_position {h s w o k} (b : Binding h) (hist : HistoryOK h b s)
    (entry : s.births[k]?=some o) (right : Compatible h w o) (bw : b.bodyAllowed w.body)
    (sw : b.spendAllowed w) (fresh : trueNF h w∉s.spent) : k∉s.debits.map Debit.pos := by
  intro present
  obtain ⟨d,hd,eq⟩ := List.mem_map.mp present
  obtain ⟨old,whereOld,opened,bo,so,used,seen⟩ := hist.debitOrigin d hd
  rw [eq,entry] at whereOld
  have same := Option.some.inj whereOld
  subst old
  have nf := same_spend_nf b bw bo sw so right opened
  exact fresh ((nf.trans used.symm) ▸ seen)

structure Slot where
  real : Bool
  w : Spend

def published (h : Hashes) (i : Slot) :=
  if i.real then trueNF h i.w else h.dummyNF i.w.nk i.w.body.rho (typed h i.w.body)

def pos (h : Hashes) (s : State) (i : Slot) := lookupPosition s (commit h i.w.body)
def consume (h : Hashes) (s : State) (i : Slot) : State where
  births := s.births
  spent := published h i :: s.spent
  debits := if i.real then ⟨pos h s i,trueNF h i.w,i.w⟩ :: s.debits else s.debits

def birth (h : Hashes) (s : State) (v : Body) : State :=
  {s with births := s.births ++ [⟨commit h v,v⟩]}

structure SlotEvidence (h : Hashes) (b : Binding h) (s : State) (count : Nat) (i : Slot) : Prop where
  fresh : published h i ∉ s.spent
  witnessScope : b.spendAllowed i.w
  bodyScope : b.bodyAllowed i.w.body
  authorized : i.real=true → owner h i.w=i.w.body.pk
  member : i.real=true → prefixHit s count (commit h i.w.body)

/-- Recovers the value-carrying occurrence and proves it has never been debited. -/
theorem funded_opening {h s count i} {b : Binding h} (ok : HistoryOK h b s)
    (ev : SlotEvidence h b s count i) (real : i.real=true) :
    ∃ o, s.births[pos h s i]?=some o ∧ Compatible h i.w o ∧
      i.w.body=o.body ∧ pos h s i < count ∧ pos h s i ∉ s.debits.map Debit.pos := by
  obtain ⟨o,idx,cm,lt,_⟩ := selected_position _ _ _ ok.distinctCM (ev.member real)
  have auth : Compatible h i.w o := ⟨ev.authorized real,cm.symm⟩
  obtain ⟨hc,hb⟩ := ok.bodies o (List.mem_of_getElem? idx)
  have body := commitment_body b ev.bodyScope hb (cm.symm.trans hc)
  have unused := fresh_nf_implies_unused_position b ok idx auth ev.bodyScope ev.witnessScope
    (by simpa [published,real] using ev.fresh)
  exact ⟨o,idx,auth,body,lt,unused⟩

theorem consume_ok {h s n i} {b : Binding h} (ok : HistoryOK h b s)
    (ev : SlotEvidence h b s n i) : HistoryOK h b (consume h s i) := by
  have preserve (d : Debit) (hd : d∈s.debits) := ok.debitOrigin d hd
  constructor
  · exact ok.distinctCM
  · cases hi : i.real with
    | false => simpa [consume,hi] using ok.distinctDebit
    | true =>
      obtain ⟨_,_,_,_,_,unused⟩ := funded_opening ok ev hi
      simpa [consume,hi] using List.nodup_cons.mpr ⟨unused,ok.distinctDebit⟩
  · exact ok.bodies
  · intro d hd
    by_cases old : d∈s.debits
    · obtain ⟨o,atD,auth,bw,sw,nf,seen⟩ := preserve d old
      exact ⟨o,atD,auth,bw,sw,nf,List.mem_cons_of_mem _ seen⟩
    · cases hi : i.real with
      | false => simp [consume,hi,old] at hd
      | true =>
        simp [consume,hi,old] at hd
        subst d
        obtain ⟨o,entry,auth,_⟩ := funded_opening ok ev hi
        exact ⟨o,entry,auth,ev.bodyScope,ev.witnessScope,rfl,by simp [consume,published,hi]⟩

theorem birth_ok {h s v} {b : Binding h} (ok : HistoryOK h b s)
    (scope : b.bodyAllowed v) (fresh : commit h v∉s.births.map Occurrence.cm) :
    HistoryOK h b (birth h s v) := by
  constructor
  · simp only [birth,List.map_append,List.map_cons,List.map_nil]
    apply List.pairwise_append.mpr
    refine ⟨ok.distinctCM,by simp,?_⟩
    intro a ha y hy
    simp at hy
    exact fun eq => fresh ((eq.trans hy) ▸ ha)
  · exact ok.distinctDebit
  · intro o ho
    simp [birth] at ho
    rcases ho with old | rfl
    · exact ok.bodies _ old
    · exact ⟨rfl,scope⟩
  · intro d hd
    obtain ⟨o,entry,rest⟩ := ok.debitOrigin _ hd
    exact ⟨o,(List.getElem?_append_left ((List.getElem?_eq_some_iff.mp entry).choose)).trans entry,rest⟩

private theorem earlier (c used k a xs) (lt : k<a) :
    liveSum c (k::used) a xs=liveSum c used a xs := by
  induction xs generalizing a with
  | nil => rfl
  | cons x xs ih =>
    simp [liveSum,show a≠k by omega,ih (a+1) (by omega)]

private theorem subtract_at (c used base k xs o) (idx : xs[k]?=some o) (free : base+k∉used) :
    liveSum c ((base+k)::used) base xs + bodyValue o.body c=liveSum c used base xs := by
  induction xs generalizing k base with
  | nil => simp at idx
  | cons x xs ih =>
    cases k with
    | zero =>
      simp at idx; subst x
      simp at free
      simp [liveSum,free,earlier c used base (base+1) xs (by omega),Nat.add_comm]
    | succ k =>
      simp only [List.getElem?_cons_succ] at idx
      have eq : base+(k+1)=(base+1)+k := by omega
      have ne : base≠base+(k+1) := by omega
      have acc := ih (base+1) k idx (eq ▸ free)
      simp only [liveSum,List.mem_cons,ne,false_or]
      rw [eq]
      omega

private theorem live_append (c used base xs ys) :
    liveSum c used base (xs++ys)=liveSum c used base xs+liveSum c used (base+xs.length) ys := by
  induction xs generalizing base with
  | nil => simp [liveSum]
  | cons x xs ih =>
    simp only [List.cons_append,liveSum,List.length_cons,ih]
    rw [show base+(xs.length+1)=base+1+xs.length by omega]
    omega

theorem consume_value {h s n i} {b : Binding h} (ok : HistoryOK h b s)
    (ev : SlotEvidence h b s n i) (c : Currency) (zero : i.real=false → bodyValue i.w.body c=0) :
    holdings (consume h s i) c + bodyValue i.w.body c=holdings s c := by
  cases hi : i.real with
  | false => simp [holdings,consume,hi,zero hi]
  | true =>
    obtain ⟨o,entry,_,eq,_,free⟩ := funded_opening ok ev hi
    have sub := subtract_at c (s.debits.map Debit.pos) 0 (pos h s i) s.births o entry (by simpa using free)
    simpa [holdings,consume,hi,eq] using sub

theorem birth_value {h s v} {b : Binding h} (ok : HistoryOK h b s) (c : Currency) :
    holdings (birth h s v) c=holdings s c+bodyValue v c := by
  have free : s.births.length∉s.debits.map Debit.pos := by
    intro hit
    obtain ⟨d,hd,eq⟩ := List.mem_map.mp hit
    obtain ⟨o,entry,_⟩ := ok.debitOrigin d hd
    have lt := (List.getElem?_eq_some_iff.mp entry).choose
    omega
  simp [holdings,birth,live_append,liveSum,free]


structure Tx where
  i : Slot
  j : Slot
  u : Body
  v : Body
  asset : AssetId

/-- Only the local equations of 1A/1B use this adapter. The NF word on its output
    Note is erased by those equations and is never stored in the occurrence ledger. -/
def noteView (body : Body) (cm nf : Nat) : Note :=
  ⟨cm,nf,body.native.val,body.token.val,body.asset⟩
def inputView (h : Hashes) (i : Slot) : Input :=
  ⟨noteView i.w.body (commit h i.w.body) (published h i),i.real,published h i⟩
def paymentView (h : Hashes) (t : Tx) : Payment :=
  ⟨inputView h t.i,inputView h t.j,noteView t.u (commit h t.u) 0,
    noteView t.v (commit h t.v) 0,t.asset⟩

@[simp] theorem value_view (b : Body) (cm nf : Nat) (c : Currency) :
    value (noteView b cm nf) c=bodyValue b c := by cases c <;> rfl

def applyTx (h : Hashes) (s : State) (t : Tx) :=
  birth h (birth h (consume h (consume h s t.i) t.j) t.u) t.v

structure TxEvidence (h : Hashes) (b : Binding h) (s : State) (n : Nat) (t : Tx) : Prop where
  i : SlotEvidence h b s n t.i
  j : SlotEvidence h b s n t.j
  distinctNF : published h t.i≠published h t.j
  freshU : commit h t.u∉s.births.map Occurrence.cm
  freshV : commit h t.v∉s.births.map Occurrence.cm
  distinctCM : commit h t.u≠commit h t.v
  scopeU : b.bodyAllowed t.u
  scopeV : b.bodyAllowed t.v
  rhoU : t.u.rho=h.rho (published h t.i) (published h t.j) 0
  rhoV : t.v.rho=h.rho (published h t.i) (published h t.j) 1

private theorem secondSlot {h b s n t} (e : TxEvidence h b s n t) :
    SlotEvidence h b (consume h s t.i) n t.j :=
  {e.j with fresh := by simp [consume,Ne.symm e.distinctNF,e.j.fresh]}

theorem distinct_real_indices {h b s n t} (ok : HistoryOK h b s) (e : TxEvidence h b s n t)
    (ri : t.i.real=true) (rj : t.j.real=true) : pos h s t.i≠pos h s t.j := by
  obtain ⟨a,atA,openA,_⟩ := funded_opening ok e.i ri
  obtain ⟨z,atZ,openZ,_⟩ := funded_opening ok e.j rj
  intro eq
  rw [eq,atZ] at atA
  cases Option.some.inj atA
  have same := same_spend_nf b e.i.bodyScope e.j.bodyScope e.i.witnessScope e.j.witnessScope openA openZ
  exact e.distinctNF (by simpa [published,ri,rj] using same)

private theorem afterU {h b s n t} (ok : HistoryOK h b s) (e : TxEvidence h b s n t) :
    HistoryOK h b (birth h (consume h (consume h s t.i) t.j) t.u) :=
  birth_ok (consume_ok (consume_ok ok e.i) (secondSlot e)) e.scopeU e.freshU

theorem apply_ok {h b s n t} (ok : HistoryOK h b s) (e : TxEvidence h b s n t) :
    HistoryOK h b (applyTx h s t) := by
  apply birth_ok (afterU ok e) e.scopeV
  simpa only [birth,consume,List.map_append,List.mem_append,List.map_cons,List.map_nil,
    List.mem_cons,List.not_mem_nil,or_false,not_or] using And.intro e.freshV (Ne.symm e.distinctCM)

private theorem zero_slot {h i} (g : dummyGate (inputView h i)) (c : Currency) (dummy : i.real=false) :
    bodyValue i.w.body c=0 := by
  have ⟨cn,cq⟩ := dummy_zero (inputView h i) ⟨i.w.body.native.isLt,i.w.body.token.isLt⟩ g dummy
  change i.w.body.native.val=0 at cn
  change i.w.body.token.val=0 at cq
  cases c <;> simp [bodyValue,cn,cq]

theorem selected_flow {h b s n t} (ok : HistoryOK h b s) (e : TxEvidence h b s n t)
    (di : dummyGate (inputView h t.i)) (dj : dummyGate (inputView h t.j)) (c : Currency) :
    holdings (applyTx h s t) c + bodyValue t.i.w.body c + bodyValue t.j.w.body c =
      holdings s c + bodyValue t.u c + bodyValue t.v c := by
  have ai := consume_value ok e.i c (zero_slot di c)
  have aj := consume_value (consume_ok ok e.i) (secondSlot e) c (zero_slot dj c)
  have au := birth_value (v:=t.u) (consume_ok (consume_ok ok e.i) (secondSlot e)) c
  have av := birth_value (v:=t.v) (afterU ok e) c
  unfold applyTx
  omega

def Consistent (s : State) (r : Registry) : Prop :=
  ∀ q, holdings s (.asset q)=outstanding r q ∧ outstanding r q<B

theorem ordinary_delta {h b s n t} (ok : HistoryOK h b s) (e : TxEvidence h b s n t)
    (g : FundedC.Gates (paymentView h t)) (c : Currency) :
    holdings (applyTx h s t) c+charge c=holdings s c := by
  have flow := selected_flow ok e g.iDummyGate g.jDummyGate c
  have localEq := local_conservation _ g c
  simp only [paymentView,inputView,value_view] at localEq
  omega

theorem token_delta {h b s n t d} (ok : HistoryOK h b s) (e : TxEvidence h b s n t)
    (g : FundedSupply.Gates (paymentView h t) d) (q : AssetId) :
    holdings (applyTx h s t) (.asset q)+forId d.publicId q (burned d)=
      holdings s (.asset q)+forId d.publicId q (minted d) := by
  have flow := selected_flow ok e g.di g.dj (.asset q)
  have localEq := local_delta _ d g q
  simp only [paymentView,inputView,value_view] at localEq
  omega

theorem supply_fee {h b s n t d} (ok : HistoryOK h b s) (e : TxEvidence h b s n t)
    (g : FundedSupply.Gates (paymentView h t) d) :
    holdings (applyTx h s t) .native+3=holdings s .native := by
  have flow := selected_flow ok e g.di g.dj .native
  have localEq := lift_cash _ d g
  change t.i.w.body.native.val+t.j.w.body.native.val=t.u.native.val+t.v.native.val+3 at localEq
  simp only [bodyValue] at flow
  omega

theorem preserve_rule {h b s n t d r ctx env row} (ok : HistoryOK h b s)
    (e : TxEvidence h b s n t) (g : FundedSupply.Gates (paymentView h t) d)
    (w : Wire ctx env (paymentView h t) d) (step : Rule ctx r (paymentView h t) d env row)
    (before : Consistent s r) : Consistent (applyTx h s t) (write r d.publicId row) := by
  intro q
  have f := token_delta ok e g q
  have old := before q
  by_cases eq : q=d.publicId
  · subst q
    have reg := registry_delta w step
    simp [forId] at f
    simp [write,outstanding]
    constructor
    · omega
    · cases step with
      | fixed => exact d.lo.isLt
      | register => exact d.lo.isLt
      | mint _ _ _ _ _ _ _ _ bound => exact bound
      | burn _ q _ _ _ _ oldRow bound =>
        simp only [outstanding,oldRow] at old
        change q-d.lo.val<B
        omega
  · simp [forId,Ne.symm eq] at f
    simpa [outstanding,write,eq,f] using old



def opening (h : Hashes) (t : Tx) : FundedRefinement.Opening :=
  let inp (i : Slot) : FundedRefinement.PrivateInput := ⟨commit h i.w.body,i.real,i.w.body.native,i.w.body.token⟩
  let out (v : Body) : FundedRefinement.PrivateOutput := ⟨0,v.native,v.token⟩
  ⟨t.asset,inp t.i,inp t.j,out t.u,out t.v⟩

/-- Only the declared public effects, typed selectors and transaction-local wires.
    All four recipient tags are opened; no output key/NF witnesses occur. -/
structure WireEffects (h : Hashes) (t : Tx) (x : FundedRefinement.Decoded) : Prop where
  nf0 : x.nf0=published h t.i
  nf1 : x.nf1=published h t.j
  cm0 : x.cm0=commit h t.u
  cm1 : x.cm1=commit h t.v
  ti : t.i.w.body.asset=FundedRefinement.noteTag t.asset t.i.w.body.token.val
  tj : t.j.w.body.asset=FundedRefinement.noteTag t.asset t.j.w.body.token.val
  tu : t.u.asset=FundedRefinement.noteTag t.asset t.u.token.val
  tv : t.v.asset=FundedRefinement.noteTag t.asset t.v.token.val

theorem same_payment {h t x} (a : WireEffects h t x) :
    FundedRefinement.payment x (opening h t)=paymentView h t := by
  simp only [FundedRefinement.payment,opening,FundedRefinement.toInput,FundedRefinement.toOutput,paymentView,inputView,noteView,
    a.nf0,a.nf1,a.cm0,a.cm1,← a.ti,← a.tj,← a.tu,← a.tv]

structure SlotWires (h : Hashes) (b : Binding h) (s : State) (n : Nat) (i : Slot) : Prop where
  witnessScope : b.spendAllowed i.w
  bodyScope : b.bodyAllowed i.w.body
  authorized : i.real=true → owner h i.w=i.w.body.pk
  member : i.real=true → prefixHit s n (commit h i.w.body)

structure PrivateWires (h : Hashes) (b : Binding h) (s : State) (n : Nat) (t : Tx) : Prop where
  i : SlotWires h b s n t.i
  j : SlotWires h b s n t.j
  scopeU : b.bodyAllowed t.u
  scopeV : b.bodyAllowed t.v
  rhoU : t.u.rho=h.rho (published h t.i) (published h t.j) 0
  rhoV : t.v.rho=h.rho (published h t.i) (published h t.j) 1

structure PublicGuards (h : Hashes) (s : State) (t : Tx) : Prop where
  distinctNF : published h t.i≠published h t.j
  distinctCM : commit h t.u≠commit h t.v
  i : published h t.i∉s.spent
  j : published h t.j∉s.spent
  u : commit h t.u∉s.births.map Occurrence.cm
  v : commit h t.v∉s.births.map Occurrence.cm

def evidence {h b s n t} (g : PublicGuards h s t) (p : PrivateWires h b s n t) :
    TxEvidence h b s n t :=
  ⟨⟨g.i,p.i.witnessScope,p.i.bodyScope,p.i.authorized,p.i.member⟩,
   ⟨g.j,p.j.witnessScope,p.j.bodyScope,p.j.authorized,p.j.member⟩,g.distinctNF,g.u,g.v,g.distinctCM,
   p.scopeU,p.scopeV,p.rhoU,p.rhoV⟩

structure PublicProjection (s : State) (p : FundedRefinement.PublicState) : Prop where
  cms : p.cms=s.births.map Occurrence.cm
  spent : p.spent.Perm s.spent

theorem checked_guards {h s t x p} (w : WireEffects h t x) (a : PublicProjection s p)
    (vm : FundedRefinement.vm p x=true) : PublicGuards h s t := by
  obtain ⟨dn,dc,fi,fj,fu,fv⟩ := FundedRefinement.vm_fresh vm
  rw [w.nf0,w.nf1] at dn
  rw [w.cm0,w.cm1] at dc
  rw [w.nf0] at fi
  rw [w.nf1] at fj
  rw [w.cm0,a.cms] at fu
  rw [w.cm1,a.cms] at fv
  exact ⟨dn,dc,fun seen => fi (a.spent.mem_iff.mpr seen),fun seen => fj (a.spent.mem_iff.mpr seen),fu,fv⟩

theorem checked_packet {h b s n t net worker raw rows} (ok : HistoryOK h b s)
    (pkt : FundedRefinement.PacketOK net worker raw (FundedRefinement.latest rows)) (eff : WireEffects h t pkt.x)
    (e : TxEvidence h b s n t) (res : FundedRefinement.residuals pkt.x (opening h t)=true)
    (height : Nat) (initial : Consistent s (FundedRefinement.latest rows)) :
    Consistent (applyTx h s t) (FundedRefinement.latest (FundedRefinement.sqlInsert rows height pkt.x)) := by
  have same := same_payment eff
  have gates := same ▸ FundedRefinement.residuals_gates res
  have wire := same ▸ FundedRefinement.checked_wire pkt (opening h t)
  rw [FundedRefinement.latest_after_insert]
  exact preserve_rule ok e gates wire (FundedRefinement.preflight_refines eff.nf0 pkt.parentGuard) initial

theorem anchored_packet {h b s t net worker raw rows p} (ok : HistoryOK h b s)
    (pkt : FundedRefinement.PacketOK net worker raw (FundedRefinement.latest rows)) (eff : WireEffects h t pkt.x)
    (proj : PublicProjection s p) (vm : FundedRefinement.vm p pkt.x=true)
    (a : FundedRefinement.Anchor) (anchor : p.anchors pkt.x.height=some a)
    (priv : PrivateWires h b s a.count t) (res : FundedRefinement.residuals pkt.x (opening h t)=true)
    (initial : Consistent s (FundedRefinement.latest rows)) :
    a.ap=pkt.x.anchor ∧ HistoryOK h b (applyTx h s t) ∧
    Consistent (applyTx h s t) (FundedRefinement.latest (FundedRefinement.sqlInsert rows (p.height+1) pkt.x)) := by
  have ev := evidence (checked_guards eff proj vm) priv
  have checks := vm
  simp [FundedRefinement.vm,anchor] at checks
  exact ⟨checks.2.2.2.2.1,apply_ok ok ev,checked_packet ok pkt eff ev res _ initial⟩

/-- The selected history is ordered. A prefix imported from an earlier rule version
    requires a faithful initial real-debit book in addition to its public NF set. -/
inductive Selected (h : Hashes) (b : Binding h) : State → Registry → State → Registry → Prop
  | start s r : Selected h b s r s r
  | ordinary {s r now cur n t} : Selected h b s r now cur → TxEvidence h b now n t →
      FundedC.Gates (paymentView h t) → Selected h b s r (applyTx h now t) cur
  | supply {s r now cur n t net worker raw} (pkt : FundedRefinement.PacketOK net worker raw cur) :
      Selected h b s r now cur → TxEvidence h b now n t → WireEffects h t pkt.x →
      FundedRefinement.residuals pkt.x (opening h t)=true →
      Selected h b s r (applyTx h now t)
        (write cur pkt.x.desc.publicId (FundedRefinement.commitRow (cur pkt.x.desc.publicId) pkt.x))
  | reward {s r now cur v fees} : Selected h b s r now cur →
      b.bodyAllowed v → commit h v∉now.births.map Occurrence.cm →
      v.token.val=0 → v.native.val=100+fees → Selected h b s r (birth h now v) cur

theorem selected_invariant {h b s r final reg} (path : Selected h b s r final reg)
    (hist : HistoryOK h b s) (initial : Consistent s r) : HistoryOK h b final ∧ Consistent final reg := by
  induction path with
  | start => exact ⟨hist,initial⟩
  | ordinary _ ev g ih =>
    obtain ⟨hok,c⟩ := ih
    refine ⟨apply_ok hok ev,fun q => ?_⟩
    have same := ordinary_delta hok ev g (.asset q)
    simp only [charge,Nat.add_zero] at same
    rw [same]
    exact c q
  | supply pkt _ ev eff res ih =>
    obtain ⟨hok,c⟩ := ih
    have eq := same_payment eff
    exact ⟨apply_ok hok ev,preserve_rule hok ev (eq ▸ FundedRefinement.residuals_gates res)
      (eq ▸ FundedRefinement.checked_wire pkt _) (FundedRefinement.preflight_refines eff.nf0 pkt.parentGuard) c⟩
  | reward _ scope fresh z _ ih =>
    obtain ⟨hok,c⟩ := ih
    refine ⟨birth_ok hok scope fresh,fun q => ?_⟩
    simpa [birth_value hok,bodyValue,z] using c q

def empty : State := ⟨[],[],[]⟩
def emptyRegistry : Registry := fun _ => none

theorem empty_history {h} (b : Binding h) : HistoryOK h b empty := by
  constructor <;> simp [empty]

theorem selected_from_empty {h b final reg} (path : Selected h b empty emptyRegistry final reg) :
    HistoryOK h b final ∧ Consistent final reg :=
  selected_invariant path (empty_history b) (fun _ => ⟨rfl,by change 0<B; decide⟩)


/-- Only the selected parent's eligible prefix can supply membership, including for
    late physical slots in the same block. Appending younger sibling outputs preserves
    the prefix used in both real membership checks. -/
theorem lift_wires {h b s now n t} (p : PrivateWires h b s n t) (count : n≤s.births.length)
    (ext : ∃ tail, now.births=s.births++tail) : PrivateWires h b now n t := by
  obtain ⟨tail,eq⟩ := ext
  have liftSlot {i} (w : SlotWires h b s n i) : SlotWires h b now n i :=
    {w with member := fun hi => by simpa [prefixHit,eq,List.take_append_of_le_length count] using w.member hi}
  exact ⟨liftSlot p.i,liftSlot p.j,p.scopeU,p.scopeV,p.rhoU,p.rhoV⟩

inductive Policy (h : Hashes) (net : Nat) (worker : FundedRefinement.Worker)
    (parent : Registry) (t : Tx) : Type where
  | ordinary : FundedC.Gates (paymentView h t) → Policy h net worker parent t
  | supply {raw} (pkt : FundedRefinement.PacketOK net worker raw parent) :
      WireEffects h t pkt.x → FundedRefinement.residuals pkt.x (opening h t)=true →
      Policy h net worker parent t

structure BlockItem (h : Hashes) (b : Binding h) (base : State) (net : Nat)
    (worker : FundedRefinement.Worker) (parent : Registry) where
  t : Tx
  count : Nat
  eligibleBound : count≤base.births.length
  wires : PrivateWires h b base count t
  policy : Policy h net worker parent t

def blockID {h b base net w parent} (x : BlockItem h b base net w parent) : Option AssetId :=
  match x.policy with | .ordinary _ => none | .supply p _ _ => some p.x.desc.publicId
def insertItem {h b base net w parent} (height : Nat) (rows : List FundedRefinement.SqlEvent)
    (x : BlockItem h b base net w parent) :=
  match x.policy with
  | .ordinary _ => rows
  | .supply p _ _ => FundedRefinement.sqlInsert rows height p.x

def marks (h : Hashes) (t : Tx) := [published h t.i,published h t.j]
def leaves (h : Hashes) (t : Tx) := [commit h t.u,commit h t.v]

private theorem apply_leaves (h s t) :
    (applyTx h s t).births.map Occurrence.cm=s.births.map Occurrence.cm++leaves h t := by
  simp [applyTx,birth,consume,leaves,List.append_assoc]
private theorem apply_marks (h s t) : (applyTx h s t).spent=published h t.j::published h t.i::s.spent := rfl

theorem extend_projection {h s t x p} (effects : WireEffects h t x) (proj : PublicProjection s p) :
    PublicProjection (applyTx h s t) (FundedRefinement.appendEffects p x) := by
  constructor
  · simp [FundedRefinement.appendEffects,apply_leaves,leaves,proj.cms,effects.cm0,effects.cm1]
  · simp only [FundedRefinement.appendEffects,apply_marks,effects.nf0,effects.nf1]
    apply List.perm_append_comm.trans
    exact (List.Perm.swap _ _ p.spent).trans ((proj.spent.cons _).cons _)

theorem selected_spent_unique {h b s r final reg} (path : Selected h b s r final reg)
    (prefixUnique : s.spent.Nodup) : final.spent.Nodup := by
  induction path with
  | start => exact prefixUnique
  | ordinary _ ev _ ih | supply _ _ ev _ _ ih =>
    rw [apply_marks]
    simpa [ev.i.fresh,ev.j.fresh,Ne.symm ev.distinctNF] using ih
  | reward _ _ _ _ _ ih => exact ih

private theorem advance_guards {h s t u} (g : PublicGuards h s u)
    (dn : ∀ a∈marks h t, ∀ z∈marks h u, a≠z)
    (dc : ∀ a∈leaves h t, ∀ z∈leaves h u, a≠z) : PublicGuards h (applyTx h s t) u := by
  have nf {k} (hk : k∈marks h u) (fr : k∉s.spent) : k∉(applyTx h s t).spent := by
    rw [apply_marks]
    simpa [fr] using And.intro (Ne.symm (dn _ (by simp [marks]) _ hk))
      (Ne.symm (dn _ (by simp [marks]) _ hk))
  have cm {k} (hk : k∈leaves h u) (fr : k∉s.births.map Occurrence.cm) :
      k∉(applyTx h s t).births.map Occurrence.cm := by
    rw [apply_leaves,List.mem_append,not_or]
    exact ⟨fr,fun seen => dc _ seen _ hk rfl⟩
  exact ⟨g.distinctNF,g.distinctCM,nf (by simp [marks]) g.i,nf (by simp [marks]) g.j,
    cm (by simp [leaves]) g.u,cm (by simp [leaves]) g.v⟩

/-- Private paths were checked at the block parent. The three public block-wide
    uniqueness guards let the fold re-use each parent's preflight on its untouched
    registry row, and derive current NF/CM freshness for every physical slot. -/
theorem block_schedule {h b base net w parent start r} (height : Nat)
    (xs : List (BlockItem h b base net w parent)) (now : State) (rows : List FundedRefinement.SqlEvent)
    (path : Selected h b start r now (FundedRefinement.latest rows))
    (ext : ∃ tail, now.births=base.births++tail)
    (fresh : ∀ x∈xs, PublicGuards h now x.t)
    (uniqueNF : (xs.flatMap (fun x => marks h x.t)).Nodup)
    (uniqueCM : (xs.flatMap (fun x => leaves h x.t)).Nodup)
    (uniqueID : (xs.filterMap blockID).Nodup)
    (same : ∀ id∈xs.filterMap blockID, FundedRefinement.latest rows id=parent id) :
    Selected h b start r (xs.foldl (fun st e => applyTx h st e.t) now)
      (FundedRefinement.latest (xs.foldl (insertItem height) rows)) := by
  induction xs generalizing now rows with
  | nil => exact path
  | cons x xs ih =>
    have ev := evidence (fresh x (by simp)) (lift_wires x.wires x.eligibleBound ext)
    obtain ⟨_,nn,crossNF⟩ := List.pairwise_append.mp uniqueNF
    obtain ⟨_,cc,crossCM⟩ := List.pairwise_append.mp uniqueCM
    have nextGuards : ∀ u∈xs, PublicGuards h (applyTx h now x.t) u.t := by
      intro u hu
      exact advance_guards (fresh u (by simp [hu]))
        (fun a ha z hz => crossNF a ha z (List.mem_flatMap.mpr ⟨u,hu,hz⟩))
        (fun a ha z hz => crossCM a ha z (List.mem_flatMap.mpr ⟨u,hu,hz⟩))
    obtain ⟨trail,old⟩ := ext
    have longer : ∃ tail, (applyTx h now x.t).births=base.births++tail := by
      simp [applyTx,birth,consume,old,List.append_assoc]
    simp only [List.foldl_cons]
    refine ih _ _ ?_ longer nextGuards nn cc ?_ ?_
    · cases hp : x.policy with
      | ordinary g =>
        simpa [insertItem,hp] using Selected.ordinary path ev g
      | supply pkt eff res =>
        have mem : pkt.x.desc.publicId ∈ (x::xs).filterMap blockID := by
          simp [blockID,List.filterMap_cons,hp]
        have row := same _ mem
        let actual : FundedRefinement.PacketOK net w _ (FundedRefinement.latest rows) :=
          {pkt with parentGuard := row ▸ pkt.parentGuard}
        have next := Selected.supply actual path ev eff res
        simpa [insertItem,hp,FundedRefinement.latest_after_insert,actual] using next
    · cases hp : x.policy with
      | ordinary => simpa only [List.filterMap_cons,blockID,hp] using uniqueID
      | supply pkt _ _ =>
        have nd : (pkt.x.desc.publicId::xs.filterMap blockID).Nodup := by
          simpa only [List.filterMap_cons,blockID,hp] using uniqueID
        exact (List.nodup_cons.mp nd).2
    · intro id hid
      have old := same id (List.mem_filterMap.mpr (by
        obtain ⟨y,hy,eq⟩ := List.mem_filterMap.mp hid
        exact ⟨y,List.mem_cons_of_mem _ hy,eq⟩))
      cases hp : x.policy with
      | ordinary => simpa [insertItem,hp] using old
      | supply pkt _ _ =>
        have unused : pkt.x.desc.publicId∉xs.filterMap blockID := by
          have nd : (pkt.x.desc.publicId::xs.filterMap blockID).Nodup := by
            simpa only [List.filterMap_cons,blockID,hp] using uniqueID
          exact (List.nodup_cons.mp nd).1
        have diff : id≠pkt.x.desc.publicId := fun eq => unused (eq ▸ hid)
        simpa [insertItem,hp,FundedRefinement.latest_after_insert,write,diff] using old

theorem checked_mixed_block {h b base net w} (height : Nat) (rows : List FundedRefinement.SqlEvent)
    (xs : List (BlockItem h b base net w (FundedRefinement.latest rows))) (capacity : xs.length≤4)
    (fresh : ∀ x∈xs, PublicGuards h base x.t)
    (nf : (xs.flatMap (fun x => marks h x.t)).Nodup)
    (cm : (xs.flatMap (fun x => leaves h x.t)).Nodup) (id : (xs.filterMap blockID).Nodup)
    (ok : HistoryOK h b base) (init : Consistent base (FundedRefinement.latest rows))
    (v : Body) (scope : b.bodyAllowed v) (zero : v.token.val=0) (amount : v.native.val=100+xs.length*3)
    (freshReward : commit h v∉(xs.foldl (fun st e => applyTx h st e.t) base).births.map Occurrence.cm) :
    let final := birth h (xs.foldl (fun st e => applyTx h st e.t) base) v
    v.native.val≤112 ∧ HistoryOK h b final ∧ Consistent final (FundedRefinement.latest (xs.foldl (insertItem height) rows)) := by
  have path := block_schedule height xs base rows (.start _ _) ⟨[],by simp⟩ fresh nf cm id (fun _ _ => rfl)
  exact ⟨by omega,selected_invariant (.reward path scope freshReward zero amount) ok init⟩

/-- The ordinary public verification adapter needs only the funding fields, since
    there is no supply descriptor, issuer preflight, or registry write in this case.
    A verified C proof must bind these fields and its private wires in one statement. -/
structure FundingPI where
  height : Nat
  depth : Nat
  anchor : Nat
  fee : Nat
  nf0 : Nat
  nf1 : Nat
  cm0 : Nat
  cm1 : Nat

def commonParent (p : FundedRefinement.PublicState) (u : FundingPI) (count : Nat) : Prop :=
  ∃ a, p.anchors u.height=some a ∧ a.ap=u.anchor ∧ a.count=count ∧
    25≤p.height+1 ∧ p.height+1<2^32 ∧ u.height<p.height+1 ∧ p.height+1-u.height≤8 ∧
    1≤count ∧ count≤4^20 ∧ FundedRefinement.depthOf count=u.depth ∧ u.fee=3 ∧
    u.nf0≠u.nf1 ∧ u.cm0≠u.cm1 ∧ u.nf0∉p.spent ∧ u.nf1∉p.spent ∧ u.cm0∉p.cms ∧ u.cm1∉p.cms

def parentChecked {h b base net w r} (p : FundedRefinement.PublicState)
    (e : BlockItem h b base net w r) : Prop :=
  match e.policy with
  | .supply pkt _ _ => FundedRefinement.vm p pkt.x=true ∧
      ∃ a, p.anchors pkt.x.height=some a ∧ a.count=e.count
  | .ordinary _ => ∃ u, commonParent p u e.count ∧
      (u.nf0,u.nf1,u.cm0,u.cm1)=(published h e.t.i,published h e.t.j,commit h e.t.u,commit h e.t.v)

theorem parent_guards {h b base net w r p} {e : BlockItem h b base net w r}
    (proj : PublicProjection base p) (hp : parentChecked p e) : PublicGuards h base e.t := by
  cases he : e.policy with
  | supply pkt eff _ =>
    simp only [parentChecked,he] at hp
    exact checked_guards eff proj hp.1
  | ordinary _ =>
    simp only [parentChecked,he] at hp
    obtain ⟨u,⟨_,_,_,_,_,_,_,_,_,_,_,_,dn,dc,fi,fj,fu,fv⟩,eff⟩ := hp
    simp only [Prod.mk.injEq] at eff
    obtain ⟨ni,nj,cu,cv⟩ := eff
    rw [ni,nj] at dn
    rw [cu,cv] at dc
    rw [ni] at fi
    rw [nj] at fj
    rw [cu,proj.cms] at fu
    rw [cv,proj.cms] at fv
    exact ⟨dn,dc,fun hm => fi (proj.spent.mem_iff.mpr hm),fun hm => fj (proj.spent.mem_iff.mpr hm),fu,fv⟩

theorem selected_parent_block {h b base net w} (p : FundedRefinement.PublicState)
    (rows : List FundedRefinement.SqlEvent)
    (xs : List (BlockItem h b base net w (FundedRefinement.latest rows))) (capacity : xs.length≤4)
    (proj : PublicProjection base p) (checked : ∀ x∈xs, parentChecked p x)
    (nf : (xs.flatMap (fun x => marks h x.t)).Nodup)
    (cm : (xs.flatMap (fun x => leaves h x.t)).Nodup) (id : (xs.filterMap blockID).Nodup)
    (ok : HistoryOK h b base) (init : Consistent base (FundedRefinement.latest rows))
    (v : Body) (scope : b.bodyAllowed v) (zero : v.token.val=0) (amount : v.native.val=100+xs.length*3)
    (freshReward : commit h v∉(xs.foldl (fun st e => applyTx h st e.t) base).births.map Occurrence.cm) :
    let final := birth h (xs.foldl (fun st e => applyTx h st e.t) base) v
    v.native.val≤112 ∧ HistoryOK h b final ∧
      Consistent final (FundedRefinement.latest (xs.foldl (insertItem (p.height+1)) rows)) :=
  checked_mixed_block (p.height+1) rows xs capacity (fun x hx => parent_guards proj (checked x hx))
    nf cm id ok init v scope zero amount freshReward

/-- Finite arithmetic/control instance. Its deliberately small functions are not a
    registered cryptographic instantiation. The admitted finite preimages below are
    collision-free for the primitive binding premises, while pk=99 has no preimage. -/
private def exampleH : Hashes :=
  ⟨fun _ _ r => r,id,fun _ _ => 0,fun _ _ r => r,fun r _ => r,
    fun _ _ r => r+100,fun _ _ r => r+200,fun _ _ idx => idx⟩
private def seedBody : Body := ⟨0,5,1,⟨100,by decide⟩,⟨17,by decide⟩,testId⟩
private def padBody : Body := ⟨0,6,2,⟨0,by decide⟩,⟨0,by decide⟩,zeroId⟩
private def bearerBody : Body := ⟨99,0,3,⟨97,by decide⟩,⟨17,by decide⟩,testId⟩
private def changeBody : Body := ⟨0,1,4,⟨0,by decide⟩,⟨0,by decide⟩,zeroId⟩
private def sample : Tx :=
  ⟨⟨true,⟨0,0,seedBody⟩⟩,⟨false,⟨0,0,padBody⟩⟩,bearerBody,changeBody,testId⟩
private def sampleBase : State := birth exampleH empty seedBody
private def sampleRegistry := write emptyRegistry testId ⟨.fixed,17,1,77⟩
private def sampleBind : Binding exampleH where
  bodyAllowed b := b=seedBody ∨ b=padBody ∨ b=bearerBody ∨ b=changeBody
  spendAllowed w := w.ask=0 ∧ w.nk=0
  cmBinding := by rintro a b (rfl|rfl|rfl|rfl) (rfl|rfl|rfl|rfl) <;> decide
  innerBinding := by rintro a b (rfl|rfl|rfl|rfl) (rfl|rfl|rfl|rfl) <;> decide
  typedBinding := by rintro a b (rfl|rfl|rfl|rfl) (rfl|rfl|rfl|rfl) <;> decide
  pkBinding := by rintro u v ⟨a,k⟩ ⟨a',k'⟩ _; simp [a,k,a',k']

private theorem sample_evidence : TxEvidence exampleH sampleBind sampleBase 1 sample := by
  constructor
  · constructor <;> first | decide | simp [sampleBind,sample,prefixHit,sampleBase,birth,empty]
  · constructor <;> first | decide | simp [sampleBind,sample,prefixHit,sampleBase,birth,empty]
  all_goals first | decide | simp [sampleBind,sample]

/-- A funded ordinary payment allocates 17 tokens to a recipient digest outside
    this finite example's owner image. Both published NFs are recorded, but only
    the real input index is marked consumed. The registered amount is unchanged. -/
theorem opaque_token_payment :
    let st := applyTx exampleH sampleBase sample
    Selected exampleH sampleBind sampleBase sampleRegistry st sampleRegistry ∧
    HistoryOK exampleH sampleBind st ∧ Consistent st sampleRegistry ∧
    st.births[1]?=some ⟨commit exampleH bearerBody,bearerBody⟩ ∧
    holdings st (.asset testId)=17 ∧ st.debits.map Debit.pos=[0] ∧ st.spent=[202,101] ∧
    (∀ ask nk, exampleH.pk (exampleH.ak ask) nk≠bearerBody.pk) := by
  have g : FundedC.Gates (paymentView exampleH sample) := by constructor <;> decide
  have path := Selected.ordinary (Selected.start (h:=exampleH) (b:=sampleBind) sampleBase sampleRegistry)
    sample_evidence g
  have hist : HistoryOK exampleH sampleBind sampleBase :=
    birth_ok (empty_history sampleBind) (by simp [sampleBind]) (by simp [empty])
  have init : Consistent sampleBase sampleRegistry := by
    intro q
    by_cases eq : q=testId
    · subst q; exact ⟨rfl,by decide⟩
    · simp [sampleBase,holdings,birth,empty,liveSum,bodyValue,seedBody,sampleRegistry,write,
        outstanding,emptyRegistry,eq,Ne.symm eq,B]
  have both := selected_invariant path hist init
  exact ⟨path,both.1,both.2,rfl,rfl,rfl,rfl,by intro _ _; change 0≠99; decide⟩

#print axioms same_spend_nf
#print axioms selected_from_empty
#print axioms checked_mixed_block
#print axioms opaque_token_payment

end FundedOccurrence
