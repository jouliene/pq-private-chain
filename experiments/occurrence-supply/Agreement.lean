import Occurrence

/-! Comparison with the historical total-nullifier model on a history where every
    selected birth has a compatible spending opening. Only this comparison uses that
    premise. Phase 1D's occurrence accounting itself admits recipient digests for
    which no spending opening is available. -/
namespace OccurrenceAgreement
open FundedC FundedOccurrence

/-- Expand an ordered vector of bodies into the old representation. The private
    labels supplied here are only meaningful under the compatibility hypotheses. -/
def legacyNote (label : Nat) (b : Occurrence) : Note :=
  ⟨b.cm,label,b.body.native.val,b.body.token.val,b.body.asset⟩

def inventory (label : Nat → Nat) (start : Nat) : List Occurrence → List Note
  | [] => []
  | b::bs => legacyNote (label start) b :: inventory label (start+1) bs

private theorem sum_aligned {label : Nat → Nat} (c : Currency) (used marks : List Nat)
    (bs : List Occurrence) (start : Nat)
    (agree : ∀ k b, bs[k]? = some b → (start+k ∈ used ↔ label (start+k) ∈ marks)) :
    liveSum c used start bs = total c (live marks (inventory label start bs)) := by
  induction bs generalizing start with
  | nil => rfl
  | cons b bs ih =>
    have head : start ∈ used ↔ label start ∈ marks := by simpa using agree 0 b rfl
    have tail := ih (start+1) (by
      intro k b' hk
      simpa [Nat.add_assoc,Nat.add_comm 1 k] using
        agree (k+1) b' (by simpa using hk))
    by_cases h : start ∈ used
    · have h' := head.mp h
      simpa [liveSum,inventory,live,legacyNote,h,h'] using tail
    · have h' := mt head.mpr h
      cases c <;> simp_all [liveSum,inventory,live,legacyNote,total,bodyValue,value]

private theorem live_same_marks {a b : List Nat} (h : a.Perm b) (xs : List Note) :
    live a xs = live b xs := by
  induction xs with
  | nil => rfl
  | cons n ns ih =>
    by_cases seen : n.nf∈a
    · simp [live,seen,h.mem_iff.mp seen,ih]
    · simp [live,seen,mt h.mem_iff.mpr seen,ih]

private theorem sum_live_perm (c : Currency) (marks : List Nat) {xs ys : List Note}
    (h : xs.Perm ys) : total c (live marks xs) = total c (live marks ys) := by
  induction h with
  | nil => rfl
  | cons n _ ih => by_cases z : n.nf∈marks <;> simp [live,total,z,ih]
  | swap a b xs =>
    by_cases x : a.nf∈marks <;> by_cases y : b.nf∈marks <;> simp [live,total,x,y] <;> omega
  | trans _ _ ih1 ih2 => exact ih1.trans ih2

/-- Historical input classifications are private data of the compared interpretation.
    Every slot emits one public mark, while only real slots produce a debit. -/
inductive InputEvent where
  | real (d : Debit)
  | dummy (nf : Nat)

def eventNF : InputEvent → Nat
  | .real d => d.nf
  | .dummy nf => nf

def realDebit : InputEvent → Option Debit
  | .real d => some d
  | .dummy _ => none

def dummyMark : InputEvent → Option Nat
  | .real _ => none
  | .dummy nf => some nf

theorem classify_marks (events : List InputEvent) :
    (events.map eventNF).Perm ((events.filterMap realDebit).map Debit.nf ++ events.filterMap dummyMark) := by
  induction events with
  | nil => exact .nil
  | cons e es ih =>
    cases e with
    | real d => simpa [eventNF,realDebit,dummyMark] using ih.cons d.nf
    | dummy nf =>
      simp only [List.map_cons,eventNF,List.filterMap_cons,realDebit,dummyMark]
      exact (ih.cons nf).trans List.perm_middle.symm

private def slotEvent (h : Hashes) (s : FundedOccurrence.State) (i : Slot) : InputEvent :=
  if i.real then .real ⟨pos h s i,trueNF h i.w,i.w⟩ else .dummy (published h i)

private theorem tx_events (h : Hashes) (s : FundedOccurrence.State) (t : Tx) :
    let events := [slotEvent h (consume h s t.i) t.j,slotEvent h s t.i]
    (applyTx h s t).spent=events.map eventNF ++ s.spent ∧
      (applyTx h s t).debits=events.filterMap realDebit ++ s.debits := by
  cases hi : t.i.real <;> cases hj : t.j.real <;>
    simp [applyTx,birth,consume,slotEvent,published,eventNF,realDebit,hi,hj]

/-- Every new selected slot is classified by its actual private real/dummy flag. Both
    public marks are retained in the state order and only real events add debit records. -/
theorem selected_classification {h b s r final reg} (path : Selected h b s r final reg) :
    ∃ suffix : List InputEvent, final.spent=suffix.map eventNF ++ s.spent ∧
      final.debits=suffix.filterMap realDebit ++ s.debits := by
  induction path with
  | start => exact ⟨[],rfl,rfl⟩
  | @ordinary now _ _ t _ _ _ ih | @supply now _ _ t _ _ _ _ _ _ _ _ ih =>
    obtain ⟨es,marks,debits⟩ := ih
    obtain ⟨nm,nd⟩ := tx_events h now t
    exact ⟨[slotEvent h (consume h now t.i) t.j,slotEvent h now t.i] ++ es,
      by simpa [List.append_assoc,marks] using nm,
      by simpa only [List.filterMap_append,List.append_assoc,debits] using nd⟩
  | reward _ _ _ _ _ ih => exact ih

/-- Only the imported prefix needs a compatible event classification. The new
    selected path supplies the remaining public-mark and real-debit projections. -/
theorem extend_imported_events {h b s r final reg} (path : Selected h b s r final reg)
    (prior : List InputEvent) (marks : s.spent.Perm (prior.map eventNF))
    (debits : s.debits.Perm (prior.filterMap realDebit)) :
    ∃ suffix : List InputEvent, final.spent.Perm ((suffix++prior).map eventNF) ∧
      final.debits.Perm ((suffix++prior).filterMap realDebit) := by
  obtain ⟨es,hm,hd⟩ := selected_classification path
  exact ⟨es,by simpa [hm] using marks.append_left (es.map eventNF),
    by simpa [hd] using debits.append_left (es.filterMap realDebit)⟩

/-- Additional facts of the *old* opened history. A label is justified by a real
    compatible key opening for that birth, even if it has never been spent. Mark
    partition records the actual slot types and includes the publicly settled dummies. -/
structure TotalOpening {h : Hashes} (bind : Binding h) (s : FundedOccurrence.State) where
  label : Nat → Nat
  complete : ∀ k b, s.births[k]? = some b → ∃ w : Spend,
    bind.bodyAllowed w.body ∧ bind.spendAllowed w ∧ Compatible h w b ∧ trueNF h w = label k
  distinct : ∀ i j b b', s.births[i]? = some b → s.births[j]? = some b' →
    label i = label j → i=j
  events : List InputEvent
  publicMarks : s.spent.Perm (events.map eventNF)
  realDebits : s.debits.Perm (events.filterMap realDebit)
  dummySeparate : ∀ k b, s.births[k]? = some b → label k ∉ events.filterMap dummyMark

private theorem mark_partition {h : Hashes} {bind : Binding h} {s : FundedOccurrence.State}
    (n : TotalOpening bind s) : s.spent.Perm (s.debits.map Debit.nf ++ n.events.filterMap dummyMark) :=
  (n.publicMarks.trans (classify_marks n.events)).trans
    ((n.realDebits.symm.map Debit.nf).append_right _)

private theorem debit_label {h : Hashes} {bind : Binding h} {s : FundedOccurrence.State}
    (n : TotalOpening bind s) (hist : HistoryOK h bind s) {d : Debit} (hd : d∈s.debits) :
    ∃ b, s.births[d.pos]?=some b ∧ d.nf = n.label d.pos := by
  obtain ⟨b,hb,dc,bd,sd,nf,_⟩ := hist.debitOrigin d hd
  obtain ⟨w,bw,sw,wc,wn⟩ := n.complete d.pos b hb
  exact ⟨b,hb,nf.trans ((same_spend_nf bind bd bw sd sw dc wc).trans wn)⟩

/-- The correspondence of the two death predicates is a conclusion for each
    birth. In particular a dummy mark cannot delete a positive occurrence. -/
theorem marked_iff_debited {h : Hashes} {bind : Binding h} {s : FundedOccurrence.State}
    (n : TotalOpening bind s) (hist : HistoryOK h bind s) {k b} (hb : s.births[k]?=some b) :
    n.label k∈s.spent ↔ k∈s.debits.map Debit.pos := by
  constructor
  · intro marked
    rcases List.mem_append.mp ((mark_partition n).mem_iff.mp marked) with real | dummy
    · obtain ⟨d,hd,nf⟩ := List.mem_map.mp real
      obtain ⟨b',hb',id⟩ := debit_label n hist hd
      exact List.mem_map.mpr ⟨d,hd,n.distinct d.pos k b' b hb' hb (id.symm.trans nf)⟩
    · exact False.elim (n.dummySeparate k b hb dummy)
  · intro consumed
    obtain ⟨d,hd,pos⟩ := List.mem_map.mp consumed
    obtain ⟨_,_,id⟩ := debit_label n hist hd
    exact (mark_partition n).mem_iff.mpr (List.mem_append_left _ (List.mem_map.mpr
      ⟨d,hd,by simpa [pos] using id⟩))

/-- Historical and occurrence holdings agree for every currency under the old
    complete-opening premises. Chronological SQL births may be permuted in the
    old model, which prepends each newly created pair. -/
theorem holdings_agree {h : Hashes} {bind : Binding h} {s : FundedOccurrence.State}
    (n : TotalOpening bind s) (hist : HistoryOK h bind s) (old : FundedC.State)
    (births : old.funded.Perm (inventory n.label 0 s.births)) (marks : old.spent.Perm s.spent)
    (c : Currency) : FundedOccurrence.holdings s c = FundedC.holdings old c := by
  unfold FundedOccurrence.holdings FundedC.holdings
  rw [live_same_marks marks]
  refine (sum_aligned c _ _ _ 0 ?_).trans (sum_live_perm c _ births).symm
  intro k b hb
  simpa using (marked_iff_debited n hist hb).symm

/-- The old outstanding-quantity invariant and its occurrence reading are equivalent
    on this common history, without requiring either invariant as a premise. -/
theorem legacy_registry_iff {h : Hashes} {bind : Binding h} {s : FundedOccurrence.State}
    (n : TotalOpening bind s) (hist : HistoryOK h bind s) (old : FundedC.State)
    (births : old.funded.Perm (inventory n.label 0 s.births)) (marks : old.spent.Perm s.spent)
    (r : FundedSupply.Registry) : FundedSupply.Consistent old r ↔
    ∀ q, FundedOccurrence.holdings s (.asset q) = FundedSupply.outstanding r q ∧
      FundedSupply.outstanding r q < B := by
  simp only [FundedSupply.Consistent,holdings_agree n hist old births marks]

end OccurrenceAgreement
