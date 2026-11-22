import Occurrence

/- A finite model of the occurrence representation. The toy functions have no security
   interpretation. No certificate for a blockchain payment is asserted in this file. -/
namespace OccurrenceReview
open FundedC FundedOccurrence

private def asset : AssetId := ⟨1, 2, 3, 4⟩
private def unknown : Body := ⟨1, 1, 0, ⟨8, by decide⟩, ⟨7, by decide⟩, asset⟩
private def pad : Body := ⟨0, 0, 0, ⟨0, by decide⟩, ⟨0, by decide⟩, zeroId⟩
private def hashes : Hashes where
  typed := fun _ q _ => q
  ak := fun _ => 0
  pk := fun _ _ => 0
  inner := fun pk _ _ => pk
  cm := fun pk _ => pk
  realNF := fun _ _ _ => 17
  dummyNF := fun _ _ _ => 17
  rho := fun _ _ i => i

private def binding : Binding hashes where
  bodyAllowed := fun b => b = unknown ∨ b = pad
  spendAllowed := fun w => w.nk = 0
  cmBinding := by
    intro a b ha hb
    rcases ha with rfl | rfl <;> rcases hb with rfl | rfl <;> decide
  innerBinding := by
    intro a b ha hb
    rcases ha with rfl | rfl <;> rcases hb with rfl | rfl <;> decide
  typedBinding := by
    intro a b ha hb
    rcases ha with rfl | rfl <;> rcases hb with rfl | rfl <;> decide
  pkBinding := by
    intro u v hu hv _
    simp [hashes, hu, hv]

private def born : FundedOccurrence.State := birth hashes empty unknown
private def dummy : Slot := ⟨false, ⟨0, 0, pad⟩⟩

theorem compatible_owner_does_not_exist :
    ¬ ∃ w : Spend, Compatible hashes w ⟨commit hashes unknown, unknown⟩ := by
  rintro ⟨w, ownerEq, cmEq⟩
  change 0 = w.body.pk at ownerEq
  change w.body.pk = 1 at cmEq
  omega

theorem birth_counts_face_value :
    HistoryOK hashes binding born ∧ FundedOccurrence.holdings born (.asset asset) = 7 := by
  exact ⟨birth_ok (empty_history binding) (Or.inl rfl) (by decide), by decide⟩

private theorem dummy_admissible : SlotEvidence hashes binding born 1 dummy := by
  constructor
  · decide
  · rfl
  · exact Or.inr rfl
  · decide
  · intro impossible
    contradiction

theorem dummy_marks_only :
    let after := consume hashes born dummy
    HistoryOK hashes binding after ∧ after.spent = [17] ∧ after.debits = [] ∧
      FundedOccurrence.holdings after (.asset asset) = 7 := by
  exact ⟨consume_ok birth_counts_face_value.1 dummy_admissible, rfl, rfl, by decide⟩

theorem public_mark_can_share_real_domain_value :
    published hashes dummy = trueNF hashes ⟨0, 0, pad⟩ := rfl

#print axioms compatible_owner_does_not_exist
#print axioms birth_counts_face_value
#print axioms dummy_marks_only
#print axioms public_mark_can_share_real_domain_value

end OccurrenceReview
