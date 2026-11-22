import Conservation

namespace FundedC.Review

/- Finite examples for the mathematical model. Identifiers represent opened notes. -/
private abbrev a : AssetId := ⟨1, 2, 3, 4⟩
private abbrev b : AssetId := ⟨1, 2, 3, 5⟩
private abbrev funding : Note := ⟨10, 11, 17, 9, a⟩
private abbrev other : Note := ⟨20, 21, 4, 19, b⟩
private abbrev spentOld : Note := ⟨30, 31, 8, 2, a⟩
private abbrev emptySlot : Note := ⟨0, 0, 0, 0, zeroId⟩
private abbrev before : State := ⟨[funding, other, spentOld], [31]⟩
private abbrev pay : Payment :=
  ⟨⟨emptySlot, false, 91⟩, ⟨funding, true, 11⟩, ⟨40, 41, 11, 6, a⟩, ⟨50, 51, 3, 3, a⟩, a⟩

theorem example_gates : Gates pay := by
  constructor <;> decide

theorem example_admission : Admission before pay := by
  constructor
  · unfold distinctNF
    decide
  · constructor <;> simp [before, pay]
  · constructor <;> simp [before, pay]
  · decide
  · decide
  · decide
  · decide
  · simp [before, pay]
  · simp [before, pay]
  · decide
  · decide

theorem realizable : ∃ s t, Gates t ∧ Admission s t :=
  ⟨before, pay, example_gates, example_admission⟩

private abbrev afterPayment := settle before pay
private abbrev reward : Note := ⟨60, 61, 103, 0, zeroId⟩

theorem one_mined_payment (currency : Currency) :
    holdings (rewardState afterPayment reward) currency = holdings before currency + subsidy currency :=
  ordinary_block before afterPayment 1 (.step (.nil before) pay example_gates example_admission)
    reward (by decide) rfl rfl currency

theorem balances :
    holdings before .native = 21 ∧ holdings afterPayment .native = 18 ∧
    holdings (rewardState afterPayment reward) .native = 121 ∧
    holdings afterPayment (.asset a) = 9 ∧ holdings afterPayment (.asset b) = 19 ∧
    holdings afterPayment (.asset zeroId) = 0 := by decide

theorem retry_rejected : ¬ Admission afterPayment pay := no_replay before pay

/- The owner could choose a different output commitment. The already consumed real input is still spent. -/
theorem changed_retry_rejected :
    ¬ Admission afterPayment { pay with u := { pay.u with cm := 70 } } := by
  intro h
  exact h.jUnseen (by decide)

/- Two outputs taking all the input's native amount omit the required fee of three. -/
theorem omitted_fee_rejected : ¬ Gates { pay with u := { pay.u with native := 14 } } := by
  intro h
  exact (by decide : ¬ ((0 + 17) % P = (((14 + 3) % P) + 3) % P)) h.nativeEq

/- The miner-credit hypothesis is material. Counting the one fee twice raises the total by 103. -/
theorem doubled_miner_fee_breaks_total :
    holdings (rewardState afterPayment { reward with native := 106 }) .native ≠
      holdings before .native + subsidy .native := by decide

theorem fourth_limb_matters : ¬ Gates { pay with u := { pay.u with asset := b } } := by
  intro h
  exact (by decide : ¬ tag a { pay.u with asset := b }) h.uTag

#print axioms realizable
#print axioms one_mined_payment
#print axioms balances
#print axioms changed_retry_rejected
#print axioms omitted_fee_rejected
#print axioms doubled_miner_fee_breaks_total
#print axioms fourth_limb_matters

end FundedC.Review
