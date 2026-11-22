import Supply

namespace FundedSupply.Review
open FundedC

/- An asset is fully burned while an unrelated asset with the same first three limbs survives. -/
private abbrev assetA : AssetId := ⟨1, 2, 3, 4⟩
private abbrev assetB : AssetId := ⟨1, 2, 3, 5⟩
private abbrev held : Note := ⟨10, 11, 8, 7, assetA⟩
private abbrev other : Note := ⟨20, 21, 4, 13, assetB⟩
private abbrev empty : Note := ⟨0, 0, 0, 0, zeroId⟩
private abbrev before : State := ⟨[held, other], []⟩
private abbrev pay : Payment :=
  ⟨⟨held, true, 11⟩, ⟨empty, false, 91⟩, ⟨40, 41, 5, 0, zeroId⟩, ⟨50, 51, 0, 0, zeroId⟩, assetA⟩
private abbrev seven : Fin B := ⟨7, by decide⟩
private abbrev z : Fin B := ⟨0, by decide⟩
private abbrev erase : Descriptor := ⟨B + 7, true, seven, assetA⟩

theorem burn_gates : FundedSupply.Gates pay erase := by
  constructor <;> decide

theorem burn_admission : Admission before pay := by
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

theorem burn_concrete :
    holdings before (.asset assetA) = 7 ∧ holdings (settle before pay) (.asset assetA) = 0 ∧
    holdings (settle before pay) (.asset assetB) = 13 ∧ holdings (settle before pay) .native = 9 := by
  decide

theorem burn_any_id (q : AssetId) :
    holdings (settle before pay) (.asset q) + forId assetA q 7 = holdings before (.asset q) := by
  simpa [erase, burned, minted, issuing, bit, forId] using
    selected_supply before pay erase burn_gates burn_admission q

theorem flag_only_rejected : ¬ FundedSupply.Gates pay ⟨B, true, z, assetA⟩ := by
  intro h
  exact (by decide : ¬ (0 < z.val)) (empty_burn_forbidden _ _ h rfl)

theorem changed_fourth_limb_rejected : ¬ FundedSupply.Gates pay { erase with publicId := assetB } := by
  intro h
  exact (by decide : ¬ publicGate { erase with publicId := assetB } pay.asset) h.publicBinding

theorem mint_with_token_inputs_rejected : ¬ FundedSupply.Gates pay ⟨7, false, seven, assetA⟩ := by
  intro h
  have hzero := (issuing_constraints _ _ h (by decide)).2.1
  exact (by decide : ¬ held.token = 0) hzero

private abbrev predecessor : Row := ⟨.managed 77, 7, 4, 73⟩
private abbrev unrelated : Row := ⟨.fixed, 13, 1, 29⟩
private abbrev registry : Registry := fun q =>
  if q = assetA then some predecessor else if q = assetB then some unrelated else none
private abbrev burnPacket : Envelope := ⟨.burn, none, 0, 0, none, 84⟩
private abbrev staleMint : Envelope := ⟨.mint, some 77, 4, 73, some 99, 88⟩
private abbrev burnRow : Row := ⟨.managed 77, 0, 5, 84⟩

/- These are finite mathematical relations for opaque identifiers. The public replay checks real signatures. -/
private def context : Context where
  network := 1
  fixedId := fun _ _ => assetB
  managedId := fun _ _ _ => assetA
  hashInner := id
  packetId := Envelope.inner
  verifies := fun m sig => m.network = 1 ∧ m.op = .mint ∧ m.pk = 77 ∧ m.seq = 4 ∧
    m.previous = 73 ∧ m.innerHash = 88 ∧ sig = 99
  opens := fun inner t d => inner = 84 ∧ t = pay ∧ d = erase

theorem initial_consistency : Consistent before registry := by
  intro q
  by_cases a : q = assetA
  · subst q
    decide
  by_cases b : q = assetB
  · subst q
    decide
  simp [before, registry, outstanding, holdings, live, total, value, a, b, Ne.symm a, Ne.symm b, B]

theorem modeled_burn : Rule context registry pay erase burnPacket burnRow := by
  exact Rule.burn 77 7 4 73 rfl (by simp [bare,burnPacket]) (by decide) (by decide)

theorem full_burn_path : Path context before registry (settle before pay) (write registry assetA burnRow) :=
  .supply (.start before registry) burn_gates burn_admission
    ⟨⟨rfl,rfl,rfl⟩, by decide, rfl⟩ modeled_burn

theorem full_burn_all_registry_rows : Consistent (settle before pay) (write registry assetA burnRow) :=
  consistent_path initial_consistency full_burn_path

theorem zero_still_registered :
    write registry assetA burnRow assetA = some ⟨.managed 77, 0, 5, 84⟩ ∧
    write registry assetA burnRow assetB = some unrelated := by decide

theorem signed_old_template : signed context staleMint 77 := by
  exact ⟨rfl, by decide, 99, rfl, by simp [context,staleMint]⟩

theorem stale_after_burn (row : Row) :
    ¬ Rule context (write registry assetA burnRow) pay ⟨7, false, seven, assetA⟩ staleMint row := by
  intro h
  obtain ⟨key, q, _, current, _, _⟩ := mint_requires_current_authority h rfl
  change some burnRow = some ⟨.managed key, q, 4, 73⟩ at current
  have rev := congrArg Row.revision (Option.some.inj current)
  exact (by decide : (5 : Nat) ≠ 4) rev

theorem fixed_asset_refuses_burn (row : Row) :
    ¬ Rule context registry pay { erase with publicId := assetB } burnPacket row :=
  fixed_supply_immutable (q := 13) (rev := 1) (tx := 29) (by decide)

#print axioms burn_gates
#print axioms burn_admission
#print axioms burn_any_id
#print axioms burn_concrete
#print axioms flag_only_rejected
#print axioms changed_fourth_limb_rejected
#print axioms mint_with_token_inputs_rejected
#print axioms full_burn_all_registry_rows
#print axioms zero_still_registered
#print axioms signed_old_template
#print axioms stale_after_burn
#print axioms fixed_asset_refuses_burn

end FundedSupply.Review
