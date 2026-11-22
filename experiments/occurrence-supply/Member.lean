import Anchored
import Occurrence

namespace OccurrenceMember
open FundedAnchor FundedOccurrence

/-- The header/height/occupancy guards select this root and count. The birth vector is the
    chronological projection of the same selected ledger. No hidden chronological index
    or match is supplied by the prover. The witness extracts only a sequence of quads. -/
structure Selected (compress : Hash) (le : Digest → Digest → Bool)
    (s : State) (count leaf : Nat) where
  root : Digest
  quads : List Quad
  inRange : 0 < count ∧ count ≤ s.births.length ∧ count ≤ 4^20
  exactDepth : quads.length = max 1 (((count-1).log2+2)/2)
  rootNonzero : root ≠ 0
  top : levels compress le ((s.births.map Occurrence.cm).take count) quads.length = [root]
  linked : Path compress leaf quads root
  binding : Binds compress le ((s.births.map Occurrence.cm).take count) quads

/-- A normalized field preimage (the 28 log words are fixed for the node header).
    Hash binding is required only for the selected and the exhibited preimages. -/
structure Header where
  parent : Digest
  height : Nat
  state : Digest
  extrinsics : Digest
  root : Digest
  logs : Fin 28 → Nat

structure Statement where
  anchor : Digest
  height : Nat
  depth : Nat

/-- Combine the selected SQL row, the registered public statement and the private
    header/preimage from that same proof. The sorted path is rooted at the *exhibited*
    header. Equality of its root with the selected header is derived. -/
def fromEligibleHeader {compress le} {s : State} {count leaf : Nat} (headerHash : Header → Digest)
    (head : Nat) (row witness : Header) (pi : Statement) (qs : List Quad)
    (_era : 25 ≤ head+1 ∧ head+1 < 2^32)
    (_age : pi.height < head+1 ∧ head+1-pi.height ≤ 8)
    (_selectedHeight : row.height=pi.height) (_provedHeight : witness.height=pi.height)
    (selectedAP : headerHash row=pi.anchor) (provedAP : headerHash witness=pi.anchor)
    (bindHeader : headerHash row=headerHash witness → row=witness)
    (range : 0<count ∧ count≤s.births.length ∧ count≤4^20)
    (publicDepth : pi.depth=max 1 (((count-1).log2+2)/2)) (pathDepth : qs.length=pi.depth)
    (tree : levels compress le ((s.births.map Occurrence.cm).take count) pi.depth=[row.root])
    (occupied : witness.root≠0) (walk : Path compress leaf qs witness.root)
    (binding : Binds compress le ((s.births.map Occurrence.cm).take count) qs) :
    Selected compress le s count leaf := by
  have equal := bindHeader (selectedAP.trans provedAP.symm)
  subst witness
  exact ⟨row.root,qs,range,pathDepth.trans publicDepth,occupied,pathDepth.symm ▸ tree,walk,binding⟩

theorem path_to_prefix {hash le s count leaf} (a : Selected hash le s count leaf) :
    prefixHit s count leaf := by
  simpa [prefixHit,List.map_take] using selected_prefix a.linked a.binding a.top

/-- Adapter into the mixed-block history induction. A dummy never supplies a path.
    For a real slot the selected ancestor, private quads and local parent binding
    produce membership; no lookup position or spent-status oracle is an input. -/
theorem slot_wires {hash le h s count} {b : Binding h} {i : Slot}
    (ws : b.spendAllowed i.w) (bs : b.bodyAllowed i.w.body)
    (auth : i.real=true → owner h i.w=i.w.body.pk)
    (path : i.real=true → Nonempty (Selected hash le s count (commit h i.w.body))) :
    SlotWires h b s count i :=
  ⟨ws,bs,auth,fun real => (path real).elim path_to_prefix⟩

/-- The real-spend occurrence conclusion from local checks. None of the arguments is a
    chosen earlier index, an asserted historical pairing, or a future recipient's secret. -/
theorem matched_real {hash le h s n i} {b : Binding h} (hist : HistoryOK h b s)
    (real : i.real = true) (bs : b.bodyAllowed i.w.body) (ws : b.spendAllowed i.w)
    (auth : owner h i.w = i.w.body.pk) (fresh : published h i ∉ s.spent)
    (a : Selected hash le s n (commit h i.w.body)) :
    ∃ o, s.births[pos h s i]? = some o ∧ i.w.body = o.body ∧ pos h s i < n ∧
         pos h s i ∉ s.debits.map Debit.pos ∧
         ∀ j birth, s.births[j]? = some birth → birth.cm = commit h i.w.body → j = pos h s i := by
  have member := path_to_prefix a
  have ev : SlotEvidence h b s n i := ⟨fresh,ws,bs,fun _ => auth,fun _ => member⟩
  obtain ⟨o,atO,_,body,bound,unused⟩ := funded_opening hist ev real
  obtain ⟨_,_,_,_,unique⟩ := selected_position s n _ hist.distinctCM member
  exact ⟨o,atO,body,bound,unused,unique⟩

end OccurrenceMember
