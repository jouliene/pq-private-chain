import Std

/-! Ordinary funded profile C, one selected branch. Monetary units are natural numbers.
    Commitments and nullifiers are opaque identifiers. This file proves the arithmetic and the
    ledger transition given opened notes and the binding/freshness interfaces below. -/
namespace FundedC

def P : Nat := 18446744069414584321
def B : Nat := 4611686018427387904

theorem registered_constants : P = 2^64 - 2^32 + 1 ∧ B = 2^62 := by decide

structure AssetId where
  w0 : Fin (2^63)
  w1 : Fin (2^63)
  w2 : Fin (2^63)
  w3 : Fin (2^63)
  deriving DecidableEq

def zeroId : AssetId := ⟨0, 0, 0, 0⟩

inductive Currency where
  | native
  | asset (id : AssetId)
  deriving DecidableEq

structure Note where
  cm : Nat
  nf : Nat  -- True real-domain nullifier of this opened occurrence.
  native : Nat
  token : Nat
  asset : AssetId
  deriving DecidableEq

def value (n : Note) : Currency → Nat
  | .native => n.native
  | .asset id => if n.asset = id then n.token else 0

def charge : Currency → Nat
  | .native => 3
  | .asset _ => 0

structure Input where
  note : Note
  real : Bool
  published : Nat  -- A dummy publishes an NF_DUMMY-domain identifier.

structure Payment where
  i : Input
  j : Input
  u : Note
  v : Note
  asset : AssetId

abbrev tag (a : AssetId) (n : Note) : Prop :=
  n.asset = if n.token = 0 then zeroId else a

abbrev ranged (n : Note) : Prop := n.native < B ∧ n.token < B

/-- The safe circuit boolean is the dummy flag. Here real=true encodes dummy=0. -/
def dummyBit (i : Input) : Nat := if i.real then 0 else 1

abbrev dummyGate (i : Input) : Prop :=
  (i.note.native * dummyBit i) % P = 0 ∧ (i.note.token * dummyBit i) % P = 0

/-- Component equations of the ordinary (delta = 0) branch. The verifier fee is the
    constant 3. The inner remainder represents the intermediate field addition. -/
structure Gates (t : Payment) : Prop where
  ri : ranged t.i.note
  rj : ranged t.j.note
  ru : ranged t.u
  rv : ranged t.v
  nativeEq : (t.i.note.native + t.j.note.native) % P =
    (((t.u.native + t.v.native) % P) + 3) % P
  tokenEq : (((t.i.note.token + t.j.note.token) % P) + 0) % P =
    (((t.u.token + t.v.token) % P) + 0) % P
  iTag : tag t.asset t.i.note
  jTag : tag t.asset t.j.note
  uTag : tag t.asset t.u
  vTag : tag t.asset t.v
  zeroAsset : t.asset = zeroId ↔ (t.i.note.token + t.j.note.token) % P = 0
  iDummyGate : dummyGate t.i
  jDummyGate : dummyGate t.j

theorem dummy_zero (i : Input) (r : ranged i.note) (h : dummyGate i) (hd : i.real = false) :
    i.note.native = 0 ∧ i.note.token = 0 := by
  have small : B < P := by decide
  have hn := Nat.lt_trans r.1 small
  have ht := Nat.lt_trans r.2 small
  simpa [dummyGate,dummyBit,hd,Nat.mod_eq_of_lt hn,Nat.mod_eq_of_lt ht] using h

theorem exact_intermediate_bounds {x y : Nat} (hx : x < B) (hy : y < B) :
    x + y ≤ 9223372036854775806 ∧ x + y + 3 ≤ 9223372036854775809 ∧ x + y + 3 < P := by
  unfold B at hx hy
  unfold P
  omega

theorem lift_native (t : Payment) (g : Gates t) :
    t.i.note.native + t.j.note.native = t.u.native + t.v.native + 3 := by
  obtain ⟨_, _, hi⟩ := exact_intermediate_bounds g.ri.1 g.rj.1
  obtain ⟨_, _, ho⟩ := exact_intermediate_bounds g.ru.1 g.rv.1
  have hi' : t.i.note.native + t.j.note.native < P := by omega
  have ho' : t.u.native + t.v.native < P := by omega
  simpa [Nat.mod_eq_of_lt hi', Nat.mod_eq_of_lt ho', Nat.mod_eq_of_lt ho] using g.nativeEq

theorem ordinary_has_real_input (t : Payment) (g : Gates t) :
    t.i.real = true ∨ t.j.real = true := by
  cases hi : t.i.real <;> cases hj : t.j.real <;> simp [hi,hj]
  have hz := (dummy_zero t.i g.ri g.iDummyGate hi).1
  have hw := (dummy_zero t.j g.rj g.jDummyGate hj).1
  have he := lift_native t g
  omega

theorem lift_token (t : Payment) (g : Gates t) :
    t.i.note.token + t.j.note.token = t.u.token + t.v.token := by
  obtain ⟨_, _, hi⟩ := exact_intermediate_bounds g.ri.2 g.rj.2
  obtain ⟨_, _, ho⟩ := exact_intermediate_bounds g.ru.2 g.rv.2
  have hi' : t.i.note.token + t.j.note.token < P := by omega
  have ho' : t.u.token + t.v.token < P := by omega
  simpa [Nat.mod_eq_of_lt hi', Nat.mod_eq_of_lt ho'] using g.tokenEq

theorem zero_asset_iff (t : Payment) (g : Gates t) :
    t.asset = zeroId ↔ t.i.note.token = 0 ∧ t.j.note.token = 0 ∧ t.u.token = 0 ∧ t.v.token = 0 := by
  have hi := (exact_intermediate_bounds g.ri.2 g.rj.2).2.2
  have hi' : t.i.note.token + t.j.note.token < P := by omega
  have h := g.zeroAsset
  rw [Nat.mod_eq_of_lt hi'] at h
  have he := lift_token t g
  constructor
  · intro hz
    have := h.mp hz
    omega
  · intro hz
    apply h.mpr
    omega

theorem effective_tag (a id : AssetId) (n : Note) (h : tag a n) :
    value n (.asset id) = if a = id then n.token else 0 := by
  unfold tag at h
  by_cases hq : n.token = 0
  · simp [value, hq]
  · simp [value, h, hq]

theorem local_conservation (t : Payment) (g : Gates t) (c : Currency) :
    value t.i.note c + value t.j.note c = value t.u c + value t.v c + charge c := by
  cases c with
  | native => exact lift_native t g
  | asset id =>
    rw [effective_tag _ _ _ g.iTag, effective_tag _ _ _ g.jTag,
        effective_tag _ _ _ g.uTag, effective_tag _ _ _ g.vTag]
    by_cases h : t.asset = id
    · simpa [h, charge] using lift_token t g
    · simp [h, charge]

/-- The consensus tree retains consumed commitments. Holdings is a projection of all
    selected, funded openings onto the real nullifiers absent from the selected spent index. -/
structure State where
  funded : List Note
  spent : List Nat

def live (spent : List Nat) : List Note → List Note
  | [] => []
  | n :: ns => if n.nf ∈ spent then live spent ns else n :: live spent ns

def total (c : Currency) : List Note → Nat
  | [] => 0
  | n :: ns => value n c + total c ns

def holdings (s : State) (c : Currency) := total c (live s.spent s.funded)

def settle (s : State) (t : Payment) : State :=
  ⟨t.u :: t.v :: s.funded, t.i.published :: t.j.published :: s.spent⟩

def without (key : Nat) : List Note → List Note
  | [] => []
  | n :: ns => if n.nf = key then without key ns else n :: without key ns

theorem live_new (notes : List Note) (spent : List Nat) (key : Nat) :
    live (key :: spent) notes = without key (live spent notes) := by
  induction notes with
  | nil => rfl
  | cons n ns ih =>
    by_cases hk : n.nf = key
    · subst key
      by_cases hs : n.nf ∈ spent <;> simp [live,without,hs,ih]
    · by_cases hs : n.nf ∈ spent <;> simp [live,without,hk,hs,ih]

theorem mem_without (n : Note) (xs : List Note) (k : Nat) :
    n ∈ without k xs ↔ n ∈ xs ∧ n.nf ≠ k := by
  induction xs with
  | nil => simp [without]
  | cons a xs ih =>
    by_cases ha : a.nf = k
    · simp only [without, if_pos ha, ih, List.mem_cons]
      constructor
      · rintro ⟨h, hn⟩
        exact ⟨Or.inr h,hn⟩
      · rintro ⟨rfl | hm, hn⟩
        · exact False.elim (hn ha)
        · exact ⟨hm,hn⟩
    · simp only [without, if_neg ha, List.mem_cons, ih]
      constructor
      · rintro (rfl | ⟨hm, hn⟩)
        · exact ⟨Or.inl rfl,ha⟩
        · exact ⟨Or.inr hm,hn⟩
      · rintro ⟨rfl | hm,hn⟩
        · exact Or.inl rfl
        · exact Or.inr ⟨hm,hn⟩

theorem without_absent (xs : List Note) (k : Nat) (h : ∀ n ∈ xs, n.nf ≠ k) :
    without k xs = xs := by
  induction xs with
  | nil => rfl
  | cons a xs ih =>
    have ha := h a (by simp)
    have ht : ∀ n ∈ xs, n.nf ≠ k := fun n hn => h n (by simp [hn])
    simp [without, ha, ih ht]

def distinctNF (xs : List Note) : Prop := xs.Pairwise (fun a b => a.nf ≠ b.nf)

theorem without_distinct (xs : List Note) (k : Nat) (h : distinctNF xs) :
    distinctNF (without k xs) := by
  induction xs with
  | nil => exact .nil
  | cons a xs ih =>
    obtain ⟨ha, ht⟩ := List.pairwise_cons.mp h
    by_cases he : a.nf = k
    · simpa [without, he] using ih ht
    · simp only [without, if_neg he]
      exact List.pairwise_cons.mpr ⟨fun b hb => ha b ((mem_without b xs k).mp hb).1, ih ht⟩

theorem debit_real (xs : List Note) (n : Note) (c : Currency)
    (hu : distinctNF xs) (hn : n ∈ xs) :
    total c (without n.nf xs) + value n c = total c xs := by
  induction xs with
  | nil => simp at hn
  | cons a xs ih =>
    obtain ⟨ha, ht⟩ := List.pairwise_cons.mp hu
    rcases List.mem_cons.mp hn with eq | hm
    · subst n
      have hj : ∀ x ∈ xs, x.nf ≠ a.nf := fun x hx => Ne.symm (ha x hx)
      simp [without, without_absent xs a.nf hj, total, Nat.add_comm]
    · have ne := ha n hm
      have debit := ih ht hm
      simp [without, ne, total]
      omega

/-- These premises expose where funded membership/authorization, binding of typed
    openings and nullifier separation are needed. A dummy identifier cannot alias a
    real funded opening. Neither private values nor conservation are assumed here. -/
structure SlotLink (xs : List Note) (i : Input) : Prop where
  realMember : i.real = true → i.note ∈ xs
  realKey : i.real = true → i.published = i.note.nf
  dummySeparate : i.real = false → ∀ n ∈ xs, n.nf ≠ i.published

theorem mem_live (n : Note) (ns : List Note) (sp : List Nat) : n ∈ live sp ns ↔ n ∈ ns ∧ n.nf ∉ sp := by
  induction ns with
  | nil => simp [live]
  | cons x xs ih =>
    by_cases hx : x.nf ∈ sp
    · simp only [live, if_pos hx, ih, List.mem_cons]
      constructor
      · rintro ⟨hm,hs⟩; exact ⟨Or.inr hm,hs⟩
      · rintro ⟨rfl | hm,hs⟩
        · exact False.elim (hs hx)
        · exact ⟨hm,hs⟩
    · simp only [live, if_neg hx, List.mem_cons, ih]
      constructor
      · rintro (rfl | ⟨hm,hs⟩)
        · exact ⟨Or.inl rfl,hx⟩
        · exact ⟨Or.inr hm,hs⟩
      · rintro ⟨rfl | hm,hs⟩
        · exact Or.inl rfl
        · exact Or.inr ⟨hm,hs⟩

theorem link_selected (s : State) (i : Input) (h : SlotLink s.funded i)
    (unseen : i.published ∉ s.spent) : SlotLink (live s.spent s.funded) i where
  realMember := fun hr => (mem_live i.note s.funded s.spent).mpr ⟨h.realMember hr, h.realKey hr ▸ unseen⟩
  realKey := h.realKey
  dummySeparate := fun hd n hn => h.dummySeparate hd n ((mem_live n s.funded s.spent).mp hn).1

theorem link_after_other (xs : List Note) (i : Input) (k : Nat)
    (h : SlotLink xs i) (ne : i.published ≠ k) : SlotLink (without k xs) i where
  realMember := fun hr => (mem_without i.note xs k).mpr ⟨h.realMember hr, h.realKey hr ▸ ne⟩
  realKey := h.realKey
  dummySeparate := fun hd n hn => h.dummySeparate hd n ((mem_without n xs k).mp hn).1

theorem debit_slot (xs : List Note) (i : Input) (c : Currency) (hu : distinctNF xs)
    (h : SlotLink xs i) (z : i.real = false → i.note.native = 0 ∧ i.note.token = 0) :
    total c (without i.published xs) + value i.note c = total c xs := by
  cases hr : i.real with
  | true =>
    rw [h.realKey hr]
    exact debit_real xs i.note c hu (h.realMember hr)
  | false =>
    rw [without_absent xs i.published (h.dummySeparate hr)]
    have hv : value i.note c = 0 := by
      obtain ⟨hn,ht⟩ := z hr
      cases c <;> simp [value,hn,ht]
    simp [hv]

structure Admission (s : State) (t : Payment) : Prop where
  selectedUnique : distinctNF (live s.spent s.funded)
  iLink : SlotLink s.funded t.i
  jLink : SlotLink s.funded t.j
  inputKeys : t.i.published ≠ t.j.published
  iUnseen : t.i.published ∉ s.spent
  jUnseen : t.j.published ∉ s.spent
  distinctOutputs : t.u.cm ≠ t.v.cm
  freshCommitments : ∀ n ∈ s.funded, t.u.cm ≠ n.cm ∧ t.v.cm ≠ n.cm
  /- True NF of a new output is a private-opening fact, not a value the node looks up.
     The circuit derives output rho from the ordered published NF pair and the output index.
     This condition states the non-aliasing interface for historical/output openings. -/
  freshIds : t.u.nf ≠ t.v.nf ∧ (∀ n ∈ s.funded, t.u.nf ≠ n.nf ∧ t.v.nf ≠ n.nf)
  uUnspent : t.u.nf ∉ t.i.published :: t.j.published :: s.spent
  vUnspent : t.v.nf ∉ t.i.published :: t.j.published :: s.spent

theorem selected_conservation (s : State) (t : Payment) (g : Gates t) (a : Admission s t)
    (c : Currency) : holdings (settle s t) c + charge c = holdings s c := by
  let xs := live s.spent s.funded
  have dj := debit_slot xs t.j c a.selectedUnique (link_selected s t.j a.jLink a.jUnseen) (dummy_zero _ g.rj g.jDummyGate)
  have di := debit_slot (without t.j.published xs) t.i c (without_distinct _ _ a.selectedUnique)
    (link_after_other xs t.i _ (link_selected s t.i a.iLink a.iUnseen) a.inputKeys) (dummy_zero _ g.ri g.iDummyGate)
  have localEq := local_conservation t g c
  unfold holdings settle
  simp only [live, if_neg a.uUnspent, if_neg a.vUnspent, total]
  rw [live_new, live_new]
  change value t.u c + (value t.v c + total c (without t.i.published (without t.j.published xs))) +
    charge c = total c xs
  omega

theorem untouched (s : State) (t : Payment) (n : Note) (nu : n.cm ≠ t.u.cm)
    (nv : n.cm ≠ t.v.cm) (ni : n.nf ≠ t.i.published) (nj : n.nf ≠ t.j.published) :
    n ∈ live (settle s t).spent (settle s t).funded ↔ n ∈ live s.spent s.funded := by
  have hu : n ≠ t.u := fun eq => nu (congrArg Note.cm eq)
  have hv : n ≠ t.v := fun eq => nv (congrArg Note.cm eq)
  simp [mem_live,settle,hu,hv,ni,nj]

theorem two_real_distinct (s : State) (t : Payment) (a : Admission s t)
    (hi : t.i.real = true) (hj : t.j.real = true) : t.i.note ≠ t.j.note := by
  intro same
  exact a.inputKeys ((a.iLink.realKey hi).trans ((congrArg Note.nf same).trans (a.jLink.realKey hj).symm))

theorem outputs_live (s : State) (t : Payment) (a : Admission s t) :
    t.u ∈ live (settle s t).spent (settle s t).funded ∧
    t.v ∈ live (settle s t).spent (settle s t).funded := by
  constructor
  · exact (mem_live ..).mpr ⟨by simp [settle],a.uUnspent⟩
  · exact (mem_live ..).mpr ⟨by simp [settle],a.vUnspent⟩

theorem preserve_commitment_uniqueness (s : State) (t : Payment) (a : Admission s t)
    (old : s.funded.Pairwise (fun x y => x.cm ≠ y.cm)) :
    (settle s t).funded.Pairwise (fun x y => x.cm ≠ y.cm) := by
  apply List.pairwise_cons.mpr
  constructor
  · intro n hn
    rcases List.mem_cons.mp hn with eq | hm
    · exact eq ▸ a.distinctOutputs
    · exact (a.freshCommitments n hm).1
  · exact List.pairwise_cons.mpr ⟨fun n hn => (a.freshCommitments n hn).2,old⟩

theorem preserve_live_uniqueness (s : State) (t : Payment) (a : Admission s t) :
    distinctNF (live (settle s t).spent (settle s t).funded) := by
  let xs := live s.spent s.funded
  let left := without t.i.published (without t.j.published xs)
  have subset : ∀ n ∈ left, n ∈ s.funded := by
    intro n hn
    have hj := ((mem_without ..).mp hn).1
    have hm : n ∈ xs := ((mem_without ..).mp hj).1
    exact ((mem_live ..).mp hm).1
  have hu := without_distinct (without t.j.published xs) t.i.published
     (without_distinct xs t.j.published a.selectedUnique)
  simp only [settle,live,if_neg a.uUnspent,if_neg a.vUnspent]
  rw [live_new,live_new]
  change distinctNF (t.u :: t.v :: left)
  apply List.pairwise_cons.mpr
  constructor
  · intro n hn
    rcases List.mem_cons.mp hn with eq | hm
    · exact eq ▸ a.freshIds.1
    · exact (a.freshIds.2 n (subset n hm)).1
  · exact List.pairwise_cons.mpr ⟨fun n hn => (a.freshIds.2 n (subset n hn)).2,hu⟩

theorem no_replay (s : State) (t : Payment) : ¬ Admission (settle s t) t := by
  intro repeated
  exact repeated.iUnseen (by simp [settle])

/-- One fee per actual ordinary inclusion; the miner reward is appended once after
    the ordered transactions. This induction does not assign the subsidy per packet. -/
inductive OrdinarySteps : State → Nat → State → Prop
  | nil (s : State) : OrdinarySteps s 0 s
  | step {s m : State} {k : Nat} (h : OrdinarySteps s k m) (t : Payment)
      (g : Gates t) (a : Admission m t) : OrdinarySteps s (k+1) (settle m t)

theorem ordinary_steps_preserve_spent {s m : State} {k nf : Nat} (h : OrdinarySteps s k m)
    (old : nf ∈ s.spent) : nf ∈ m.spent := by
  induction h with
  | nil => exact old
  | step prior t g a ih => exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ ih)

/-- Both published keys, including a dummy-domain key, stay unavailable to both slots of
    every later admitted payment on a branch retaining this spend. Rewards leave spent unchanged. -/
theorem same_branch_no_nf_reuse (s later : State) (old next : Payment)
    (retained : ∀ nf ∈ (settle s old).spent, nf ∈ later.spent) (a : Admission later next) :
    ∀ nf ∈ [old.i.published, old.j.published], nf ∉ [next.i.published, next.j.published] := by
  intro nf was
  have inPast : nf ∈ (settle s old).spent := by
    rcases List.mem_cons.mp was with eq | tail
    · simp [settle,eq]
    · have eq : nf = old.j.published := by simpa using tail
      simp [settle,eq]
  have known := retained nf inPast
  intro used
  rcases List.mem_cons.mp used with eq | tail
  · exact a.iUnseen (eq ▸ known)
  · have eq : nf = next.j.published := by simpa using tail
    exact a.jUnseen (eq ▸ known)

theorem steps_account (s m : State) (k : Nat) (h : OrdinarySteps s k m) (c : Currency) :
    holdings m c + k * charge c = holdings s c := by
  induction h with
  | nil => simp
  | step prior t g a ih =>
    have hs := selected_conservation _ t g a c
    rw [Nat.add_mul]
    simp only [Nat.one_mul]
    omega

def rewardState (s : State) (r : Note) : State := ⟨r :: s.funded,s.spent⟩

theorem miner_credit (s : State) (r : Note) (c : Currency) (fresh : r.nf ∉ s.spent) :
    holdings (rewardState s r) c = value r c + holdings s c := by
  simp [holdings,rewardState,live,fresh,total]

def subsidy : Currency → Nat
  | .native => 100
  | .asset _ => 0

theorem ordinary_block (s m : State) (k : Nat) (steps : OrdinarySteps s k m)
    (r : Note) (fresh : r.nf ∉ m.spent) (cash : r.native = 100 + k*3)
    (noToken : r.token = 0) (c : Currency) :
    holdings (rewardState m r) c = holdings s c + subsidy c := by
  rw [miner_credit m r c fresh]
  have totals := steps_account s m k steps c
  cases c with
  | native =>
    simp only [value,charge,subsidy,cash] at *
    omega
  | asset id =>
    simp [value,charge,subsidy,noToken] at *
    omega

theorem block_reward_bound {k : Nat} (capacity : k ≤ 4) : 100+k*3 ≤ 112 := by omega

/-- Per-height ordinary packet counts. Payments use one physical frame apiece. -/
def packetCount : List (Fin 5) → Nat
  | [] => 0
  | k :: ks => k.val + packetCount ks

theorem packet_count_bound (counts : List (Fin 5)) :
    packetCount counts ≤ 4 * counts.length := by
  induction counts with
  | nil => decide
  | cons k ks ih =>
    have bound := k.isLt
    simp only [packetCount,List.length_cons,Nat.mul_add] at *
    omega

theorem ordinary_prefix_bounds (counts : List (Fin 5)) (height : counts.length < 2^32) :
    3 * packetCount counts ≤ 51539607540 ∧
    100 * counts.length ≤ 429496729500 ∧
    3 * packetCount counts + 100 * counts.length ≤ 481036337040 ∧
    3 * packetCount counts + 100 * counts.length < 2^63 ∧
    3 * packetCount counts + 100 * counts.length < P := by
  have bound := packet_count_bound counts
  unfold P
  omega

/- Ground gate controls. Both real inputs have maximum native and token values.
   The two output token values also saturate their range. The last native output pays the fee. -/
def maximumTransfer : Payment :=
  let a : AssetId := ⟨1,0,0,0⟩
  ⟨⟨⟨1,11,B-1,B-1,a⟩,true,11⟩,⟨⟨2,12,B-1,B-1,a⟩,true,12⟩,
   ⟨3,13,B-1,B-1,a⟩,⟨4,14,B-4,B-1,a⟩,a⟩

theorem maximum_transfer_satisfies_gates : Gates maximumTransfer := by constructor <;> decide

def firstOutOfRange : Payment :=
  let t := maximumTransfer
  { t with i := { t.i with note := { t.i.note with native := B, token := B } },
           j := { t.j with note := { t.j.note with native := B-2, token := B-2 } } }

theorem first_out_of_range_rejected :
    (firstOutOfRange.i.note.native + firstOutOfRange.j.note.native) % P =
      (((firstOutOfRange.u.native + firstOutOfRange.v.native) % P) + 3) % P ∧
    (firstOutOfRange.i.note.token + firstOutOfRange.j.note.token) % P =
      (firstOutOfRange.u.token + firstOutOfRange.v.token) % P ∧
    ¬ Gates firstOutOfRange := by
  refine ⟨by decide,by decide,?_⟩
  intro gates
  exact (Nat.lt_irrefl B) gates.ri.1

end FundedC
