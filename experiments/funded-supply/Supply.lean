import Conservation

/-! Selected profile-C supply operations. The imported model defines funded openings and
    the spent-nullifier projection. Neither proof knowledge, opening binding, signature
    unforgeability nor hash collision resistance is asserted by these arithmetic theorems. -/
namespace FundedSupply
open FundedC

structure Descriptor where
  word : Nat
  high : Bool
  lo : Fin B
  publicId : AssetId

def bit (b : Bool) : Nat := if b then 1 else 0
def issuing (d : Descriptor) : Bool := decide (d.lo.val ≠ 0) && !d.high
def minted (d : Descriptor) := bit (issuing d) * d.lo.val
def burned (d : Descriptor) := bit d.high * d.lo.val
def available (t : Payment) (d : Descriptor) :=
  ((t.i.note.token + t.j.note.token) % P + minted d) % P
def allocated (t : Payment) (d : Descriptor) :=
  ((t.u.token + t.v.token) % P + burned d) % P

abbrev limbGate (d : Descriptor) (out inner : Fin (2^63)) : Prop :=
  out.val = (bit (decide (d.lo.val ≠ 0)) * inner.val) % P

abbrev publicGate (d : Descriptor) (a : AssetId) : Prop :=
  limbGate d d.publicId.w0 a.w0 ∧ limbGate d d.publicId.w1 a.w1 ∧
  limbGate d d.publicId.w2 a.w2 ∧ limbGate d d.publicId.w3 a.w3

structure Gates (t : Payment) (d : Descriptor) : Prop where
  ri : ranged t.i.note
  rj : ranged t.j.note
  ru : ranged t.u
  rv : ranged t.v
  nativeEq : (t.i.note.native + t.j.note.native) % P =
    (((t.u.native + t.v.native) % P) + 3) % P
  encoded : d.word = (d.lo.val + bit d.high * B) % P
  emptyBurn : (bit (decide (d.lo.val = 0)) * bit d.high) % P = 0
  publicBinding : publicGate d t.asset
  tokenEq : available t d = allocated t d
  issuerInput : (bit (issuing d) * ((t.i.note.token + t.j.note.token) % P)) % P = 0
  issuerDummy : (bit (issuing d) * dummyBit t.i) % P = 0
  zeroIdGate : t.asset = zeroId ↔ available t d = 0
  ti : tag t.asset t.i.note
  tj : tag t.asset t.j.note
  tu : tag t.asset t.u
  tv : tag t.asset t.v
  di : dummyGate t.i
  dj : dummyGate t.j

theorem word_split (t : Payment) (d : Descriptor) (g : Gates t d) :
    d.word = d.lo.val + bit d.high * B := by
  have hl := d.lo.isLt
  have small : d.lo.val + bit d.high * B < P := by
    cases h : d.high <;> simp [h,bit,B,P] at * <;> omega
  simpa [Nat.mod_eq_of_lt small] using g.encoded

theorem descriptor_lift (t : Payment) (d : Descriptor) (g : Gates t d) :
    d.word < 2^63 ∧ (d.word + P - bit d.high * B) % P = d.lo.val := by
  have hl := d.lo.isLt
  unfold B at hl
  have he := word_split t d g
  cases hh : d.high <;> simp [hh,bit,B,P] at he ⊢ <;> omega

theorem empty_burn_forbidden (t : Payment) (d : Descriptor) (g : Gates t d)
    (hb : d.high = true) : 0 < d.lo.val := by
  by_cases h0 : d.lo.val = 0
  · have e := g.emptyBurn
    simp [h0,hb,bit,P] at e
  · omega

theorem amount_bounds (d : Descriptor) : minted d < B ∧ burned d < B := by
  have hl := d.lo.isLt
  cases hi : issuing d <;> cases hh : d.high <;> simp [minted,burned,bit,hi,hh,B] at * <;> omega

theorem three_term_bounds {x y z : Nat} (hx : x<B) (hy : y<B) (hz : z<B) :
    x+y ≤ 9223372036854775806 ∧ x+y+z ≤ 13835058055282163709 ∧ x+y+z < P := by
  unfold B at *
  unfold P
  omega

theorem field_sum (x y z : Nat) (hx : x<B) (hy : y<B) (hz : z<B) :
    ((x+y)%P + z)%P = x+y+z := by
  have h := (three_term_bounds hx hy hz).2.2
  have hh : x+y<P := by omega
  simp [Nat.mod_eq_of_lt h,Nat.mod_eq_of_lt hh]

theorem lift_token (t : Payment) (d : Descriptor) (g : Gates t d) :
    t.i.note.token + t.j.note.token + minted d = t.u.token + t.v.token + burned d := by
  simpa [available,allocated,field_sum _ _ _ g.ri.2 g.rj.2 (amount_bounds d).1,
    field_sum _ _ _ g.ru.2 g.rv.2 (amount_bounds d).2] using g.tokenEq

theorem lift_cash (t : Payment) (d : Descriptor) (g : Gates t d) :
    t.i.note.native + t.j.note.native = t.u.native + t.v.native + 3 := by
  have h := (exact_intermediate_bounds g.ri.1 g.rj.1).2.2
  have hh : t.i.note.native + t.j.note.native < P := by omega
  simpa [Nat.mod_eq_of_lt hh,field_sum _ _ 3 g.ru.1 g.rv.1 (by decide)] using g.nativeEq

theorem private_zero (t : Payment) (d : Descriptor) (g : Gates t d) :
    t.asset = zeroId ↔ t.i.note.token = 0 ∧ t.j.note.token = 0 ∧ minted d = 0 := by
  have hz := g.zeroIdGate
  rw [available,field_sum _ _ _ g.ri.2 g.rj.2 (amount_bounds d).1] at hz
  constructor
  · intro h
    have := hz.mp h
    omega
  · intro h
    exact hz.mpr (by omega)

theorem issuing_constraints (t : Payment) (d : Descriptor) (g : Gates t d) (hi : issuing d = true) :
    t.i.real = true ∧ t.i.note.token = 0 ∧ t.j.note.token = 0 := by
  have h := (exact_intermediate_bounds g.ri.2 g.rj.2).2.2
  have hh : t.i.note.token + t.j.note.token < P := by omega
  have inputs := g.issuerInput
  simp [hi,bit,Nat.mod_eq_of_lt hh] at inputs
  have first := g.issuerDummy
  cases hr : t.i.real <;> simp [hi,bit,dummyBit,hr,P] at * <;> omega

private theorem limb_active (d : Descriptor) (h : d.lo.val ≠ 0) (x y : Fin (2^63))
    (hg : limbGate d x y) : x = y := by
  have hy := y.isLt
  have hs : y.val < P := by unfold P; omega
  exact Fin.ext (by simpa [limbGate,bit,h,Nat.mod_eq_of_lt hs] using hg)

private theorem limb_inactive (d : Descriptor) (h : d.lo.val = 0) (x y : Fin (2^63))
    (hg : limbGate d x y) : x = 0 := by
  exact Fin.ext (by simpa [limbGate,bit,h] using hg)

private theorem id_ext {a b : AssetId} (h0 : a.w0=b.w0) (h1 : a.w1=b.w1)
    (h2 : a.w2=b.w2) (h3 : a.w3=b.w3) : a=b := by cases a; cases b; simp_all

theorem public_selector (t : Payment) (d : Descriptor) (g : Gates t d) :
    d.publicId = if d.lo.val=0 then zeroId else t.asset := by
  obtain ⟨a,b,c,e⟩ := g.publicBinding
  by_cases h : d.lo.val=0
  · simp only [if_pos h]
    exact id_ext (limb_inactive _ h _ _ a) (limb_inactive _ h _ _ b)
      (limb_inactive _ h _ _ c) (limb_inactive _ h _ _ e)
  · simp only [if_neg h]
    exact id_ext (limb_active _ h _ _ a) (limb_active _ h _ _ b)
      (limb_active _ h _ _ c) (limb_active _ h _ _ e)

theorem active_id_nonzero (t : Payment) (d : Descriptor) (g : Gates t d) (h : d.lo.val ≠ 0) :
    d.publicId = t.asset ∧ t.asset ≠ zeroId := by
  refine ⟨by simpa [h] using public_selector t d g,?_⟩
  intro hz
  obtain ⟨hi,hj,hm⟩ := (private_zero t d g).mp hz
  have eq := lift_token t d g
  cases hh : d.high <;> simp [minted,burned,issuing,bit,hh,h,hi,hj] at hm eq <;> omega

def forId (key query : AssetId) (amount : Nat) := if key = query then amount else 0

theorem local_delta (t : Payment) (d : Descriptor) (g : Gates t d) (q : AssetId) :
    value t.i.note (.asset q) + value t.j.note (.asset q) + forId d.publicId q (minted d) =
    value t.u (.asset q) + value t.v (.asset q) + forId d.publicId q (burned d) := by
  rw [effective_tag _ _ _ g.ti,effective_tag _ _ _ g.tj,effective_tag _ _ _ g.tu,effective_tag _ _ _ g.tv]
  have he := lift_token t d g
  by_cases z : d.lo.val=0
  · have hm : minted d=0 := by simp [minted,z]
    have hb : burned d=0 := by simp [burned,z]
    by_cases h : t.asset=q <;> simp [forId,h,hm,hb] at * <;> omega
  · obtain ⟨hk,_⟩ := active_id_nonzero t d g z
    by_cases h : t.asset=q <;> simp [forId,h,hk] at * <;> omega

theorem selected_openings (s : State) (t : Payment) (d : Descriptor)
    (g : Gates t d) (a : Admission s t) (c : Currency) :
    holdings (settle s t) c + value t.i.note c + value t.j.note c =
      holdings s c + value t.u c + value t.v c := by
  let xs := live s.spent s.funded
  have dj := debit_slot xs t.j c a.selectedUnique (link_selected s t.j a.jLink a.jUnseen)
    (dummy_zero _ g.rj g.dj)
  have di := debit_slot (without t.j.published xs) t.i c (without_distinct _ _ a.selectedUnique)
    (link_after_other xs t.i _ (link_selected s t.i a.iLink a.iUnseen) a.inputKeys)
    (dummy_zero _ g.ri g.di)
  unfold holdings settle
  simp only [live,if_neg a.uUnspent,if_neg a.vUnspent,total]
  rw [live_new,live_new]
  change value t.u c + (value t.v c + total c (without t.i.published (without t.j.published xs))) +
    value t.i.note c + value t.j.note c = total c xs + value t.u c + value t.v c
  omega

theorem selected_supply (s : State) (t : Payment) (d : Descriptor) (g : Gates t d)
    (a : Admission s t) (q : AssetId) :
    holdings (settle s t) (.asset q) + forId d.publicId q (burned d) =
      holdings s (.asset q) + forId d.publicId q (minted d) := by
  have h := selected_openings s t d g a (.asset q)
  have l := local_delta t d g q
  omega

theorem selected_fee (s : State) (t : Payment) (d : Descriptor) (g : Gates t d) (a : Admission s t) :
    holdings (settle s t) .native + 3 = holdings s .native := by
  have h := selected_openings s t d g a .native
  simp only [value] at h
  have l := lift_cash t d g
  omega

inductive Op where | fixed | register | mint | burn
  deriving DecidableEq
inductive Mode where | fixed | managed (key : Nat)
  deriving DecidableEq
structure Row where
  mode : Mode
  quantity : Nat
  revision : Nat
  headTx : Nat
  deriving DecidableEq
abbrev Registry := AssetId → Option Row

def outstanding (r : Registry) (id : AssetId) : Nat :=
  match r id with | none => 0 | some row => row.quantity

def write (r : Registry) (id : AssetId) (row : Row) : Registry :=
  fun q => if q = id then some row else r q

/-- Byte strings and hashes are abstracted as opaque identifiers. Signature verification
    takes the typed MNG3 authorization message including the actual inner-frame hash.
    The issuer key and the authority spending either note are independent. -/
structure Envelope where
  op : Op
  pk : Option Nat
  seq : Nat
  previous : Nat
  signature : Option Nat
  inner : Nat
structure AuthMessage where
  network : Nat
  op : Op
  pk : Nat
  seq : Nat
  previous : Nat
  innerHash : Nat
structure Context where
  network : Nat
  fixedId : Nat → Nat → AssetId
  managedId : Nat → Nat → Nat → AssetId
  hashInner : Nat → Nat
  packetId : Envelope → Nat
  verifies : AuthMessage → Nat → Prop
  opens : Nat → Payment → Descriptor → Prop

def signed (ctx : Context) (e : Envelope) (key : Nat) : Prop :=
  e.pk = some key ∧ e.seq < 2^63 ∧ ∃ sig, e.signature = some sig ∧
    ctx.verifies ⟨ctx.network,e.op,key,e.seq,e.previous,ctx.hashInner e.inner⟩ sig

def bare (e : Envelope) : Prop :=
  e.pk = none ∧ e.signature = none ∧ e.seq = 0 ∧ e.previous = 0

structure Wire (ctx : Context) (e : Envelope) (t : Payment) (d : Descriptor) : Prop where
  sameInner : ctx.opens e.inner t d
  active : 0 < d.lo.val
  sign : d.high = decide (e.op = .burn)

/-- The latest selected row determines the next revision. An unsigned burn does not
    carry an issuer predecessor. It still appends a new row with the old managed key. -/
inductive Rule (ctx : Context) (r : Registry) (t : Payment) (d : Descriptor) (e : Envelope) : Row → Prop
  | fixed (op : e.op = .fixed) (shape : bare e) (unused : r d.publicId = none)
      (id : d.publicId = ctx.fixedId ctx.network t.i.published) :
      Rule ctx r t d e ⟨.fixed,d.lo.val,1,ctx.packetId e⟩
  | register (key : Nat) (op : e.op = .register) (auth : signed ctx e key)
      (init : e.seq = 0 ∧ e.previous = 0) (unused : r d.publicId = none)
      (id : d.publicId = ctx.managedId ctx.network key t.i.published) :
      Rule ctx r t d e ⟨.managed key,d.lo.val,1,ctx.packetId e⟩
  | mint (key q rev prev : Nat) (op : e.op = .mint) (auth : signed ctx e key)
      (row : r d.publicId = some ⟨.managed key,q,rev,prev⟩)
      (current : e.seq = rev ∧ e.previous = prev) (ceiling : q+d.lo.val < B) :
      Rule ctx r t d e ⟨.managed key,q+d.lo.val,rev+1,ctx.packetId e⟩
  | burn (key q rev prev : Nat) (op : e.op = .burn) (shape : bare e)
      (row : r d.publicId = some ⟨.managed key,q,rev,prev⟩) (enough : d.lo.val ≤ q) :
      Rule ctx r t d e ⟨.managed key,q-d.lo.val,rev+1,ctx.packetId e⟩

theorem positive_decode (t : Payment) (d : Descriptor) (g : Gates t d)
    (h : d.high = false) (nz : 0<d.lo.val) :
    d.word = d.lo.val ∧ minted d = d.lo.val ∧ burned d = 0 ∧
    t.i.real = true ∧ t.i.note.token = 0 ∧ t.j.note.token = 0 := by
  have ne : d.lo.val ≠ 0 := by omega
  have hi : issuing d = true := by simp [issuing,h,ne]
  exact ⟨by simpa [h,bit] using word_split t d g,by simp [minted,hi,bit],by simp [burned,bit,h],
         issuing_constraints t d g hi⟩

theorem burn_decode (t : Payment) (d : Descriptor) (g : Gates t d) (h : d.high = true) :
    d.word = B + d.lo.val ∧ minted d = 0 ∧ burned d = d.lo.val ∧ 0 < d.lo.val := by
  exact ⟨by simpa [h,bit,Nat.add_comm] using word_split t d g,by simp [minted,issuing,h,bit],
         by simp [burned,h,bit],empty_burn_forbidden t d g h⟩

private theorem adds {d : Descriptor} (nz : 0 < d.lo.val) (hs : d.high=false) :
    minted d = d.lo.val ∧ burned d = 0 := by
  have h : d.lo.val ≠ 0 := by omega
  simp [minted,burned,issuing,bit,hs,h]

private theorem subtracts {d : Descriptor} (hs : d.high=true) :
    minted d = 0 ∧ burned d = d.lo.val := by simp [minted,burned,issuing,bit,hs]

theorem registry_delta {ctx r t d e new} (w : Wire ctx e t d) (step : Rule ctx r t d e new) :
    new.quantity + burned d = outstanding r d.publicId + minted d := by
  cases step with
  | fixed op _ unused _ =>
    have ⟨hm,hb⟩ := adds w.active (by simpa [op] using w.sign)
    simp [outstanding,unused,hm,hb]
  | register key op _ _ unused _ =>
    have ⟨hm,hb⟩ := adds w.active (by simpa [op] using w.sign)
    simp [outstanding,unused,hm,hb]
  | mint key q rev prev op _ row _ _ =>
    have ⟨hm,hb⟩ := adds w.active (by simpa [op] using w.sign)
    simp [outstanding,row,hm,hb]
  | burn key q rev prev op _ row enough =>
    have ⟨hm,hb⟩ := subtracts (d := d) (by simpa [op] using w.sign)
    simp [outstanding,row,hm,hb]
    omega

theorem other_rows_unchanged (r : Registry) (id q : AssetId) (row : Row) (h : q ≠ id) :
    write r id row q = r q := by simp [write,h]

theorem other_assets_unchanged {s t d} (g : Gates t d) (a : Admission s t) {q}
    (h : q ≠ d.publicId) : holdings (settle s t) (.asset q) = holdings s (.asset q) := by
  simpa [forId,Ne.symm h] using selected_supply s t d g a q

theorem new_registration_is_unique {ctx r t d e row} (h : Rule ctx r t d e row)
    (reg : e.op = .fixed ∨ e.op = .register) : r d.publicId = none := by
  cases h <;> simp_all

theorem mint_requires_current_authority {ctx r t d e row} (h : Rule ctx r t d e row) (op : e.op=.mint) :
    ∃ key q, signed ctx e key ∧ r d.publicId=some ⟨.managed key,q,e.seq,e.previous⟩ ∧
      q+d.lo.val<B ∧ row=⟨.managed key,q+d.lo.val,e.seq+1,ctx.packetId e⟩ := by
  cases h with
  | fixed o _ _ _ => simp_all
  | register k o _ _ _ _ => simp_all
  | mint k q rev prev _ auth old current bound =>
    exact ⟨k,q,auth,by simpa [current.1,current.2] using old,bound,by simp [current.1]⟩
  | burn _ _ _ _ o _ _ _ => simp_all

theorem burn_requires_managed_funding {ctx r t d e row} (h : Rule ctx r t d e row) (op : e.op=.burn) :
    ∃ key q rev prev, bare e ∧ r d.publicId=some ⟨.managed key,q,rev,prev⟩ ∧
      d.lo.val ≤ q ∧ row=⟨.managed key,q-d.lo.val,rev+1,ctx.packetId e⟩ := by
  cases h with
  | fixed o _ _ _ => simp_all
  | register k o _ _ _ _ => simp_all
  | mint _ _ _ _ o _ _ _ _ => simp_all
  | burn k q rev prev _ shape old bound => exact ⟨k,q,rev,prev,shape,old,bound,rfl⟩

theorem full_burn_keeps_registration {ctx r t d e row} (h : Rule ctx r t d e row) (op : e.op=.burn)
    (all : outstanding r d.publicId = d.lo.val) :
    ∃ key rev, row=⟨.managed key,0,rev+1,ctx.packetId e⟩ := by
  obtain ⟨k,q,rev,prev,_,old,_,hn⟩ := burn_requires_managed_funding h op
  have eq : q = d.lo.val := by simpa [outstanding,old] using all
  exact ⟨k,rev,by simpa [eq] using hn⟩

theorem fixed_supply_immutable {ctx r t d e row q rev tx}
    (h : r d.publicId=some ⟨.fixed,q,rev,tx⟩) : ¬ Rule ctx r t d e row := by
  intro step
  cases step <;> simp_all

def Consistent (s : State) (r : Registry) : Prop :=
  ∀ q, holdings s (.asset q) = outstanding r q ∧ outstanding r q < B

theorem preserve_supply {s t d ctx r e row} (g : Gates t d) (a : Admission s t) (w : Wire ctx e t d)
    (step : Rule ctx r t d e row) (before : Consistent s r) :
    Consistent (settle s t) (write r d.publicId row) := by
  intro q
  by_cases eq : q=d.publicId
  · subst q
    have fund := selected_supply s t d g a d.publicId
    have reg := registry_delta w step
    have old := before d.publicId
    simp [forId] at fund
    simp [outstanding,write]
    constructor
    · omega
    · cases step with
      | fixed => exact d.lo.isLt
      | register => exact d.lo.isLt
      | mint _ _ _ _ _ _ _ _ bound => exact bound
      | burn _ q _ _ _ _ oldRow bound =>
        simp only [outstanding,oldRow] at old
        change q-d.lo.val < B
        omega
  · simpa [outstanding,write,eq,other_assets_unchanged g a eq] using before q

theorem reward_token_neutral (s : State) (r : Note) (fresh : r.nf ∉ s.spent) (z : r.token=0)
    (q : AssetId) : holdings (rewardState s r) (.asset q) = holdings s (.asset q) := by
  rw [miner_credit _ _ _ fresh]
  simp [value,z]

/-- Selected transitions only. Rewinds choose another path from its own fork-point state.
    The ordinary branch neither reads nor writes the supply registry. -/
inductive Path (ctx : Context) : State → Registry → State → Registry → Prop
  | start (s r) : Path ctx s r s r
  | supply {s r m reg} (p : Path ctx s r m reg) {t d e row}
      (g : Gates t d) (a : Admission m t) (w : Wire ctx e t d) (h : Rule ctx reg t d e row) :
      Path ctx s r (settle m t) (write reg d.publicId row)
  | transfer {s r m reg} (p : Path ctx s r m reg) {t} (g : FundedC.Gates t) (a : Admission m t) :
      Path ctx s r (settle m t) reg
  | reward {s r m reg} (p : Path ctx s r m reg) (n : Note) (fresh : n.nf ∉ m.spent) (z : n.token=0) :
      Path ctx s r (rewardState m n) reg

theorem consistent_path {ctx s r final reg} (start : Consistent s r)
    (p : Path ctx s r final reg) : Consistent final reg := by
  induction p with
  | start => exact start
  | supply _ g a w h ih => exact preserve_supply g a w h (ih)
  | transfer _ g a ih =>
    intro q
    have ht := selected_conservation _ _ g a (.asset q)
    simp only [charge,Nat.add_zero] at ht
    rw [ht]
    exact ih q
  | reward _ n hf hz ih =>
    intro q
    rw [reward_token_neutral _ n hf hz q]
    exact ih q

theorem empty_consistent : Consistent ⟨[],[]⟩ (fun _ => none) := by
  intro q
  simp [holdings,live,total,outstanding,B]

theorem unregistered_has_no_funded_tokens {s r} (h : Consistent s r) {q : AssetId}
    (absent : r q=none) : holdings s (.asset q)=0 := by simpa [outstanding,absent] using (h q).1

theorem remint_from_zero {ctx r t d e key rev previous}
    (head : r d.publicId=some ⟨.managed key,0,rev,previous⟩)
    (op : e.op=.mint) (auth : signed ctx e key) (current : e.seq=rev ∧ e.previous=previous) :
    Rule ctx r t d e ⟨.managed key,d.lo.val,rev+1,ctx.packetId e⟩ := by
  simpa using Rule.mint key 0 rev previous op auth head current (by simp)

/-- Preflight checks all supply events against the block parent. Since the node rejects
    two supply events for one ID in a block, earlier event writes leave this lookup unchanged. -/
def applyWrites (r : Registry) : List (AssetId × Row) → Registry
  | [] => r
  | (id,row)::xs => applyWrites (write r id row) xs

theorem same_block_lookup (r : Registry) (events : List (AssetId × Row)) (id : AssetId)
    (fresh : id ∉ events.map Prod.fst) : applyWrites r events id = r id := by
  induction events generalizing r with
  | nil => rfl
  | cons hd xs ih =>
    rcases hd with ⟨key,row⟩
    simp only [List.map_cons,List.mem_cons,not_or] at fresh
    rw [applyWrites,ih _ fresh.2,other_rows_unchanged _ _ _ _ fresh.1]

/- These ground controls verify arithmetic gates and isolated registry guards. They
   do not stand in for a registered proof or an authenticated issuer signature. -/
def testId : AssetId := ⟨1,0,0,0⟩
def testNote (cm nf cash qty : Nat) : Note :=
  ⟨cm,nf,cash,qty,if qty=0 then zeroId else testId⟩

def issueCeiling : Payment :=
  ⟨⟨testNote 1 11 0 0,true,11⟩,⟨testNote 2 12 3 0,true,12⟩,
   testNote 3 13 0 (B-1),testNote 4 14 0 0,testId⟩
def issueDescriptor : Descriptor := ⟨B-1,false,⟨B-1,by decide⟩,testId⟩
theorem issue_ceiling_gates : Gates issueCeiling issueDescriptor := by constructor <;> decide

def burnCeiling : Payment :=
  ⟨⟨testNote 1 41 0 0,false,41⟩,⟨testNote 2 12 3 (B-1),true,12⟩,
   testNote 3 13 0 0,testNote 4 14 0 0,testId⟩
def burnDescriptor : Descriptor := ⟨2*B-1,true,⟨B-1,by decide⟩,testId⟩
theorem full_burn_dummy_first_gates : Gates burnCeiling burnDescriptor := by constructor <;> decide

def burnChange : Payment :=
  { burnCeiling with u := testNote 3 13 0 (B-2) }
def burnOne : Descriptor := ⟨B+1,true,⟨1,by decide⟩,testId⟩
theorem burn_with_change_gates : Gates burnChange burnOne := by constructor <;> decide

theorem empty_burn_rejected : ¬ Gates burnCeiling ⟨B,true,⟨0,by decide⟩,testId⟩ := by
  intro g
  exact (Nat.lt_irrefl 0) (empty_burn_forbidden _ _ g rfl)

def inputOnIssue : Payment :=
  { issueCeiling with i := ⟨testNote 1 11 0 1,true,11⟩, v := testNote 4 14 0 1 }
theorem issue_cannot_recycle_tokens :
    available inputOnIssue issueDescriptor = allocated inputOnIssue issueDescriptor ∧
    ¬ Gates inputOnIssue issueDescriptor := by
  refine ⟨by decide,?_⟩
  intro g
  have h := issuing_constraints _ _ g (by decide)
  exact (by decide : (1:Nat) ≠ 0) h.2.1

theorem ceiling_rejects_one_more {ctx r t d e new key rev tx} (limit : r d.publicId=some ⟨.managed key,B-1,rev,tx⟩)
    (op : e.op=.mint) (n : 0<d.lo.val) : ¬ Rule ctx r t d e new := by
  intro h
  obtain ⟨_,q,_,old,bound,_⟩ := mint_requires_current_authority h op
  rw [limit] at old
  have qeq : B-1=q := congrArg Row.quantity (Option.some.inj old)
  unfold B at *
  omega

#print axioms selected_supply
#print axioms registry_delta
#print axioms preserve_supply
#print axioms consistent_path
#print axioms full_burn_keeps_registration
end FundedSupply
