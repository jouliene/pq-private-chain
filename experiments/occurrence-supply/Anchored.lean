import Std

/-! The validator groups chronological digests by fours, pads each short group with zero,
and hashes the four digests in wire-byte order. A C witness provides an ordered preimage
and a private selector. Its order is not itself constrained to be sorted. -/
namespace FundedAnchor

abbrev Digest := Nat
abbrev Quad := List Digest
abbrev Hash := Quad → Digest

def groups : List Digest → List Quad
  | [] => []
  | [a] => [[a,0,0,0]]
  | [a,b] => [[a,b,0,0]]
  | [a,b,c] => [[a,b,c,0]]
  | a::b::c::d::rest => [a,b,c,d] :: groups rest

theorem nonpadding {q : Quad} {x : Digest} {xs : List Digest}
    (g : q ∈ groups xs) (hx : x ∈ q) (nz : x ≠ 0) : x ∈ xs := by
  induction xs using groups.induct with
  | case1 => simp [groups] at g
  | case2 a => simp [groups] at g; subst q; simpa [nz] using hx
  | case3 a b => simp [groups] at g; subst q; simpa [nz] using hx
  | case4 a b c => simp [groups] at g; subst q; simpa [nz] using hx
  | case5 a b c d rest ih =>
    simp only [groups,List.mem_cons] at g
    rcases g with rfl | tail
    · simpa using (List.mem_append_left rest hx)
    · exact List.mem_append_right [a,b,c,d] (ih tail)

-- The ordering may be any fixed wire encoding. No numeric-index information follows from sorting.
def ordered (le : Digest → Digest → Bool) (q : Quad) := q.mergeSort le

def up (h : Hash) (le : Digest → Digest → Bool) (xs : List Digest) :=
  (groups xs).map (fun q => h (ordered le q))

def levels (h : Hash) (le : Digest → Digest → Bool) (xs : List Digest) : Nat → List Digest
  | 0 => xs
  | n+1 => levels h le (up h le xs) n

inductive Path (h : Hash) : Digest → List Quad → Digest → Prop
  | nil (x : Digest) : Path h x [] x
  | step {x q qs root} (arity : q.length = 4) (occupied : x ≠ 0) (chosen : x ∈ q)
      (next : Path h (h q) qs root) : Path h x (q::qs) root

/-- Only exclude second preimages between this witness's ordered quad and actually
    evaluated selected-prefix quads at the same level. No global hash injectivity. -/
def Binds (h : Hash) (le : Digest → Digest → Bool) (xs : List Digest) : List Quad → Prop
  | [] => True
  | q::qs => (∀ g ∈ groups xs, h (ordered le g) = h q → ordered le g = q) ∧
             Binds h le (up h le xs) qs

theorem occupied_member {h le xs x qs root} (path : Path h x qs root)
    (bind : Binds h le xs qs) (top : root ∈ levels h le xs qs.length) : x ∈ xs := by
  induction path generalizing xs with
  | nil => exact top
  | @step x q qs root _ nz chosen next ih =>
    have above : h q ∈ up h le xs := ih bind.2 top
    obtain ⟨g,inGroup,eqHash⟩ := List.mem_map.mp above
    have member : x ∈ ordered le g := bind.1 g inGroup eqHash ▸ chosen
    exact nonpadding inGroup ((List.mergeSort_perm g le).mem_iff.mp member) nz

theorem selected_prefix {h le} {history : List Digest} {count x qs root}
    (path : Path h x qs root) (bind : Binds h le (history.take count) qs)
    (anchor : levels h le (history.take count) qs.length = [root]) : x ∈ history.take count :=
  occupied_member path bind (by simp [anchor])

def walk (h : Hash) (x : Digest) : List Quad → Option Digest
  | [] => some x
  | q::qs => if q.length = 4 ∧ x ≠ 0 ∧ x ∈ q then walk h (h q) qs else none

theorem walk_path {h x qs root} (ok : walk h x qs = some root) : Path h x qs root := by
  induction qs generalizing x with
  | nil => simp [walk] at ok; subst root; exact Path.nil x
  | cons q qs ih =>
    simp only [walk] at ok
    split at ok
    · rename_i cond; exact Path.step cond.1 cond.2.1 cond.2.2 (ih ok)
    · contradiction

def checkPreimages (h : Hash) (le : Digest → Digest → Bool) (xs : List Digest) : List Quad → Bool
  | [] => true
  | q::qs => (groups xs).all (fun g => h (ordered le g) != h q || ordered le g == q) &&
             checkPreimages h le (up h le xs) qs

theorem checked_preimages {h le xs qs} (ok : checkPreimages h le xs qs = true) : Binds h le xs qs := by
  induction qs generalizing xs with
  | nil => trivial
  | cons q qs ih =>
    have pair := Bool.and_eq_true_iff.mp ok
    refine ⟨?_,ih pair.2⟩
    intro g hg eq
    have one := List.all_eq_true.mp pair.1 g hg
    simpa [eq] using one

theorem checked_membership {h le} {history : List Digest} {count leaf qs root}
    (walks : walk h leaf qs = some root)
    (checks : checkPreimages h le (history.take count) qs = true)
    (top : levels h le (history.take count) qs.length = [root]) : leaf ∈ history.take count :=
  selected_prefix (walk_path walks) (checked_preimages checks) top

end FundedAnchor
