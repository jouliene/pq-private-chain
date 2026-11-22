import Anchored
import Lean.Data.Json

/-! Independent executable check for the private restored path. The inputs stay in the
    wallet's private directory. No path, leaf, identifier or value is printed. -/
open Lean FundedAnchor

private def prime := 18446744069414584321
private abbrev Vec := Array Nat
private structure Constants where
  initial : Vec
  internal : Vec
  terminal : Vec
  diag : Vec
  deriving FromJson
private structure Example where
  leaves : List Nat
  count : Nat
  depth : Nat
  root : Nat
  anchor : Nat
  anchorHeight : Nat
  spendHeight : Nat
  parentHash : Nat
  stateHash : Nat
  extrinsicsHash : Nat
  leaf : Nat
  quads : List Quad
  deriving FromJson

private def at12 (f : Nat → Nat) : Vec := Array.ofFn (fun i : Fin 12 => f i.val)

private def external (s : Vec) : Vec := Id.run do
  let mut m := #[]
  for j in [0,4,8] do
    let a := s[j]!
    let b := s[j+1]!
    let c := s[j+2]!
    let d := s[j+3]!
    m := m ++ #[2*a+3*b+c+d, a+2*b+3*c+d, a+b+2*c+3*d, 3*a+b+c+2*d]
  return at12 fun j =>
    let k := j%4
    (m[j]! + m[k]! + m[k+4]! + m[k+8]!) % prime

private def full (s keys : Vec) : Vec := Id.run do
  let mut v := s
  for j in [:keys.size/12] do
    v := external (at12 fun i => (v[i]! + keys[12*j+i]!)^7 % prime)
  return v

private def permute (rc : Constants) (s : Vec) : Vec := Id.run do
  let mut v := full (external s) rc.initial
  for k in rc.internal do
    v := v.set! 0 ((v[0]! + k)^7 % prime)
    let total := v.foldl (·+·) 0
    v := at12 fun i => (total + v[i]! * rc.diag[i]!) % prime
  return full v rc.terminal

private def limbs (x : Nat) : List Nat := (List.range 4).map (fun i => (x >>> (64*i)) % 2^64)
private def valid (x : Nat) := x < 2^256 && (limbs x).all (· < prime)
private def wireKey (x : Nat) := (List.range 32).foldl (fun k i => (k <<< 8) + (x >>> (8*i)) % 256) 0
private def wireLE (x y : Nat) : Bool := wireKey x ≤ wireKey y

private def hashFields (rc : Constants) (words : List Nat) : Nat := Id.run do
  let input := (words ++ [1] ++ List.replicate ((7+8-words.length%8)%8) 0).toArray
  let mut v := at12 fun _ => 0
  for block in [:input.size/8] do
    let start := 8*block
    v := permute rc (at12 fun j => if j<8 then (v[j]! + input[start+j]!) % prime else v[j]!)
  return (List.range 4).foldl (fun n i => n + (v[i]! <<< (64*i))) 0

private def parent (rc : Constants) (q : Quad) := hashFields rc (q.flatMap limbs)

private def demand (ok : Bool) (msg : String) : IO Unit :=
  unless ok do throw (IO.userError msg)

def main (args : List String) : IO Unit := do
  let [params,observation] := args | throw (IO.userError "expected parameters and private path")
  let rc : Constants ← IO.ofExcept (fromJson? (← IO.ofExcept (Json.parse (← IO.FS.readFile params))))
  let e : Example ← IO.ofExcept (fromJson? (← IO.ofExcept (Json.parse (← IO.FS.readFile observation))))
  demand (rc.initial.size==48 && rc.terminal.size==48 && rc.internal.size==22 && rc.diag.size==12)
    "unexpected hash parameters"
  demand (e.count==e.leaves.length && e.count>0 && e.count≤4^20 && e.depth==max 1 (((e.count-1).log2+2)/2) &&
    e.depth==e.quads.length && e.root != 0 && valid e.root && e.leaves.all (fun x => x != 0 && valid x) &&
    e.leaves.eraseDups.length==e.count && e.quads.all (fun q => q.length==4 && q.all valid)) "selected tree shape"
  -- 110 zero log bytes, byte terminator 1, padded to 28 little-endian u32 field words.
  let header := limbs e.parentHash ++ [e.anchorHeight] ++ (limbs e.stateHash).map (· % prime) ++
    (limbs e.extrinsicsHash).map (· % prime) ++ limbs e.root ++ List.replicate 27 0 ++ [65536]
  demand (e.spendHeight≥25 && e.spendHeight<2^32 && e.anchorHeight<e.spendHeight &&
    e.spendHeight-e.anchorHeight≤8 && header.length==45 && hashFields rc header==e.anchor) "registered eligible header"
  let h := parent rc
  demand (levels h wireLE e.leaves e.depth == [e.root]) "independent selected root"
  demand (walk h e.leaf e.quads == some e.root) "restored private path"
  demand (checkPreimages h wireLE e.leaves e.quads) "finite parent opening check"
  demand (e.leaves.count e.leaf == 1) "selected occurrence uniqueness"
  IO.println "Checked eligible header, selected root, restored path, finite parent binding and unique occurrence."
