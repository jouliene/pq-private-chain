import Wire
import Lean.Data.Json

/- Reads only selected public records, proofs and public worker replies. The surrounding
   experiment keeps this case private to avoid correlating the public packets to wallets.
   This lookup replays recorded native responses; it never verifies a proof or signature. -/
open Lean SwapWire FundedRefinement

private structure HeaderRecord where
  height : Nat
  ap : Nat
  count : Nat
  deriving FromJson

private structure ParentRecord where
  height : Nat
  cms : List Nat
  spent : List Nat
  anchors : List HeaderRecord
  deriving FromJson

private structure Committed where
  nfs : List Nat
  cms : List Nat
  fees : List Nat
  registryWrites : Nat
  reward : Nat
  blockHeight : Nat
  deriving FromJson

private def ensure (ok : Bool) (msg : String) : IO Unit :=
  unless ok do throw (IO.userError msg)

private def readJSON [FromJson α] (p : System.FilePath) : IO α := do
  IO.ofExcept (fromJson? (← IO.ofExcept (Json.parse (← IO.FS.readFile p))))

def main (args : List String) : IO Unit := do
  let [directory] := args | throw (IO.userError "expected a private case directory")
  let path : System.FilePath := directory
  let read := fun (name : String) => IO.FS.readBinFile (path/name)
  let raw ← read "bundle.bin"
  let network ← read "network.bin"
  let some f := pair raw | throw (IO.userError "could not pair the selected frames")
  let reply0 ← read "reply0.bin"
  let reply1 ← read "reply1.bin"
  let req0 ← read "request0.bin"
  let req1 ← read "request1.bin"
  let sig0 ← read "sigreply0.bin"
  let sig1 ← read "sigreply1.bin"
  let original := [(f.left.leg,reply0),(f.right.leg,reply1),(req0,sig0),(req1,sig1)]
  ensure ((original.map Prod.fst).eraseDups.length==4) "repeated verifier input"
  let worker : Worker := fun request =>
    ((original.find? (fun row => row.1==request)).map Prod.snd).getD ByteArray.empty
  let parent : ParentRecord ← readJSON (path/"parent.json")
  let committed : Committed ← readJSON (path/"committed.json")
  ensure (parent.anchors.map HeaderRecord.height).Nodup "repeated height in selected history"
  let p : PublicState := ⟨parent.height,fun h => (parent.anchors.find? (·.height==h)).map
    (fun a => ⟨a.ap,a.count⟩),parent.cms,parent.spent⟩
  let some ok := admit network p worker raw | throw (IO.userError "accepted pair failed replay")
  ensure (ok.a.row.nfs++ok.b.row.nfs==committed.nfs && ok.a.row.cms++ok.b.row.cms==committed.cms &&
    [ok.a.row.pi.fee,ok.b.row.pi.fee]==committed.fees && committed.fees.sum==3 &&
    committed.registryWrites==0 && committed.reward==100+committed.fees.sum && committed.blockHeight==p.height+1)
    "physical writes or reward disagree"
  let some (left,right) := framed raw | throw (IO.userError "missing source frames")
  let wrap := fun x y : Bytes => magic "SWB3" ++ putLE x.size 4 ++ x ++ putLE y.size 4 ++ y
  ensure ((admit network p worker (wrap right left)).isNone && (admit network p worker left).isNone)
    "partial or reordered group accepted"
  let withoutRightAuth : Worker := fun request => if request==req1 then ByteArray.empty else worker request
  ensure ((admit network p withoutRightAuth raw).isNone) "missing second authorization"
  let conflict := {p with spent := ok.b.row.pi.nf0::p.spent}
  ensure ((admit network conflict worker raw).isNone) "stale right-leg spent state"
  IO.println "Replayed four exact native requests and replies, both selected slots, zero registry writes and one fee. Four negative controls passed."
