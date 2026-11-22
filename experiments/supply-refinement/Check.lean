import Refinement
import Lean.Data.Json

open Lean FundedC FundedSupply FundedRefinement

private def hx := "0123456789abcdef".toList.toArray
private def hex (b : Bytes) : String := String.mk <| b.data.toList.flatMap (fun x =>
  [hx[x.toNat/16]!,hx[x.toNat%16]!])
private def word (x : Nat) := hex (putLE x 32)
private def idHex (id : AssetId) := hex (putLE id.w0.val 8 ++ putLE id.w1.val 8 ++ putLE id.w2.val 8 ++ putLE id.w3.val 8)
private def fromHex (s : String) : Option Bytes := do
  guard (s.length==64)
  let chars := s.toList.toArray
  let mut out := ByteArray.empty
  for i in [:32] do
    let a ← hx.toList.idxOf? chars[2*i]!
    let b ← hx.toList.idxOf? chars[2*i+1]!
    out := out.push (16*a+b).toUInt8
  return out
private def requireIO (ok : Bool) (msg : String) : IO Unit := unless ok do throw (IO.userError msg)
private def readRow (path : String) : IO (Option Row) := do
  let j ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
  if j == .null then return none
  let mode ← IO.ofExcept (j.getObjValAs? String "mode")
  let key ← IO.ofExcept (j.getObjValAs? String "authority")
  let m ← if mode=="fixed" && key=="" then pure Mode.fixed else do
    let some bs := fromHex key | throw (IO.userError "invalid authority hex")
    requireIO (mode=="managed") "invalid mode"
    pure (Mode.managed (uLE bs))
  let q ← IO.ofExcept (j.getObjValAs? Nat "supply")
  let rev ← IO.ofExcept (j.getObjValAs? Nat "sequence")
  let tx ← IO.ofExcept (j.getObjValAs? String "tx")
  let some hash := fromHex tx | throw (IO.userError "invalid prior tx")
  return some ⟨m,q,rev,uLE hash⟩
private def readWord (s : String) : IO Nat := do
  let some b := fromHex s | throw (IO.userError "expected a 32-byte lowercase identifier")
  return uLE b
private def readState (path : String) : IO PublicState := do
  let j ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
  let height ← IO.ofExcept (j.getObjValAs? Nat "height")
  let anchors ← IO.ofExcept (j.getObjValAs? (List Json) "anchors")
  let rows ← anchors.mapM fun entry => do
    let h ← IO.ofExcept (entry.getObjValAs? Nat "height")
    let a ← readWord (← IO.ofExcept (entry.getObjValAs? String "ap"))
    let n ← IO.ofExcept (entry.getObjValAs? Nat "count")
    pure (h,(⟨a,n⟩ : Anchor))
  requireIO ((rows.map Prod.fst).eraseDups.length==rows.length) "duplicate selected height"
  let cms ← (← IO.ofExcept (j.getObjValAs? (List String) "cms")).mapM readWord
  let spent ← (← IO.ofExcept (j.getObjValAs? (List String) "spent")).mapM readWord
  return ⟨height,fun h => (rows.lookup h),cms,spent⟩
private def amount (j : Json) (name : String) : IO (Fin B) := do
  let n ← IO.ofExcept (j.getObjValAs? Nat name)
  if h : n<B then return ⟨n,h⟩ else throw (IO.userError "private value exceeds 62 bits")
private def inputOpening (j : Json) : IO PrivateInput := do
  return ⟨← readWord (← IO.ofExcept (j.getObjValAs? String "cm")),
    ← IO.ofExcept (j.getObjValAs? Bool "real"),← amount j "cash",← amount j "qty"⟩
private def outputOpening (j : Json) : IO PrivateOutput := do
  return ⟨← readWord (← IO.ofExcept (j.getObjValAs? String "true_nf")),← amount j "cash",← amount j "qty"⟩
private def readOpening (path : String) : IO Opening := do
  let j ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
  let some assetBytes := fromHex (← IO.ofExcept (j.getObjValAs? String "asset")) | throw (IO.userError "private asset")
  let some id := assetOf assetBytes | throw (IO.userError "private asset encoding")
  let [i,k] ← IO.ofExcept (j.getObjValAs? (List Json) "inputs") | throw (IO.userError "expected two private inputs")
  let [u,v] ← IO.ofExcept (j.getObjValAs? (List Json) "outputs") | throw (IO.userError "expected two private outputs")
  return ⟨id,← inputOpening i,← inputOpening k,← outputOpening u,← outputOpening v⟩
private def rowJSON (r : Row) : Json :=
  let (mode,pk) := match r.mode with | .fixed => ("fixed","") | .managed k => ("managed",word k)
  Json.mkObj [("mode",toJson mode),("authority",toJson pk),("supply",toJson r.quantity),
              ("sequence",toJson r.revision),("tx",toJson (word r.headTx))]

def main (args : List String) : IO Unit := do
  let packetPath :: replyPath :: networkHex :: rest := args | throw (IO.userError "expected PACKET REPLY NETWORK_HEX [V_REQUEST V_REPLY] --prior PRIOR_JSON --state STATE_JSON")
  let some net := fromHex networkHex | throw (IO.userError "invalid network")
  let packet ← IO.FS.readBinFile packetPath
  let reply ← IO.FS.readBinFile replyPath
  let some x := decode packet reply | throw (IO.userError "rejected packet/effect framing or fields")
  let (rest,openingPath) := match rest.reverse with
    | path::"--opening"::tail => (tail.reverse,some path)
    | _ => (rest,none)
  let (vreq,vrep,prior,statePath) ← match rest with
    | ["--prior",p,"--state",sp] => pure (ByteArray.empty,ByteArray.empty,p,sp)
    | [rq,rp,"--prior",p,"--state",sp] => pure (← IO.FS.readBinFile rq,← IO.FS.readBinFile rp,p,sp)
    | _ => throw (IO.userError "expected [V_REQUEST V_REPLY] --prior PRIOR_JSON --state STATE_JSON")
  let netId := uLE net
  let e := x.env
  let sigOK := match e.pk,e.signature with
    | some k,some s => vreq == authFrame netId e k s && vrep == success
    | _,_ => false
  requireIO (if isSigned e.op then sigOK else vreq.size==0 && vrep.size==0) "issuer transcript mismatch"
  let exactInner := unblob e.inner
  let w : Worker := fun req => if req == exactInner then reply else
    if vreq.size>0 && req == vreq then vrep else ByteArray.empty
  let old ← readRow prior
  let registry : Registry := fun id => if id=x.desc.publicId then old else none
  let some ok := checkPacket netId w packet registry | throw (IO.userError "rejected original packet or pre-block issuer policy")
  let x := ok.x
  let public ← readState statePath
  requireIO (vm public x) "rejected selected anchor, freshness or public fields"
  let op := match e.op with | .fixed => "fixed" | .register => "register" | .mint => "mint" | .burn => "burn"
  let expected := match e.op with
    | .fixed => some (idHex (fixedId netId x.nf0))
    | .register => some (idHex (managedId netId (e.pk.getD 0) x.nf0))
    | _ => none
  let mut checkedPrivate := false
  if let some path := openingPath then
    requireIO (e.op==.burn) "private control is scoped to holder burn"
    let o ← readOpening path
    requireIO (residuals x o) "private monetary residual rejected"
    checkedPrivate := true
  let info := Json.mkObj [
    ("checked_private_residuals",toJson checkedPrivate),
    ("public_guards",toJson true),("op",toJson op),("pk",toJson ((e.pk.map word).getD "")),("seq",toJson e.seq),
    ("previous",toJson (word e.previous)),("inner_sha256",toJson (hex (sha256 (unblob e.inner)))),
    ("tx_sha256",toJson (hex (sha256 packet))),("anchor",toJson (word x.anchor)),("height",toJson x.height),
    ("nf0",toJson (word x.nf0)),("nf1",toJson (word x.nf1)),("cm0",toJson (word x.cm0)),("cm1",toJson (word x.cm1)),
    ("fee",toJson x.fee),("public_id",toJson (idHex x.desc.publicId)),("word",toJson x.desc.word),
    ("high",toJson x.desc.high),("magnitude",toJson x.desc.lo.val),("depth",toJson x.depth),
    ("expected_issue_id",toJson expected),("issuer_request_verified",toJson sigOK),("row",rowJSON (commitRow old x))]
  IO.println info.compress
