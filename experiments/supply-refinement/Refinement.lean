import Supply

set_option maxRecDepth 4096

namespace FundedRefinement
open FundedC
open FundedSupply

abbrev Bytes := ByteArray
instance : DecidableEq ByteArray := fun ⟨a⟩ ⟨b⟩ =>
  if h : a=b then isTrue (h ▸ rfl) else isFalse (fun he => h (congrArg ByteArray.data he))
def bytes (xs : List Nat) : Bytes := ⟨(xs.map UInt8.ofNat).toArray⟩
def cut (b : Bytes) (i n : Nat) := b.extract i (i+n)
def uLE (b : Bytes) : Nat := b.data.foldr (fun x n => 256*n+x.toNat) 0
def atLE (b : Bytes) (i n : Nat) := uLE (cut b i n)
def putLE (n width : Nat) : Bytes := Id.run do
  let mut b := ByteArray.emptyWithCapacity width
  for i in [:width] do b := b.push ((n >>> (8*i)).toUInt8)
  return b

/-- A length-preserving natural identifier for opaque variable-length byte strings. Binary
    divide and conquer avoids a quadratic bigint fold over an entire 179 kB proof. -/
private def wide (b : Bytes) (i n : Nat) : Nat :=
  if n ≤ 32 then atLE b i n else
    let k := n / 2
    wide b i k + ((wide b (i+k) (n-k)) <<< (8*k))
termination_by n
decreasing_by all_goals omega

def blob (b : Bytes) := wide b 0 b.size + (1 <<< (8*b.size))

private def unwide (x n : Nat) : Bytes :=
  if n ≤ 32 then putLE x n else
    let k := n/2
    unwide (x % (1 <<< (8*k))) k ++ unwide (x >>> (8*k)) (n-k)
termination_by n
decreasing_by all_goals omega

def unblob (x : Nat) := unwide x (x.log2/8)

-- FIPS 180-4 SHA-256. Constants are shared with vendor/sha2-0.11.1/src/consts.rs.
private def k256 : Array UInt32 := #[
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
private def init256 : Array UInt32 :=
  #[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
private def rot (x n : UInt32) := (x >>> n) ||| (x <<< (32-n))
private def be (x n : Nat) : Bytes := ⟨(putLE x n).data.reverse⟩

def sha256 (b : Bytes) : Bytes := Id.run do
  let zeros := (119 - b.size%64)%64
  let input := b.push 128 ++ ⟨Array.replicate zeros 0⟩ ++ be (8*b.size) 8
  let mut v := init256
  for j in [:input.size/64] do
    let mut w : Array UInt32 := #[]
    for i in [:16] do
      w := w.push (uLE ⟨(cut input (64*j+4*i) 4).data.reverse⟩).toUInt32
    for i in [16:64] do
      let x := w[i-15]!
      let y := w[i-2]!
      w := w.push (w[i-16]! + (rot x 7 ^^^ rot x 18 ^^^ (x >>> 3)) + w[i-7]! +
        (rot y 17 ^^^ rot y 19 ^^^ (y >>> 10)))
    let mut a := v[0]!; let mut c1 := v[1]!; let mut c2 := v[2]!; let mut c3 := v[3]!
    let mut e := v[4]!; let mut f := v[5]!; let mut g := v[6]!; let mut h := v[7]!
    for i in [:64] do
      let t1 := h + (rot e 6 ^^^ rot e 11 ^^^ rot e 25) + ((e &&& f) ^^^ ((~~~e) &&& g)) + k256[i]! + w[i]!
      let t2 := (rot a 2 ^^^ rot a 13 ^^^ rot a 22) + ((a &&& c1) ^^^ (a &&& c2) ^^^ (c1 &&& c2))
      h := g; g := f; f := e; e := c3+t1; c3 := c2; c2 := c1; c1 := a; a := t1+t2
    v := Array.zipWith (·+·) v #[a,c1,c2,c3,e,f,g,h]
  return v.foldl (fun bs x => bs ++ be x.toNat 4) ByteArray.empty

@[irreducible] def hashNat (b : Bytes) : Nat := uLE (sha256 b)
def opCode : Op → Nat | .fixed => 1 | .register => 2 | .mint => 3 | .burn => 4
def opOf : Nat → Option Op | 1 => some .fixed | 2 => some .register | 3 => some .mint | 4 => some .burn | _ => none
def isSigned : Op → Bool | .register | .mint => true | _ => false
def outer := "MSP3".toUTF8.push 1
def innerMagic := "MNG3".toUTF8.push 1

def pack (e : Envelope) : Bytes :=
  let h := outer.push (opCode e.op).toUInt8
  let s := if isSigned e.op then putLE (e.pk.getD 0) 32 ++ putLE e.seq 8 ++ putLE e.previous 32 ++
    unblob (e.signature.getD 0) else ByteArray.empty
  h ++ s ++ unblob e.inner

def parse (packet : Bytes) : Option Envelope := do
  guard (packet.size > 6 && packet.size ≤ 262144 && cut packet 0 5 == outer)
  let op ← opOf (atLE packet 5 1)
  let sig := isSigned op
  let offset := if sig then 78+17088 else 6
  guard (offset < packet.size)
  let inner := packet.extract offset packet.size
  let n := atLE inner 5 4
  guard (inner.size ≥ 9 && cut inner 0 5 == innerMagic && 0 < n && inner.size == 9+n+3584)
  let e : Envelope := ⟨op,if sig then some (atLE packet 6 32) else none,
    if sig then atLE packet 38 8 else 0,if sig then atLE packet 46 32 else 0,
    if sig then some (blob (cut packet 78 17088)) else none,blob inner⟩
  guard (e.seq < 2^63 && pack e == packet && unblob e.inner == inner)
  return e

def limb (b : Bytes) (i : Nat) : Option (Fin (2^63)) :=
  let v := atLE b i 8
  if h : v < 2^63 then some ⟨v,h⟩ else none

def assetOf (b : Bytes) : Option AssetId := do
  guard (b.size == 32)
  return ⟨← limb b 0,← limb b 8,← limb b 16,← limb b 24⟩

def canonical (b : Bytes) : Bool :=
  b.size==32 && [0,8,16,24].all (fun i => atLE b i 8 < P)

structure Decoded where
  env : Envelope
  anchor : Nat
  height : Nat
  nf0 : Nat
  nf1 : Nat
  cm0 : Nat
  cm1 : Nat
  fee : Nat
  depth : Nat
  desc : Descriptor
  nonzero : 0 < desc.lo.val
  signedWord : desc.word = desc.lo.val + (if desc.high then B else 0)
  burnFlag : desc.high = decide (env.op=.burn)

private theorem delta_bounds (n : Nat) (h1 : 0<n) (h2 : n<2*B) (h3 : n≠B) :
    0<n%B ∧ n=n%B+(if decide (n≥B) then B else 0) := by
  by_cases h : n≥B <;> simp [h] <;> unfold B at * <;> omega

private def mkDecoded (e : Envelope) (id : AssetId) (delta anchor height nf0 nf1 cm0 cm1 fee depth : Nat) :
    Option Decoded :=
  if h : id ≠ zeroId ∧ delta>0 ∧ delta<2*B ∧ delta≠B ∧ decide (delta≥B)=decide (e.op=.burn) then
    let d : Descriptor := ⟨delta,decide (delta≥B),⟨delta % B, Nat.mod_lt _ (by decide)⟩,id⟩
    have hw := delta_bounds delta h.2.1 h.2.2.1 h.2.2.2.1
    some ⟨e,anchor,height,nf0,nf1,cm0,cm1,fee,depth,d,hw.1,hw.2,h.2.2.2.2⟩
  else none

def decodeReply (e : Envelope) (reply : Bytes) : Option Decoded := do
  guard (reply.size==3798 && reply[0]? == some 49)
  let anchor := cut reply 1 32
  let nf0 := cut reply 37 32
  let nf1 := cut reply 69 32
  let cm0 := cut reply 101 32
  let cm1 := cut reply 133 32
  let inner := unblob e.inner
  let ct := cut reply 173 3584
  let fee := atLE reply 165 8
  let id ← assetOf (cut reply 3757 32)
  let delta := atLE reply 3789 8
  let depth := atLE reply 3797 1
  -- Registered successful rows have distinct NF/CM and 63-bit asset limbs. The node
  -- independently checks fresh selected effects, and checks suite activation and anchor below.
  guard ([anchor,nf0,nf1,cm0,cm1].all canonical && nf0 != nf1 && cm0 != cm1 &&
    uLE cm0 != 0 && uLE cm1 != 0 && fee==3 && depth ≥ 1 && depth ≤ 20 &&
    ct == inner.extract (inner.size-3584) inner.size)
  mkDecoded e id delta (uLE anchor) (atLE reply 33 4) (uLE nf0) (uLE nf1)
    (uLE cm0) (uLE cm1) fee depth

def decode (packet reply : Bytes) := (parse packet).bind (fun e => decodeReply e reply)

def tagged (digest : Bytes) : AssetId :=
  let w := fun i => (⟨atLE digest i 8 % 2^63,Nat.mod_lt _ (by decide)⟩ : Fin (2^63))
  ⟨w 0,w 8,w 16,w 24⟩

def domain (s : String) := s.toUTF8.push 0
def fixedId (network nf : Nat) := tagged (sha256 (domain "AST1/issue-id/v1" ++ putLE network 32 ++ putLE nf 32))
def managedId (network pk nf : Nat) := tagged (sha256 (domain "MNG1/managed-id/v1" ++ putLE network 32 ++ putLE pk 32 ++ putLE nf 32))
def message (m : AuthMessage) :=
  sha256 (domain "MNG3/supply-auth/v1" ++ putLE m.network 32 ++ putLE (opCode m.op) 1 ++
    putLE m.pk 32 ++ putLE m.seq 8 ++ putLE m.previous 32 ++ putLE m.innerHash 32)

def authFrame (network : Nat) (e : Envelope) (key sig : Nat) :=
  bytes [86] ++ putLE key 32 ++ message ⟨network,e.op,key,e.seq,e.previous,hashNat (unblob e.inner)⟩ ++ unblob sig

abbrev Worker := Bytes → Bytes
def success := bytes [49]

def ctx (network : Nat) (worker : Worker) : Context where
  network := network
  fixedId := fixedId
  managedId := managedId
  hashInner := fun i => hashNat (unblob i)
  packetId := fun e => hashNat (pack e)
  verifies := fun m sig => worker (bytes [86] ++ putLE m.pk 32 ++ message m ++ unblob sig) = success
  opens := fun i t d => ∃ (e : Envelope) (x : Decoded), e.inner=i ∧ decodeReply e (worker (unblob i))=some x ∧
    x.desc=d ∧ (x.nf0,x.nf1,x.cm0,x.cm1)=(t.i.published,t.j.published,t.u.cm,t.v.cm)

def bareOK (e : Envelope) := e.pk.isNone && e.signature.isNone && e.seq==0 && e.previous==0
def signedOK (network : Nat) (w : Worker) (e : Envelope) (k : Nat) :=
  match e.signature with
  | none => false
  | some sig => e.pk == some k && e.seq < 2^63 && w (authFrame network e k sig) == success

private theorem bare_refines {e : Envelope} (h : bareOK e=true) : bare e := by
  simpa [bare,bareOK,Bool.and_eq_true,and_assoc] using h

private theorem signed_refines {n w e k} (h : signedOK n w e k=true) : signed (ctx n w) e k := by
  cases hs : e.signature with
  | none => simp [signedOK,hs] at h
  | some sig =>
    simp only [signedOK,hs,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] at h
    exact ⟨h.1.1,h.1.2,sig,hs,h.2⟩

/-- Selected latest row is read before any write. The authenticator workers' exact byte
    requests include both original packet content and the issuer metadata. -/
def preflight (network : Nat) (worker : Worker) (old : Option Row) (x : Decoded) : Bool :=
  let e := x.env
  let d := x.desc
  match e.op with
  | .fixed => bareOK e && old.isNone && d.publicId == fixedId network x.nf0
  | .register => match e.pk with
    | none => false
    | some key => signedOK network worker e key && e.seq==0 && e.previous==0 && old.isNone &&
        d.publicId == managedId network key x.nf0
  | .mint => match old with
    | some ⟨.managed k,q,rev,prev⟩ => signedOK network worker e k && rev==e.seq && prev==e.previous && q+d.word < B
    | _ => false
  | .burn => match old with
    | some ⟨.managed _,q,_,_⟩ => bareOK e && q ≥ d.word-B
    | _ => false

/-- Independent translation of the SQL event writer: choose former mode/key, increment
    last sequence and use the actual public word in the supply addition or subtraction. -/
def commitRow (old : Option Row) (x : Decoded) : Row :=
  let e := x.env
  let kind := old.map (·.mode) |>.getD (if e.op=.fixed then Mode.fixed else .managed (e.pk.getD 0))
  let q := (old.map (·.quantity)).getD 0
  let seq := (old.map (·.revision)).getD 0
  ⟨kind,if e.op=.burn then q+B-x.desc.word else q+x.desc.word,seq+1,hashNat (pack e)⟩

theorem preflight_refines {n w} {r : Registry} {x : Decoded} {t : Payment}
    (first : x.nf0 = t.i.published)
    (ok : preflight n w (r x.desc.publicId) x=true) :
    Rule (ctx n w) r t x.desc x.env (commitRow (r x.desc.publicId) x) := by
  have word := x.signedWord
  have sign := x.burnFlag
  cases op : x.env.op with
  | fixed =>
    simp [preflight,op] at ok
    obtain ⟨⟨shape,unused⟩,id⟩ := ok
    have wd : x.desc.word=x.desc.lo.val := by simpa [sign,op] using word
    simpa [commitRow,ctx,unused,op,wd] using Rule.fixed (ctx:=ctx n w) (t:=t) (d:=x.desc) op
      (bare_refines shape) unused (by simpa [ctx,first] using id)
  | register =>
    cases pk : x.env.pk with
    | none => simp [preflight,op,pk] at ok
    | some key =>
      simp [preflight,op,pk] at ok
      obtain ⟨⟨⟨⟨auth,seq⟩,prev⟩,unused⟩,id⟩ := ok
      have wd : x.desc.word=x.desc.lo.val := by simpa [sign,op] using word
      simpa [commitRow,ctx,unused,op,wd,pk] using Rule.register (ctx:=ctx n w) (t:=t) (d:=x.desc) key op
        (signed_refines (n:=n) (w:=w) (e:=x.env) (k:=key) auth) ⟨seq,prev⟩ unused (by simpa [ctx,first] using id)
  | mint =>
    cases prior : r x.desc.publicId with
    | none => simp [preflight,op,prior] at ok
    | some row =>
      rcases row with ⟨mode,q,rev,prev⟩
      cases mode with
      | fixed => simp [preflight,op,prior] at ok
      | managed key =>
        have wd : x.desc.word=x.desc.lo.val := by simpa [sign,op] using word
        simp [preflight,op,prior,wd] at ok
        obtain ⟨⟨⟨auth,s⟩,p⟩,bound⟩ := ok
        simpa [commitRow,ctx,op,wd] using Rule.mint (ctx:=ctx n w) (t:=t) (d:=x.desc) key q rev prev
          op (signed_refines (n:=n) (w:=w) (e:=x.env) (k:=key) auth) prior ⟨s.symm,p.symm⟩ bound
  | burn =>
    cases prior : r x.desc.publicId with
    | none => simp [preflight,op,prior] at ok
    | some row =>
      rcases row with ⟨mode,q,rev,prev⟩
      cases mode with
      | fixed => simp [preflight,op,prior] at ok
      | managed key =>
        have wd : x.desc.word=x.desc.lo.val+B := by simpa [sign,op] using word
        simp [preflight,op,prior,wd] at ok
        have sub : q+B-(x.desc.lo.val+B)=q-x.desc.lo.val := by omega
        simpa [commitRow,ctx,op,wd,sub] using Rule.burn (ctx:=ctx n w) (t:=t) (d:=x.desc) key q rev prev
          op (bare_refines ok.1) prior ok.2

deriving instance DecidableEq for Envelope

/-- Successful execution keeps its original byte provenance. The redundant reconstruction
    checks establish a literal interpretation of the earlier model's natural-number atoms. -/
structure PacketOK (n : Nat) (w : Worker) (raw : Bytes) (r : Registry) where
  x : Decoded
  parsed : parse raw = some x.env
  exactPacket : pack x.env = raw
  fromWorker : decodeReply x.env (w (unblob x.env.inner)) = some x
  parentGuard : preflight n w (r x.desc.publicId) x = true

def checkPacket (n : Nat) (w : Worker) (raw : Bytes) (r : Registry) : Option (PacketOK n w raw r) :=
  match hp : parse raw with
  | none => none
  | some e =>
    match hv : decodeReply e (w (unblob e.inner)) with
    | none => none
    | some x => if he : x.env=e then
      if hpkt : pack x.env=raw then
        if hok : preflight n w (r x.desc.publicId) x=true then
          some ⟨x,he ▸ hp,hpkt,he ▸ hv,hok⟩
        else none
      else none
    else none

structure Anchor where
  ap : Nat
  count : Nat
structure PublicState where
  height : Nat
  anchors : Nat → Option Anchor
  cms : List Nat
  spent : List Nat

def depthOf (count : Nat) := max 1 (((count-1).log2 + 2) / 2)
-- In Python bit_length(0)=0, whereas Nat.log2(0)=0; the outer max makes depth(1)=1.
def vm (p : PublicState) (x : Decoded) : Bool :=
  match p.anchors x.height with
  | none => false
  | some a => decide (25 ≤ p.height+1 ∧ p.height+1 < 2^32 ∧ x.height<p.height+1 ∧
       p.height+1-x.height ≤ 8 ∧ a.ap=x.anchor ∧ 1≤a.count ∧ a.count≤4^20 ∧
       depthOf a.count=x.depth ∧ x.fee=3 ∧ x.nf0 ≠ x.nf1 ∧ x.cm0 ≠ x.cm1 ∧
       x.nf0 ∉ p.spent ∧ x.nf1 ∉ p.spent ∧ x.cm0 ∉ p.cms ∧ x.cm1 ∉ p.cms)

structure Fresh (p : PublicState) (x : Decoded) : Prop where
  distinctNF : x.nf0 ≠ x.nf1
  distinctCM : x.cm0 ≠ x.cm1
  free0 : x.nf0 ∉ p.spent
  free1 : x.nf1 ∉ p.spent
  new0 : x.cm0 ∉ p.cms
  new1 : x.cm1 ∉ p.cms

theorem vm_fresh {p x} (h : vm p x=true) : Fresh p x := by
  cases ha : p.anchors x.height with
  | none => simp [vm,ha] at h
  | some a =>
    simp only [vm,ha,decide_eq_true_eq] at h
    obtain ⟨_,_,_,_,_,_,_,_,_,nn,cc,f0,f1,c0,c1⟩ := h
    exact ⟨nn,cc,f0,f1,c0,c1⟩

structure PrivateInput where
  cm : Nat
  real : Bool
  cash : Fin B
  qty : Fin B
structure PrivateOutput where
  trueNF : Nat
  cash : Fin B
  qty : Fin B
structure Opening where
  asset : AssetId
  i : PrivateInput
  j : PrivateInput
  u : PrivateOutput
  v : PrivateOutput

def noteTag (asset : AssetId) (qty : Nat) := if qty=0 then zeroId else asset
def toInput (w : PrivateInput) (nf : Nat) (asset : AssetId) : Input :=
  ⟨⟨w.cm,nf,w.cash.val,w.qty.val,noteTag asset w.qty.val⟩,w.real,nf⟩
def toOutput (w : PrivateOutput) (cm : Nat) (asset : AssetId) : Note :=
  ⟨cm,w.trueNF,w.cash.val,w.qty.val,noteTag asset w.qty.val⟩
def payment (x : Decoded) (o : Opening) : Payment :=
  ⟨toInput o.i x.nf0 o.asset,toInput o.j x.nf1 o.asset,
   toOutput o.u x.cm0 o.asset,toOutput o.v x.cm1 o.asset,o.asset⟩

/-- An executable finite relation slice. The proof worker does not return these openings.
    Establishing that a successful registered proof admits a witness for these residuals
    and correctly opens the actual commitments is a separate cryptographic obligation. -/
def fieldAdd (a b : Nat) := (a+b)%P
def fieldMul (a b : Nat) := (a*b)%P
def checkedLimb (enabled x actual : Nat) := fieldMul enabled x == actual

def residuals (x : Decoded) (o : Opening) : Bool :=
  let d := x.desc
  let on := bit (decide (d.lo.val ≠ 0))
  let sign := bit d.high
  let issue := bit (issuing d)
  let input := fieldAdd o.i.qty.val o.j.qty.val
  let output := fieldAdd o.u.qty.val o.v.qty.val
  let avail := fieldAdd input (issue*d.lo.val)
  let allocatedWord := fieldAdd output (sign*d.lo.val)
  let di := bit (!o.i.real)
  let dj := bit (!o.j.real)
  decide (fieldAdd o.i.cash.val o.j.cash.val = fieldAdd (fieldAdd o.u.cash.val o.v.cash.val) 3 ∧
    fieldMul (bit (decide (d.lo.val=0))) sign = 0 ∧
    checkedLimb on o.asset.w0.val d.publicId.w0.val = true ∧
    checkedLimb on o.asset.w1.val d.publicId.w1.val = true ∧
    checkedLimb on o.asset.w2.val d.publicId.w2.val = true ∧
    checkedLimb on o.asset.w3.val d.publicId.w3.val = true ∧
    avail=allocatedWord ∧ fieldMul issue input=0 ∧ fieldMul issue di=0 ∧
    decide (o.asset=zeroId) = decide (avail=0) ∧
    fieldMul o.i.cash.val di=0 ∧ fieldMul o.i.qty.val di=0 ∧
    fieldMul o.j.cash.val dj=0 ∧ fieldMul o.j.qty.val dj=0)

private theorem dummy_bit (w : PrivateInput) (nf : Nat) (a : AssetId) :
    dummyBit (toInput w nf a) = bit (!w.real) := by cases h : w.real <;> simp [dummyBit,toInput,bit,h]

theorem residuals_gates {x o} (h : residuals x o=true) : FundedSupply.Gates (payment x o) x.desc := by
  simp only [residuals,decide_eq_true_eq] at h
  obtain ⟨cash,empty,g0,g1,g2,g3,bal,issuer,issuerDummy,zero,ic,iq,jc,jq⟩ := h
  have wd := x.signedWord
  have hl := x.desc.lo.isLt
  have enc : x.desc.word=(x.desc.lo.val+bit x.desc.high*B)%P := by
    cases hh : x.desc.high <;> simp [hh,bit] at wd ⊢
    · exact wd.trans (Nat.mod_eq_of_lt (by unfold B at hl; unfold P; omega)).symm
    · exact wd.trans (Nat.mod_eq_of_lt (by unfold B at *; unfold P; omega)).symm
  simp only [checkedLimb,beq_iff_eq] at g0 g1 g2 g3
  refine ⟨⟨o.i.cash.isLt,o.i.qty.isLt⟩,⟨o.j.cash.isLt,o.j.qty.isLt⟩,⟨o.u.cash.isLt,o.u.qty.isLt⟩,
    ⟨o.v.cash.isLt,o.v.qty.isLt⟩,cash,enc,empty,⟨g0.symm,g1.symm,g2.symm,g3.symm⟩,bal,issuer,?_,?_,
    rfl,rfl,rfl,rfl,?_,?_⟩
  · simpa only [payment,dummy_bit] using issuerDummy
  · have iffdec (p q : Prop) [Decidable p] [Decidable q] (eq : decide p=decide q) : p ↔ q := by
      by_cases hp : p <;> by_cases hq : q <;> simp_all
    exact iffdec _ _ zero
  · simpa only [payment,dummyGate,dummy_bit,fieldMul] using And.intro ic iq
  · simpa only [payment,dummyGate,dummy_bit,fieldMul] using And.intro jc jq

/-- SQL positions are chronological, whereas the formal state prepends two new outputs.
    A permutation of *full notes* relates those conventions. Public commitments are unique,
    so one SQL position cannot stand for two ghost notes with different amounts. -/
structure Represents (p : PublicState) (s : State) where
  chronological : List Note
  positions : chronological.map Note.cm = p.cms
  sameNotes : chronological.Perm s.funded
  cmUnique : p.cms.Nodup
  sameMarks : p.spent.Perm s.spent
  nfUnique : p.spent.Nodup

theorem represented_cm {p s} (v : Represents p s) {n} (hn : n∈s.funded) : n.cm∈p.cms := by
  rw [← v.positions]
  exact List.mem_map.mpr ⟨n,v.sameNotes.mem_iff.mpr hn,rfl⟩

/-- Opening-to-occurrence correspondence is conditional on binding and real membership.
    An index lies strictly within the checked ancestor's exact chronological prefix. Other
    hypotheses describe true NF separation across earlier births, historical marks and
    dummy domains; the selected DB contains no public column for an output's true NF. -/
structure BirthFacts (p : PublicState) (s : State) (x : Decoded) (o : Opening) (v : Represents p s) where
  count : Nat
  countBound : count≤v.chronological.length
  selectedAnchor : p.anchors x.height=some ⟨x.anchor,count⟩
  iOccurrence : o.i.real=true → ∃ k : Nat, k<count ∧ v.chronological[k]? = some (payment x o).i.note
  jOccurrence : o.j.real=true → ∃ k : Nat, k<count ∧ v.chronological[k]? = some (payment x o).j.note
  oldDistinct : distinctNF (live s.spent s.funded)
  noAliasI : o.i.real=false → ∀ n ∈ s.funded, n.nf≠x.nf0
  noAliasJ : o.j.real=false → ∀ n ∈ s.funded, n.nf≠x.nf1
  siblings : o.u.trueNF≠o.v.trueNF
  freshBirths : ∀ n ∈ s.funded, o.u.trueNF≠n.nf ∧ o.v.trueNF≠n.nf
  noPriorMarks : o.u.trueNF∉s.spent ∧ o.v.trueNF∉s.spent
  noLocalMarks : o.u.trueNF≠x.nf0 ∧ o.u.trueNF≠x.nf1 ∧ o.v.trueNF≠x.nf0 ∧ o.v.trueNF≠x.nf1

theorem derive_admission {p s x o} (represented : Represents p s) (h : Fresh p x)
    (b : BirthFacts p s x o represented) : Admission s (payment x o) := by
  refine ⟨b.oldDistinct,⟨?_,fun _ => rfl,b.noAliasI⟩,⟨?_,fun _ => rfl,b.noAliasJ⟩,
    h.distinctNF,fun m => h.free0 (represented.sameMarks.mem_iff.mpr m),fun m => h.free1 (represented.sameMarks.mem_iff.mpr m),
    h.distinctCM,?_,⟨b.siblings,b.freshBirths⟩,?_,?_⟩
  · intro hr
    obtain ⟨k,_,hk⟩ := b.iOccurrence hr
    exact represented.sameNotes.mem_iff.mp (List.mem_of_getElem? hk)
  · intro hr
    obtain ⟨k,_,hk⟩ := b.jOccurrence hr
    exact represented.sameNotes.mem_iff.mp (List.mem_of_getElem? hk)
  · intro n hn
    exact ⟨fun eq => h.new0 (by change x.cm0=n.cm at eq; rw [eq]; exact represented_cm represented hn),
           fun eq => h.new1 (by change x.cm1=n.cm at eq; rw [eq]; exact represented_cm represented hn)⟩
  · exact fun m => by
      rcases List.mem_cons.mp m with h0 | rest
      · exact b.noLocalMarks.1 h0
      rcases List.mem_cons.mp rest with h1 | older
      · exact b.noLocalMarks.2.1 h1
      exact b.noPriorMarks.1 older
  · exact fun m => by
      rcases List.mem_cons.mp m with h0 | rest
      · exact b.noLocalMarks.2.2.1 h0
      rcases List.mem_cons.mp rest with h1 | older
      · exact b.noLocalMarks.2.2.2 h1
      exact b.noPriorMarks.2 older

def appendEffects (p : PublicState) (x : Decoded) : PublicState :=
  {p with cms := p.cms ++ [x.cm0,x.cm1], spent := p.spent ++ [x.nf0,x.nf1]}

private theorem addTwoUnique (xs : List Nat) (a b : Nat) (n : xs.Nodup) (h : a≠b)
    (ha : a∉xs) (hb : b∉xs) : (xs ++ [a,b]).Nodup := by
  apply List.pairwise_append.mpr
  refine ⟨n,by simp [h],?_⟩
  intro v hv u hu
  simp only [List.mem_cons,List.not_mem_nil,or_false] at hu
  rcases hu with rfl | rfl
  · intro eq; exact ha (eq ▸ hv)
  · intro eq; exact hb (eq ▸ hv)

def extend_projection {p s x o} (v : Represents p s) (h : Fresh p x) :
    Represents (appendEffects p x) (settle s (payment x o)) where
  chronological := v.chronological ++ [(payment x o).u,(payment x o).v]
  positions := by simp [appendEffects,v.positions,payment,toOutput]
  sameNotes := List.perm_append_comm.trans (List.Perm.append_left _ v.sameNotes)
  cmUnique := addTwoUnique _ _ _ v.cmUnique h.distinctCM h.new0 h.new1
  sameMarks := List.perm_append_comm.trans (List.Perm.append_left _ v.sameMarks)
  nfUnique := addTwoUnique _ _ _ v.nfUnique h.distinctNF h.free0 h.free1

structure SqlEvent where
  asset : AssetId
  height : Nat
  payload : Row

/-- ORDER BY sequence DESC LIMIT 1 for an asset on the selected branch. In a valid
    SQL table (id,sequence) is unique. This fold also handles unordered history. -/
def latest : List SqlEvent → Registry
  | [], _ => none
  | event::older, id =>
    let old := latest older id
    if event.asset≠id then old else match old with
    | none => some event.payload
    | some a => if a.revision ≤ event.payload.revision then some event.payload else old

def sqlInsert (rows : List SqlEvent) (height : Nat) (x : Decoded) :=
  ⟨x.desc.publicId,height,commitRow (latest rows x.desc.publicId) x⟩ :: rows

theorem latest_after_insert (rows : List SqlEvent) (height : Nat) (x : Decoded) :
    latest (sqlInsert rows height x) = write (latest rows) x.desc.publicId (commitRow (latest rows x.desc.publicId) x) := by
  funext id
  by_cases h : id=x.desc.publicId
  · subst id
    cases hp : latest rows x.desc.publicId <;> simp [sqlInsert,latest,write,hp,commitRow]
  · simp [sqlInsert,latest,write,h,Ne.symm h]

theorem checked_wire {net worker raw r} (ok : PacketOK net worker raw r) (o : Opening) :
    Wire (ctx net worker) ok.x.env (payment ok.x o) ok.x.desc :=
  ⟨⟨ok.x.env,ok.x,rfl,ok.fromWorker,rfl,rfl⟩,ok.x.nonzero,ok.x.burnFlag⟩

/-- From actual decoded bytes and the selected SQL prechecks to the previous selected
    supply invariant. Private residual checks can be executed with disclosed openings.
    Extraction of such openings from every accepted C proof is outside this theorem. -/
theorem selected_refinement {net worker raw rows p s} (ok : PacketOK net worker raw (latest rows))
    (o : Opening) (v : Represents p s) (funding : vm p ok.x=true)
    (equations : residuals ok.x o=true) (birth : BirthFacts p s ok.x o v) (before : Consistent s (latest rows)) :
    Consistent (settle s (payment ok.x o)) (latest (sqlInsert rows (p.height+1) ok.x)) := by
  rw [latest_after_insert]
  exact preserve_supply (residuals_gates equations) (derive_admission v (vm_fresh funding) birth)
    (checked_wire ok o) (preflight_refines (t:=payment ok.x o) rfl ok.parentGuard) before

/-- The original batch preflights against its parent, then inserts in physical order.
    Compare that writer against the independently planned parent-row writes for every
    prefix, for every ID. This is the no-duplicate-supply-ID block guard. -/
def planned (parent : Registry) (xs : List Decoded) : List (AssetId × Row) :=
  xs.map (fun x => (x.desc.publicId,commitRow (parent x.desc.publicId) x))

def commitBlock (r : Registry) : List Decoded → Registry
  | [] => r
  | x::xs => commitBlock (write r x.desc.publicId (commitRow (r x.desc.publicId) x)) xs

theorem snapshot_schedule (parent current : Registry) (xs : List Decoded)
    (unique : (xs.map (fun x => x.desc.publicId)).Nodup)
    (untouched : ∀ x∈xs, current x.desc.publicId=parent x.desc.publicId) :
    commitBlock current xs = applyWrites current (planned parent xs) := by
  induction xs generalizing current with
  | nil => rfl
  | cons x xs ih =>
    have hd := (List.nodup_cons.mp unique).1
    have ht := (List.nodup_cons.mp unique).2
    have same := untouched x (by simp)
    simp only [commitBlock,planned,List.map_cons,applyWrites,same]
    apply ih _ ht
    intro y hy
    have ne : y.desc.publicId≠x.desc.publicId := by
      intro eq
      exact hd (List.mem_map.mpr ⟨y,hy,eq⟩)
    rw [other_rows_unchanged _ _ _ _ ne]
    exact untouched y (by simp [hy])

theorem sql_block_fold (rows : List SqlEvent) (h : Nat) (xs : List Decoded) :
    latest (xs.foldl (fun history x => sqlInsert history h x) rows) = commitBlock (latest rows) xs := by
  induction xs generalizing rows with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons,ih,latest_after_insert,commitBlock]

theorem preblock_to_sql (rows : List SqlEvent) (h : Nat) (xs : List Decoded)
    (unique : (xs.map (fun x => x.desc.publicId)).Nodup) :
    latest (xs.foldl (fun history x => sqlInsert history h x) rows) =
    applyWrites (latest rows) (planned (latest rows) xs) :=
  (sql_block_fold rows h xs).trans (snapshot_schedule _ _ _ unique (fun _ _ => rfl))

theorem checked_monetary_effects {n w raw rows p s} (ok : PacketOK n w raw (latest rows))
    (o : Opening) (v : Represents p s) (funding : vm p ok.x=true)
    (eq : residuals ok.x o=true) (birth : BirthFacts p s ok.x o v) (q : AssetId) :
    let t := payment ok.x o
    let d := ok.x.desc
    let new := commitRow (latest rows d.publicId) ok.x
    o.asset = d.publicId ∧
    holdings (settle s t) .native + 3 = holdings s .native ∧
    holdings (settle s t) (.asset q) + forId d.publicId q (burned d) =
      holdings s (.asset q) + forId d.publicId q (minted d) ∧
    new.quantity + burned d = outstanding (latest rows) d.publicId + minted d ∧
    new.headTx = hashNat raw := by
  have g := residuals_gates eq
  have a := derive_admission v (vm_fresh funding) birth
  have id := (active_id_nonzero _ _ g (Nat.ne_of_gt ok.x.nonzero)).1
  have rule := preflight_refines (t:=payment ok.x o) rfl ok.parentGuard
  exact ⟨id.symm,selected_fee _ _ _ g a, selected_supply _ _ _ g a q,
         registry_delta (checked_wire ok o) rule,congrArg hashNat ok.exactPacket⟩

theorem real_occurrences_distinct {p s x o v} (b : BirthFacts p s x o v)
    (funding : vm p x=true) (hi : o.i.real=true) (hj : o.j.real=true) :
    ∃ i j : Nat, i<b.count ∧ j<b.count ∧ i≠j ∧
       v.chronological[i]?=some (payment x o).i.note ∧ v.chronological[j]?=some (payment x o).j.note := by
  obtain ⟨i,bi,mi⟩ := b.iOccurrence hi
  obtain ⟨j,bj,mj⟩ := b.jOccurrence hj
  refine ⟨i,j,bi,bj,?_,mi,mj⟩
  intro h
  subst j
  exact (vm_fresh funding).distinctNF (congrArg Note.nf (Option.some.inj (mi.symm.trans mj)))

/-- Every result of the executable packet path is a typed checked record. No positive
    result can use a response detached from its actual worker input. -/
theorem checkPacket_refinement (n : Nat) (worker : Worker) (raw : Bytes) (rows : List SqlEvent)
    (p : PublicState) (s : State) :
    match checkPacket n worker raw (latest rows) with
    | none => True
    | some ok => ∀ (o : Opening) (v : Represents p s),
       vm p ok.x=true → residuals ok.x o=true → BirthFacts p s ok.x o v →
       Consistent s (latest rows) →
       Consistent (settle s (payment ok.x o)) (latest (sqlInsert rows (p.height+1) ok.x)) := by
  cases h : checkPacket n worker raw (latest rows) with
  | none => trivial
  | some ok => exact fun o v public eq birth before => selected_refinement ok o v public eq birth before

/-- A supply-only block, in physical slot order. Each signature/issuer check was run on
    the same parent registry. During the fold monetary witnesses use the *current*
    chronological and nullifier projections. In particular a new output's true NF may
    not alias a sibling's earlier dummy mark. This is an explicit cryptographic condition. -/
structure BlockItem (net : Nat) (worker : Worker) (parent : Registry) where
  raw : Bytes
  ok : PacketOK net worker raw parent
  opening : Opening

private def itemId {n w r} (e : BlockItem n w r) := e.ok.x.desc.publicId
private def nfs {n w r} (e : BlockItem n w r) := [e.ok.x.nf0,e.ok.x.nf1]
private def cms {n w r} (e : BlockItem n w r) := [e.ok.x.cm0,e.ok.x.cm1]

private theorem split_unique {old tail : List Nat} {a b : Nat}
    (h : (old ++ ([a,b] ++ tail)).Nodup) :
    a≠b ∧ a∉old ∧ b∉old ∧ ((old++[a,b])++tail).Nodup := by
  have ⟨_,right,cross⟩ := List.pairwise_append.mp h
  have diff := (List.nodup_cons.mp right).1
  refine ⟨fun eq => diff (by simp [eq]),?_,?_,by simpa [List.append_assoc] using h⟩
  · intro hm; exact cross a hm a (by simp) rfl
  · intro hm; exact cross b hm b (by simp) rfl

/-- Auxiliary projected ghost states are supplied at each slot, never as a premise that
    the SQL operation implements the ideal transition. All public NF/CM disjointness
    is derived in the block fold from the lists checked by consensus. -/
def PrivateBlock {n w parent} (p : PublicState) (s : State) :
    List (BlockItem n w parent) → Prop
  | [] => True
  | e::es =>
    (∃ v : Represents p s, Nonempty (BirthFacts p s e.ok.x e.opening v)) ∧
    residuals e.ok.x e.opening=true ∧
    PrivateBlock (appendEffects p e.ok.x) (settle s (payment e.ok.x e.opening)) es

def noteFold {n w r} (s : State) (xs : List (BlockItem n w r)) :=
  xs.foldl (fun st item => settle st (payment item.ok.x item.opening)) s

theorem block_fold_invariant {net w parent} (p : PublicState) (s : State) (rows : List SqlEvent)
    (xs : List (BlockItem net w parent)) (privateFacts : PrivateBlock p s xs)
    (ids : (xs.map itemId).Nodup) (nn : (p.spent++xs.flatMap nfs).Nodup)
    (cc : (p.cms++xs.flatMap cms).Nodup)
    (same : ∀ e∈xs, latest rows (itemId e)=parent (itemId e))
    (initial : Consistent s (latest rows)) :
    Consistent (noteFold s xs)
      (latest (xs.foldl (fun hist e => sqlInsert hist (p.height+1) e.ok.x) rows)) := by
  induction xs generalizing p s rows with
  | nil => exact initial
  | cons e es ih =>
    obtain ⟨⟨v,⟨birth⟩⟩,eq,rest⟩ := privateFacts
    have nd := split_unique (a:=e.ok.x.nf0) (b:=e.ok.x.nf1) (old:=p.spent) (tail:=es.flatMap nfs) nn
    have cd := split_unique (a:=e.ok.x.cm0) (b:=e.ok.x.cm1) (old:=p.cms) (tail:=es.flatMap cms) cc
    have fresh : Fresh p e.ok.x := ⟨nd.1,cd.1,nd.2.1,nd.2.2.1,cd.2.1,cd.2.2.1⟩
    have sameHead := same e (by simp)
    have worked := e.ok.parentGuard
    change latest rows e.ok.x.desc.publicId=parent e.ok.x.desc.publicId at sameHead
    rw [← sameHead] at worked
    have a := derive_admission v fresh birth
    have rule := preflight_refines (t:=payment e.ok.x e.opening) rfl worked
    have next := preserve_supply (residuals_gates eq) a (checked_wire e.ok e.opening) rule initial
    have nextSQL : Consistent (settle s (payment e.ok.x e.opening)) (latest (sqlInsert rows (p.height+1) e.ok.x)) := by
      rw [latest_after_insert]
      exact next
    have nod := List.nodup_cons.mp ids
    have pending : ∀ y∈es,latest (sqlInsert rows (p.height+1) e.ok.x) (itemId y)=parent (itemId y) := by
      intro y hy
      have diff : itemId y ≠ itemId e := fun he => nod.1 (List.mem_map.mpr ⟨y,hy,he⟩)
      change itemId y ≠ e.ok.x.desc.publicId at diff
      rw [latest_after_insert,other_rows_unchanged _ _ _ _ diff]
      exact same y (by simp [hy])
    exact ih (appendEffects p e.ok.x) _ _ rest nod.2 nd.2.2.2 cd.2.2.2 pending nextSQL

theorem checked_parent_block {n w} (p : PublicState) (s : State) (rows : List SqlEvent)
    (xs : List (BlockItem n w (latest rows))) (capacity : xs.length≤4)
    (eligibility : ∀ e∈xs,vm p e.ok.x=true)
    (privateFacts : PrivateBlock p s xs) (ids : (xs.map itemId).Nodup)
    (nn : (p.spent++xs.flatMap nfs).Nodup) (cc : (p.cms++xs.flatMap cms).Nodup)
    (initial : Consistent s (latest rows)) :
    xs.length≤4 ∧ (∀ e∈xs,vm p e.ok.x=true) ∧ Consistent (noteFold s xs)
      (latest (xs.foldl (fun hist e => sqlInsert hist (p.height+1) e.ok.x) rows)) :=
  ⟨capacity,eligibility,block_fold_invariant p s rows xs privateFacts ids nn cc (fun _ _ => rfl) initial⟩

#print axioms checkPacket_refinement
#print axioms checked_monetary_effects
#print axioms real_occurrences_distinct
#print axioms preblock_to_sql
#print axioms checked_parent_block
end FundedRefinement
