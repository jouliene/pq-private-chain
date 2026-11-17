//! Fixed depth-40 selective frontier. Private local state, not authenticated bootstrap.
//! Only completed siblings enter serialized state; padding mutates a clone only.
use super::Failure;
use compact_arity_v3::{hash,permutation::P};
type Result<T> = std::result::Result<T,Failure>;
type Digest = [u64;8];
type Token = [u8;16];
const D:usize=40;
const CAP:u64=1u64<<D;
const KMAX:usize=64;
const LEAVES:usize=256;
pub(super) const STATE_MAX:usize=64+40*80+KMAX*(96+D*64);
pub(super) const REQUEST_MAX:usize=41+24+STATE_MAX+KMAX*16+LEAVES*152;
pub(super) const RESPONSE_MAX:usize=92+STATE_MAX+KMAX*(24+D*64);
fn need(ok:bool)->Result<()>{if ok{Ok(())}else{Err(Failure::Input)}}
struct Reader<'a>{b:&'a[u8],at:usize}
impl<'a> Reader<'a>{
 fn new(b:&'a[u8])->Self{Self{b,at:0}}
 fn take(&mut self,n:usize)->Result<&'a[u8]>{let end=self.at.checked_add(n).ok_or(Failure::Input)?;let x=self.b.get(self.at..end).ok_or(Failure::Input)?;self.at=end;Ok(x)}
 fn u8(&mut self)->Result<u8>{Ok(self.take(1)?[0])}
 fn u16(&mut self)->Result<u16>{Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))}
 fn u32(&mut self)->Result<u32>{Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))}
 fn u64(&mut self)->Result<u64>{Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))}
 fn token(&mut self)->Result<Token>{Ok(self.take(16)?.try_into().unwrap())}
 fn digest(&mut self)->Result<Digest>{let mut out=[0;8];for x in &mut out{*x=self.u64()?;need(*x<P)?;}Ok(out)}
 fn zeros(&mut self,n:usize)->Result<()>{need(self.take(n)?.iter().all(|x|*x==0))}
 fn end(&self)->Result<()>{need(self.at==self.b.len())}
}
fn put_digest(out:&mut Vec<u8>,value:&Digest){for x in value{out.extend(x.to_le_bytes())}}
fn leaf(chain:&[u8;32],origin:&Digest,cm:&Digest)->Digest{let mut words=[0;16];words[..8].copy_from_slice(origin);words[8..].copy_from_slice(cm);let out=hash::hash(chain,hash::LEAF,&words);words.fill(0);out}
fn node(chain:&[u8;32],level:usize,left:&Digest,right:&Digest)->Digest{let mut words=[0;17];words[0]=level as u64;words[1..9].copy_from_slice(left);words[9..].copy_from_slice(right);let out=hash::hash(chain,hash::NODE,&words);words.fill(0);out}
fn empty(chain:&[u8;32])->[Digest;D+1]{let mut out=[[0;8];D+1];for level in 0..D{out[level+1]=node(chain,level,&out[level],&out[level]);}out}
fn sibling_start(index:u64,level:usize)->u64{((index>>level)^1)<<level}
fn completed_mask(index:u64,count:u64)->u64{let mut mask=0;for level in 0..D{if sibling_start(index,level)+(1u64<<level)<=count{mask|=1u64<<level;}}mask}
#[derive(Clone)]
struct Branch{start:u64,level:usize,value:Digest}
impl Drop for Branch{fn drop(&mut self){self.value.fill(0);self.start=0;self.level=0;}}
#[derive(Clone)]
struct Target{token:Token,index:u64,leaf:Digest,path:[Option<Digest>;D]}
impl Drop for Target{fn drop(&mut self){self.token.fill(0);self.index=0;self.leaf.fill(0);for slot in &mut self.path{if let Some(value)=slot{value.fill(0)}*slot=None;}}}
#[derive(Clone)]
struct State{chain:[u8;32],k:usize,count:u64,forest:Vec<Branch>,targets:Vec<Target>}
impl Drop for State{fn drop(&mut self){self.chain.fill(0);self.count=0;self.k=0;}}
impl State{
 fn new(chain:[u8;32],k:usize)->Self{Self{chain,k,count:0,forest:Vec::new(),targets:Vec::new()}}
 fn decode(b:&[u8],chain:&[u8;32],k:usize)->Result<Self>{
  need(b.len()<=STATE_MAX)?;let mut r=Reader::new(b);need(r.take(8)?==b"CPTRST06"&&r.u16()?==1&&r.u16()?==D as u16&&r.take(32)?==chain)?;
  need(r.u16()?as usize==k)?;let live=r.u16()?as usize;let branches=r.u8()?as usize;r.zeros(7)?;let count=r.u64()?;
  need(live<=k&&branches<=D&&count<=CAP)?;
  let mut state=Self::new(*chain,k);state.count=count;
  for _ in 0..branches{let start=r.u64()?;let level=r.u8()?as usize;r.zeros(7)?;let value=r.digest()?;state.forest.push(Branch{start,level,value});}
  for _ in 0..live{
   let token=r.token()?;let index=r.u64()?;let leaf=r.digest()?;let mask=r.u64()?;
   need(index<count&&state.targets.last().is_none_or(|old|old.index<index)&&!state.targets.iter().any(|old|old.token==token)&&mask==completed_mask(index,count))?;
   let mut path=[None;D];for(level,slot)in path.iter_mut().enumerate(){if mask&(1u64<<level)!=0{*slot=Some(r.digest()?);}}
   state.targets.push(Target{token,index,leaf,path});
  }
  r.end()?;state.shape()?;Ok(state)
 }
 fn shape(&self)->Result<()>{
  need((1..=KMAX).contains(&self.k)&&self.count<=CAP&&self.targets.len()<=self.k&&self.forest.len()<=D)?;
  let mut at=0;let mut j=0;
  for level in(0..=D).rev(){if self.count&(1u64<<level)!=0{let branch=self.forest.get(j).ok_or(Failure::Input)?;need(branch.start==at&&branch.level==level)?;at+=1u64<<level;j+=1;}}
  need(j==self.forest.len()&&at==self.count)?;
  for(i,target)in self.targets.iter().enumerate(){
   need(target.index<self.count&&(i==0||self.targets[i-1].index<target.index)&&!self.targets[..i].iter().any(|old|old.token==target.token))?;
   let mut mask=0;for(level,slot)in target.path.iter().enumerate(){if slot.is_some(){mask|=1u64<<level;}}
   need(mask==completed_mask(target.index,self.count))?;
  }Ok(())
 }
 fn capture(&mut self,start:u64,level:usize,value:&Digest)->Result<()>{
  if level>=D{return Ok(())}
  for target in &mut self.targets{if sibling_start(target.index,level)==start{match target.path[level]{Some(old)=>need(old==*value)?,None=>target.path[level]=Some(*value)}}}Ok(())
 }
 fn subtree(&mut self,mut start:u64,mut level:usize,mut value:Digest)->Result<()>{
  need(level<=D&&start%(1u64<<level)==0&&start.checked_add(1u64<<level).is_some_and(|n|n<=CAP))?;self.capture(start,level,&value)?;
  while self.forest.last().is_some_and(|old|old.level==level){
   need(level<D)?;let old=self.forest.pop().ok_or(Failure::Input)?;need(old.start+(1u64<<level)==start&&old.start%(2u64<<level)==0)?;
   let next=node(&self.chain,level,&old.value,&value);value.fill(0);value=next;start=old.start;level+=1;self.capture(start,level,&value)?;
  }
  self.forest.push(Branch{start,level,value});value.fill(0);Ok(())
 }
 fn append(&mut self,value:Digest,token:Option<Token>)->Result<()>{
  need(self.count<CAP)?;
  if let Some(token)=token{
   need(self.targets.len()<self.k&&!self.targets.iter().any(|old|old.token==token))?;let mut path=[None;D];
   for(level,slot)in path.iter_mut().enumerate(){if self.count&(1u64<<level)!=0{let start=sibling_start(self.count,level);let branch=self.forest.iter().find(|b|b.start==start&&b.level==level).ok_or(Failure::Input)?;*slot=Some(branch.value);}}
   self.targets.push(Target{token,index:self.count,leaf:value,path});
  }
  self.subtree(self.count,0,value)?;self.count+=1;Ok(())
 }
 fn view(&self)->Result<Self>{
  let mut temporary=self.clone();let empties=empty(&self.chain);let mut at=self.count;
  if at==0{temporary.forest.push(Branch{start:0,level:D,value:empties[D]});}
  else{while at<CAP{let level=at.trailing_zeros()as usize;temporary.subtree(at,level,empties[level])?;at+=1u64<<level;}}
  need(temporary.forest.len()==1&&temporary.forest[0].start==0&&temporary.forest[0].level==D)?;let root=temporary.forest[0].value;
  for target in &temporary.targets{
   let mut value=target.leaf;
   for level in 0..D{let sibling=target.path[level].ok_or(Failure::Input)?;let next=if target.index&(1u64<<level)==0{node(&self.chain,level,&value,&sibling)}else{node(&self.chain,level,&sibling,&value)};value.fill(0);value=next;}
   let matches=value==root;value.fill(0);need(matches)?;
  }Ok(temporary)
 }
 fn encode(&self)->Result<Vec<u8>>{
  self.shape()?;let mut out=b"CPTRST06".to_vec();out.extend(1u16.to_le_bytes());out.extend((D as u16).to_le_bytes());out.extend(self.chain);out.extend((self.k as u16).to_le_bytes());out.extend((self.targets.len()as u16).to_le_bytes());out.push(self.forest.len()as u8);out.extend([0;7]);out.extend(self.count.to_le_bytes());
  for branch in &self.forest{out.extend(branch.start.to_le_bytes());out.push(branch.level as u8);out.extend([0;7]);put_digest(&mut out,&branch.value)}
  for target in &self.targets{out.extend(target.token);out.extend(target.index.to_le_bytes());put_digest(&mut out,&target.leaf);out.extend(completed_mask(target.index,self.count).to_le_bytes());for value in target.path.iter().flatten(){put_digest(&mut out,value)}}
  need(out.len()<=STATE_MAX)?;Ok(out)
 }
}
struct Tokens(Vec<Token>);
impl Drop for Tokens{fn drop(&mut self){for token in &mut self.0{token.fill(0)}}}
struct Incoming{origin:Digest,cm:Digest,token:Option<Token>}
impl Drop for Incoming{fn drop(&mut self){self.origin.fill(0);self.cm.fill(0);if let Some(token)=&mut self.token{token.fill(0)}}}
pub(super) fn advance(chain:&[u8;32],payload:&[u8])->Result<Vec<u8>>{
 need(payload.len()<=REQUEST_MAX-41)?;let mut r=Reader::new(payload);need(r.take(8)?==b"CPTRQ006"&&r.u16()?==1)?;let k=r.u16()?as usize;let state_len=r.u32()?as usize;let forget_count=r.u16()?as usize;let leaf_count=r.u16()?as usize;r.zeros(4)?;
 need((1..=KMAX).contains(&k)&&state_len<=STATE_MAX&&forget_count<=KMAX&&leaf_count<=LEAVES&&payload.len()==24+state_len+16*forget_count+152*leaf_count)?;
 let state_bytes=r.take(state_len)?;let mut state=if state_len==0{State::new(*chain,k)}else{State::decode(state_bytes,chain,k)?};
 let mut forget=Tokens(Vec::with_capacity(forget_count));for _ in 0..forget_count{let token=r.token()?;need(forget.0.last().is_none_or(|old|*old<token)&&state.targets.iter().any(|old|old.token==token))?;forget.0.push(token);}
 let mut incoming:Vec<Incoming>=Vec::with_capacity(leaf_count);let mut discoveries=0;
 for _ in 0..leaf_count{
  let origin=r.digest()?;let cm=r.digest()?;let flag=r.u8()?;r.zeros(7)?;let raw=r.token()?;need(flag<=1&&(flag==1||raw==[0;16]))?;
  let token=if flag==1{need(!state.targets.iter().any(|old|old.token==raw)&&!incoming.iter().any(|old|old.token==Some(raw)))?;discoveries+=1;Some(raw)}else{None};incoming.push(Incoming{origin,cm,token});
 }
 r.end()?;need(state.count.checked_add(leaf_count as u64).is_some_and(|n|n<=CAP)&&state.targets.len()-forget_count+discoveries<=k)?;
 // Prior state is a canonical consistent local tree, not authenticated chain state.
 // This fold also rejects malformed completed paths before any tentative append.
 drop(state.view()?);
 state.targets.retain(|target|!forget.0.iter().any(|token|*token==target.token));
 for leaf_input in &incoming{let value=leaf(chain,&leaf_input.origin,&leaf_input.cm);state.append(value,leaf_input.token)?;}
 state.shape()?;let projected=state.view()?;let mut serialized=state.encode()?;
 let mut out=b"CPTRP006".to_vec();out.extend(1u16.to_le_bytes());out.extend((k as u16).to_le_bytes());out.extend(state.count.to_le_bytes());put_digest(&mut out,&projected.forest[0].value);out.extend((serialized.len()as u32).to_le_bytes());out.extend((projected.targets.len()as u16).to_le_bytes());out.extend(0u16.to_le_bytes());out.extend_from_slice(&serialized);serialized.fill(0);
 for target in &projected.targets{out.extend(target.token);out.extend(target.index.to_le_bytes());for sibling in &target.path{put_digest(&mut out,&sibling.ok_or(Failure::Input)?);}}
 need(out.len()<=RESPONSE_MAX)?;Ok(out)
}

#[cfg(test)]
mod tests{
 use super::*;
 fn good<T>(value:Result<T>)->T{match value{Ok(x)=>x,Err(_)=>panic!("PUBLIC_TREE_CONTROL_UNEXPECTED_REJECTION")}}
 fn token(n:u8)->Token{[n;16]}
 fn funded(n:u64)->(Digest,Digest){([n;8],[n+100;8])}
 fn request(state:&[u8],k:u16,forget:&[Token],leaves:&[(Digest,Digest,Option<Token>)])->Vec<u8>{
  let mut b=b"CPTRQ006".to_vec();b.extend(1u16.to_le_bytes());b.extend(k.to_le_bytes());b.extend((state.len()as u32).to_le_bytes());b.extend((forget.len()as u16).to_le_bytes());b.extend((leaves.len()as u16).to_le_bytes());b.extend(0u32.to_le_bytes());b.extend(state);for t in forget{b.extend(t)}
  for(origin,cm,t)in leaves{put_digest(&mut b,origin);put_digest(&mut b,cm);b.push(u8::from(t.is_some()));b.extend([0;7]);b.extend(t.unwrap_or([0;16]));}b
 }
 fn next(state:&[u8],k:u16,forget:&[Token],leaves:&[(Digest,Digest,Option<Token>)])->Vec<u8>{good(advance(&[7;32],&request(state,k,forget,leaves)))}
 fn encoded(reply:&[u8])->Vec<u8>{let n=u32::from_le_bytes(reply[84..88].try_into().unwrap())as usize;reply[92..92+n].to_vec()}
 fn root(reply:&[u8])->Digest{let mut r=Reader::new(&reply[20..84]);good(r.digest())}
 fn public_oracle(chain:&[u8;32],leaves:&[Digest])->(Digest,Vec<Vec<Digest>>){
  // Test-only small full tree; runtime State never owns an all-history vector.
  let e=empty(chain);let mut levels=vec![leaves.to_vec()];
  for d in 0..D{let v=&levels[d];let mut parents=Vec::new();for pair in v.chunks(2){parents.push(node(chain,d,&pair[0],pair.get(1).unwrap_or(&e[d])));}if parents.is_empty(){parents.push(e[d+1]);}levels.push(parents);}
  (levels[D][0],levels)
 }
 #[test]
 fn padding_is_temporary_and_real_sibling_replaces_view(){
  let(a,b)=funded(1);let first=next(&[],2,&[],&[(a,b,Some(token(1)))]);let state=encoded(&first);let parsed=good(State::decode(&state,&[7;32],2));assert!(parsed.targets[0].path.iter().all(Option::is_none),"PUBLIC_TREE_UNPADDED_MASK");
  let unchanged=next(&state,2,&[],&[]);assert!(encoded(&unchanged)==state,"PUBLIC_TREE_EMPTY_APPEND_STATE");
  let(c,d)=funded(2);let second=next(&state,2,&[],&[(c,d,None)]);let parsed=good(State::decode(&encoded(&second),&[7;32],2));let right=leaf(&[7;32],&c,&d);assert!(parsed.targets[0].path[0]==Some(right)&&parsed.targets[0].path[1..].iter().all(Option::is_none),"PUBLIC_TREE_REAL_RIGHT_SIBLING");
  let(expected,_)=public_oracle(&[7;32],&[leaf(&[7;32],&a,&b),right]);assert!(root(&second)==expected,"PUBLIC_TREE_TWO_LEAF_ROOT");
 }
 #[test]
 fn sequential_block_roots_and_paths_match_small_full_oracle(){
  let mut state=Vec::new();let mut all=Vec::new();let mut last=Vec::new();
  for n in 0..65u64{
   let(origin,cm)=funded(n+1);let t=if[0,1,7,31,64].contains(&n){Some(token(n as u8))}else{None};last=next(&state,8,&[],&[(origin,cm,t)]);state.fill(0);state=encoded(&last);all.push(leaf(&[7;32],&origin,&cm));
   let(expected,levels)=public_oracle(&[7;32],&all);assert!(root(&last)==expected,"PUBLIC_TREE_ORACLE_ROOT");let projected=good(good(State::decode(&state,&[7;32],8)).view());let empties=empty(&[7;32]);
   for target in &projected.targets{for d in 0..D{let sibling=((target.index>>d)^1)as usize;let expected=levels[d].get(sibling).copied().unwrap_or(empties[d]);assert!(target.path[d]==Some(expected),"PUBLIC_TREE_ORACLE_PATH");}}
  }
  assert!(!last.is_empty(),"PUBLIC_TREE_CONTROL_COMPLETED");state.fill(0);last.fill(0);
 }
 #[test]
 fn malformed_state_shapes_and_fields_fail_closed(){
  let(a,b)=funded(1);let first=next(&[],2,&[],&[(a,b,Some(token(1)))]);let state=encoded(&first);
  for offset in[0usize,8,10,12,44,48,49,56,64,72,73,144+16,144+24,144+88]{let mut bad=state.clone();bad[offset]^=1;assert!(advance(&[7;32],&request(&bad,2,&[],&[])).is_err(),"PUBLIC_TREE_MUTATED_STATE_REJECTED");bad.fill(0);}
  let mut bad=state.clone();bad[80..88].copy_from_slice(&P.to_le_bytes());assert!(advance(&[7;32],&request(&bad,2,&[],&[])).is_err(),"PUBLIC_TREE_NONCANONICAL_DIGEST");
  let mut wire=request(&state,2,&[],&[]);wire.push(0);assert!(advance(&[7;32],&wire).is_err(),"PUBLIC_TREE_TRAILING_INPUT");assert!(advance(&[8;32],&request(&state,2,&[],&[])).is_err(),"PUBLIC_TREE_CHAIN_BOUND");assert!(advance(&[7;32],&request(&state,3,&[],&[])).is_err(),"PUBLIC_TREE_K_BOUND");
 }
 #[test]
 fn forget_discovery_uniqueness_and_capacity(){
  let(a,b)=funded(1);let first=next(&[],1,&[],&[(a,b,Some(token(1)))]);let state=encoded(&first);let(c,d)=funded(2);
  assert!(advance(&[7;32],&request(&state,1,&[],&[(c,d,Some(token(2)))])).is_err(),"PUBLIC_TREE_OWNED_CAP");
  assert!(advance(&[7;32],&request(&state,1,&[token(2)],&[])).is_err(),"PUBLIC_TREE_UNKNOWN_FORGET");assert!(advance(&[7;32],&request(&state,1,&[token(1),token(1)],&[])).is_err(),"PUBLIC_TREE_DUPLICATE_FORGET");
  assert!(advance(&[7;32],&request(&state,1,&[token(1)],&[(c,d,Some(token(1)))])).is_err(),"PUBLIC_TREE_SAME_CALL_TOKEN_ALIAS");
  let second=next(&state,1,&[token(1)],&[(c,d,Some(token(2)))]);let parsed=good(State::decode(&encoded(&second),&[7;32],1));assert!(parsed.targets.len()==1&&parsed.targets[0].token==token(2)&&parsed.targets[0].index==1,"PUBLIC_TREE_FORGET_THEN_DISCOVER");
  assert!(advance(&[7;32],&request(&[],64,&[],&vec![(a,b,Some(token(1)));2])).is_err(),"PUBLIC_TREE_DUPLICATE_DISCOVERY");assert!(advance(&[7;32],&request(&[],64,&[],&vec![(a,b,None);257])).is_err(),"PUBLIC_TREE_LEAF_CAP");
 }
 #[test]
 fn full_capacity_geometry_and_exact_caps(){
  assert!(STATE_MAX==173248&&REQUEST_MAX==213249&&RESPONSE_MAX==338716&&RESPONSE_MAX<1024*1024,"PUBLIC_TREE_FIXED_CAPS");
  let state=State{chain:[7;32],k:1,count:CAP,forest:vec![Branch{start:0,level:40,value:[3;8]}],targets:vec![]};let encoded=good(state.encode());let reply=next(&encoded,1,&[],&[]);assert!(root(&reply)==[3;8],"PUBLIC_TREE_FULL_STRUCTURAL_ROOT");let(a,b)=funded(1);assert!(advance(&[7;32],&request(&encoded,1,&[],&[(a,b,None)])).is_err(),"PUBLIC_TREE_FULL_REJECTS_APPEND");
  let genesis=next(&[],64,&[],&[]);assert!(root(&genesis)==empty(&[7;32])[40],"PUBLIC_TREE_GENESIS_EMPTY_ROOT");
 }
}
