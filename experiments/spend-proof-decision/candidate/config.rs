// Native-only oracle configuration. Monetary constraints and algebraic PI hashing use the baseline code.
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::hash::hash_types::{BytesHash, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qnero_notes::encrypt::candidate_sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest as HashDigest, Sha3_384, Shake256,
};

#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub struct ChallengeState<F: RichField>([F;16]);
impl<F: RichField> AsRef<[F]> for ChallengeState<F> {fn as_ref(&self)->&[F]{&self.0}}
impl<F: RichField> PlonkyPermutation<F> for ChallengeState<F> {
    const WIDTH: usize=16;
    const RATE: usize=8;
    fn new<I: IntoIterator<Item=F>>(words:I)->Self {
        let mut state=Self::default();
        state.set_from_iter(words,0);
        state
    }
    fn set_elt(&mut self,value:F,i:usize){self.0[i]=value;}
    fn set_from_iter<I:IntoIterator<Item=F>>(&mut self,words:I,start:usize){
        for (slot,word) in self.0[start..].iter_mut().zip(words){*slot=word;}
    }
    fn set_from_slice(&mut self,words:&[F],start:usize){self.0[start..start+words.len()].copy_from_slice(words);}
    fn permute(&mut self){
        let mut x=Shake256::default();
        Update::update(&mut x,b"K384/FS/v1\0");
        for word in self.0 {Update::update(&mut x,&word.to_canonical_u64().to_le_bytes());}
        let mut reader=x.finalize_xof();
        for word in &mut self.0 {
            loop{
                let mut out=[0;8];
                reader.read(&mut out);
                let n=u64::from_le_bytes(out);
                if n<F::ORDER{*word=F::from_canonical_u64(n);break}
            }
        }
    }
    fn squeeze(&self)->&[F]{&self.0[..Self::RATE]}
}

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Oracle;
fn fields<F:RichField>(tag:&[u8],input:&[F])->BytesHash<48>{
    let mut h=Sha3_384::new();
    HashDigest::update(&mut h,tag);
    HashDigest::update(&mut h,(input.len() as u64).to_le_bytes());
    for x in input {HashDigest::update(&mut h,x.to_canonical_u64().to_le_bytes());}
    BytesHash(h.finalize().into())
}
impl<F: RichField> Hasher<F> for Oracle {
    const HASH_SIZE:usize=48;
    type Hash=BytesHash<48>;
    type Permutation=ChallengeState<F>;
    fn hash_no_pad(input:&[F])->Self::Hash { fields(b"K384/H/v1\0",input) }
    fn hash_leaf(input:&[F])->Self::Hash {fields(b"K384/LEAF/v1\0",input)}
    fn two_to_one(l:Self::Hash,r:Self::Hash)->Self::Hash {
        let mut h=Sha3_384::new();
        HashDigest::update(&mut h,b"K384/NODE/v1\0");
        HashDigest::update(&mut h,l.0);
        HashDigest::update(&mut h,r.0);
        BytesHash(h.finalize().into())
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct C;
impl GenericConfig<2> for C {
    type F=qnero_circuit::F;
    type FE=QuadraticExtension<Self::F>;
    type Hasher=Oracle;
    type InnerHasher=<qnero_circuit::C as GenericConfig<2>>::InnerHasher;
}
pub type Proof=ProofWithPublicInputs<qnero_circuit::F,C,2>;
