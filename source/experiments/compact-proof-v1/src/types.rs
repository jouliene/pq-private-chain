use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_fri::HidingFriPcs;
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;

use crate::hash::{LeafHash, NodeHash, TranscriptHash};

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 5>;
pub type Digest = [u64; 8];
// Scalar leaves/digests deliberately avoid architecture-specific packed hash APIs.
pub type InputMmcs = MerkleTreeHidingMmcs<Val, u64, LeafHash, NodeHash, StdRng, 2, 8, 8>;
pub type FriMmcs = ExtensionMmcs<Val, Challenge, InputMmcs>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, TranscriptHash, 64>>;
pub type Pcs = HidingFriPcs<Val, Radix2Dit<Val>, InputMmcs, FriMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type Proof = p3_uni_stark::Proof<Config>;
pub type Cap = p3_symmetric::MerkleCap<Val, Digest>;
pub type Paths = p3_merkle_tree::PrunedMerklePaths<u64, 8>;
