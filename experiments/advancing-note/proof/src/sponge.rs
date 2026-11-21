//! Fixed-length field encodings over the upstream width-12 Poseidon2 permutation.
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::Field};
use plonky2::hash::{
    hashing::PlonkyPermutation,
    poseidon2::{P2Permuter, Poseidon2Hash, Poseidon2Permutation},
};
use plonky2::iop::target::Target;
use plonky2::plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher};

pub const OWNER: u64 = 1;
pub const NOTE: u64 = 2;
pub const NULLIFIER: u64 = 3;
pub const EMPTY: u64 = 4;
pub const PADDING: u64 = 6;
pub const PARENT: u64 = 0x100;

pub trait Arithmetic {
    type Word: Copy;
    fn constant(&mut self, value: u64) -> Self::Word;
    fn add(&mut self, x: Self::Word, y: Self::Word) -> Self::Word;
    fn permute(&mut self, state: [Self::Word; 12]) -> [Self::Word; 12];
}

pub struct Host;
impl Arithmetic for Host {
    type Word = F;
    fn constant(&mut self, value: u64) -> F {
        F::from_canonical_u64(value)
    }
    fn add(&mut self, x: F, y: F) -> F {
        x + y
    }
    fn permute(&mut self, state: [F; 12]) -> [F; 12] {
        F::permute(state)
    }
}
pub type Builder = CircuitBuilder<F, 4>;
impl Arithmetic for Builder {
    type Word = Target;
    fn constant(&mut self, value: u64) -> Target {
        Builder::constant(self, F::from_canonical_u64(value))
    }
    fn add(&mut self, x: Target, y: Target) -> Target {
        Builder::add(self, x, y)
    }
    fn permute(&mut self, state: [Target; 12]) -> [Target; 12] {
        let swap = self._false();
        let perm = Poseidon2Hash::permute_swapped(Poseidon2Permutation::new(state), swap, self);
        perm.as_ref().try_into().unwrap()
    }
}

pub fn hash<A: Arithmetic>(a: &mut A, tag: u64, words: &[A::Word]) -> [A::Word; 7] {
    let mut state = [a.constant(0); 12];
    state[5] = a.constant(0x4e375032);
    state[6] = a.constant(tag);
    state[7] = a.constant(words.len() as u64);
    if words.is_empty() {
        state = a.permute(state);
    }
    for block in words.chunks(5) {
        for (slot, &word) in state.iter_mut().zip(block) {
            *slot = a.add(*slot, word);
        }
        state = a.permute(state);
    }
    let first = state;
    let second = a.permute(state);
    [
        first[0], first[1], first[2], first[3], first[4], second[0], second[1],
    ]
}
