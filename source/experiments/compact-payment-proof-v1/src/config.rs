//! Literal root-approved research config; public setup and fresh proof RNGs differ.
use crate::Error;
use compact_proof_v1::{
    frame::Frame,
    hash::{LeafHash, NodeHash, TranscriptHash},
    types::{Challenge, Challenger, Config, FriMmcs, InputMmcs, Pcs},
};
use p3_challenger::HashChallenger;
use p3_dft::Radix2Dit;
use p3_fri::FriParameters;
use rand::{
    SeedableRng, TryRng,
    rngs::{StdRng, SysRng},
};
pub const N: usize = 512;
pub const QUERIES: usize = 160;
pub const LOG_BLOWUP: usize = 4;
pub const HELPERS: usize = 5;
pub const CHUNKS: usize = 8;
fn build(challenger: Challenger, input: StdRng, fri: StdRng, pcs_rng: StdRng) -> Config {
    let input = InputMmcs::new(LeafHash, NodeHash, 0, input);
    let fri = FriMmcs::new(InputMmcs::new(LeafHash, NodeHash, 0, fri));
    let parameters = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: fri,
    };
    let pcs = Pcs::new::<Challenge>(Radix2Dit::default(), input, parameters, HELPERS, pcs_rng);
    Config::new(pcs, challenger)
        .with_ood_proof_of_work_bits(0)
        .with_lookup_proof_of_work_bits(0)
}
/// Exact root public setup seed; public randomness is never proof randomness.
pub fn setup_seed(profile: &[u8; 64], program: &[u8; 64]) -> [u8; 32] {
    let mut bytes = b"PQPC/CP-FRI/01/PUBLIC-SETUP\0".to_vec();
    bytes.extend(profile);
    bytes.extend(program);
    compact_proof_v1::hash::sha3_512(&bytes)[..32]
        .try_into()
        .unwrap()
}
/// Only setup_preprocessed may consume this configuration. The challenger is
/// unused by that deterministic public commitment operation, not a proof frame.
pub(crate) fn public_setup(profile: &[u8; 64], program: &[u8; 64]) -> Config {
    let seed = setup_seed(profile, program);
    let challenger = Challenger::new(HashChallenger::new(Vec::new(), TranscriptHash));
    build(
        challenger,
        StdRng::from_seed(seed),
        StdRng::from_seed(seed),
        StdRng::from_seed(seed),
    )
}
fn fresh_os_rng() -> Result<StdRng, Error> {
    // rand0.10.1 sys_rng feature -> getrandom SysRng::try_fill_bytes. Each
    // invocation makes a separate fallible OS fill; no derived/cloned caller seed.
    let mut seed = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed)
        .map_err(|_| Error::Entropy)?;
    let rng = StdRng::from_seed(seed);
    seed.fill(0);
    Ok(rng)
}
/// Generic framed caller boundary. OS fills precede challenger construction,
/// preserving the historical caller's entropy and allocation ordering.
pub(crate) fn fresh_config(challenger: impl FnOnce() -> Challenger) -> Result<Config, Error> {
    let input = fresh_os_rng()?;
    let fri = fresh_os_rng()?;
    let pcs = fresh_os_rng()?;
    Ok(build(challenger(), input, fri, pcs))
}
pub(crate) fn fresh_proof(frame: &Frame) -> Result<Config, Error> {
    fresh_config(|| frame.challenger())
}
/// Verification never commits or produces masks. These unused PUBLIC RNG states
/// are separate from proof generation, and every verification resets the frame.
pub(crate) fn fresh_verifier(frame: &Frame, profile: &[u8; 64], program: &[u8; 64]) -> Config {
    let seed = setup_seed(profile, program);
    build(
        frame.challenger(),
        StdRng::from_seed(seed),
        StdRng::from_seed(seed),
        StdRng::from_seed(seed),
    )
}
/// Fixed caller-control path only: the campaign constructs one known context
/// mutation after parsing an authentic proof. No CLI accepts a challenger/frame.
pub(crate) fn context_control(
    challenger: Challenger,
    profile: &[u8; 64],
    program: &[u8; 64],
) -> Config {
    let seed = setup_seed(profile, program);
    build(
        challenger,
        StdRng::from_seed(seed),
        StdRng::from_seed(seed),
        StdRng::from_seed(seed),
    )
}
