//! Test the pinned transparent Keccak component on the actual CP03 leaf absorber.
//! The verified claim is the hash-accelerator transcript, not a payment or a block.
use risc0_circuit_keccak::{KeccakState, compute_keccak_digest, prove::keccak_prover};
use risc0_core::field::baby_bear::Elem;
use std::time::Instant;
use std::{env, fs};

const PO2: usize = 14;

fn absorb(message: &[u8]) -> (Vec<KeccakState>, Vec<u8>) {
    let mut padded = message.to_vec();
    padded.push(0x06);
    padded.resize(padded.len().next_multiple_of(72), 0);
    *padded.last_mut().unwrap() ^= 0x80;
    let mut state = [0u64; 25];
    let mut inputs = Vec::new();
    for block in padded.chunks_exact(72) {
        for (lane, word) in state.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(word.try_into().unwrap());
        }
        inputs.push(state);
        keccak::f1600(&mut state);
    }
    let digest = state[..8].iter().flat_map(|n| n.to_le_bytes()).collect();
    (inputs, digest)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 5);
    let (inputs, actual) = absorb(&fs::read(&args[2]).unwrap());
    assert_eq!(actual, fs::read(&args[3]).unwrap());
    assert_eq!(inputs.len(), 67);
    let digest = compute_keccak_digest(bytemuck::cast_slice(&inputs));
    let prover = keccak_prover().unwrap();
    let start = Instant::now();
    if args[1] == "prove" {
        let seal = prover.prove(&inputs, PO2).unwrap();
        fs::write(&args[4], bytemuck::cast_slice(&seal)).unwrap();
    } else {
        assert_eq!(args[1], "verify");
        let proof = fs::read(&args[4]).unwrap();
        assert_eq!(proof.len() % 4, 0);
        let seal: Vec<u32> = proof
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect();
        assert!(seal.len() > 18);
        let out: Vec<u32> = seal[..17]
            .iter()
            .map(|&v| Elem::new_raw(v).as_u32())
            .collect();
        assert_eq!(out[16], 1 << PO2);
        assert_eq!(seal[17], PO2 as u32);
        for (i, &word) in digest.as_words().iter().enumerate() {
            assert!(out[2 * i] < 65536 && out[2 * i + 1] < 65536);
            assert_eq!(
                out[2 * i] | (out[2 * i + 1] << 16),
                word,
                "expected public input/output transcript"
            );
        }
        prover
            .verify(&seal)
            .expect("transparent cryptographic seal verification");
    }
    println!(
        "{} {} {} {} {}",
        args[1],
        inputs.len(),
        fs::metadata(&args[4]).unwrap().len(),
        digest,
        start.elapsed().as_secs_f64()
    );
}
