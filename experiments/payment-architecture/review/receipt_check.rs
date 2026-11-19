//! Public DLF1 receipt digest check using qp-poseidon-core from the locked build.
use std::{env, fs};

fn main() {
    for file in env::args_os().skip(1) {
        let packet = fs::read(file).expect("public packet");
        assert_eq!(&packet[..5], b"DLF1\x01");
        let proof_bytes = u32::from_le_bytes(packet[5..9].try_into().unwrap()) as usize;
        let end = 9 + proof_bytes;
        assert_eq!(packet.len(), end + 2 * 1792);
        let pi = &packet[end - 26 * 8..end];
        assert_eq!(packet[end - 26 * 8 - 8..end - 26 * 8], 26u64.to_le_bytes());
        let mut receipts = [&packet[end..end + 1792], &packet[end + 1792..]];
        for original_order in [true, false] {
            let mut material = b"qnero/ct".to_vec();
            material.extend_from_slice(&2u32.to_le_bytes());
            for receipt in receipts {
                material.extend_from_slice(&1792u32.to_le_bytes());
                material.extend_from_slice(receipt);
            }
            let digest = qp_poseidon_core::hash_bytes(&material);
            assert_eq!(digest.as_slice() == &pi[22 * 8..], original_order);
            receipts.swap(0, 1);
        }
        println!("two complete public receipts match the authorized order only");
    }
}
