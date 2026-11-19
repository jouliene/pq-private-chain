//! Check the clear founding schedule using the unmodified upstream note primitives.
use qnero_notes::{Digest, Felt, Note};
use std::io::{self, Read};

fn main() {
    let mut bytes = Vec::new();
    io::stdin().take(112 * 128 + 1).read_to_end(&mut bytes).unwrap();
    assert!(!bytes.is_empty() && bytes.len() % 112 == 0 && bytes.len() <= 112 * 128);
    for row in bytes.chunks_exact(112) {
        let body = &row[..80];
        let pk = Digest::from_slice(&body[32..64]).unwrap();
        let native = u64::from_le_bytes(body[64..72].try_into().unwrap());
        let token = u64::from_le_bytes(body[72..80].try_into().unwrap());
        assert!(native < 1 << 62 && token < 1 << 62);
        let rho = Digest::hash_bytes(&[b"TKN1/genesis/rho", body]);
        let raw = Digest::hash_bytes(&[b"TKN1/genesis/raw", body]);
        let typed = Digest::hash_felts(Felt::new(0x544b4e310001), &[&[Felt::new(token)], raw.felts()]);
        let commitment = Note::new(pk,native,rho,typed).unwrap().commitment();
        assert_eq!(commitment.to_bytes(), row[80..]);
        println!("{native} {token} {}",commitment.to_hex());
    }
}
