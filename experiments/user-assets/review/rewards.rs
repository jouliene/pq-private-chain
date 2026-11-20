//! Recompute the AST1 native-only reward commitment using the unmodified note library.
use qnero_notes::{Digest, Felt, Note};
use std::io::{self, Read};

fn main() {
    let mut rows = Vec::new();
    io::stdin().take(104 * 128 + 1).read_to_end(&mut rows).unwrap();
    assert!(!rows.is_empty() && rows.len() % 104 == 0 && rows.len() <= 104 * 128);
    for row in rows.chunks_exact(104) {
        let mut opening = Vec::from(&row[..72]);
        opening.extend_from_slice(&0u64.to_le_bytes());
        let pk = Digest::from_slice(&opening[32..64]).unwrap();
        let native = u64::from_le_bytes(opening[64..72].try_into().unwrap());
        let rho = Digest::hash_bytes(&[b"AST1/reward/rho", &opening]);
        let raw = Digest::hash_bytes(&[b"AST1/reward/raw", &opening]);
        let typed = Digest::hash_felts(Felt::new(0x415354310001), &[&[Felt::new(0);5], raw.felts()]);
        let expected = Note::new(pk,native,rho,typed).unwrap().commitment();
        assert_eq!(expected.to_bytes(),row[72..]);
        println!("{}", expected.to_hex());
    }
}
