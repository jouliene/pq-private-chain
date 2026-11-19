//! Rebuild public roots with the pinned upstream full-tree wallet implementation.
use qnero_circuit::{CommitmentTree, HeaderInputs};
use qnero_circuit::header::DIGEST_LOGS_SIZE;
use qnero_notes::Digest;
use std::io::{self, Read};

fn main() {
    let mut bytes = Vec::new();
    io::stdin().take((32 << 20) + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 32 << 20 && !bytes.is_empty());
    if std::env::args().nth(1).as_deref() == Some("--ciphertext-digests") {
        let ct = qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES;
        assert_eq!(bytes.len() % (2*ct), 0);
        for pair in bytes.chunks_exact(2*ct) {
            let digest = qnero_circuit::chain::ct_digest(&[&pair[..ct], &pair[ct..]]);
            println!("{}", Digest::from_bytes(&digest).unwrap().to_hex());
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--header-ids") {
        assert_eq!(bytes.len() % 132, 0);
        for h in bytes.chunks_exact(132) {
            let height = u32::from_le_bytes(h[32..36].try_into().unwrap());
            let header = HeaderInputs::new(
                Digest::from_slice(&h[..32]).unwrap(), height,
                h[36..68].try_into().unwrap(), h[68..100].try_into().unwrap(),
                Digest::from_slice(&h[100..]).unwrap(), &[0; DIGEST_LOGS_SIZE],
            ).unwrap();
            println!("{height} {}", header.block_hash().to_hex());
        }
        return;
    }
    assert_eq!(bytes.len() % 32, 0);
    let leaves: Vec<_> = bytes.chunks_exact(32).map(|raw| Digest::from_slice(raw).unwrap()).collect();
    for argument in std::env::args().skip(1) {
        let n: usize = argument.parse().unwrap();
        assert!(n >= 1 && n <= leaves.len());
        let depth = CommitmentTree::depth_for(n).unwrap();
        let tree = CommitmentTree::new(&leaves[..n], depth).unwrap();
        println!("{n} {depth} {}", tree.root().to_hex());
    }
}
