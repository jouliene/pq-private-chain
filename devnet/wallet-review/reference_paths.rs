//! Compare local positional siblings against the full pristine upstream Qnero tree.
//! Private witness material stays off stdout and stderr. Only aggregate counts leave the checker.
use qnero_circuit::{CommitmentTree, MerklePath};
use qnero_notes::Digest;
use std::collections::HashMap;
use std::io::{self, Cursor, Read};

fn bytes<const N: usize>(src: &mut impl Read) -> [u8; N] {
    let mut buf = [0; N];
    src.read_exact(&mut buf).expect("truncated path check");
    buf
}
fn word(src: &mut impl Read) -> Digest {
    Digest::from_slice(&bytes::<32>(src)).expect("invalid field word")
}
fn count(src: &mut impl Read) -> usize {
    u32::from_le_bytes(bytes(src)) as usize
}

fn main() {
    let mut all = Vec::new();
    io::stdin().take((64 << 20) + 1).read_to_end(&mut all).unwrap();
    assert!(all.len() <= 64 << 20);
    let length = all.len();
    let mut src = Cursor::new(all);
    assert!(&bytes::<6>(&mut src) == b"QPATH1");
    let n = count(&mut src);
    let cases = count(&mut src);
    assert!(n > 0 && n <= 262144 && cases <= n);
    let leaves: Vec<_> = (0..n).map(|_| word(&mut src)).collect();
    let tree = CommitmentTree::new(&leaves, CommitmentTree::depth_for(n).unwrap()).unwrap();
    assert!(word(&mut src) == tree.root(), "independent funded root mismatch");
    let zero = Digest::from_slice(&[0; 32]).unwrap();
    let mut cache = HashMap::new();
    let mut checked = 0;
    for _ in 0..cases {
        let index = count(&mut src);
        assert!(index < n && bytes::<1>(&mut src)[0] as usize == tree.depth());
        let mut raw = Vec::new();
        let mut size = 1;
        for level in 0..tree.depth() {
            let left = index / (4 * size) * (4 * size);
            let own = index / size % 4;
            let claimed = [word(&mut src), word(&mut src), word(&mut src)];
            let mut k = 0;
            for slot in 0..4 {
                if slot == own { continue; }
                let start = left + slot * size;
                let right = (start + size).min(n);
                let expected = if start >= n {
                    zero
                } else if level == 0 {
                    leaves[start]
                } else {
                    *cache.entry((start, level)).or_insert_with(|| {
                        CommitmentTree::new(&leaves[start..right], level).unwrap().root()
                    })
                };
                assert!(expected == claimed[k], "positional sibling differs");
                k += 1;
                checked += 1;
            }
            raw.push(claimed);
            size *= 4;
        }
        let path = MerklePath::from_unsorted(&raw, leaves[index]).unwrap();
        assert!(path == tree.path(index).unwrap(), "circuit-format witness differs");
        assert!(path.root(leaves[index]).unwrap() == tree.root());
    }
    assert!(src.position() as usize == length);
    println!("{} {} {} {}", n, tree.depth(), cases, checked);
}
