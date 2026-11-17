//! PRIVATE worker packet v4. No serde/Debug/logging/secret digest or file intake.
use crate::{Error, frame};
use compact_arity_v3::{
    statement::Statement,
    witness::{Input, Witness},
};
use std::io::Read;

pub(crate) const MAX_PACKET: usize = 128 * 1024;
const MAGIC: &[u8; 8] = b"CPPRV004";
const INPUT_BYTES: usize = 2836;
const FIXED_WITNESS_BYTES: usize = 324;
const P: u64 = compact_proof_v1::codec::MODULUS;

/// Clearing is explicit best effort, not a compiler/allocator/native erasure theorem.
struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// No Debug/Serialize/Clone: accidental diagnostic formatting is not exposed.
pub(crate) struct OwnedWitness {
    value: Witness,
}
impl OwnedWitness {
    pub(crate) fn new(value: Witness) -> Self {
        Self { value }
    }
    pub(crate) fn get(&self) -> &Witness {
        &self.value
    }
    pub(crate) fn clear(&mut self) {
        for input in &mut self.value.inputs {
            input.note.fill(0);
            input.key.fill(0);
            input.origin.fill(0);
            input.index = 0;
            for sibling in &mut input.siblings {
                sibling.fill(0);
            }
            input.siblings.clear();
        }
        self.value.inputs.clear();
        for output in &mut self.value.outputs {
            output.fill(0);
        }
    }
}
impl Drop for OwnedWitness {
    fn drop(&mut self) {
        self.clear();
    }
}
pub(crate) struct PrivateInput {
    pub(crate) statement: Statement,
    pub(crate) statement_bytes: Vec<u8>,
    pub(crate) witness: OwnedWitness,
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn canonical_words(b: &[u8]) -> Result<(), Error> {
    if !b.len().is_multiple_of(8)
        || b.chunks_exact(8)
            .any(|w| u64::from_le_bytes(w.try_into().unwrap()) >= P)
    {
        return Err(Error::Input);
    }
    Ok(())
}
/// Called only after the PRIVATE entry installs the payload-free panic hook.
/// The whole bounded packet must end at EOF. All fallible length/canonical checks
/// precede materialization of the owned secret Witness, avoiding partial parses.
pub(crate) fn read<R: Read>(reader: R) -> Result<PrivateInput, Error> {
    let mut packet = SecretBytes(Vec::with_capacity(MAX_PACKET + 1));
    reader
        .take((MAX_PACKET + 1) as u64)
        .read_to_end(&mut packet.0)
        .map_err(|_| Error::Io)?;
    let b = &packet.0;
    if b.len() > MAX_PACKET
        || b.len() < 20
        || &b[..8] != MAGIC
        || u16_at(b, 8) != 4
        || u16_at(b, 10) != 0
    {
        return Err(Error::Input);
    }
    let statement_len = u32_at(b, 12) as usize;
    if statement_len > frame::MAX_STATEMENT || ![448, 464, 528].contains(&statement_len) {
        return Err(Error::Statement);
    }
    let statement_end = 16usize.checked_add(statement_len).ok_or(Error::Input)?;
    let count_end = statement_end.checked_add(4).ok_or(Error::Input)?;
    if count_end > b.len() {
        return Err(Error::Input);
    }
    let statement_bytes = b[16..statement_end].to_vec();
    let statement = Statement::parse(&statement_bytes).map_err(|_| Error::Statement)?;
    let n = statement.arity.n();
    let expected = FIXED_WITNESS_BYTES
        .checked_add(INPUT_BYTES.checked_mul(n).ok_or(Error::Input)?)
        .ok_or(Error::Input)?;
    let witness_len = u32_at(b, statement_end) as usize;
    if witness_len != expected || count_end.checked_add(witness_len) != Some(b.len()) {
        return Err(Error::Input);
    }
    let w = &b[count_end..];
    if w[0] != n as u8 || w[1] != 2 || u16_at(w, 2) != 0 {
        return Err(Error::Input);
    }
    for i in 0..n {
        let at = 4 + i * INPUT_BYTES;
        canonical_words(&w[at..at + 272])?;
        if u16_at(w, at + 272) != 40 || u16_at(w, at + 274) != 0 {
            return Err(Error::Input);
        }
        canonical_words(&w[at + 276..at + INPUT_BYTES])?;
    }
    let outputs_at = 4 + n * INPUT_BYTES;
    canonical_words(&w[outputs_at..])?;
    // Every offset/count was validated above; construction below has no fallible
    // secret-dependent parsing or error text. Allocation/internal panic is opaque.
    let mut witness = OwnedWitness::new(Witness {
        inputs: Vec::with_capacity(n),
        outputs: [[0; 20]; 2],
    });
    for i in 0..n {
        let at = 4 + i * INPUT_BYTES;
        witness.value.inputs.push(Input {
            note: core::array::from_fn(|j| u64_at(w, at + 8 * j)),
            key: core::array::from_fn(|j| u64_at(w, at + 160 + 8 * j)),
            origin: core::array::from_fn(|j| u64_at(w, at + 200 + 8 * j)),
            index: u64_at(w, at + 264),
            siblings: (0..40)
                .map(|d| core::array::from_fn(|j| u64_at(w, at + 276 + 64 * d + 8 * j)))
                .collect(),
        });
    }
    for j in 0..2 {
        witness.value.outputs[j] =
            core::array::from_fn(|k| u64_at(w, outputs_at + 160 * j + 8 * k));
    }
    // Reuse the actual existing Witness shape/canonicality gate without logging it.
    witness
        .get()
        .canonical(statement.arity)
        .map_err(|_| Error::Input)?;
    Ok(PrivateInput {
        statement,
        statement_bytes,
        witness,
    })
}
