//! No serde decoder. Sizes/options come exclusively from the trusted shape.
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_uni_stark::{Commitments, OpenedValues, PreprocessedOpenedValues};

use crate::shape::TrustedShape;
use crate::types::{Cap, Challenge, Digest, FriMmcs, InputMmcs, Paths, Proof, Val};

pub const MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Limit,
    Overflow,
    Truncated,
    Trailing,
    NonCanonical,
    Allocation,
    Identity,
}

fn allocated<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
    Ok(v)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn available(&self, count: usize, size: usize) -> Result<(), Error> {
        let bytes = count.checked_mul(size).ok_or(Error::Overflow)?;
        if bytes > self.bytes.len() - self.at {
            return Err(Error::Truncated);
        }
        Ok(())
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.available(1, N)?;
        let value = self.bytes[self.at..self.at + N]
            .try_into()
            .map_err(|_| Error::Truncated)?;
        self.at += N;
        Ok(value)
    }
    fn base(&mut self) -> Result<Val, Error> {
        let word = u64::from_le_bytes(self.take()?);
        if word >= MODULUS {
            return Err(Error::NonCanonical);
        }
        Ok(Val::new(word))
    }
    fn zero(&mut self) -> Result<Val, Error> {
        let value = self.base()?;
        if value.as_canonical_u64() != 0 {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    fn ef(&mut self) -> Result<Challenge, Error> {
        let mut coefficients = [Val::new(0); 5];
        for v in &mut coefficients {
            *v = self.base()?;
        }
        Challenge::from_basis_coefficients_slice(&coefficients).ok_or(Error::Shape)
    }
    fn bases(&mut self, n: usize) -> Result<Vec<Val>, Error> {
        self.available(n, 8)?;
        let mut v = allocated(n)?;
        for _ in 0..n {
            v.push(self.base()?);
        }
        Ok(v)
    }
    fn efs(&mut self, n: usize) -> Result<Vec<Challenge>, Error> {
        self.available(n, 40)?;
        let mut v = allocated(n)?;
        for _ in 0..n {
            v.push(self.ef()?);
        }
        Ok(v)
    }
    fn digest(&mut self) -> Result<Digest, Error> {
        let mut out = [0; 8];
        for word in &mut out {
            *word = u64::from_le_bytes(self.take()?);
        }
        Ok(out)
    }
    fn cap(&mut self) -> Result<Cap, Error> {
        Ok(Cap::new(vec![self.digest()?]))
    }
    fn paths(&mut self, limit: usize) -> Result<Paths, Error> {
        let count =
            usize::try_from(u32::from_le_bytes(self.take()?)).map_err(|_| Error::Overflow)?;
        if count > limit {
            return Err(Error::Limit);
        }
        self.available(count, 64)?; // Both checks precede allocation.
        let mut sibling_hashes = allocated(count)?;
        for _ in 0..count {
            sibling_hashes.push(self.digest()?);
        }
        Ok(Paths { sibling_hashes })
    }
    fn rows(&mut self, queries: usize, widths: &[usize]) -> Result<Vec<Vec<Vec<Val>>>, Error> {
        let total_width = widths
            .iter()
            .try_fold(0usize, |a, &b| a.checked_add(b).ok_or(Error::Overflow))?;
        self.available(queries.checked_mul(total_width).ok_or(Error::Overflow)?, 8)?;
        let mut rows = allocated(queries)?;
        for _ in 0..queries {
            let mut matrices = allocated(widths.len())?;
            for &width in widths {
                matrices.push(self.bases(width)?);
            }
            rows.push(matrices);
        }
        Ok(rows)
    }
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Writer {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::Overflow)?
            > self.limit
        {
            return Err(Error::Limit);
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| Error::Allocation)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn base(&mut self, value: Val) -> Result<(), Error> {
        self.put(&value.as_canonical_u64().to_le_bytes())
    }
    fn zero(&mut self, value: Val) -> Result<(), Error> {
        if value.as_canonical_u64() != 0 {
            return Err(Error::NonCanonical);
        }
        self.base(value)
    }
    fn bases(&mut self, values: &[Val], n: usize) -> Result<(), Error> {
        if values.len() != n {
            return Err(Error::Shape);
        }
        for &value in values {
            self.base(value)?;
        }
        Ok(())
    }
    fn efs(&mut self, values: &[Challenge], n: usize) -> Result<(), Error> {
        if values.len() != n {
            return Err(Error::Shape);
        }
        for value in values {
            self.bases(value.as_basis_coefficients_slice(), 5)?;
        }
        Ok(())
    }
    fn digest(&mut self, digest: &Digest) -> Result<(), Error> {
        for word in digest {
            self.put(&word.to_le_bytes())?;
        }
        Ok(())
    }
    fn cap(&mut self, cap: &Cap) -> Result<(), Error> {
        if cap.num_roots() != 1 {
            return Err(Error::Shape);
        }
        self.digest(&cap.roots()[0])
    }
    fn paths(&mut self, paths: &Paths, limit: usize) -> Result<(), Error> {
        let count = paths.sibling_hashes.len();
        if count > limit {
            return Err(Error::Limit);
        }
        self.put(
            &u32::try_from(count)
                .map_err(|_| Error::Overflow)?
                .to_le_bytes(),
        )?;
        for digest in &paths.sibling_hashes {
            self.digest(digest)?;
        }
        Ok(())
    }
    fn rows(
        &mut self,
        rows: &[Vec<Vec<Val>>],
        queries: usize,
        widths: &[usize],
    ) -> Result<(), Error> {
        if rows.len() != queries {
            return Err(Error::Shape);
        }
        for matrices in rows {
            if matrices.len() != widths.len() {
                return Err(Error::Shape);
            }
            for (row, &width) in matrices.iter().zip(widths) {
                self.bases(row, width)?;
            }
        }
        Ok(())
    }
}

/// Decode a structurally canonical payload. The caller MUST then run verification.
pub fn decode(shape: &TrustedShape, bytes: &[u8]) -> Result<Proof, Error> {
    if bytes.len() > shape.max_wire_bytes {
        return Err(Error::Limit);
    }
    if bytes.len() < shape.minimum_bytes()? {
        return Err(Error::Truncated);
    }
    let mut r = Reader { bytes, at: 0 };
    let degree_bits =
        usize::try_from(u32::from_le_bytes(r.take()?)).map_err(|_| Error::Overflow)?;
    if degree_bits != shape.degree_bits() {
        return Err(Error::Shape);
    }
    let trace = r.cap()?;
    let quotient_chunks = r.cap()?;
    let random = Some(r.cap()?);
    let trace_local = r.efs(shape.main_width)?;
    let trace_next = Some(r.efs(shape.main_width)?);
    let preprocessed = Some(PreprocessedOpenedValues {
        local: r.efs(shape.fixed_width)?,
        next: Some(r.efs(shape.fixed_width)?),
    });
    let mut quotient = allocated(shape.chunks)?;
    for _ in 0..shape.chunks {
        quotient.push(r.efs(5)?);
    }
    let opened_values = OpenedValues {
        trace_local,
        trace_next,
        preprocessed,
        quotient_chunks: quotient,
        random: Some(r.efs(5)?),
    };
    // Helper openings use exact P3 round/matrix/point nesting, including empty
    // preprocessing helper vectors; absence is never a producer-selected flag.
    let mut helpers = allocated(4)?;
    for batch in 0..4 {
        let matrices = if batch == 2 { shape.chunks } else { 1 };
        let points = if batch == 1 || batch == 3 { 2 } else { 1 };
        let mut mats = allocated(matrices)?;
        for _ in 0..matrices {
            let mut pts = allocated(points)?;
            for _ in 0..points {
                pts.push(r.efs(if batch == 3 { 0 } else { 5 })?);
            }
            mats.push(pts);
        }
        helpers.push(mats);
    }
    let batch_pow_witness = r.zero()?;
    let mut commits = allocated(shape.folds())?;
    let mut commit_pow_witnesses = allocated(shape.folds())?;
    for _ in 0..shape.folds() {
        commits.push(r.cap()?);
        commit_pow_witnesses.push(r.zero()?);
    }
    let mut input_openings: Vec<BatchMultiOpening<Val, InputMmcs>> = allocated(4)?;
    for batch in 0..4 {
        let widths = shape.input_widths(batch);
        let opened = r.rows(shape.queries, &widths)?;
        let salts = r.rows(shape.queries, &vec![8; widths.len()])?;
        let paths = r.paths(shape.path_limit(shape.lde_log())?)?;
        input_openings.push(BatchMultiOpening {
            opened_values: opened,
            opening_proof: (salts, paths),
        });
    }
    let mut commit_phase_openings: Vec<CommitPhaseMultiStep<Challenge, FriMmcs>> =
        allocated(shape.folds())?;
    for round in 0..shape.folds() {
        let mut sibling_values = allocated(shape.queries)?;
        for _ in 0..shape.queries {
            sibling_values.push(r.efs(1)?);
        }
        let salts = r.rows(shape.queries, &[8])?;
        let paths = r.paths(shape.path_limit(shape.lde_log() - round - 1)?)?;
        commit_phase_openings.push(CommitPhaseMultiStep {
            sibling_values,
            opening_proof: (salts, paths),
        });
    }
    let final_poly = r.efs(1)?;
    let query_pow_witness = r.zero()?;
    let ood_pow_witness = r.zero()?;
    if r.at != bytes.len() {
        return Err(Error::Trailing);
    }
    Ok(Proof {
        commitments: Commitments {
            trace,
            quotient_chunks,
            random,
        },
        opened_values,
        opening_proof: (
            helpers,
            FriProof {
                batch_pow_witness,
                commit_phase_commits: commits,
                commit_pow_witnesses,
                input_openings,
                commit_phase_openings,
                final_poly,
                query_pow_witness,
            },
        ),
        degree_bits: shape.degree_bits(),
        ood_pow_witness,
    })
}

pub fn encode(shape: &TrustedShape, proof: &Proof) -> Result<Vec<u8>, Error> {
    if proof.degree_bits != shape.degree_bits() {
        return Err(Error::Shape);
    }
    let mut w = Writer {
        bytes: Vec::new(),
        limit: shape.max_wire_bytes,
    };
    w.put(
        &u32::try_from(proof.degree_bits)
            .map_err(|_| Error::Overflow)?
            .to_le_bytes(),
    )?;
    w.cap(&proof.commitments.trace)?;
    w.cap(&proof.commitments.quotient_chunks)?;
    w.cap(proof.commitments.random.as_ref().ok_or(Error::Shape)?)?;
    let opened = &proof.opened_values;
    w.efs(&opened.trace_local, shape.main_width)?;
    w.efs(
        opened.trace_next.as_deref().ok_or(Error::Shape)?,
        shape.main_width,
    )?;
    let pre = opened.preprocessed.as_ref().ok_or(Error::Shape)?;
    w.efs(&pre.local, shape.fixed_width)?;
    w.efs(pre.next.as_deref().ok_or(Error::Shape)?, shape.fixed_width)?;
    if opened.quotient_chunks.len() != shape.chunks {
        return Err(Error::Shape);
    }
    for chunk in &opened.quotient_chunks {
        w.efs(chunk, 5)?;
    }
    w.efs(opened.random.as_deref().ok_or(Error::Shape)?, 5)?;
    let (helpers, fri) = &proof.opening_proof;
    if helpers.len() != 4 {
        return Err(Error::Shape);
    }
    for (batch, mats) in helpers.iter().enumerate() {
        let matrices = if batch == 2 { shape.chunks } else { 1 };
        let points = if batch == 1 || batch == 3 { 2 } else { 1 };
        if mats.len() != matrices {
            return Err(Error::Shape);
        }
        for pts in mats {
            if pts.len() != points {
                return Err(Error::Shape);
            }
            for point in pts {
                w.efs(point, if batch == 3 { 0 } else { 5 })?;
            }
        }
    }
    w.zero(fri.batch_pow_witness)?;
    if fri.commit_phase_commits.len() != shape.folds()
        || fri.commit_pow_witnesses.len() != shape.folds()
        || fri.input_openings.len() != 4
        || fri.commit_phase_openings.len() != shape.folds()
    {
        return Err(Error::Shape);
    }
    for (cap, &pow) in fri
        .commit_phase_commits
        .iter()
        .zip(&fri.commit_pow_witnesses)
    {
        w.cap(cap)?;
        w.zero(pow)?;
    }
    for (batch, opening) in fri.input_openings.iter().enumerate() {
        let widths = shape.input_widths(batch);
        w.rows(&opening.opened_values, shape.queries, &widths)?;
        w.rows(
            &opening.opening_proof.0,
            shape.queries,
            &vec![8; widths.len()],
        )?;
        w.paths(&opening.opening_proof.1, shape.path_limit(shape.lde_log())?)?;
    }
    for (round, step) in fri.commit_phase_openings.iter().enumerate() {
        if step.sibling_values.len() != shape.queries {
            return Err(Error::Shape);
        }
        for sibling in &step.sibling_values {
            w.efs(sibling, 1)?;
        }
        w.rows(&step.opening_proof.0, shape.queries, &[8])?;
        w.paths(
            &step.opening_proof.1,
            shape.path_limit(shape.lde_log() - round - 1)?,
        )?;
    }
    w.efs(&fri.final_poly, 1)?;
    w.zero(fri.query_pow_witness)?;
    w.zero(proof.ood_pow_witness)?;
    Ok(w.bytes)
}
