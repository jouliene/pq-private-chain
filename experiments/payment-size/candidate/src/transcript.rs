//! CP03 transcript replay through the original typed drivers. The only purpose
//! of replay is to reconstruct transport bytes before the original verifier runs.
use compact_all_payments_v3::{frame, registry};
use compact_arity_v3::{air::PaymentAir, statement::Statement};
use compact_proof_v1::{
    hash::{self, LeafHash, NodeHash, TranscriptHash},
    types::{Cap, Challenge, Challenger, FriMmcs, InputMmcs, Val},
};
use p3_air::BaseAir;
use p3_challenger::HashChallenger;
use p3_commit::{CommitmentOpening, Mmcs, Pcs};
use p3_dft::Radix2Dit;
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_fri::{
    BatchMultiOpening, FriParameters, FriShape, PcsShape, PcsVerifierTranscript, TwoAdicFriPcs,
    VerifierTranscript as FriVerifierTranscript,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{StarkShape, StarkVerifierTranscript};
use rand::{SeedableRng, rngs::StdRng};

use crate::{Error, Reader, Result};

pub const QUERIES: usize = 160;
pub const FOLDS: usize = 10;
pub const LDE_LOG: usize = 14;
pub const WIDTHS: [usize; 4] = [10, 584, 80, 114];
pub const MATRICES: [usize; 4] = [1, 1, 8, 1];
pub const FIXED: usize = 3;
pub const LEGACY_HEAD: usize = 60_364;
pub const LEGACY_TAIL: usize = 56;

type FixedTree = <InputMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
type FixedPcs = TwoAdicFriPcs<Val, Radix2Dit<Val>, InputMmcs, FriMmcs>;
type Claims = Vec<CommitmentOpening<Challenge, (), ()>>;

pub struct PublicFixed {
    air: PaymentAir,
    profile: [u8; 64],
    program: [u8; 64],
    table_id: [u8; 64],
    root: [u8; 64],
    commitment: Cap,
    mmcs: InputMmcs,
    tree: FixedTree,
}

fn mmcs(seed: [u8; 32]) -> InputMmcs {
    InputMmcs::new(LeafHash, NodeHash, 0, StdRng::from_seed(seed))
}

fn fri_params(mmcs: FriMmcs) -> FriParameters<FriMmcs> {
    FriParameters {
        log_blowup: 4,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs,
    }
}

impl PublicFixed {
    pub fn prepare(statement: &Statement) -> Result<Self> {
        let arity = statement.arity;
        let air = PaymentAir::new(arity);
        let table = air.program().approved_layout_bytes();
        if table.len() != 512 * WIDTHS[FIXED] * 8
            || registry::sha256(&table) != registry::TABLE_SHA[arity.n()]
        {
            return Err(Error::FixedSetup);
        }
        let profile = hash::sha3_512(registry::PROFILE);
        let program = hash::sha3_512(registry::PROGRAMS[arity.n()]);
        let mut table_descriptor = b"PQPC/CP-FRI/03/PREPROCESSING\0".to_vec();
        table_descriptor.push(arity.n() as u8);
        table_descriptor.extend(512u32.to_le_bytes());
        table_descriptor.extend((WIDTHS[FIXED] as u32).to_le_bytes());
        table_descriptor.extend(table);
        let table_id = hash::sha3_512(&table_descriptor);

        let mut setup = b"PQPC/CP-FRI/01/PUBLIC-SETUP\0".to_vec();
        setup.extend(profile);
        setup.extend(program);
        let seed: [u8; 32] = hash::sha3_512(&setup)[..32].try_into().unwrap();

        // This is the preprocessing branch of HidingFriPcs::commit_preprocessing:
        // alternate each public row with a zero row and use the inner PCS.
        let mut evaluation = air.preprocessed_trace().ok_or(Error::FixedSetup)?;
        if evaluation.width != WIDTHS[FIXED] || evaluation.values.len() != 512 * WIDTHS[FIXED] {
            return Err(Error::FixedSetup);
        }
        evaluation = evaluation.with_zero_cols(WIDTHS[FIXED]);
        evaluation.width = WIDTHS[FIXED];
        let pcs = FixedPcs::new(
            Radix2Dit::default(),
            mmcs(seed),
            fri_params(FriMmcs::new(mmcs(seed))),
        );
        let domain = Pcs::<Challenge, Challenger>::natural_domain_for_degree(&pcs, 1 << FOLDS);
        let (commitment, tree) = Pcs::<Challenge, Challenger>::commit(&pcs, [(domain, evaluation)])
            .map_err(|_| Error::FixedSetup)?;
        if commitment.num_roots() != 1 {
            return Err(Error::FixedSetup);
        }
        let mut root = [0u8; 64];
        for (bytes, word) in root.chunks_exact_mut(8).zip(commitment.roots()[0]) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(Self {
            air,
            profile,
            program,
            table_id,
            root,
            commitment,
            mmcs: mmcs(seed),
            tree,
        })
    }

    pub fn check_header(&self, bytes: &[u8], digest: &[u8; 64]) -> Result<()> {
        if bytes[10..74] != self.profile
            || bytes[74..138] != self.program
            || bytes[138..202] != *digest
        {
            return Err(Error::Identity);
        }
        Ok(())
    }

    pub fn check_registry_root(&self, prepared: &registry::Prepared) -> Result<()> {
        if prepared.describe()["preprocessing_commitment"] != registry::hex(&self.root) {
            return Err(Error::FixedSetup);
        }
        Ok(())
    }

    fn initial_challenger(&self, statement_bytes: &[u8], values: &[Val]) -> (Challenger, [u8; 64]) {
        let mut bytes = Vec::new();
        bytes.extend((frame::TAG.len() as u16).to_le_bytes());
        bytes.extend(frame::TAG);
        bytes.extend(3u16.to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.program);
        bytes.extend(hash::sha3_512(frame::CONTEXT));
        bytes.extend(self.table_id);
        bytes.extend(self.root);
        bytes.extend((statement_bytes.len() as u32).to_le_bytes());
        bytes.extend(statement_bytes);
        bytes.extend((values.len() as u32).to_le_bytes());
        for value in values {
            bytes.extend(value.as_canonical_u64().to_le_bytes());
        }
        let digest = hash::sha3_512(&bytes);
        (
            Challenger::new(HashChallenger::new(bytes, TranscriptHash)),
            digest,
        )
    }

    pub fn frame_digest(&self, statement: &Statement, statement_bytes: &[u8]) -> Result<[u8; 64]> {
        let values = statement.projection().map_err(|_| Error::Statement)?;
        Ok(self.initial_challenger(statement_bytes, &values).1)
    }

    pub fn open(&self, indices: &[usize]) -> BatchMultiOpening<Val, InputMmcs> {
        let (opened_values, opening_proof) = self.mmcs.open_multi_batch(indices, &self.tree);
        BatchMultiOpening {
            opened_values,
            opening_proof,
        }
    }

    pub fn query_indices(
        &self,
        statement: &Statement,
        statement_bytes: &[u8],
        header: &[u8],
        head: &[u8],
        tail: &[u8],
    ) -> Result<Vec<usize>> {
        let values = statement.projection().map_err(|_| Error::Statement)?;
        let (mut challenger, digest) = self.initial_challenger(statement_bytes, &values);
        self.check_header(header, &digest)?;
        let material = TranscriptMaterial::parse(head, tail)?;
        let shape = StarkShape::new::<Val, PaymentAir>(
            &self.air,
            WIDTHS[FIXED],
            FOLDS,
            FOLDS - 1,
            8,
            true,
            0,
        );
        let mut stark = StarkVerifierTranscript::<_, Val, Challenge>::new(&mut challenger, shape);
        let _ = stark
            .constraint_phase(material.trace, Some(self.commitment.clone()), &values)
            .map_err(|_| Error::Transcript)?;
        let _ = stark
            .ood_phase(material.quotient, Some(material.random), material.ood_pow)
            .map_err(|_| Error::Transcript)?;

        let params = fri_params(FriMmcs::new(mmcs([0; 32])));
        let indices = stark.delegate(|challenger| {
            let shape = PcsShape::from_claims(&params, &material.claims);
            let mut pcs = PcsVerifierTranscript::<_, Val, Challenge>::new(challenger, shape);
            // The PCS transcript consumes values only, in commitment/matrix/point
            // order. The unit commitment/domain and default point are unused here.
            pcs.claimed_openings(&material.claims)
                .map_err(|_| Error::Transcript)?;
            let _ = pcs
                .batch_phase(Some(material.batch_pow))
                .map_err(|_| Error::Transcript)?;
            let indices = pcs.delegate(|challenger| {
                let shape = FriShape::new(&params, &[LDE_LOG], LDE_LOG);
                let mut fri = FriVerifierTranscript::<_, Val, Challenge>::new(challenger, shape);
                fri.commit_rounds(&material.folds, &material.fold_pow)
                    .map_err(|_| Error::Transcript)?;
                let indices = fri
                    .query_phase(&material.terminal, Some(material.query_pow))
                    .map_err(|_| Error::Transcript)?;
                fri.finish();
                Ok(indices)
            });
            pcs.finish();
            indices
        });
        stark.finish();
        indices
    }
}

struct TranscriptMaterial {
    trace: Cap,
    quotient: Cap,
    random: Cap,
    claims: Claims,
    batch_pow: Val,
    folds: Vec<Cap>,
    fold_pow: Vec<Val>,
    terminal: Vec<Challenge>,
    query_pow: Val,
    ood_pow: Val,
}

fn append_helper(target: &mut Vec<Challenge>, reader: &mut Reader<'_>) -> Result<()> {
    target.extend(reader.efs(5)?);
    Ok(())
}

impl TranscriptMaterial {
    fn parse(head: &[u8], tail: &[u8]) -> Result<Self> {
        let mut r = Reader::new(head);
        if r.u32()? as usize != FOLDS {
            return Err(Error::Shape);
        }
        let trace = r.cap()?;
        let quotient = r.cap()?;
        let random = r.cap()?;
        let mut trace_local = r.efs(WIDTHS[1] - 5)?;
        let mut trace_next = r.efs(WIDTHS[1] - 5)?;
        let fixed_local = r.efs(WIDTHS[FIXED])?;
        let fixed_next = r.efs(WIDTHS[FIXED])?;
        let mut chunks = (0..8).map(|_| r.efs(5)).collect::<Result<Vec<_>>>()?;
        let mut random_values = r.efs(5)?;
        append_helper(&mut random_values, &mut r)?;
        append_helper(&mut trace_local, &mut r)?;
        append_helper(&mut trace_next, &mut r)?;
        for chunk in &mut chunks {
            append_helper(chunk, &mut r)?;
        }
        let batch_pow = r.zero()?;
        let mut folds = Vec::with_capacity(FOLDS);
        let mut fold_pow = Vec::with_capacity(FOLDS);
        for _ in 0..FOLDS {
            folds.push(r.cap()?);
            fold_pow.push(r.zero()?);
        }
        r.finish()?;
        let mut r = Reader::new(tail);
        let terminal = r.efs(1)?;
        let query_pow = r.zero()?;
        let ood_pow = r.zero()?;
        r.finish()?;
        let z = Challenge::from_basis_coefficients_slice(&[Val::new(0); 5]).unwrap();
        let claims = vec![
            ((), vec![((), vec![(z, random_values)])]).into(),
            ((), vec![((), vec![(z, trace_local), (z, trace_next)])]).into(),
            (
                (),
                chunks
                    .into_iter()
                    .map(|chunk| ((), vec![(z, chunk)]))
                    .collect::<Vec<_>>(),
            )
                .into(),
            ((), vec![((), vec![(z, fixed_local), (z, fixed_next)])]).into(),
        ];
        Ok(Self {
            trace,
            quotient,
            random,
            claims,
            batch_pow,
            folds,
            fold_pow,
            terminal,
            query_pow,
            ood_pow,
        })
    }
}
