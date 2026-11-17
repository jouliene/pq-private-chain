//! Sealed operator-owned three-program registry. No manifest/program/VK intake.
use crate::{Error, config, frame};
use compact_arity_v3::{air::PaymentAir, statement::Arity};
use compact_proof_v1::{
    hash,
    shape::TrustedShape,
    types::{Challenge, Challenger, Config, Pcs, Val},
};
use p3_air::{
    BaseAir,
    symbolic::{AirLayout, get_symbolic_constraints},
};
use p3_commit::Pcs as PcsTrait;
use p3_uni_stark::{
    AirConstraints, PreprocessedProverData, PreprocessedVerifierKey, StarkGenericConfig,
    setup_preprocessed,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
pub const PROFILE: &[u8] = include_bytes!("../data/profile.json");
pub const PROGRAMS: [&[u8]; 3] = [
    include_bytes!("../data/program0.json"),
    include_bytes!("../data/program1.json"),
    include_bytes!("../data/program2.json"),
];
pub const ASSERTIONS: [usize; 3] = [965, 966, 966];
pub const TABLE_SHA: [&str; 3] = [
    "dda9d10930acd97a6d3d27acf7a2f56520fb4e1719181dc8d3d7dcbb7c437f14",
    "06256b21e554172a81a4889cbbbb5c6a2c19dd89110a8ce8eb43f84e1fb32d4b",
    "31f7741e15873062257efdb27a34a248ac8961ce8ceab65076d33c8d6f52743d",
];
#[derive(Clone)]
pub(crate) struct Identities {
    pub profile: [u8; 64],
    pub program: [u8; 64],
    pub preprocessing: [u8; 64],
    pub preprocessing_commitment: [u8; 64],
}
pub struct Prepared {
    pub(crate) arity: Arity,
    pub(crate) air: PaymentAir,
    pub(crate) ids: Identities,
    pub(crate) shape: TrustedShape,
    pub(crate) prover_data: PreprocessedProverData<Config>,
    pub(crate) verifier_key: PreprocessedVerifierKey<Config>,
}
pub struct Registry {
    programs: [Prepared; 3],
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn manifest(bytes: &[u8]) -> Result<Value, Error> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Manifest)?;
    fn allowed(v: &Value) -> bool {
        match v {
            Value::Null => false,
            Value::Bool(_) => true,
            Value::Number(n) => n.as_u64().is_some(),
            Value::String(s) => s.is_ascii(),
            Value::Array(a) => a.iter().all(allowed),
            Value::Object(m) => {
                m.keys().collect::<Vec<_>>().windows(2).all(|w| w[0] < w[1])
                    && m.iter().all(|(k, v)| k.is_ascii() && allowed(v))
            }
        }
    }
    let mut canonical = serde_json::to_vec(&value).map_err(|_| Error::Manifest)?;
    canonical.push(b'\n');
    if !allowed(&value) || canonical != bytes {
        return Err(Error::Manifest);
    }
    Ok(value)
}
pub fn expected_shape(arity: Arity) -> Value {
    json!({"arity":arity.n(),"statement_bytes":arity.bytes(),"public_values":arity.public_fields(),"assertions_per_row":ASSERTIONS[arity.n()],"original_rows":512,"hiding_rows":1024,"main_columns":579,"preprocessing_columns":114,"main_next":true,"preprocessing_next":true,"max_constraint_degree":3,"quotient_chunks":8,"real_permutations":174*arity.n()+8})
}
impl Registry {
    pub fn prepare_public() -> Result<Self, Error> {
        let profile = manifest(PROFILE)?;
        let program_ids = PROGRAMS
            .iter()
            .map(|b| hex(&hash::sha3_512(b)))
            .collect::<Vec<_>>();
        let shapes = (0..3)
            .map(|n| expected_shape(Arity::from_n(n).unwrap()))
            .collect::<Vec<_>>();
        if profile["schema"] != "CP-FRI-ALL-PROFILE-03"
            || profile["program_ids"] != json!(program_ids)
            || profile["shape_policy"] != json!(shapes)
            || profile["fri"]
                != json!({"log_blowup":4,"blowup":16,"queries":160,"max_log_arity":1,"log_final_poly_len":0,"final_degree_bound":1})
            || profile["grinding"]
                != json!({"batch_combination":0,"commit_fold":0,"query":0,"out_of_domain":0,"lookup_challenge":0})
        {
            return Err(Error::Identity);
        }
        let programs = [
            prepare(Arity::Credit)?,
            prepare(Arity::One)?,
            prepare(Arity::Two)?,
        ];
        if programs[0].ids.program == programs[1].ids.program
            || programs[0].ids.program == programs[2].ids.program
            || programs[1].ids.program == programs[2].ids.program
        {
            return Err(Error::Identity);
        }
        Ok(Self { programs })
    }
    pub fn program(&self, arity: Arity) -> &Prepared {
        &self.programs[arity.n()]
    }
    pub fn describe(&self) -> Value {
        json!({"profile":hex(&hash::sha3_512(PROFILE)),"programs":self.programs.iter().map(|p|p.describe()).collect::<Vec<_>>()})
    }
}
impl Prepared {
    pub fn arity(&self) -> Arity {
        self.arity
    }
    pub fn describe(&self) -> Value {
        json!({"shape":expected_shape(self.arity),"program":hex(&self.ids.program),"profile":hex(&self.ids.profile),"preprocessing":hex(&self.ids.preprocessing),"preprocessing_commitment":hex(&self.ids.preprocessing_commitment),"minimum_inner_bytes":self.shape.minimum_bytes().ok()})
    }
}
fn prepare(arity: Arity) -> Result<Prepared, Error> {
    let program = manifest(PROGRAMS[arity.n()])?;
    if program["schema"] != "CP-P2-ALL-PROGRAM-03"
        || program["shape"] != expected_shape(arity)
        || program["preprocessing"]["sha256"] != TABLE_SHA[arity.n()]
    {
        return Err(Error::Identity);
    }
    let air = PaymentAir::new(arity);
    let layout = AirLayout::from_air(&air);
    let constraints = AirConstraints::<Val>::evaluate(&air, layout);
    constraints
        .check_next_row_reads()
        .map_err(|_| Error::Shape)?;
    if (
        air.width(),
        air.preprocessed_width(),
        air.num_public_values(),
        constraints.max_constraint_degree(config::N),
        get_symbolic_constraints::<Val, _>(&air, layout).len(),
    ) != (579, 114, arity.public_fields(), 3, ASSERTIONS[arity.n()])
        || air.main_next_row_columns() != (0..579).collect::<Vec<_>>()
        || air.preprocessed_next_row_columns() != (0..114).collect::<Vec<_>>()
    {
        return Err(Error::Shape);
    }
    let table = air.program().approved_layout_bytes();
    if table.len() != 512 * 114 * 8 || sha256(&table) != TABLE_SHA[arity.n()] {
        return Err(Error::Identity);
    }
    let profile = hash::sha3_512(PROFILE);
    let program_id = hash::sha3_512(PROGRAMS[arity.n()]);
    let mut pp = b"PQPC/CP-FRI/03/PREPROCESSING\0".to_vec();
    pp.push(arity.n() as u8);
    pp.extend(512u32.to_le_bytes());
    pp.extend(114u32.to_le_bytes());
    pp.extend(&table);
    let preprocessing = hash::sha3_512(&pp);
    let setup = config::public_setup(&profile, &program_id);
    if setup.is_zk() != 1 {
        return Err(Error::Shape);
    }
    let domain =
        <Pcs as PcsTrait<Challenge, Challenger>>::natural_domain_for_degree(setup.pcs(), 512);
    let chunks = 1usize
        .checked_shl(
            (constraints.log_num_quotient_chunks(domain, setup.is_zk()) + setup.is_zk()) as u32,
        )
        .ok_or(Error::Shape)?;
    if chunks != 8 {
        return Err(Error::Shape);
    }
    let (prover_data, verifier_key) = setup_preprocessed(&setup, &air, 9)
        .map_err(|_| Error::Preparation)?
        .ok_or(Error::Preparation)?;
    if (
        prover_data.width,
        verifier_key.width,
        prover_data.degree_bits,
        verifier_key.degree_bits,
    ) != (114, 114, 10, 10)
    {
        return Err(Error::Shape);
    }
    let roots: &[[u64; 8]] = verifier_key.commitment.as_ref();
    let proots: &[[u64; 8]] = prover_data.commitment.as_ref();
    if roots.len() != 1 || proots != roots {
        return Err(Error::Preparation);
    }
    let mut root = [0u8; 64];
    for (j, word) in roots[0].iter().enumerate() {
        root[8 * j..8 * j + 8].copy_from_slice(&word.to_le_bytes());
    }
    let ids = Identities {
        profile,
        program: program_id,
        preprocessing,
        preprocessing_commitment: root,
    };
    let shape =
        TrustedShape::new(579, 114, 8, 9, 4, 160, frame::INNER_CAP).map_err(|_| Error::Shape)?;
    Ok(Prepared {
        arity,
        air,
        ids,
        shape,
        prover_data,
        verifier_key,
    })
}
