//! PUBLIC complete-arity frontend controls. No proof, secret RNG, source authorization or admission.
use compact_arities_v3::{
    air::PaymentAir,
    hash::Digest,
    layout::*,
    statement::{Arity, MAX, Statement},
    witness::{self, Witness},
};
use p3_air::{BaseAir, check_all_constraints, symbolic::AirLayout};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as F;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::AirConstraints;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    format: String,
    programs: BTreeMap<String, ProgramExpected>,
    cases: Vec<Case>,
    parser_cases: Vec<ParserCase>,
    legacy_differential_statement_hex: String,
    legacy_differential_witness: Witness,
    linkage: Value,
    primitive_security_claim: bool,
    source_signature_verified: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramExpected {
    preprocessing_sha256: String,
    program_sha256: String,
    real_rows: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    statement_hex: String,
    base_statement_hex: String,
    public_patch: BTreeMap<String, u64>,
    witness: Witness,
    expected_accept: bool,
    failures: Vec<String>,
    expected: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    projection: Vec<u64>,
    hash_outputs: Vec<Digest>,
    core: Digest,
    output_origins: [Digest; 2],
    statement_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParserCase {
    name: String,
    bytes_hex: String,
}
fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex length".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| {
            let nib = |x| match x {
                b'0'..=b'9' => Ok(x - b'0'),
                b'a'..=b'f' => Ok(x - b'a' + 10),
                _ => Err("canonical hex".to_string()),
            };
            Ok(nib(c[0])? * 16 + nib(c[1])?)
        })
        .collect()
}
fn bounded(path: &Path) -> Result<Vec<u8>, String> {
    let f = File::open(path).map_err(|_| "fixture open")?;
    let mut b = Vec::new();
    f.take(8_000_001)
        .read_to_end(&mut b)
        .map_err(|_| "fixture read")?;
    if b.len() > 8_000_000 {
        return Err("fixture bound".into());
    }
    Ok(b)
}
fn check(
    air: &PaymentAir,
    s: &Statement,
    m: &RowMajorMatrix<F>,
    name: &str,
    expected: bool,
) -> Value {
    let r = check_all_constraints(air, m, &s.projection().unwrap(), Some(16));
    assert_eq!(
        r.is_ok(),
        expected,
        "actual AIR outcome for PUBLIC case {name}"
    );
    json!({"name":name,"class":"actual-AIR-constraints","arity":s.arity.n(),"expected_accept":expected,"actual_accept":r.is_ok(),"assertions_per_row":r.total_constraints_per_row,"recorded_failures_capped":r.failures.len()})
}
fn controls(air: &PaymentAir, s: &Statement, w: &Witness) -> Vec<Value> {
    let mut c = Vec::new();
    let n = s.arity.n();
    let real = air.program().real_rows();
    for (name, row, col) in [
        ("live-context-copy", 1, note(5)),
        ("first-balance", 0, BALANCE),
        ("last-balance", 511, BALANCE),
        ("padding-context", real + 1, note(7)),
        ("padding-zero-input", 511, 0),
        ("padding-inactive-range", 511, RANGE_A),
    ] {
        let mut t = witness::generate(air, s, w).unwrap();
        t.matrix.values[row * WIDTH + col] += F::ONE;
        c.push(check(air, s, &t.matrix, name, false));
    }
    if n == 0 {
        for row in [9, 10] {
            let mut t = witness::generate(air, s, w).unwrap();
            // Same reconstructed integer; only Booleanity may rule out these altered bits.
            t.matrix.values[row * WIDTH + RANGE_A] += F::from_u8(2);
            t.matrix.values[row * WIDTH + RANGE_A + 1] -= F::ONE;
            c.push(check(
                air,
                s,
                &t.matrix,
                &format!("credit-nonboolean-same-value-row{row}"),
                false,
            ));
        }
        let mut t = witness::generate(air, s, w).unwrap();
        for row in real..512 {
            t.matrix.values[row * WIDTH + BALANCE] += F::from_u64(s.credit);
        }
        c.push(check(
            air,
            s,
            &t.matrix,
            "double-credit-after-output",
            false,
        ));
    } else {
        let i = n - 1;
        let start = 174 * i;
        let mut t = witness::generate(air, s, w).unwrap();
        for row in start..start + 174 {
            t.matrix.values[row * WIDTH + bit(0)] += F::from_u8(2);
            t.matrix.values[row * WIDTH + bit(1)] -= F::ONE;
        }
        c.push(check(
            air,
            s,
            &t.matrix,
            "input-nonboolean-same-index",
            false,
        ));
    }
    if s.fee > 0 {
        let mut t = witness::generate(air, s, w).unwrap();
        for row in real..512 {
            t.matrix.values[row * WIDTH + BALANCE] += F::from_u64(s.fee);
        }
        c.push(check(air, s, &t.matrix, "omitted-fee-transition", false));
    }
    c
}
fn run() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "controls" {
        return Err("usage: compact-arities-v3 controls PUBLIC-fixtures.json".into());
    }
    let bytes = bounded(Path::new(&args[2]))?;
    let bundle: Bundle = serde_json::from_slice(&bytes).map_err(|_| "public fixture JSON")?;
    if bundle.format != "CP-P2-03-PUBLIC-ARITY-FIXTURES"
        || bundle.primitive_security_claim
        || bundle.source_signature_verified
    {
        return Err("fixture scope/grammar".into());
    }
    assert_eq!(
        compact_arities_v3::statement::source_chunks(&[255; 48]),
        [
            (1 << 56) - 1,
            (1 << 56) - 1,
            (1 << 56) - 1,
            (1 << 56) - 1,
            (1 << 56) - 1,
            (1 << 56) - 1,
            (1 << 48) - 1
        ]
    );
    let mut shapes = Vec::new();
    let mut program_ids = Vec::new();
    for n in 0..3 {
        let a = Arity::from_n(n)?;
        let air = PaymentAir::new(a);
        let symbolic = AirConstraints::<F>::evaluate(&air, AirLayout::from_air(&air));
        symbolic
            .check_next_row_reads()
            .expect("actual next-row declaration");
        let degree = symbolic.max_constraint_degree(512);
        assert!(
            degree <= 3,
            "actual degree changed; do not omit constraints"
        );
        let p = air.program();
        let actual_rows = (0..512).filter(|&row| p.op(row).is_some()).count();
        assert_eq!(actual_rows, 174 * n + 8);
        let expected = &bundle.programs[&n.to_string()];
        assert_eq!(actual_rows, expected.real_rows);
        assert_eq!(
            sha(&p.approved_layout_bytes()),
            expected.preprocessing_sha256
        );
        let id = sha(&p.identity_material());
        assert_eq!(id, expected.program_sha256);
        program_ids.push(id.clone());
        shapes.push(json!({"arity":n,"height":512,"real_permutations":actual_rows,"main_columns":WIDTH,"fixed_columns":PP_WIDTH,"public_fields":air.num_public_values(),"symbolic_max_degree":degree,"main_next_columns":air.main_next_row_columns().len(),"fixed_next_columns":air.preprocessed_next_row_columns().len(),"program_sha256":id}));
    }
    assert!(
        program_ids[0] != program_ids[1]
            && program_ids[1] != program_ids[2]
            && program_ids[0] != program_ids[2]
    );
    let mut results = Vec::new();
    let mut first: BTreeMap<usize, (Statement, Witness)> = BTreeMap::new();
    for case in &bundle.cases {
        let raw = unhex(&case.statement_hex)?;
        let mut s = Statement::parse(&unhex(&case.base_statement_hex)?)?;
        if case.public_patch.is_empty() {
            assert_eq!(s, Statement::parse(&raw)?);
        } else {
            assert!(
                Statement::parse(&raw).is_err(),
                "direct AIR invalid-public case must remain parser-distinct"
            );
            for (k, v) in &case.public_patch {
                match k.as_str() {
                    "credit" => s.credit = *v,
                    "debit" => s.debit = *v,
                    "fee" => s.fee = *v,
                    "count" => s.count = *v,
                    _ => return Err("unsupported PUBLIC diagnostic patch".into()),
                }
            }
        }
        assert_eq!(
            s.bytes()?,
            raw,
            "independent malformed/public semantic fixture identity"
        );
        assert_eq!(sha(&raw), case.expected.statement_sha256);
        assert_eq!(
            s.projection()?
                .iter()
                .map(|x| x.as_canonical_u64())
                .collect::<Vec<_>>(),
            case.expected.projection
        );
        let air = PaymentAir::new(s.arity);
        let t = witness::generate(&air, &s, &case.witness)?;
        assert_eq!(
            t.hash_outputs, case.expected.hash_outputs,
            "independent complete hash schedule: {}",
            case.name
        );
        assert_eq!(s.core()?, case.expected.core);
        assert_eq!(s.output_origins()?, case.expected.output_origins);
        assert_eq!(
            case.failures.is_empty(),
            case.expected_accept,
            "independent host classification"
        );
        results.push(check(&air, &s, &t.matrix, &case.name, case.expected_accept));
        if case.expected_accept && !first.contains_key(&s.arity.n()) {
            first.insert(s.arity.n(), (s, case.witness.clone()));
        }
    }
    let mut internal = Vec::new();
    for (n, (s, w)) in &first {
        assert_eq!(*n, w.inputs.len());
        internal.extend(controls(&PaymentAir::new(s.arity), s, w));
    }
    let (cs, cw) = &first[&0];
    let (os, ow) = &first[&1];
    let (_, tw) = &first[&2];
    assert_eq!(ow.inputs[0].note, cw.outputs[0]);
    assert_eq!(ow.inputs[0].origin, cs.output_origins()?[0]);
    assert_eq!(tw.inputs[0].note, cw.outputs[1]);
    assert_eq!(tw.inputs[0].origin, cs.output_origins()?[1]);
    assert_eq!(tw.inputs[1].note, ow.outputs[0]);
    assert_eq!(tw.inputs[1].origin, os.output_origins()?[0]);
    assert_eq!(bundle.linkage["credit_core"], json!(cs.core()?));
    let mut host_identity_controls = Vec::new();
    for (n, (s, _)) in &first {
        let original = s.core()?;
        let mut changed = s.clone();
        changed.receipts[0][0] ^= 1;
        assert_eq!(
            changed.core()?,
            original,
            "receipt is excluded from immutable CORE"
        );
        changed = s.clone();
        changed.root[0] = (changed.root[0] + 1) % compact_arities_v3::permutation::P;
        changed.count = (changed.count + 1).min(1u64 << 40);
        assert_eq!(
            changed.core()?,
            original,
            "anchor/count excluded from immutable CORE"
        );
        changed = s.clone();
        changed.nonce[31] ^= 1;
        assert_ne!(
            changed.core()?,
            original,
            "nonce changes the immutable CORE"
        );
        if *n == 0 {
            changed = s.clone();
            changed.source_id.as_mut().unwrap()[0] ^= 1;
            assert_eq!(
                changed.projection()?,
                s.projection()?,
                "source is transcript/host context, not an AIR public field"
            );
            assert_ne!(
                changed.core()?,
                original,
                "source identity enters credit CORE"
            );
        }
        host_identity_controls.push(json!({"arity":n,"class":"public-host-identity-only","receipt_and_anchor_core_excluded":true,"nonce_core_bound":true,"credit_source_core_bound":*n==0,"source_authorization_checked":false}));
    }
    let sample = ow.inputs[0].clone();
    let mut shape_controls = Vec::new();
    for (n, (s, w)) in &first {
        let mut bad = w.clone();
        bad.inputs.push(sample.clone());
        assert!(bad.canonical(s.arity).is_err());
        shape_controls
            .push(json!({"arity":n,"class":"witness-interface","extra_input_rejected":true}));
        let other = Arity::from_n((*n + 1) % 3)?;
        assert!(witness::generate(&PaymentAir::new(other), s, w).is_err());
    }
    let mut parser_results = Vec::new();
    for case in &bundle.parser_cases {
        assert!(
            Statement::parse(&unhex(&case.bytes_hex)?).is_err(),
            "parser case {}",
            case.name
        );
        parser_results.push(json!({"name":case.name,"class":"parser","rejected":true}));
    }
    let legacy_s = compact_payment_v1::statement::Statement::parse(&unhex(
        &bundle.legacy_differential_statement_hex,
    )?)?;
    let legacy_w = compact_payment_v1::witness::Witness {
        inputs: bundle
            .legacy_differential_witness
            .inputs
            .clone()
            .try_into()
            .map_err(|_| "legacy arity")?,
        outputs: bundle.legacy_differential_witness.outputs,
    };
    let legacy_air = compact_payment_v1::air::PaymentAir::new(512)?;
    let legacy_trace = compact_payment_v1::witness::generate(&legacy_air, &legacy_s, &legacy_w)?;
    assert!(
        check_all_constraints(
            &legacy_air,
            &legacy_trace.matrix,
            &legacy_s.projection(),
            Some(16)
        )
        .is_ok()
    );
    let mut v3bytes = unhex(&bundle.legacy_differential_statement_hex)?;
    v3bytes[..8].copy_from_slice(b"CP-P2-03");
    v3bytes[8] = 3;
    let v3s = Statement::parse(&v3bytes)?;
    let v3air = PaymentAir::new(Arity::Two);
    let v3trace = witness::generate(&v3air, &v3s, &bundle.legacy_differential_witness)?;
    assert!(check_all_constraints(&v3air, &v3trace.matrix, &v3s.projection()?, Some(16)).is_ok());
    assert_eq!(v3trace.hash_outputs, legacy_trace.hash_outputs);
    assert_eq!(v3s.core()?, legacy_s.core());
    assert_eq!(v3s.output_origins()?, legacy_s.output_origins());
    Ok(
        json!({"status":"PUBLIC_COMPLETE_ARITIES_CONTROLS_PASS","proof":false,"security_claim":false,"source_signature_verified":false,"fixture_sha256":sha(&bytes),"shapes":shapes,"cases":results,"internal_trace_controls":internal,"parser_controls":parser_results,"shape_controls":shape_controls,"host_identity_controls":host_identity_controls,"actual_old_2x2_differential":true,"actual_credit_to_1x2_to_2x2_note_origin_links":true,"MAX":MAX}),
    )
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string(&v).unwrap()),
        Err(e) => {
            eprintln!("PUBLIC_ARITY_FRONTEND_ERROR: {e}");
            std::process::exit(1)
        }
    }
}
