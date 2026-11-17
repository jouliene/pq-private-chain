//! PUBLIC complete-frontend controls. No proof, private RNG or ledger admission.
use compact_payment_v1::{
    air::PaymentAir,
    hash::{self, Digest},
    layout::*,
    permutation::{self, P},
    statement::{MAX, Statement},
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
    fixtures: Vec<Fixture>,
    permutation_vectors: Vec<PermVector>,
    program_sha256: BTreeMap<String, String>,
    host_negative_expectations: Vec<HostNegative>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNegative {
    name: String,
    input_sha256: String,
    failures: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    name: String,
    statement_hex: String,
    witness: Witness,
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
struct PermVector {
    input: [u64; 16],
    output: [u64; 16],
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
        .map(|x| {
            let nib = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err("noncanonical hex".to_string()),
            };
            Ok(nib(x[0])? * 16 + nib(x[1])?)
        })
        .collect()
}
fn bounded(path: &Path) -> Result<Vec<u8>, String> {
    let f = File::open(path).map_err(|_| "fixture open")?;
    let mut b = Vec::new();
    f.take(2_000_001)
        .read_to_end(&mut b)
        .map_err(|_| "fixture read")?;
    if b.len() > 2_000_000 {
        return Err("fixture limit".into());
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
    let r = check_all_constraints(air, m, &s.projection(), Some(16));
    assert_eq!(r.is_ok(), expected, "AIR outcome for PUBLIC control {name}");
    json!({"name":name,"class":"AIR-constraint","expected_accept":expected,"actual_accept":r.is_ok(),"recorded_failures_capped":r.failures.len(),"assertions_per_row":r.total_constraints_per_row})
}
fn fresh(air: &PaymentAir, s: &Statement, w: &Witness, name: &str, expected: bool) -> Value {
    let t = witness::generate(air, s, w).expect("PUBLIC trace shape/canonicality");
    let mut result = check(air, s, &t.matrix, name, expected);
    let mut input = s.bytes();
    // Value's default Map uses ordered keys; match independent Python's exact
    // sort_keys+compact-separators encoding, not Rust struct member order.
    input.extend(serde_json::to_vec(&serde_json::to_value(w).unwrap()).unwrap());
    result["input_sha256"] = json!(sha(&input));
    result
}
fn refresh(s: &mut Statement, w: &Witness) {
    s.nullifiers = w.nullifiers(&s.chain);
    s.commitments = core::array::from_fn(|j| hash::hash(&s.chain, hash::NOTE, &w.outputs[j]));
}
/// Construct an independent sparse anchor for PUBLIC malicious-range cases.
/// This authenticates no real funding; the AIR must reject ranges even with all
/// hash/membership equations rebuilt coherently under the supplied test root.
fn reanchor(s: &mut Statement, w: &mut Witness) {
    let leaves = w.leaves(&s.chain);
    let mut empty = [0; 8];
    let mut level: BTreeMap<u64, Digest> = BTreeMap::new();
    for i in 0..2 {
        assert!(w.inputs[i].index < 1u64 << 40);
        assert!(level.insert(w.inputs[i].index, leaves[i]).is_none());
    }
    for d in 0..40 {
        for i in 0..2 {
            w.inputs[i].siblings[d] = *level.get(&((w.inputs[i].index >> d) ^ 1)).unwrap_or(&empty);
        }
        let mut parents = BTreeMap::new();
        for &idx in level.keys() {
            let idx = idx / 2;
            if parents.contains_key(&idx) {
                continue;
            }
            let left = *level.get(&(2 * idx)).unwrap_or(&empty);
            let right = *level.get(&(2 * idx + 1)).unwrap_or(&empty);
            let mut p = vec![d as u64];
            p.extend(left);
            p.extend(right);
            parents.insert(idx, hash::hash(&s.chain, hash::NODE, &p));
        }
        let mut p = vec![d as u64];
        p.extend(empty);
        p.extend(empty);
        empty = hash::hash(&s.chain, hash::NODE, &p);
        level = parents;
    }
    s.root = level[&0];
}
fn parser_controls(base: &[u8]) -> Vec<Value> {
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut b = base.to_vec();
    b.push(0);
    cases.push(("suffix", b));
    cases.push(("truncated", base[..527].to_vec()));
    for (name, at, value) in [
        ("magic", 0, 0),
        ("reserved", 13, 1),
        ("arity", 10, 1),
        ("kind", 12, 0),
        ("version", 8, 2),
    ] {
        let mut b = base.to_vec();
        b[at] = value;
        cases.push((name, b));
    }
    for at in [80, 208, 344] {
        let mut b = base.to_vec();
        b[at..at + 8].copy_from_slice(&P.to_le_bytes());
        cases.push(("field-equals-p", b));
    }
    for (name, at, value) in [
        ("fee-over-max", 336, MAX + 1),
        ("count-zero", 408, 0),
        ("count-over-tree", 408, (1u64 << 40) + 1),
        ("credit", 416, 1),
        ("debit", 424, 1),
    ] {
        let mut b = base.to_vec();
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
        cases.push((name, b));
    }
    let mut b = base.to_vec();
    let nf = b[80..144].to_vec();
    b[144..208].copy_from_slice(&nf);
    cases.push(("duplicate-nullifier", b));
    cases
        .into_iter()
        .map(|(name, b)| {
            assert!(Statement::parse(&b).is_err(), "parser control {name}");
            json!({"name":name,"class":"parser","rejected":true})
        })
        .collect()
}
fn negatives(air: &PaymentAir, s: &Statement, w: &Witness) -> Vec<Value> {
    let mut c = Vec::new();
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[0].key[0] += 1;
    refresh(&mut ss, &ww);
    c.push(fresh(air, &ss, &ww, "wrong-authority-recomputed-NF", false));
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[0].note[10] += 1;
    refresh(&mut ss, &ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "unauthorized-note-recomputed-CM-NF",
        false,
    ));
    let mut ss = s.clone();
    ss.nullifiers[0][0] = (ss.nullifiers[0][0] + 1) % P;
    c.push(fresh(air, &ss, w, "wrong-public-NF-fresh-trace", false));
    let mut ww = w.clone();
    ww.inputs[0].origin[0] += 1;
    let mut ss = s.clone();
    refresh(&mut ss, &ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "wrong-origin-recomputed-leaf-NF",
        false,
    ));
    let mut ww = w.clone();
    ww.inputs[0].siblings[17][0] = (ww.inputs[0].siblings[17][0] + 1) % P;
    c.push(fresh(air, s, &ww, "wrong-depth17-sibling-rehashed", false));
    let mut ww = w.clone();
    ww.inputs[0].index ^= 1;
    c.push(fresh(air, s, &ww, "wrong-index-rehashed-path", false));
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[1].index = 2;
    reanchor(&mut ss, &mut ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "index-equals-count-coherent-anchor",
        false,
    ));
    let mut ss = s.clone();
    ss.count = 1;
    c.push(fresh(air, &ss, w, "count-prefix-excludes-input1", false));
    let mut ww = w.clone();
    ww.inputs[0].index = 1u64 << 40;
    c.push(fresh(air, s, &ww, "index-over-40bits", false));
    let mut ss = s.clone();
    ss.root[0] = (ss.root[0] + 1) % P;
    c.push(fresh(air, &ss, w, "wrong-public-root", false));
    let mut ww = w.clone();
    ww.outputs[0][2] = (ww.outputs[0][2] + 1) % P;
    c.push(fresh(
        air,
        s,
        &ww,
        "wrong-output-owner-old-CM-fresh-trace",
        false,
    ));
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.outputs[0][1] += 1;
    refresh(&mut ss, &ww);
    c.push(fresh(air, &ss, &ww, "balance-recomputed-output-CM", false));
    let mut ss = s.clone();
    ss.commitments[0][0] = (ss.commitments[0][0] + 1) % P;
    c.push(fresh(air, &ss, w, "wrong-public-output-CM", false));
    let mut ss = s.clone();
    ss.fee += 1;
    c.push(fresh(air, &ss, w, "fee-conservation", false));
    for (name, k) in [("credit-direct-AIR", 0), ("debit-direct-AIR", 1)] {
        let mut ss = s.clone();
        if k == 0 {
            ss.credit = 1
        } else {
            ss.debit = 1
        }
        c.push(fresh(air, &ss, w, name, false));
    }
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[0].note[0] = 1;
    refresh(&mut ss, &ww);
    reanchor(&mut ss, &mut ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "nonzero-input-asset-coherent-hashes",
        false,
    ));
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.outputs[0][0] = 1;
    refresh(&mut ss, &ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "nonzero-output-asset-coherent-CM",
        false,
    ));
    // Field-balanced modular attack: -1+3=0+0+2 in F. Every hash/path is rebuilt.
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[0].note[1] = P - 1;
    ww.inputs[1].note[1] = 3;
    ww.outputs[0][1] = 0;
    ww.outputs[1][1] = 0;
    ss.fee = 2;
    refresh(&mut ss, &ww);
    reanchor(&mut ss, &mut ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "negative-amount-modular-balance-coherent-anchor",
        false,
    ));
    // All ranges except output0 are valid, conservation is exact, hashes rebuilt.
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[0].note[1] = MAX;
    ww.inputs[1].note[1] = 1;
    ww.outputs[0][1] = MAX + 1;
    ww.outputs[1][1] = 0;
    ss.fee = 0;
    refresh(&mut ss, &ww);
    reanchor(&mut ss, &mut ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "MAX-plus1-output-exact-balance",
        false,
    ));
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.inputs[0].note[1] = MAX;
    ww.inputs[1].note[1] = 1;
    ww.outputs[0][1] = 0;
    ww.outputs[1][1] = 0;
    ss.fee = MAX + 1;
    refresh(&mut ss, &ww);
    reanchor(&mut ss, &mut ww);
    c.push(fresh(
        air,
        &ss,
        &ww,
        "MAX-plus1-fee-direct-AIR-exact-balance",
        false,
    ));
    // A fully recomputed recipient replacement is a DIFFERENT valid payment.
    let mut ww = w.clone();
    let mut ss = s.clone();
    ww.outputs[0][2] = (ww.outputs[0][2] + 1) % P;
    refresh(&mut ss, &ww);
    ss.validate().unwrap();
    c.push(fresh(
        air,
        &ss,
        &ww,
        "changed-owner-and-CM-valid-new-statement",
        true,
    ));
    let mut ss = s.clone();
    ss.count = 1u64 << 40;
    c.push(fresh(
        air,
        &ss,
        w,
        "count-upper-bound-AIR-only-not-funding-history",
        true,
    ));
    // Context-only changes intentionally preserve exactly the AIR vector.
    let mut ss = s.clone();
    ss.nonce[0] ^= 1;
    ss.receipts[0][0] ^= 1;
    ss.validate().unwrap();
    assert_eq!(ss.projection(), s.projection());
    assert_ne!(ss.core(), s.core());
    c.push(fresh(
        air,
        &ss,
        w,
        "nonce-receipt-context-only-AIR-accept",
        true,
    ));
    // Separate local trace-fault controls supplement the rebuilt-witness cases.
    for (name, row, col) in [
        ("context-copy-cell", 100, note(0, 1)),
        ("sibling-shared-across-blocks", 16, SIBLING),
        ("selected-output-CM-cell", 348, WORK_CM),
        (
            "padding-final-permutation-cell",
            air.program().height() - 1,
            319,
        ),
    ] {
        let mut t = witness::generate(air, s, w).unwrap();
        t.matrix.values[row * WIDTH + col] += F::ONE;
        c.push(check(air, s, &t.matrix, name, false));
    }
    // Nonbinary scratch with reconstructed amount unchanged: 2*b0+... = old.
    let mut t = witness::generate(air, s, w).unwrap();
    t.matrix.values[RANGE_A] += F::from_u64(2);
    t.matrix.values[RANGE_A + 1] -= F::ONE;
    c.push(check(
        air,
        s,
        &t.matrix,
        "nonboolean-range-same-reconstruction",
        false,
    ));
    // Valid P3 permutation on a nonzero padding input must still fail the program.
    let mut t = witness::generate(air, s, w).unwrap();
    let mut x = [F::ZERO; 16];
    x[0] = F::ONE;
    let prefix = p3_poseidon2_air::generate_trace_rows::<
        F,
        p3_goldilocks::GenericPoseidon2LinearLayersGoldilocks,
        16,
        7,
        1,
        4,
        24,
    >(vec![x], &permutation::constants(), 0);
    let row = air.program().height() - 1;
    t.matrix.values[row * WIDTH..row * WIDTH + permutation::PERM_COLS]
        .copy_from_slice(&prefix.values);
    c.push(check(
        air,
        s,
        &t.matrix,
        "padding-valid-permutation-nonzero-input",
        false,
    ));
    // A different constant set is a different program, not an accepted producer
    // parameter. Its freshly generated P3 auxiliary row fails the approved AIR.
    let mut t = witness::generate(air, s, w).unwrap();
    let constants = permutation::constants();
    let mut first = *constants.beginning_full_round_constants();
    first[0][0] += F::ONE;
    let altered = p3_poseidon2_air::RoundConstants::new(
        first,
        *constants.partial_round_constants(),
        *constants.ending_full_round_constants(),
    );
    let prefix = p3_poseidon2_air::generate_trace_rows::<
        F,
        p3_goldilocks::GenericPoseidon2LinearLayersGoldilocks,
        16,
        7,
        1,
        4,
        24,
    >(vec![[F::ZERO; 16]], &altered, 0);
    t.matrix.values[row * WIDTH..row * WIDTH + permutation::PERM_COLS]
        .copy_from_slice(&prefix.values);
    c.push(check(
        air,
        s,
        &t.matrix,
        "altered-constant-valid-auxiliary-prefix",
        false,
    ));
    let layout = air.program().approved_layout_bytes();
    let mut changed = layout.clone();
    changed[PP_ROLE * 8] ^= 1;
    assert_ne!(sha(&layout), sha(&changed));
    c.push(json!({"name":"altered-preprocessing-identity","class":"program-identity-only","different_digest":true,"cryptographic_verifier":false}));
    let mut ww = w.clone();
    ww.outputs[0][10] = P;
    assert!(witness::generate(air, s, &ww).is_err());
    c.push(
        json!({"name":"witness-field-equals-p","class":"witness-canonical-parser","rejected":true}),
    );
    c
}
fn run() -> Result<Value, String> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 || a[1] != "controls" {
        return Err("usage: compact-payment-v1 controls PUBLIC-fixtures.json".into());
    }
    let bytes = bounded(Path::new(&a[2]))?;
    let bundle: Bundle = serde_json::from_slice(&bytes).map_err(|_| "fixture JSON")?;
    if bundle.format != "CP-P2-PUBLIC-FIXTURES-01" || bundle.fixtures.len() != 5 {
        return Err("fixture grammar".into());
    }
    assert_eq!(
        hash::chunks(&[255; 32]),
        [
            (1u64 << 56) - 1,
            (1u64 << 56) - 1,
            (1u64 << 56) - 1,
            (1u64 << 56) - 1,
            (1u64 << 32) - 1
        ]
    );
    for p in &bundle.permutation_vectors {
        if p.input.iter().chain(p.output.iter()).any(|&x| x >= P) {
            return Err("permutation noncanonical".into());
        }
        assert_eq!(
            permutation::permute(p.input.map(F::from_u64)).map(|x| x.as_canonical_u64()),
            p.output
        );
    }
    let air = PaymentAir::new(512)?;
    let symbolic = AirConstraints::<F>::evaluate(&air, AirLayout::from_air(&air));
    symbolic
        .check_next_row_reads()
        .expect("declared next-row closure");
    let degree = symbolic.max_constraint_degree(512);
    for height in [512, 1024] {
        let p = PaymentAir::new(height)?;
        assert_eq!(
            sha(&p.program().approved_layout_bytes()),
            bundle.program_sha256[&height.to_string()],
            "independent public schedule identity"
        );
    }
    let mut controls = Vec::new();
    let mut positives = Vec::new();
    let mut first = None;
    for fixture in bundle.fixtures {
        let b = unhex(&fixture.statement_hex)?;
        let s = Statement::parse(&b)?;
        assert_eq!(s.bytes(), b);
        assert_eq!(sha(&b), fixture.expected.statement_sha256);
        assert_eq!(
            s.projection().map(|x| x.as_canonical_u64()).as_slice(),
            fixture.expected.projection
        );
        let t = witness::generate(&air, &s, &fixture.witness)?;
        assert_eq!(
            t.hash_outputs, fixture.expected.hash_outputs,
            "independent90 full-relation hashes"
        );
        assert_eq!(s.core(), fixture.expected.core);
        assert_eq!(s.output_origins(), fixture.expected.output_origins);
        positives.push(check(&air, &s, &t.matrix, &fixture.name, true));
        if first.is_none() {
            first = Some((s, fixture.witness, b));
        }
    }
    let (s, w, b) = first.unwrap();
    controls.extend(parser_controls(&b));
    controls.extend(negatives(&air, &s, &w));
    assert_eq!(bundle.host_negative_expectations.len(), 15);
    for expected in &bundle.host_negative_expectations {
        assert!(!expected.failures.is_empty());
        let actual = controls
            .iter()
            .find(|c| c["name"] == expected.name)
            .expect("independent negative name");
        assert_eq!(
            actual["input_sha256"], expected.input_sha256,
            "independent malicious witness identity"
        );
        assert_eq!(actual["actual_accept"], false);
    }
    Ok(
        json!({"status":"PUBLIC_FRONTEND_CONTROLS_PASS","proof":false,"security_claim":false,"fixture_sha256":sha(&bytes),"main_columns":WIDTH,"fixed_columns":PP_WIDTH,"public_fields":49,"height":512,"real_permutations":356,"hash_outputs":90,"symbolic_max_degree":degree,"main_next_columns":air.main_next_row_columns().len(),"fixed_next_columns":air.preprocessed_next_row_columns().len(),"independent_rebuilt_negative_identities":bundle.host_negative_expectations.len(),"positive_fixtures":positives,"controls":controls}),
    )
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string(&v).unwrap()),
        Err(e) => {
            eprintln!("PUBLIC_FRONTEND_ERROR: {e}");
            std::process::exit(1)
        }
    }
}
