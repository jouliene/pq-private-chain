//! Same actual bounded uni-STARK path for PUBLIC diagnostics and a PRIVATE worker.
use crate::{
    Error, config,
    frame::{self, Frame},
    metrics,
    registry::{self, Prepared, Registry},
};
use compact_arity_v3::{
    statement::{Arity, MAX, Statement},
    witness::{self, Witness},
};
use compact_proof_v1::{
    hash,
    types::{Challenge, Challenger, Proof},
};
use p3_air::check_all_constraints;
use p3_challenger::HashChallenger;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove_with_preprocessed, verify_with_preprocessed};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Instant,
};
pub const FEES: [u64; 3] = [2_116_775, 2_112_174, 2_112_248];
pub fn bounded(path: &Path, max: usize) -> Result<Vec<u8>, Error> {
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Io)?;
    if !meta.file_type().is_file() || meta.len() > max as u64 {
        return Err(Error::Input);
    }
    let f = File::open(path).map_err(|_| Error::Io)?;
    let meta = f.metadata().map_err(|_| Error::Io)?;
    if !meta.file_type().is_file() || meta.len() > max as u64 {
        return Err(Error::Input);
    }
    let mut bytes = Vec::new();
    f.take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() > max {
        return Err(Error::Input);
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error::Io)?
        .write_all(bytes)
        .map_err(|_| Error::Io)
}
fn unhex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Input);
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).map_err(|_| Error::Input)?, 16)
                .map_err(|_| Error::Input)
        })
        .collect()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBundle {
    format: String,
    qualification: String,
    fixtures: Vec<PublicFixture>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFixture {
    arity: usize,
    name: String,
    statement_hex: String,
    witness: Witness,
}
fn fixture(path: &Path, arity: Arity) -> Result<(Statement, Vec<u8>, Witness), Error> {
    let bytes = bounded(path, 2_000_000)?;
    let pin: Value = serde_json::from_slice(include_bytes!("../data/fixture-pins.json"))
        .map_err(|_| Error::Manifest)?;
    if pin["format"] != "CP-ALL-PUBLIC-LINKED-03" || pin["sha256"] != registry::sha256(&bytes) {
        return Err(Error::Identity);
    }
    let mut bundle: PublicBundle = serde_json::from_slice(&bytes).map_err(|_| Error::Input)?;
    if bundle.format != "CP-ALL-PUBLIC-LINKED-03"
        || bundle.fixtures.len() != 3
        || bundle.qualification
            != "PUBLIC synthetic prefix history; source authorization, receipt encryption and canonical admission unverified"
    {
        return Err(Error::Input);
    }
    for (n, f) in bundle.fixtures.iter().enumerate() {
        if f.arity != n || f.name != format!("linked-{n}x2") {
            return Err(Error::Input);
        }
    }
    let f = bundle.fixtures.remove(arity.n());
    let statement = unhex(&f.statement_hex)?;
    let s = Statement::parse(&statement).map_err(|_| Error::Statement)?;
    if s.arity != arity || s.fee != FEES[arity.n()] || s.credit > MAX {
        return Err(Error::Statement);
    }
    f.witness.canonical(arity).map_err(|_| Error::Input)?;
    Ok((s, statement, f.witness))
}
fn observations(proof: &Proof) -> Value {
    // Count-only descendant of historical engine::proof_observations; no values.
    let (helpers, fri) = &proof.opening_proof;
    let ordinary = proof.opened_values.trace_local.len()
        + proof.opened_values.trace_next.as_ref().map_or(0, Vec::len)
        + proof
            .opened_values
            .preprocessed
            .as_ref()
            .map_or(0, |p| p.local.len() + p.next.as_ref().map_or(0, Vec::len))
        + proof
            .opened_values
            .quotient_chunks
            .iter()
            .map(Vec::len)
            .sum::<usize>()
        + proof.opened_values.random.as_ref().map_or(0, Vec::len);
    let helper = helpers
        .iter()
        .flat_map(|m| m.iter())
        .flat_map(|p| p.iter())
        .map(Vec::len)
        .sum::<usize>();
    let inputs=fri.input_openings.iter().enumerate().map(|(batch,x)|json!({"batch":batch,"queries":x.opened_values.len(),"matrix_widths":x.opened_values.first().map(|m|m.iter().map(Vec::len).collect::<Vec<_>>()),"base_fields":x.opened_values.iter().flat_map(|m|m.iter()).map(Vec::len).sum::<usize>(),"salt_base_fields":x.opening_proof.0.iter().flat_map(|m|m.iter()).map(Vec::len).sum::<usize>(),"path_digests":x.opening_proof.1.sibling_hashes.len()})).collect::<Vec<_>>();
    let folds=fri.commit_phase_openings.iter().enumerate().map(|(round,x)|json!({"round":round,"queries":x.sibling_values.len(),"extension_fields":x.sibling_values.iter().map(Vec::len).sum::<usize>(),"salt_base_fields":x.opening_proof.0.iter().flat_map(|m|m.iter()).map(Vec::len).sum::<usize>(),"path_digests":x.opening_proof.1.sibling_hashes.len()})).collect::<Vec<_>>();
    json!({"ordinary_ood_extension_fields":ordinary,"helper_ood_extension_fields":helper,"requested_queries":160,"folds":folds,"input_batches":inputs,"terminal_extension_fields":fri.final_poly.len(),"main_mask_budget":512,"required_main_mask_budget":340,"distinct_query_positions":"not instrumented; requested count used without dedup credit","base_bytes":8,"extension_bytes":40,"digest_bytes":64})
}
fn verify_parsed(p: &Prepared, frame: &Frame, proof: &Proof) -> Result<(), Error> {
    if proof.degree_bits != 10 || proof.opened_values.quotient_chunks.len() != 8 {
        return Err(Error::Shape);
    }
    let config = config::context_control(frame.challenger(), &p.ids.profile, &p.ids.program);
    verify_with_preprocessed(
        &config,
        &p.air,
        proof,
        frame.public_values(),
        Some(&p.verifier_key),
    )
    .map_err(|_| Error::Crypto)
}
/// One complete call: cap -> canonical parser -> approved enum -> fresh frame ->
/// canonical codec -> real verification -> proof destruction. No verdict cache.
pub fn verify_bytes(
    registry: &Registry,
    statement: &[u8],
    envelope: &[u8],
) -> Result<Value, Error> {
    if envelope.len() > frame::MAX_ENVELOPE {
        return Err(Error::ProofTooLarge);
    }
    if statement.len() > frame::MAX_STATEMENT {
        return Err(Error::Statement);
    }
    let total = Instant::now();
    let parsed = Statement::parse(statement).map_err(|_| Error::Statement)?;
    let p = registry.program(parsed.arity);
    verify_for(p, statement, envelope, total)
}
fn verify_for(
    p: &Prepared,
    statement: &[u8],
    envelope: &[u8],
    total: Instant,
) -> Result<Value, Error> {
    if envelope.len() > frame::MAX_ENVELOPE {
        return Err(Error::ProofTooLarge);
    }
    let frame = Frame::new(&p.ids, p.arity, statement)?;
    let proof = frame.decode(&p.shape, envelope)?;
    let decode = total.elapsed().as_secs_f64();
    let begin = Instant::now();
    verify_parsed(p, &frame, &proof)?;
    let crypto = begin.elapsed().as_secs_f64();
    let observed = observations(&proof);
    drop(proof);
    drop(frame);
    Ok(
        json!({"accepted":true,"arity":p.arity.n(),"parse_bind_decode_seconds":decode,"crypto_seconds":crypto,"complete_call_seconds":total.elapsed().as_secs_f64(),"observations":observed}),
    )
}
pub fn inspect() -> Result<Value, Error> {
    let begin = Instant::now();
    let registry = Registry::prepare_public()?;
    Ok(
        json!({"mode":"inspect","registry":registry.describe(),"preparation_seconds":begin.elapsed().as_secs_f64(),"process_self":metrics::process_self()?}),
    )
}
fn map_proving_error(error: p3_uni_stark::ProvingError<p3_fri::HidingFriProverError>) -> Error {
    use p3_challenger::bounded_ef5::BoundedChallengeError as B;
    use p3_fri::{FriProverError as F, HidingFriProverError as H};
    use p3_uni_stark::{ProvingError as P, StarkTranscriptFailure as T};
    match error {
        P::Transcript(T::BoundedChallenge(B::BothCandidatesInBaseField)) => Error::BoundedOodAbort,
        P::Pcs {
            source: H::Fri(F::BoundedChallenge(B::BothCandidatesInBaseField)),
            ..
        } => Error::BoundedPcsAbort,
        P::Transcript(T::BoundedChallenge(B::UnsupportedAlgebra))
        | P::Pcs {
            source: H::Fri(F::BoundedChallenge(B::UnsupportedAlgebra)),
            ..
        } => Error::ChallengeAlgebra,
        _ => Error::Prove,
    }
}
/// Retained pinned PUBLIC diagnostic loader, not the private-wallet input path.
pub fn prove_public(arity: Arity, path: &Path, out: &Path) -> Result<Value, Error> {
    let total = Instant::now();
    let (s, statement, witness) = fixture(path, arity)?;
    prove_owned(
        s,
        statement,
        crate::private_packet::OwnedWitness::new(witness),
        out,
        false,
        total,
    )
}
/// Dedicated private worker boundary. The process-global hook is intentionally
/// installed before any secret read and is NOT silently restored. This is not a
/// general thread-safe embedding API. Ordinary typed Results retain their class.
pub fn prove_private<R: Read>(reader: R, out: &Path) -> Result<Value, Error> {
    install_private_panic_hook();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let total = Instant::now();
        let input = crate::private_packet::read(reader)?;
        prove_owned(
            input.statement,
            input.statement_bytes,
            input.witness,
            out,
            true,
            total,
        )
    }))
    .unwrap_or(Err(Error::Prove))
}
pub fn install_private_panic_hook() {
    std::panic::set_hook(Box::new(|_| eprintln!("PRIVATE_PROVER_PANIC")));
}
/// One shared genuine proving function; no fixture pin or caller-selected program.
fn prove_owned(
    s: Statement,
    statement: Vec<u8>,
    mut witness: crate::private_packet::OwnedWitness,
    out: &Path,
    private_input: bool,
    total: Instant,
) -> Result<Value, Error> {
    let begin = Instant::now();
    let registry = Registry::prepare_public()?;
    let preparation = begin.elapsed().as_secs_f64();
    let arity = s.arity;
    let p = registry.program(arity);
    let frame = Frame::new(&p.ids, arity, &statement)?;
    let begin = Instant::now();
    witness.get().canonical(arity).map_err(|_| Error::Input)?;
    let mut trace = witness::generate(&p.air, &s, witness.get()).map_err(|_| Error::Input)?;
    witness.clear();
    drop(witness);
    // These auxiliary generator digests are not needed for proving or public output.
    for digest in &mut trace.hash_outputs {
        digest.fill(0);
    }
    trace.hash_outputs.clear();
    let report = check_all_constraints(&p.air, &trace.matrix, frame.public_values(), Some(1));
    if !report.is_ok() || report.total_constraints_per_row != registry::ASSERTIONS[arity.n()] {
        return Err(Error::Input);
    }
    drop(report);
    let trace_seconds = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    let config = config::fresh_config(|| frame.challenger())?;
    let proof = prove_with_preprocessed(
        &config,
        &p.air,
        trace.matrix,
        frame.public_values(),
        Some(&p.prover_data),
    )
    .map_err(map_proving_error)?;
    let proving = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    let envelope = frame.encode(&p.shape, &proof)?;
    let decoded = frame.decode(&p.shape, &envelope)?;
    if frame.encode(&p.shape, &decoded)? != envelope {
        return Err(Error::Encode);
    }
    let encoding = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    verify_parsed(p, &frame, &decoded)?;
    let local = begin.elapsed().as_secs_f64();
    let observed = observations(&decoded);
    drop(decoded);
    drop(proof);
    // No publication before typed proving, cap, canonical round-trip and local verify.
    if out.exists() {
        return Err(Error::Io);
    }
    fs::create_dir(out).map_err(|_| Error::Io)?;
    write_new(&out.join("statement.bin"), &statement)?;
    write_new(&out.join("proof.bin"), &envelope)?;
    let result = json!({"mode":if private_input{"prove-private"}else{"prove-public"},"private_input_boundary":private_input,"private_input_debug_digest_created":false,"private_packet_persisted":false,"arity":arity.n(),"genuine_proof_created":true,"private_fixture":false,"source_authorization_verified":false,"encrypted_receiving_verified":false,"canonical_admission":false,"prepared":p.describe(),"preparation_seconds":preparation,"trace_check_seconds":trace_seconds,"proving_including_entropy_seconds":proving,"encoding_roundtrip_seconds":encoding,"local_verification_seconds":local,"statement_bytes":statement.len(),"envelope_bytes":envelope.len(),"payload_bytes":envelope.len()-frame::HEADER,"statement_sha256":registry::sha256(&statement),"proof_sha256":registry::sha256(&envelope),"observations":observed,"operation_wall_until_sample_seconds":total.elapsed().as_secs_f64(),"process_self":metrics::process_self()?,"whole_protocol_security_claim":false});
    let mut bytes = serde_json::to_vec_pretty(&result).map_err(|_| Error::Io)?;
    bytes.push(b'\n');
    write_new(&out.join("manifest.json"), &bytes)?;
    Ok(result)
}
fn record_error(
    cases: &mut Vec<Value>,
    name: &str,
    class: &str,
    result: Result<Value, Error>,
    expected: Option<Error>,
) -> Result<(), Error> {
    let error = match result {
        Ok(_) => return Err(Error::Crypto),
        Err(e) => e,
    };
    if expected.is_some_and(|e| e != error) {
        return Err(Error::Crypto);
    }
    cases.push(json!({"name":name,"class":class,"rejected":true,"error":format!("{error:?}"),"decoded_before_crypto":error==Error::Crypto}));
    Ok(())
}
fn rewrap(envelope: &[u8], frame: &Frame) -> Result<Vec<u8>, Error> {
    if envelope.len() < 206 {
        return Err(Error::Decode);
    }
    let mut bytes = envelope.to_vec();
    bytes[138..202].copy_from_slice(frame.digest());
    Ok(bytes)
}
pub fn campaign(
    registry: &Registry,
    statement: &[u8],
    envelope: &[u8],
) -> Result<Vec<Value>, Error> {
    let original = Statement::parse(statement).map_err(|_| Error::Statement)?;
    let p = registry.program(original.arity);
    let frame = Frame::new(&p.ids, p.arity, statement)?;
    let mut cases = Vec::new();
    let mut candidates = Vec::new();
    candidates.push(("truncated", envelope[..envelope.len() - 1].to_vec()));
    let mut b = envelope.to_vec();
    b.push(0);
    candidates.push(("trailing-header-length", b));
    for (name, at) in [
        ("magic", 0),
        ("version", 8),
        ("profile-header", 10),
        ("program-header", 74),
        ("frame-header", 138),
    ] {
        let mut b = envelope.to_vec();
        b[at] ^= 1;
        candidates.push((name, b));
    }
    let mut b = envelope.to_vec();
    b[202..206].copy_from_slice(&u32::MAX.to_le_bytes());
    candidates.push(("payload-count-cap", b));
    let mut b = envelope.to_vec();
    b.push(0);
    let len = (b.len() - 206) as u32;
    b[202..206].copy_from_slice(&len.to_le_bytes());
    candidates.push(("trailing-coherent-length-codec", b));
    let mut b = envelope.to_vec();
    b[206..210].copy_from_slice(&9u32.to_le_bytes());
    candidates.push(("wrong-degree-bits", b));
    let mut b = envelope.to_vec();
    b[402..410].copy_from_slice(&compact_proof_v1::codec::MODULUS.to_le_bytes());
    candidates.push(("noncanonical-OOD", b));
    for (name, b) in candidates {
        let expected = if matches!(name, "profile-header" | "program-header" | "frame-header") {
            Error::Identity
        } else {
            Error::Decode
        };
        record_error(
            &mut cases,
            name,
            "parser-header-codec",
            verify_bytes(registry, statement, &b),
            Some(expected),
        )?;
    }
    let mut b = envelope.to_vec();
    b[210] ^= 1;
    record_error(
        &mut cases,
        "corrupt-root",
        "real-crypto",
        verify_bytes(registry, statement, &b),
        Some(Error::Crypto),
    )?;
    let mut proof = frame.decode(&p.shape, envelope)?;
    proof.opened_values.trace_local[0] += Challenge::ONE;
    let b = frame.encode(&p.shape, &proof)?;
    record_error(
        &mut cases,
        "corrupt-canonical-OOD",
        "real-crypto",
        verify_bytes(registry, statement, &b),
        Some(Error::Crypto),
    )?;
    drop(proof);
    let mut names = vec![
        "chain",
        "nonce",
        "fee",
        "commitment",
        "root",
        "count",
        "receipt",
    ];
    if p.arity.n() == 0 {
        names.extend(["credit", "source"])
    } else {
        names.push("nullifier")
    }
    for name in names {
        let mut s = original.clone();
        match name {
            "chain" => s.chain[0] ^= 1,
            "nonce" => s.nonce[31] ^= 1,
            "fee" => s.fee += 1,
            "commitment" => {
                s.commitments[0][0] = (s.commitments[0][0] + 1) % compact_proof_v1::codec::MODULUS
            }
            "root" => s.root[0] = (s.root[0] + 1) % compact_proof_v1::codec::MODULUS,
            "count" => s.count += 1,
            "receipt" => s.receipts[1][47] ^= 1,
            "credit" => s.credit += 1,
            "source" => s.source_id.as_mut().ok_or(Error::Shape)?[0] ^= 1,
            "nullifier" => {
                s.nullifiers[0][0] = (s.nullifiers[0][0] + 1) % compact_proof_v1::codec::MODULUS
            }
            _ => return Err(Error::Shape),
        }
        let changed = s.bytes().map_err(|_| Error::Statement)?;
        Statement::parse(&changed).map_err(|_| Error::Statement)?;
        let newframe = Frame::new(&p.ids, p.arity, &changed)?;
        let wrapped = rewrap(envelope, &newframe)?;
        if wrapped[206..] != envelope[206..] {
            return Err(Error::Shape);
        }
        record_error(
            &mut cases,
            name,
            "coherent-statement-real-crypto",
            verify_bytes(registry, &changed, &wrapped),
            Some(Error::Crypto),
        )?;
    }
    // Deliberately invalid credit/debit remain parser failures, never AIR claims.
    let mut invalid = original.clone();
    invalid.debit = 1;
    record_error(
        &mut cases,
        "nonzero-debit",
        "canonical-statement-parser",
        verify_bytes(
            registry,
            &invalid.bytes().map_err(|_| Error::Statement)?,
            envelope,
        ),
        Some(Error::Statement),
    )?;
    if p.arity.n() > 0 {
        let mut s = original.clone();
        s.credit = 1;
        record_error(
            &mut cases,
            "transfer-credit",
            "canonical-statement-parser",
            verify_bytes(
                registry,
                &s.bytes().map_err(|_| Error::Statement)?,
                envelope,
            ),
            Some(Error::Statement),
        )?;
    }
    let mut unsupported = statement.to_vec();
    unsupported[10] = 3;
    record_error(
        &mut cases,
        "unsupported-arity",
        "canonical-statement-parser",
        verify_bytes(registry, &unsupported, envelope),
        Some(Error::Statement),
    )?;
    for n in 0..3 {
        if n != p.arity.n() {
            let wrong = registry.program(Arity::from_n(n).map_err(|_| Error::Shape)?);
            record_error(
                &mut cases,
                &format!("wrong-prepared-{n}"),
                "prepared-program-arity",
                verify_for(wrong, statement, envelope, Instant::now()),
                Some(Error::Identity),
            )?;
        }
    }
    // Private fixed mutation controls only: authentic proof decoded first; changed
    // trusted identity is NOT accepted by any production or CLI identity API.
    for name in [
        "profile",
        "program",
        "preprocessing",
        "preprocessing-commitment",
    ] {
        let mut ids = p.ids.clone();
        match name {
            "profile" => ids.profile[0] ^= 1,
            "program" => ids.program[0] ^= 1,
            "preprocessing" => ids.preprocessing[0] ^= 1,
            _ => ids.preprocessing_commitment[0] ^= 1,
        }
        let changed = Frame::new(&ids, p.arity, statement)?;
        let mut wrapped = rewrap(envelope, &changed)?;
        wrapped[10..74].copy_from_slice(&ids.profile);
        wrapped[74..138].copy_from_slice(&ids.program);
        let decoded = changed.decode(&p.shape, &wrapped)?;
        if verify_parsed(p, &changed, &decoded) != Err(Error::Crypto) {
            return Err(Error::Crypto);
        }
        cases.push(json!({"name":name,"class":"fixed-identity-real-crypto","rejected":true,"decoded_before_crypto":true}));
    }
    let decoded = frame.decode(&p.shape, envelope)?;
    let mut bytes = frame.bytes().to_vec();
    let at = 2 + frame::TAG.len() + 2 + 128;
    if bytes[at..at + 64] != hash::sha3_512(frame::CONTEXT) {
        return Err(Error::Identity);
    }
    bytes[at] ^= 1;
    let changed = Challenger::new(HashChallenger::new(bytes, hash::TranscriptHash));
    let c = config::context_control(changed, &p.ids.profile, &p.ids.program);
    if verify_with_preprocessed(
        &c,
        &p.air,
        &decoded,
        frame.public_values(),
        Some(&p.verifier_key),
    )
    .is_ok()
    {
        return Err(Error::Crypto);
    }
    cases.push(json!({"name":"raw-trusted-context","class":"fixed-context-real-crypto","rejected":true,"decoded_before_crypto":true}));
    drop(decoded);
    let mut exact = envelope.to_vec();
    exact.resize(frame::MAX_ENVELOPE, 0);
    let len = (exact.len() - 206) as u32;
    exact[202..206].copy_from_slice(&len.to_le_bytes());
    record_error(
        &mut cases,
        "exact-cap-reaches-codec",
        "API-cap-boundary",
        verify_bytes(registry, statement, &exact),
        Some(Error::Decode),
    )?;
    exact.push(0);
    record_error(
        &mut cases,
        "over-cap-before-decode",
        "API-cap-boundary",
        verify_bytes(registry, statement, &exact),
        Some(Error::ProofTooLarge),
    )?;
    if cases.len() != 33 {
        return Err(Error::Shape);
    }
    Ok(cases)
}
pub fn verify_public(dir: &Path, controls: bool) -> Result<Value, Error> {
    let total = Instant::now();
    let statement = bounded(&dir.join("statement.bin"), frame::MAX_STATEMENT)?;
    let envelope = bounded(&dir.join("proof.bin"), frame::MAX_ENVELOPE)?;
    let begin = Instant::now();
    let registry = Registry::prepare_public()?;
    let prep = begin.elapsed().as_secs_f64();
    let valid = verify_bytes(&registry, &statement, &envelope)?;
    let negatives = if controls {
        campaign(&registry, &statement, &envelope)?
    } else {
        Vec::new()
    };
    let final_valid = if controls {
        Some(verify_bytes(&registry, &statement, &envelope)?)
    } else {
        None
    };
    Ok(
        json!({"mode":if controls{"public-campaign"}else{"public-valid-only"},"registry":registry.describe(),"preparation_seconds":prep,"valid":valid,"negative_controls":negatives,"final_valid":final_valid,"operation_wall_until_sample_seconds":total.elapsed().as_secs_f64(),"process_self":metrics::process_self()?}),
    )
}

/// Heap-free CPU snapshots keep previous JSON/RSS bookkeeping outside each span.
/// This repeats the reviewed Linux RUSAGE_SELF ABI, not any verification logic.
#[derive(Clone, Copy)]
struct CpuReading {
    user: f64,
    system: f64,
}
impl CpuReading {
    fn read() -> Result<Self, Error> {
        let mut raw = core::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: Linux writes its ABI rusage into a valid writable pointer.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, raw.as_mut_ptr()) } != 0 {
            return Err(Error::Resource);
        }
        let raw = unsafe { raw.assume_init() };
        let seconds = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 * 1e-6;
        let reading = Self {
            user: seconds(raw.ru_utime),
            system: seconds(raw.ru_stime),
        };
        if !reading.user.is_finite()
            || !reading.system.is_finite()
            || reading.user < 0.0
            || reading.system < 0.0
        {
            return Err(Error::Resource);
        }
        Ok(reading)
    }
}
fn measured<T>(call: impl FnOnce() -> Result<T, Error>) -> Result<(T, Value), Error> {
    let before = CpuReading::read()?;
    let begin = Instant::now();
    let value = call()?;
    let wall = begin.elapsed().as_secs_f64();
    let after = CpuReading::read()?;
    let user = after.user - before.user;
    let system = after.system - before.system;
    if user < 0.0 || system < 0.0 {
        return Err(Error::Resource);
    }
    // JSON construction and later current-RSS reads occur AFTER the second sample.
    let usage = json!({"wall_seconds":wall,"cpu_user_seconds":user,"cpu_system_seconds":system,"cpu_total_seconds":user+system,
        "before_user_seconds":before.user,"before_system_seconds":before.system,"after_user_seconds":after.user,"after_system_seconds":after.system,
        "scope":"Linux RUSAGE_SELF all threads; explicit before/after operation, including clock/syscall boundary overhead, excluding metric JSON construction and following RSS/result bookkeeping"});
    Ok((value, usage))
}
fn measured_verify(registry: &Registry, statement: &[u8], envelope: &[u8]) -> Result<Value, Error> {
    let (mut value, operation) = measured(|| verify_bytes(registry, statement, envelope))?;
    value["outer_complete_seconds"] = operation["wall_seconds"].clone();
    value["operation"] = operation;
    value["process_self"] = metrics::process_self()?;
    value["current_rss_kib"] = json!(current_rss()?);
    Ok(value)
}
/// All bundles are public. Initial read/pinning warms statement/proof pages; first
/// call means first cryptographic call, not a cold-cache measurement.
pub fn mixed_prepared(dirs: [&Path; 3]) -> Result<Value, Error> {
    let total = Instant::now();
    let mut inputs = Vec::new();
    for (n, dir) in dirs.iter().enumerate() {
        let statement = bounded(&dir.join("statement.bin"), frame::MAX_STATEMENT)?;
        if Statement::parse(&statement)
            .map_err(|_| Error::Statement)?
            .arity
            .n()
            != n
        {
            return Err(Error::Identity);
        }
        let proof = bounded(&dir.join("proof.bin"), frame::MAX_ENVELOPE)?;
        inputs.push((statement, proof));
    }
    let (registry, preparation_operation) = measured(Registry::prepare_public)?;
    let registry_info = registry.describe();
    let mut positives = Vec::new();
    for n in [0, 1, 2, 2, 0, 1] {
        positives.push(measured_verify(&registry, &inputs[n].0, &inputs[n].1)?);
    }
    let mut negatives = Vec::new();
    let mut negative_group_operations = Vec::new();
    for (s, p) in &inputs {
        let (cases, operation) = measured(|| campaign(&registry, s, p))?;
        negatives.push(cases);
        negative_group_operations.push(operation);
    }
    let final_valid = measured_verify(&registry, &inputs[2].0, &inputs[2].1)?;
    let (_, registry_cleanup_operation) = measured(|| {
        drop(registry);
        Ok(())
    })?;
    let (_, public_input_cleanup_operation) = measured(|| {
        drop(inputs);
        Ok(())
    })?;
    Ok(
        json!({"mode":"mixed-prepared","registry":registry_info,"preparation_seconds":preparation_operation["wall_seconds"],
        "preparation_operation":preparation_operation,"positive_order":[0,1,2,2,0,1],"six_positive_calls":positives,
        "negative_controls_by_arity":negatives,"negative_group_operations":negative_group_operations,
        "seventh_final_arity2":final_valid,"positive_count":7,"negative_count":99,
        "registry_cleanup_operation":registry_cleanup_operation,"public_input_cleanup_operation":public_input_cleanup_operation,
        "cleanup_scope":"Each verify_bytes drops decoded proof/frame inside its call. Registry destruction and public input buffer destruction are separately timed; result JSON/process teardown is excluded.",
        "page_cache":"bundle reads before preparation warm six public files; external cache uncontrolled","current_rss_kib":current_rss()?,
        "process_self":metrics::process_self()?,"operation_wall_until_sample_seconds":total.elapsed().as_secs_f64()}),
    )
}
fn current_rss() -> Result<u64, Error> {
    let text = fs::read_to_string("/proc/self/status").map_err(|_| Error::Resource)?;
    let line = text
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .ok_or(Error::Resource)?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some("VmRSS:") {
        return Err(Error::Resource);
    }
    let value = parts
        .next()
        .ok_or(Error::Resource)?
        .parse::<u64>()
        .map_err(|_| Error::Resource)?;
    if value == 0 || parts.next() != Some("kB") || parts.next().is_some() {
        return Err(Error::Resource);
    }
    Ok(value)
}
