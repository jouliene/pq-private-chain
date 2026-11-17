//! Lossless transform of the exact CP03 binary proof grammar.
use compact_all_payments_v3::{engine, frame, registry::Registry};
use compact_arity_v3::statement::Arity;
use compact_proof_v1::types::Val;
use p3_field::PrimeField64;
use serde_json::{Value, json};
use std::time::Instant;
use tiny_keccak::{Hasher, Shake};

use crate::transcript::{
    FIXED, FOLDS, LDE_LOG, LEGACY_HEAD, LEGACY_TAIL, MATRICES, PublicFixed, QUERIES, WIDTHS,
};
use crate::{Error, Reader, Result};

pub const BODY_MAGIC: &[u8; 8] = b"CPBODC01";
pub const PROOF_MAGIC: &[u8; 8] = b"CPFRC001";
const LEGACY_BODY_MAGIC: &[u8; 8] = b"CPBODY03";
const BODY_HEADER: usize = 20;
const DIGEST: usize = 64;
const BASE: usize = 8;
const SALT: usize = 8 * BASE;
const EF: usize = 5 * BASE;

#[derive(Clone, Copy)]
enum Direction {
    Pack,
    Expand,
}

struct Savings {
    fixed: usize,
    repeated: usize,
}

fn prefix_len(body: &[u8]) -> Result<usize> {
    if body.len() < BODY_HEADER || body.len() > cp03_history::BODY_MAX {
        return Err(Error::Shape);
    }
    match u16::from_le_bytes(body[10..12].try_into().unwrap()) {
        448 => Ok(9423),
        464 => Ok(4812),
        528 => Ok(4876),
        _ => Err(Error::Shape),
    }
}

fn validate_proof_envelope(envelope: &[u8], magic: &[u8; 8]) -> Result<()> {
    if envelope.len() > frame::MAX_ENVELOPE
        || envelope.len() < frame::HEADER + LEGACY_HEAD + LEGACY_TAIL
        || &envelope[..8] != magic
        || envelope[8..10] != 3u16.to_le_bytes()
    {
        return Err(Error::Shape);
    }
    let declared = u32::from_le_bytes(envelope[202..206].try_into().unwrap()) as usize;
    if declared != envelope.len() - frame::HEADER {
        return Err(Error::Shape);
    }
    Ok(())
}

fn take_paths<'a>(reader: &mut Reader<'a>, depth: usize) -> Result<&'a [u8]> {
    let count = reader.peek_u32()? as usize;
    if count > QUERIES * depth {
        return Err(Error::Shape);
    }
    reader.take(4 + count * DIGEST)
}

fn first_occurrences(indices: &[usize], shift: usize) -> Vec<usize> {
    let mut first = vec![usize::MAX; 1 << (LDE_LOG - shift)];
    indices
        .iter()
        .enumerate()
        .map(|(q, &index)| {
            let slot = &mut first[index >> shift];
            if *slot == usize::MAX {
                *slot = q;
            }
            *slot
        })
        .collect()
}

// The first occurrence in original transcript order owns the canonical bytes
// for that coordinate. Neither the index nor the first-occurrence map is sent.
fn transform_rows(
    direction: Direction,
    reader: &mut Reader<'_>,
    out: &mut Vec<u8>,
    indices: &[usize],
    shift: usize,
    row_bytes: usize,
) -> Result<usize> {
    let first = first_occurrences(indices, shift);
    let output_start = out.len();
    let mut omitted = 0;
    let mut rows = Vec::with_capacity(QUERIES);
    for (q, &previous) in first.iter().enumerate() {
        match direction {
            Direction::Pack => {
                let row = reader.take(row_bytes)?;
                if previous == q {
                    out.extend_from_slice(row);
                } else {
                    if row != rows[previous] {
                        return Err(Error::DuplicateMismatch);
                    }
                    omitted += row_bytes;
                }
                rows.push(row);
            }
            Direction::Expand => {
                if previous == q {
                    out.extend_from_slice(reader.take(row_bytes)?);
                } else {
                    let start = output_start + previous * row_bytes;
                    out.extend_from_within(start..start + row_bytes);
                    omitted += row_bytes;
                }
            }
        }
    }
    Ok(omitted)
}

fn write_vals(out: &mut Vec<u8>, values: &[Val]) {
    for value in values {
        out.extend(value.as_canonical_u64().to_le_bytes());
    }
}

fn fixed_opening(fixed: &PublicFixed, indices: &[usize]) -> Vec<u8> {
    let opening = fixed.open(indices);
    let mut bytes = Vec::new();
    for matrices in &opening.opened_values {
        write_vals(&mut bytes, &matrices[0]);
    }
    let (salts, paths) = opening.opening_proof;
    for matrices in &salts {
        write_vals(&mut bytes, &matrices[0]);
    }
    bytes.extend((paths.sibling_hashes.len() as u32).to_le_bytes());
    for digest in paths.sibling_hashes {
        for word in digest {
            bytes.extend(word.to_le_bytes());
        }
    }
    bytes
}

fn transform_sections(
    direction: Direction,
    reader: &mut Reader<'_>,
    out: &mut Vec<u8>,
    fixed: &PublicFixed,
    indices: &[usize],
) -> Result<Savings> {
    let mut savings = Savings {
        fixed: 0,
        repeated: 0,
    };
    for batch in 0..WIDTHS.len() {
        if batch == FIXED {
            let fixed_bytes = fixed_opening(fixed, indices);
            savings.fixed = fixed_bytes.len();
            match direction {
                Direction::Pack => {
                    if reader.take(fixed_bytes.len())? != fixed_bytes {
                        return Err(Error::FixedMismatch);
                    }
                }
                Direction::Expand => out.extend(fixed_bytes),
            }
            continue;
        }
        savings.repeated +=
            transform_rows(direction, reader, out, indices, 0, WIDTHS[batch] * BASE)?;
        savings.repeated +=
            transform_rows(direction, reader, out, indices, 0, MATRICES[batch] * SALT)?;
        out.extend(take_paths(reader, LDE_LOG)?);
    }
    for round in 0..FOLDS {
        // Sibling values key on the parent row AND the queried child parity.
        // Salts key on the parent row alone.
        savings.repeated += transform_rows(direction, reader, out, indices, round, EF)?;
        savings.repeated += transform_rows(direction, reader, out, indices, round + 1, SALT)?;
        out.extend(take_paths(reader, LDE_LOG - round - 1)?);
    }
    reader.finish()?;
    Ok(savings)
}

fn transform(
    body: &[u8],
    direction: Direction,
    fixed: &PublicFixed,
) -> Result<(Vec<u8>, Savings, usize)> {
    let split = prefix_len(body)?;
    let (prefix, envelope) = body.split_at_checked(split).ok_or(Error::Truncated)?;
    let (body_magic, proof_magic, out_body, out_proof) = match direction {
        Direction::Pack => (LEGACY_BODY_MAGIC, frame::MAGIC, BODY_MAGIC, PROOF_MAGIC),
        Direction::Expand => (BODY_MAGIC, PROOF_MAGIC, LEGACY_BODY_MAGIC, frame::MAGIC),
    };
    if &prefix[..8] != body_magic {
        return Err(Error::Shape);
    }
    validate_proof_envelope(envelope, proof_magic)?;
    let mut old_prefix = prefix.to_vec();
    old_prefix[..8].copy_from_slice(LEGACY_BODY_MAGIC);
    let prefix_view =
        cp03_history::body::parse_prefix(&old_prefix).map_err(|_| Error::Statement)?;
    if prefix_view.declared_proof_length() != envelope.len() {
        return Err(Error::Shape);
    }
    let tail_at = envelope.len() - LEGACY_TAIL;
    let head_at = frame::HEADER + LEGACY_HEAD;
    let indices = fixed.query_indices(
        prefix_view.statement(),
        prefix_view.statement_bytes(),
        &envelope[..frame::HEADER],
        &envelope[frame::HEADER..head_at],
        &envelope[tail_at..],
    )?;
    let mut reader = Reader::new(&envelope[head_at..tail_at]);
    let mut out = prefix.to_vec();
    out.extend_from_slice(&envelope[..head_at]);
    let savings = transform_sections(direction, &mut reader, &mut out, fixed, &indices)?;
    out.extend_from_slice(&envelope[tail_at..]);
    let proof_len = out.len() - split;
    if proof_len > frame::MAX_ENVELOPE || out.len() > cp03_history::BODY_MAX {
        return Err(Error::Shape);
    }
    out[..8].copy_from_slice(out_body);
    out[12..16].copy_from_slice(&(proof_len as u32).to_le_bytes());
    out[split..split + 8].copy_from_slice(out_proof);
    out[split + 202..split + 206]
        .copy_from_slice(&((proof_len - frame::HEADER) as u32).to_le_bytes());
    let distinct = first_occurrences(&indices, 0)
        .iter()
        .enumerate()
        .filter(|&(q, previous)| q == *previous)
        .count();
    Ok((out, savings, distinct))
}

fn receipt_digests(
    statement: &compact_arity_v3::statement::Statement,
    envelopes: [&[u8]; 2],
) -> Result<[[u8; 48]; 2]> {
    // Same public receipt/context binding as ledger-cp03 encoding::receipt.
    let core = statement.core().map_err(|_| Error::Statement)?;
    let label = b"PQPC/CP3/RECEIPT";
    let mut digests = [[0; 48]; 2];
    for (ordinal, receipt) in envelopes.into_iter().enumerate() {
        let mut shake = Shake::v256();
        shake.update(&(label.len() as u16).to_le_bytes());
        shake.update(label);
        shake.update(&statement.chain);
        for word in core {
            shake.update(&word.to_le_bytes());
        }
        shake.update(&(ordinal as u16).to_le_bytes());
        shake.update(&(receipt.len() as u32).to_le_bytes());
        shake.update(receipt);
        shake.finalize(&mut digests[ordinal]);
    }
    Ok(digests)
}

fn crypto(registry: &Registry, full: &[u8]) -> Result<Value> {
    let parsed = cp03_history::body::parse_full(full).map_err(|_| Error::Shape)?;
    engine::verify_bytes(registry, parsed.prefix().statement_bytes(), parsed.proof()).map_err(
        |error| match error {
            compact_all_payments_v3::Error::Crypto => Error::Crypto,
            _ => Error::LegacyDecode,
        },
    )
}

pub fn run(body: &[u8], pack: bool) -> Result<(Vec<u8>, Value)> {
    let begin = Instant::now();
    let split = prefix_len(body)?;
    let mut prefix = body.get(..split).ok_or(Error::Truncated)?.to_vec();
    let expected_magic = if pack { LEGACY_BODY_MAGIC } else { BODY_MAGIC };
    if &prefix[..8] != expected_magic {
        return Err(Error::Shape);
    }
    prefix[..8].copy_from_slice(LEGACY_BODY_MAGIC);
    let statement = cp03_history::body::parse_prefix(&prefix).map_err(|_| Error::Statement)?;
    if statement.statement().arity != Arity::Two || statement.statement().fee < engine::FEES[2] {
        return Err(Error::Statement);
    }
    if receipt_digests(statement.statement(), statement.envelopes())?
        != statement.statement().receipts
    {
        return Err(Error::Receipt);
    }
    let prelude_seconds = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    let fixed = PublicFixed::prepare(statement.statement())?;
    let fixed_prep_seconds = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    let registry = Registry::prepare_public().map_err(|_| Error::FixedSetup)?;
    fixed.check_registry_root(registry.program(statement.statement().arity))?;
    let registry_prep_seconds = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    let (candidate, full, savings, distinct) = if pack {
        let (candidate, savings, distinct) = transform(body, Direction::Pack, &fixed)?;
        let (full, _, _) = transform(&candidate, Direction::Expand, &fixed)?;
        if full != body {
            return Err(Error::RoundTrip);
        }
        (Some(candidate), full, savings, distinct)
    } else {
        let (full, savings, distinct) = transform(body, Direction::Expand, &fixed)?;
        (None, full, savings, distinct)
    };
    let transport_seconds = begin.elapsed().as_secs_f64();
    let begin = Instant::now();
    let verified = crypto(&registry, &full)?;
    let full_verify_seconds = begin.elapsed().as_secs_f64();
    let candidate_len = candidate.as_ref().map_or(body.len(), Vec::len);
    let result = json!({
        "accepted": true,
        "arity": statement.statement().arity.n(),
        "candidate_body_bytes": candidate_len,
        "candidate_proof_bytes": candidate_len - split,
        "legacy_body_bytes": full.len(),
        "legacy_proof_bytes": full.len() - split,
        "fixed_batch_omitted_bytes": savings.fixed,
        "repeated_coordinates_omitted_bytes": savings.repeated,
        "distinct_input_coordinates": distinct,
        "distinct_main_trace_row_bytes": distinct * (WIDTHS[1] - 5) * BASE,
        "legacy_body_sha256": compact_all_payments_v3::registry::sha256(&full),
        "prelude_seconds": prelude_seconds,
        "public_fixed_prepare_seconds": fixed_prep_seconds,
        "legacy_registry_prepare_and_root_check_seconds": registry_prep_seconds,
        "transport_seconds": transport_seconds,
        "legacy_call_seconds": full_verify_seconds,
        "legacy_verifier": verified,
        "legacy_body_roundtrip_checked": pack,
        "ledger_admission": false
    });
    Ok((candidate.unwrap_or(full), result))
}

fn alter_word(word: &mut u64) {
    *word = if *word == crate::MODULUS - 1 {
        0
    } else {
        *word + 1
    };
}

pub fn controls(body: &[u8]) -> Result<Value> {
    fn rejected(input: &[u8], expected: Error) -> Result<Value> {
        match run(input, false) {
            Err(error) if error == expected => Ok(json!(format!("{error:?}"))),
            _ => Err(Error::Control),
        }
    }

    let (candidate, positive) = run(body, true)?;
    let split = prefix_len(&candidate)?;
    let ciphertext = BODY_HEADER + Arity::Two.bytes() + 1588;
    let mut actual_ciphertext = candidate.clone();
    actual_ciphertext[ciphertext] ^= 1;
    let receipt_reject = rejected(&actual_ciphertext, Error::Receipt)?;

    let distinct = positive["distinct_input_coordinates"]
        .as_u64()
        .ok_or(Error::Control)? as usize;
    let first_paths = split + frame::HEADER + LEGACY_HEAD + distinct * (WIDTHS[0] * BASE + SALT);
    let path_count =
        u32::from_le_bytes(candidate[first_paths..first_paths + 4].try_into().unwrap()) as usize;
    let main = first_paths + 4 + path_count * DIGEST;
    let mut changed_main = candidate.clone();
    let mut word = u64::from_le_bytes(changed_main[main..main + BASE].try_into().unwrap());
    alter_word(&mut word);
    changed_main[main..main + BASE].copy_from_slice(&word.to_le_bytes());
    let main_reject = rejected(&changed_main, Error::Crypto)?;

    let mut bad_field = candidate.clone();
    bad_field[main..main + BASE].copy_from_slice(&crate::MODULUS.to_le_bytes());
    let field_reject = rejected(&bad_field, Error::LegacyDecode)?;
    let mut wrong_length = candidate.clone();
    wrong_length.pop();
    let length_reject = rejected(&wrong_length, Error::Shape)?;
    let mut trailing = candidate.clone();
    let tail = trailing.len() - LEGACY_TAIL;
    trailing.insert(tail, 0);
    let size = trailing.len() - split;
    trailing[12..16].copy_from_slice(&(size as u32).to_le_bytes());
    trailing[split + 202..split + 206]
        .copy_from_slice(&((size - frame::HEADER) as u32).to_le_bytes());
    let trailing_reject = rejected(&trailing, Error::Trailing)?;

    let mut fee_below_tariff = candidate.clone();
    let fee_at = BODY_HEADER + 80 + 4 * 64;
    fee_below_tariff[fee_at..fee_at + BASE].copy_from_slice(&(engine::FEES[2] - 1).to_le_bytes());
    let fee_reject = rejected(&fee_below_tariff, Error::Statement)?;

    // The original complete verifier sees canonical replacement statements,
    // recomputed receipt digests and exact frame identities. Its legacy proof
    // grammar is intact, so these cases must reach actual cryptography.
    let parsed = cp03_history::body::parse_full(body).map_err(|_| Error::Shape)?;
    let original = parsed.prefix().statement();
    let fixed = PublicFixed::prepare(original)?;
    let registry = Registry::prepare_public().map_err(|_| Error::FixedSetup)?;
    let (expanded, _, _) = transform(&candidate, Direction::Expand, &fixed)?;
    let mut semantic = Vec::new();
    for name in [
        "fee_value",
        "commitment_owner_binding",
        "membership_root",
        "nullifier",
        "ciphertext_and_receipt_digest",
    ] {
        let mut replay = expanded.clone();
        let mut statement = original.clone();
        match name {
            "fee_value" => {
                if statement.fee < compact_arity_v3::statement::MAX {
                    statement.fee += 1;
                } else {
                    statement.fee -= 1;
                }
            }
            "commitment_owner_binding" => alter_word(&mut statement.commitments[0][0]),
            "membership_root" => alter_word(&mut statement.root[0]),
            "nullifier" => {
                alter_word(&mut statement.nullifiers[0][0]);
                if statement.nullifiers[0] == statement.nullifiers[1] {
                    alter_word(&mut statement.nullifiers[0][0]);
                }
            }
            "ciphertext_and_receipt_digest" => replay[ciphertext] ^= 1,
            _ => unreachable!(),
        }
        let envelope_at = BODY_HEADER + Arity::Two.bytes();
        let envelopes = [
            &replay[envelope_at..envelope_at + 2164],
            &replay[envelope_at + 2164..split],
        ];
        statement.receipts = receipt_digests(&statement, envelopes)?;
        let bytes = statement.bytes().map_err(|_| Error::Statement)?;
        let frame_digest = fixed.frame_digest(&statement, &bytes)?;
        replay[BODY_HEADER..BODY_HEADER + bytes.len()].copy_from_slice(&bytes);
        replay[split + 138..split + 202].copy_from_slice(&frame_digest);
        if !matches!(crypto(&registry, &replay), Err(Error::Crypto)) {
            return Err(Error::Control);
        }
        semantic.push(json!({"case": name, "result": "Crypto", "expanded_legacy_verifier": true}));
    }
    crypto(&registry, &expanded)?;
    Ok(json!({
        "candidate_controls": {
            "actual_ciphertext_mutation": receipt_reject,
            "canonical_main_query_row_mutation": main_reject,
            "noncanonical_main_query_field": field_reject,
            "truncation": length_reject,
            "trailing_opening_bytes": trailing_reject,
            "fee_below_tariff": fee_reject,
        },
        "coherent_changes_after_expansion": semantic,
        "final_positive_reverified": true,
        "validated_ledger_transition": false,
    }))
}
