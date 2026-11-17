//! Mandatory real proof path. No callback, test acceptance flag or signature substitute.
use crate::{
    Error, Result,
    encoding::{Digest, field_bytes, integer, receipt},
    trusted::{Installed, claim_message, verify_source_signature},
};
use compact_all_payments_v3::engine;
use compact_arities_v3::statement::{Arity, MAX};
use cp03_history::body::UnverifiedFullBody;
use rusqlite::{Connection, OptionalExtension, params};
pub fn minimum_fee(arity: Arity) -> u64 {
    match arity {
        Arity::Credit => 2_116_775,
        Arity::One => 2_112_174,
        Arity::Two => 2_112_248,
    }
}
pub(crate) fn verify(
    db: &Connection,
    installed: &Installed,
    parent_count: u64,
    body: &UnverifiedFullBody<'_>,
) -> Result<()> {
    #[cfg(feature = "admission-cost-trace")]
    let _cost_checks = crate::cost_trace::span("admission-checks-core");
    let prefix = body.prefix();
    let s = prefix.statement();
    if s.chain != installed.syntax.chain {
        return Err(Error::Chain);
    }
    if s.fee < minimum_fee(s.arity) || s.fee > MAX {
        return Err(Error::Fee);
    }
    if s.count > parent_count {
        return Err(Error::Anchor);
    }
    let anchor: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM anchors WHERE root=?1 AND leaf_count=?2)",
        params![field_bytes(&s.root), integer(s.count)?],
        |r| r.get(0),
    )?;
    if !anchor {
        return Err(Error::Anchor);
    }
    let core = s.core().map_err(|_| Error::Codec)?;
    let replay: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM cores WHERE id=?1)",
        [field_bytes(&core)],
        |r| r.get(0),
    )?;
    if replay {
        return Err(Error::Replay);
    }
    for nf in &s.nullifiers {
        let spent: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM nullifiers WHERE id=?1)",
            [field_bytes(nf)],
            |r| r.get(0),
        )?;
        if spent {
            return Err(Error::Replay);
        }
    }
    #[cfg(feature = "admission-cost-trace")]
    drop(_cost_checks);
    #[cfg(feature = "admission-cost-trace")]
    let _cost_receipts = crate::cost_trace::span("receipt-reconstruction");
    verify_receipts(body, &core)?;
    #[cfg(feature = "admission-cost-trace")]
    drop(_cost_receipts);
    if s.arity == Arity::Credit {
        #[cfg(feature = "admission-cost-trace")]
        let _cost_source = crate::cost_trace::span("credit-source-authority");

        let id = s.source_id.ok_or(Error::Source)?;
        let row: Option<(i64, Vec<u8>, Option<i64>)> = db
            .query_row(
                "SELECT credit,public_key,consumed_height FROM sources WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (credit, key, consumed) = row.ok_or(Error::Source)?;
        if consumed.is_some() {
            return Err(Error::Source);
        }
        verify_credit_contents(installed, body, &id, credit, &key)?;
    } else {
        verify_ordinary_source(body)?;
    }
    {
    #[cfg(feature = "admission-cost-trace")]
    let _cost_proof = crate::cost_trace::span("fresh-complete-proof");
    verify_complete_proof(installed, body)?;
    }
    Ok(())
}

// These helpers establish immutable contents only. None consumes a source or
// authorizes a state transition; live verify retains every dynamic check above.
fn verify_receipts(body: &UnverifiedFullBody<'_>, core: &Digest) -> Result<()> {
    let prefix = body.prefix();
    let s = prefix.statement();
    for (j, envelope) in prefix.envelopes().into_iter().enumerate() {
        if receipt(&s.chain, core, j as u16, envelope)? != s.receipts[j] {
            return Err(Error::Receipt);
        }
    }
    Ok(())
}

fn verify_credit_contents(
    installed: &Installed,
    body: &UnverifiedFullBody<'_>,
    id: &[u8; 48],
    credit: i64,
    key: &[u8],
) -> Result<()> {
    let prefix = body.prefix();
    let s = prefix.statement();
    if credit != integer(s.credit)? || s.debit != 0 {
        return Err(Error::Source);
    }
    let message = claim_message(
        &s.chain,
        id,
        s.credit,
        &installed.syntax.profile,
        &installed.syntax.programs[0],
        prefix.statement_bytes(),
    )?;
    verify_source_signature(installed, key, &message, prefix.authorization())
}

fn verify_ordinary_source(body: &UnverifiedFullBody<'_>) -> Result<()> {
    let prefix = body.prefix();
    let s = prefix.statement();
    if !prefix.authorization().is_empty() || s.credit != 0 || s.debit != 0 {
        return Err(Error::Source);
    }
    Ok(())
}

fn verify_complete_proof(installed: &Installed, body: &UnverifiedFullBody<'_>) -> Result<()> {
    engine::verify_bytes(&installed.registry, body.prefix().statement_bytes(), body.proof())
        .map(|_| ())
        .map_err(|_| Error::Proof)
}

/// Reverify contents bound by the caller to an already admitted local header.
/// This crate-private function produces no admission token and performs no writes.
/// It deliberately cannot establish historical anchor/current-state validity or
/// consensus. Its caller must authenticate the full/reduced/header association.
/// Catch-up and reinclusion must instead use ordinary live Ledger admission.
pub(crate) fn verify_historical_contents(
    db: &Connection,
    installed: &Installed,
    body: &UnverifiedFullBody<'_>,
) -> Result<()> {
    let s = body.prefix().statement();
    if s.chain != installed.syntax.chain {
        return Err(Error::Chain);
    }
    if s.fee < minimum_fee(s.arity) || s.fee > MAX {
        return Err(Error::Fee);
    }
    let core = s.core().map_err(|_| Error::Codec)?;
    verify_receipts(body, &core)?;
    if s.arity == Arity::Credit {
        let id = s.source_id.ok_or(Error::Source)?;
        // The immutable registry is checked against installed genesis on open.
        // Consumed status must remain intact; this is not a second issuance.
        let row: Option<(i64, Vec<u8>)> = db
            .query_row(
                "SELECT credit,public_key FROM sources WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (credit, key) = row.ok_or(Error::Source)?;
        verify_credit_contents(installed, body, &id, credit, &key)?;
    } else {
        verify_ordinary_source(body)?;
    }
    verify_complete_proof(installed, body)
}
