//! Root-owned SQL/session side of the local archive boundary.
//! File I/O and historical proof verification finish before the write transaction.
use super::*;
use crate::archive_io::{
    CatalogBinding, CatalogView, DurableBatch, ExportInput, IoReconcile, LocalArchive,
    MAX_OPEN_RECORDS, ObjectLocator, RECORD_HEADER_BYTES, SEGMENT_BYTES, SEGMENT_HEADER_BYTES,
    SegmentReservation, SegmentState,
};

fn catalog_binding(ledger: &Ledger) -> Result<CatalogBinding> {
    ledger.ready()?;
    CatalogBinding::new(
        ledger.installed.syntax.chain,
        ledger.genesis_id,
        ledger.catalog_id,
        ledger.db_path.clone(),
        ledger.db_device,
        ledger.db_inode,
    )
}

fn open_segment(db: &Connection) -> Result<Option<SegmentState>> {
    let mut statement = db.prepare(
        "SELECT segment,committed_end,sealed FROM archive_segments WHERE sealed=0 LIMIT 2",
    )?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > 1 {
        return Err(Error::State);
    }
    rows.into_iter()
        .next()
        .map(|(segment, end, sealed)| {
            let value = SegmentState {
                segment: natural(segment)?,
                committed_end: natural(end)?,
                sealed,
            };
            if value.sealed
                || value.committed_end > SEGMENT_BYTES
                || (value.committed_end != 0 && value.committed_end < SEGMENT_HEADER_BYTES)
            {
                return Err(Error::State);
            }
            Ok(value)
        })
        .transpose()
}

/// The vector is bounded by one64MiB segment's conservative minimum record size,
/// not the number of objects in the complete archive. Its real cost is measured.
fn fresh_view(ledger: &mut Ledger) -> Result<CatalogView> {
    let binding = catalog_binding(ledger)?;
    transaction(
        &mut ledger.db,
        &mut ledger.poisoned,
        &mut ledger.last_error,
        TransactionBehavior::Deferred,
        |tx| {
            let usage = cache::usage(tx)?;
            let open = open_segment(tx)?;
            let mut objects = Vec::new();
            if let Some(segment) = open {
                if segment.segment >= usage.next_segment {
                    return Err(Error::State);
                }
                let mut query = tx.prepare(
                    "SELECT id,full_length,record_offset FROM archive_objects WHERE segment=?1 ORDER BY record_offset LIMIT ?2",
                )?;
                let rows = query
                    .query_map(
                        params![
                            integer(segment.segment)?,
                            integer(MAX_OPEN_RECORDS as u64 + 1)?
                        ],
                        |r| {
                            Ok((
                                r.get::<_, Vec<u8>>(0)?,
                                r.get::<_, i64>(1)?,
                                r.get::<_, i64>(2)?,
                            ))
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                if rows.len() > MAX_OPEN_RECORDS {
                    return Err(Error::Capacity);
                }
                for (body_id, length, offset) in rows {
                    let length = natural(length)?;
                    if length == 0 || length > cp03_history::BODY_MAX as u64 {
                        return Err(Error::State);
                    }
                    objects.push(ObjectLocator {
                        id: id(body_id)?,
                        full_length: length as u32,
                        segment: segment.segment,
                        record_offset: natural(offset)?,
                        committed_end: segment.committed_end,
                    });
                }
            }
            Ok(CatalogView {
                binding,
                open,
                objects,
                archive_committed_bytes: usage.archive_committed_bytes,
                archive_limit_bytes: usage.policy.archive_limit_bytes(),
            })
        },
    )
}

/// Copy admitted pending bytes under a bounded snapshot, then release it before
/// hashing, fresh proof/source verification or any archive file operation.
fn prepare_inputs(ledger: &mut Ledger) -> Result<Vec<ExportInput>> {
    ledger.ready()?;
    let captured = transaction(
        &mut ledger.db,
        &mut ledger.poisoned,
        &mut ledger.last_error,
        TransactionBehavior::Deferred,
        |tx| {
            let mut query = tx.prepare(
                "SELECT p.height,p.ordinal,p.id,b.id,b.full_length,b.full,b.reduced,h.header FROM archive_pending p JOIN bodies b ON b.height=p.height AND b.ordinal=p.ordinal JOIN blocks h ON h.height=p.height ORDER BY p.height,p.ordinal LIMIT 16",
            )?;
            let rows = query
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<Vec<u8>>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, Vec<u8>>(7)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.len() > cache::MAX_BATCH {
                return Err(Error::Capacity);
            }
            let mut result = Vec::new();
            for (height, ordinal, pending_id, stored_id, full_length, full, reduced, header) in rows
            {
                let full = full.ok_or(Error::State)?;
                let length = natural(full_length)?;
                if height <= 0
                    || !(0..16).contains(&ordinal)
                    || pending_id != stored_id
                    || length != full.len() as u64
                    || length == 0
                    || length > cp03_history::BODY_MAX as u64
                    || reduced.len() > 9499
                    || header.len() > 1232
                {
                    return Err(Error::State);
                }
                result.push((
                    ExportInput {
                        height: natural(height)?,
                        ordinal: ordinal as u16,
                        id: id(stored_id)?,
                        full,
                        reduced,
                    },
                    header,
                ));
            }
            Ok(result)
        },
    )?;
    let mut result = Vec::new();
    for (input, raw_header) in captured {
        let header = history::parse_header(&raw_header)?;
        if header.height() != input.height
            || raw_header[12..44] != ledger.installed.syntax.chain
            || header.body_ids().get(input.ordinal as usize) != Some(&input.id)
        {
            return Err(Error::State);
        }
        let parsed = body::parse_full(&input.full)?;
        if parsed.body_id() != input.id || parsed.reduced_bytes()? != input.reduced {
            return Err(Error::State);
        }
        admission::verify_historical_contents(&ledger.db, &ledger.installed, &parsed)?;
        result.push(input);
    }
    Ok(result)
}

/// The caller must hold the exact namespace lease; this only reserves SQL state.
/// A fresh view/reconciliation is required after it and before file append.
fn reserve_segment(ledger: &mut Ledger, first: &ExportInput) -> Result<SegmentReservation> {
    let binding = catalog_binding(ledger)?;
    let first_bytes = RECORD_HEADER_BYTES
        .checked_add(first.full.len() as u64)
        .ok_or(Error::Capacity)?;
    if first_bytes > SEGMENT_BYTES - SEGMENT_HEADER_BYTES {
        return Err(Error::Capacity);
    }
    transaction(
        &mut ledger.db,
        &mut ledger.poisoned,
        &mut ledger.last_error,
        TransactionBehavior::Immediate,
        |tx| {
            let usage = cache::usage(tx)?;
            let current = open_segment(tx)?;
            let usable = current.filter(|segment| {
                let start = if segment.committed_end == 0 {
                    SEGMENT_HEADER_BYTES
                } else {
                    segment.committed_end
                };
                start
                    .checked_add(first_bytes)
                    .is_some_and(|end| end <= SEGMENT_BYTES)
            });
            let need_header = usable.is_none_or(|segment| segment.committed_end == 0);
            let extra = first_bytes
                .checked_add(if need_header { SEGMENT_HEADER_BYTES } else { 0 })
                .ok_or(Error::Capacity)?;
            if usage
                .archive_committed_bytes
                .checked_add(extra)
                .ok_or(Error::Capacity)?
                > usage.policy.archive_limit_bytes()
            {
                return Err(Error::ArchiveBacklog);
            }
            let segment = if let Some(segment) = usable {
                segment
            } else {
                if let Some(old) = current {
                    if tx.execute(
                        "UPDATE archive_segments SET sealed=1 WHERE segment=?1 AND committed_end=?2 AND sealed=0",
                        params![integer(old.segment)?, integer(old.committed_end)?],
                    )? != 1 { return Err(Error::State); }
                }
                let next = usage.next_segment.checked_add(1).ok_or(Error::Capacity)?;
                integer(next)?;
                tx.execute(
                    "INSERT INTO archive_segments(segment,committed_end,sealed) VALUES(?1,0,0)",
                    [integer(usage.next_segment)?],
                )?;
                if tx.execute(
                    "UPDATE body_cache SET next_segment=?1 WHERE singleton=1 AND next_segment=?2",
                    params![integer(next)?, integer(usage.next_segment)?],
                )? != 1
                {
                    return Err(Error::State);
                }
                SegmentState {
                    segment: usage.next_segment,
                    committed_end: 0,
                    sealed: false,
                }
            };
            Ok(SegmentReservation {
                binding,
                segment: segment.segment,
                old_committed_end: segment.committed_end,
                archive_committed_bytes: usage.archive_committed_bytes,
                archive_limit_bytes: usage.policy.archive_limit_bytes(),
            })
        },
    )
}

impl LocalArchive {
    pub fn open_for(ledger: &Ledger, root: &Path) -> Result<Self> {
        Self::open(catalog_binding(ledger)?, root)
    }
}

#[derive(PartialEq, Eq)]
struct BodyIdentity {
    id: Id,
    full_length: u32,
    reduced: Vec<u8>,
}

struct CapturedBody {
    identity: BodyIdentity,
    cached: Option<Vec<u8>>,
    locator: Option<ObjectLocator>,
}

struct CapturedHistory {
    height: u64,
    id: Id,
    header: Vec<u8>,
    bodies: Vec<CapturedBody>,
}

/// Only this module constructs a checked bundle, using fresh full verification.
/// The parent may consume it only after rechecking canonical association inside
/// its actual transaction. It is not a live-admission or consensus verdict.
pub(super) struct VerifiedHistorical {
    height: u64,
    id: Id,
    identities: Vec<BodyIdentity>,
    block: StoredBlock,
}

impl VerifiedHistorical {
    pub(super) fn recheck(&self, db: &Connection, height: u64) -> Result<()> {
        if height != self.height {
            return Err(Error::State);
        }
        let row: Option<(Vec<u8>, Vec<u8>)> = db
            .query_row(
                "SELECT id,header FROM blocks WHERE height=?1",
                [integer(height)?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (block_id, header) = row.ok_or(Error::Missing)?;
        if block_id != self.id || header != self.block.header {
            return Err(Error::State);
        }
        let mut query = db.prepare(
            "SELECT ordinal,id,full_length,reduced FROM bodies WHERE height=?1 ORDER BY ordinal LIMIT 17",
        )?;
        let rows = query
            .query_map([integer(height)?], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() != self.identities.len() {
            return Err(Error::State);
        }
        for (j, (ordinal, body_id, length, reduced)) in rows.into_iter().enumerate() {
            let expected = &self.identities[j];
            if ordinal != j as i64
                || body_id != expected.id
                || length != i64::from(expected.full_length)
                || reduced != expected.reduced
            {
                return Err(Error::State);
            }
        }
        Ok(())
    }

    pub(super) fn into_block(self) -> StoredBlock {
        self.block
    }
}

fn capture_history(db: &Connection, height: u64, chain: &[u8; 32]) -> Result<CapturedHistory> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT id,header FROM blocks WHERE height=?1",
            [integer(height)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (block_id, raw_header) = row.ok_or(Error::Missing)?;
    let block_id = id(block_id)?;
    let header = history::parse_header(&raw_header)?;
    if header.height() != height || header.block_id() != block_id || &raw_header[12..44] != chain {
        return Err(Error::State);
    }
    let mut query = db.prepare(
        "SELECT b.ordinal,b.id,b.full_length,b.reduced,b.full,a.full_length,a.segment,a.record_offset,s.committed_end FROM bodies b LEFT JOIN archive_objects a ON a.id=b.id LEFT JOIN archive_segments s ON s.segment=a.segment WHERE b.height=?1 ORDER BY b.ordinal LIMIT 17",
    )?;
    let rows = query
        .query_map([integer(height)?], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, Option<i64>>(7)?,
                r.get::<_, Option<i64>>(8)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() != header.body_ids().len() {
        return Err(Error::State);
    }
    let mut bodies = Vec::with_capacity(rows.len());
    for (j, (ordinal, body_id, length, reduced, cached, archived_length, segment, offset, end)) in
        rows.into_iter().enumerate()
    {
        let body_id = id(body_id)?;
        let length = natural(length)?;
        if ordinal != j as i64
            || body_id != header.body_ids()[j]
            || length == 0
            || length > cp03_history::BODY_MAX as u64
            || reduced.len() > cp03_history::REDUCED_MAX
            || cached
                .as_ref()
                .is_some_and(|bytes| bytes.len() as u64 != length)
        {
            return Err(Error::State);
        }
        let locator = match (archived_length, segment, offset, end) {
            (None, None, None, None) => None,
            (Some(archived_length), Some(segment), Some(offset), Some(end)) => {
                if natural(archived_length)? != length {
                    return Err(Error::State);
                }
                Some(ObjectLocator {
                    id: body_id,
                    full_length: length as u32,
                    segment: natural(segment)?,
                    record_offset: natural(offset)?,
                    committed_end: natural(end)?,
                })
            }
            _ => return Err(Error::State),
        };
        if cached.is_none() && locator.is_none() {
            return Err(Error::HistoryUnavailable);
        }
        bodies.push(CapturedBody {
            identity: BodyIdentity {
                id: body_id,
                full_length: length as u32,
                reduced,
            },
            cached,
            locator,
        });
    }
    drop(header);
    Ok(CapturedHistory {
        height,
        id: block_id,
        header: raw_header,
        bodies,
    })
}

fn verified_history(
    ledger: &mut Ledger,
    height: u64,
    archive: &LocalArchive,
) -> Result<VerifiedHistorical> {
    let binding = catalog_binding(ledger)?;
    archive.check_binding(&binding)?;
    if !archive.is_ready() {
        return Err(Error::HistoryUnavailable);
    }
    let chain = ledger.installed.syntax.chain;
    let captured = transaction(
        &mut ledger.db,
        &mut ledger.poisoned,
        &mut ledger.last_error,
        TransactionBehavior::Deferred,
        |tx| capture_history(tx, height, &chain),
    )?;
    let mut full_bodies = Vec::with_capacity(captured.bodies.len());
    let mut identities = Vec::with_capacity(captured.bodies.len());
    for body in captured.bodies {
        let full = match body.cached {
            Some(bytes) => bytes,
            None => {
                archive.read_object(&binding, &body.locator.ok_or(Error::HistoryUnavailable)?)?
            }
        };
        if full.len() != body.identity.full_length as usize {
            return Err(Error::ArchiveCorrupt);
        }
        let parsed = body::parse_full(&full)?;
        if parsed.body_id() != body.identity.id || parsed.reduced_bytes()? != body.identity.reduced
        {
            return Err(Error::ArchiveCorrupt);
        }
        // Recompute receipt binding, immutable source authorization, exact
        // statement rules and a genuine complete proof. Current spent/anchor
        // state is deliberately not substituted for historical admission.
        admission::verify_historical_contents(&ledger.db, &ledger.installed, &parsed)?;
        full_bodies.push(full);
        identities.push(body.identity);
    }
    Ok(VerifiedHistorical {
        height: captured.height,
        id: captured.id,
        identities,
        block: StoredBlock {
            header: captured.header,
            bodies: full_bodies,
        },
    })
}

impl Ledger {
    /// Returns freshly verified historical contents tied to a still-canonical
    /// local header. This does not prove external fork choice or live validity.
    pub fn full_block_with_archive(
        &mut self,
        height: u64,
        archive: &LocalArchive,
    ) -> Result<StoredBlock> {
        let result = (|| {
            let checked = verified_history(self, height, archive)?;
            transaction(
                &mut self.db,
                &mut self.poisoned,
                &mut self.last_error,
                TransactionBehavior::Deferred,
                |tx| checked.recheck(tx, height),
            )?;
            Ok(checked.into_block())
        })();
        result.map_err(|error| operation_error(self, error))
    }

    /// All external reads and complete historical checks finish before any
    /// state mutation. The original atomic rollback rechecks the exact tip and
    /// retained association and uses only local undo, never archive-supplied undo.
    pub fn rollback_tip_with_archive(
        &mut self,
        expected_tip: Id,
        archive: &LocalArchive,
    ) -> Result<StoredBlock> {
        let result = (|| {
            let tip = self.head()?;
            if tip.height == 0 || tip.id != expected_tip {
                return Err(Error::Identity);
            }
            let checked = verified_history(self, tip.height, archive)?;
            self.rollback_tip_prepared(expected_tip, Some(checked))
        })();
        result.map_err(|error| operation_error(self, error))
    }
}

pub struct ArchiveSession<'a> {
    ledger: &'a mut Ledger,
    archive: &'a mut LocalArchive,
}

pub struct PendingPublication<'a> {
    ledger: &'a mut Ledger,
    batch: DurableBatch<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportProgress {
    pub objects: u8,
    /// Incremental segment bytes, including record headers and any new segment header.
    pub bytes: u64,
    pub evicted_rows: u8,
    pub evicted_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileProgress {
    Clean,
    DiscardedUnpublishedTail { bytes: u64 },
    ResolvedCommitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortProgress {
    Aborted { discarded_bytes: u64 },
}

fn reconcile_result(value: IoReconcile) -> ReconcileProgress {
    match value {
        IoReconcile::Clean => ReconcileProgress::Clean,
        IoReconcile::DiscardedUnpublishedTail { bytes } => {
            ReconcileProgress::DiscardedUnpublishedTail { bytes }
        }
        IoReconcile::ResolvedCommitted => ReconcileProgress::ResolvedCommitted,
    }
}

fn operation_error(ledger: &mut Ledger, error: Error) -> Error {
    if !ledger.poisoned {
        ledger.last_error = Some(error);
    }
    error
}

impl Ledger {
    pub fn archive_session<'a>(
        &'a mut self,
        archive: &'a mut LocalArchive,
    ) -> Result<ArchiveSession<'a>> {
        self.ready()?;
        archive.check_binding(&catalog_binding(self)?)?;
        Ok(ArchiveSession {
            ledger: self,
            archive,
        })
    }
}

impl ArchiveSession<'_> {
    /// A poisoned Ledger must be dropped/reopened by the caller. This operation
    /// never clears its poison, retries a publication or replaces a connection.
    pub fn reconcile(&mut self) -> Result<ReconcileProgress> {
        self.ledger.ready()?;
        let view = fresh_view(self.ledger)?;
        self.archive
            .reconcile_catalog(&view)
            .map(reconcile_result)
            .map_err(|error| operation_error(self.ledger, error))
    }

    pub fn append<'s>(&'s mut self) -> Result<Option<PendingPublication<'s>>> {
        self.ledger.ready()?;
        if !self.archive.is_ready() {
            return Err(Error::HistoryUnavailable);
        }
        self.archive.check_binding(&catalog_binding(self.ledger)?)?;
        let prepared = (|| {
            let inputs = prepare_inputs(self.ledger)?;
            if inputs.is_empty() {
                return Ok(None);
            }
            let reservation = reserve_segment(self.ledger, &inputs[0])?;
            // A new reservation is authoritative SQL state; reconcile the exact
            // fresh view under the still-held lease before using its file offset.
            let view = fresh_view(self.ledger)?;
            self.archive.reconcile_catalog(&view)?;
            Ok(Some((reservation, inputs)))
        })();
        let (reservation, inputs) = match prepared {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.archive.invalidate();
                return Err(operation_error(self.ledger, error));
            }
        };
        let batch = self
            .archive
            .append_leased(&reservation, &inputs)
            .map_err(|error| operation_error(self.ledger, error))?;
        Ok(Some(PendingPublication {
            ledger: self.ledger,
            batch,
        }))
    }
}

impl PendingPublication<'_> {
    pub fn publish(self) -> Result<ExportProgress> {
        let Self { ledger, batch } = self;
        ledger.ready()?;
        batch
            .validate_for_publication()
            .map_err(|error| operation_error(ledger, error))?;
        let binding = catalog_binding(ledger)?;
        let reservation = batch.reservation();
        let entries = batch.objects();
        if reservation.binding != binding
            || batch.binding() != &binding
            || entries.is_empty()
            || entries.len() > cache::MAX_BATCH
            || batch.new_end() <= reservation.old_committed_end
            || batch.new_end() > SEGMENT_BYTES
            || batch.raw_bytes() != batch.new_end() - reservation.old_committed_end
        {
            return Err(operation_error(ledger, Error::State));
        }
        let result = transaction(
            &mut ledger.db,
            &mut ledger.poisoned,
            &mut ledger.last_error,
            TransactionBehavior::Immediate,
            |tx| {
                let current = cache::usage(tx)?;
                let stored_id: Vec<u8> = tx.query_row(
                    "SELECT catalog_id FROM body_cache WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )?;
                if stored_id != binding.catalog_id()
                    || current.archive_committed_bytes != reservation.archive_committed_bytes
                    || current.policy.archive_limit_bytes() != reservation.archive_limit_bytes
                    || current
                        .archive_committed_bytes
                        .checked_add(batch.raw_bytes())
                        .ok_or(Error::Capacity)?
                        > current.policy.archive_limit_bytes()
                {
                    return Err(Error::State);
                }
                if tx.execute(
                    "UPDATE archive_segments SET committed_end=?1 WHERE segment=?2 AND committed_end=?3 AND sealed=0",
                    params![integer(batch.new_end())?, integer(reservation.segment)?, integer(reservation.old_committed_end)?],
                )? != 1 { return Err(Error::State); }
                let mut at = if reservation.old_committed_end == 0 {
                    SEGMENT_HEADER_BYTES
                } else {
                    reservation.old_committed_end
                };
                for entry in entries {
                    let length = u64::from(entry.full_length);
                    if entry.segment != reservation.segment
                        || entry.record_offset != at
                        || entry.committed_end != batch.new_end()
                        || length == 0
                        || length > cp03_history::BODY_MAX as u64
                    {
                        return Err(Error::State);
                    }
                    at = at
                        .checked_add(RECORD_HEADER_BYTES)
                        .and_then(|n| n.checked_add(length))
                        .ok_or(Error::Capacity)?;
                    // Every physically appended object is retained globally,
                    // even if ordinary rollback removed its canonical row.
                    tx.execute(
                        "INSERT INTO archive_objects(id,full_length,segment,record_offset) VALUES(?1,?2,?3,?4)",
                        params![entry.id.as_slice(), i64::from(entry.full_length), integer(entry.segment)?, integer(entry.record_offset)?],
                    )?;
                }
                if at != batch.new_end() {
                    return Err(Error::State);
                }
                let (evicted_rows, evicted_bytes) = match cache::evict(tx)? {
                    EvictionProgress::Freed { rows, bytes } => (rows, bytes),
                    EvictionProgress::AtWatermark | EvictionProgress::PendingExport => (0, 0),
                };
                Ok(ExportProgress {
                    objects: entries.len() as u8,
                    bytes: batch.raw_bytes(),
                    evicted_rows,
                    evicted_bytes,
                })
            },
        )?;
        // A confirmed commit is already authoritative. Settling has no I/O or
        // fallible recheck that could relabel it as a no-change failure.
        #[cfg(feature = "archive-crash-controls")]
        archive_after_publication_stop();
        batch.settle_committed();
        Ok(result)
    }

    pub fn abort(self) -> Result<AbortProgress> {
        let Self { ledger, batch } = self;
        ledger.ready()?;
        let view = fresh_view(ledger)?;
        let result = batch
            .abort_with_view(&view)
            .map_err(|error| operation_error(ledger, error))?;
        match result {
            IoReconcile::DiscardedUnpublishedTail { bytes } => Ok(AbortProgress::Aborted {
                discarded_bytes: bytes,
            }),
            IoReconcile::Clean => Ok(AbortProgress::Aborted { discarded_bytes: 0 }),
            IoReconcile::ResolvedCommitted => Err(operation_error(ledger, Error::State)),
        }
    }
}

#[cfg(feature = "archive-crash-controls")]
fn archive_after_publication_stop() {
    if std::env::var("CP03_ARCHIVE_CRASH_POINT").ok().as_deref() != Some("after-publication") {
        return;
    }
    if std::io::stderr()
        .write_all(b"CP03_ARCHIVE_CRASH_POINT after-publication\n")
        .is_err()
        || unsafe { libc::raise(libc::SIGSTOP) } != 0
    {
        std::process::exit(126);
    }
}
