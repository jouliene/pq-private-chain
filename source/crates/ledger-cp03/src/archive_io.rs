//! Bounded Linux local archive IO. No SQL, verdict cache or producer-selected path.
//! The OS writer lock belongs to LocalArchive until it drops, including poisoned
//! periods between sessions. Root's store_archive owns fresh catalog/SQL decisions.
#[cfg(not(target_os = "linux"))]
compile_error!("CP03 archive_io currently requires reviewed Linux filesystem semantics");

use crate::{Error, Result};
use std::{
    cell::Cell,
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::{self, File},
    io,
    marker::PhantomData,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Component, Path, PathBuf},
    rc::Rc,
};

pub(crate) const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const SEGMENT_HEADER_BYTES: u64 = 148;
pub(crate) const RECORD_HEADER_BYTES: u64 = 68;
pub(crate) const MAX_OPEN_RECORDS: usize = ((SEGMENT_BYTES - SEGMENT_HEADER_BYTES) / 69) as usize;
const MARKER_CAP: usize = 4272;
const MAX_BATCH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatalogBinding {
    chain: [u8; 32],
    genesis: [u8; 64],
    catalog_id: [u8; 32],
    db_path: PathBuf,
    db_device: u64,
    db_inode: u64,
}
impl CatalogBinding {
    pub(crate) fn new(
        chain: [u8; 32],
        genesis: [u8; 64],
        catalog_id: [u8; 32],
        db_path: PathBuf,
        db_device: u64,
        db_inode: u64,
    ) -> Result<Self> {
        let path = fs::canonicalize(db_path).map_err(|_| Error::ArchiveIo)?;
        if path.as_os_str().as_bytes().len() > 4096 {
            return Err(Error::Capacity);
        }
        let value = Self {
            chain,
            genesis,
            catalog_id,
            db_path: path,
            db_device,
            db_inode,
        };
        value.check_file()?;
        Ok(value)
    }
    fn check_file(&self) -> Result<()> {
        let (parent, name) = parent_and_name(&self.db_path)?;
        let dir = walk_directory(&parent, false)?;
        let file = open_regular_at(&dir, &name, libc::O_RDONLY, 0)?;
        let m = file.metadata().map_err(|_| Error::ArchiveIo)?;
        if m.dev() != self.db_device || m.ino() != self.db_inode {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub(crate) fn chain(&self) -> [u8; 32] {
        self.chain
    }
    pub(crate) fn genesis(&self) -> [u8; 64] {
        self.genesis
    }
    pub(crate) fn catalog_id(&self) -> [u8; 32] {
        self.catalog_id
    }
    pub(crate) fn db_path(&self) -> &Path {
        &self.db_path
    }
    pub(crate) fn db_device(&self) -> u64 {
        self.db_device
    }
    pub(crate) fn db_inode(&self) -> u64 {
        self.db_inode
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SegmentState {
    pub segment: u64,
    pub committed_end: u64,
    pub sealed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectLocator {
    pub id: [u8; 64],
    pub full_length: u32,
    pub segment: u64,
    pub record_offset: u64,
    pub committed_end: u64,
}
pub(crate) struct CatalogView {
    pub binding: CatalogBinding,
    pub open: Option<SegmentState>,
    /// ALL open-segment catalog entries, ordered by record_offset; bounded below.
    pub objects: Vec<ObjectLocator>,
    pub archive_committed_bytes: u64,
    pub archive_limit_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SegmentReservation {
    pub binding: CatalogBinding,
    pub segment: u64,
    pub old_committed_end: u64,
    pub archive_committed_bytes: u64,
    pub archive_limit_bytes: u64,
}
pub(crate) struct ExportInput {
    pub height: u64,
    pub ordinal: u16,
    pub id: [u8; 64],
    pub full: Vec<u8>,
    pub reduced: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IoReconcile {
    Clean,
    DiscardedUnpublishedTail { bytes: u64 },
    ResolvedCommitted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileKey {
    device: u64,
    inode: u64,
}
#[derive(Clone)]
struct ReadyState {
    open: Option<SegmentState>,
    open_file: Option<FileKey>,
    total: u64,
    limit: u64,
}
#[derive(Clone)]
struct Attempt {
    segment: u64,
    old_end: u64,
    new_end: u64,
    entries: Vec<ObjectLocator>,
}
enum Health {
    NeedsReconcile,
    Ready(ReadyState),
    Pending,
    Quarantined,
}

/// Local combined-role demonstrator only, not an external archive transport.
/// No Clone/Serialize/Send/Sync or raw-fd escape. Lock file drops last.
pub struct LocalArchive {
    root: File,
    segments: File,
    binding: CatalogBinding,
    marker: Vec<u8>,
    root_key: FileKey,
    lock_key: FileKey,
    health: Health,
    last_attempt: Option<Attempt>,
    // Shared-reference retrieval cannot silently keep a Ready capability after
    // an IO failure. Only successful authoritative reconcile clears this bit.
    read_fault: Cell<bool>,
    _thread_affine: PhantomData<Rc<()>>,
    lock: File,
}
impl LocalArchive {
    pub(crate) fn open(binding: CatalogBinding, path: &Path) -> Result<Self> {
        binding.check_file()?;
        let root = walk_directory(path, true)?;
        let root_key = key(&root)?;
        let (lock, _) = create_or_open_regular(&root, cstr(b"LOCK\0"), libc::O_RDWR)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Error::ArchiveBusy
            } else {
                Error::ArchiveIo
            });
        }
        // Exists may mean a prior initializer died before its barriers. Complete
        // them under the acquired lease on every successful open, not just create.
        lock.sync_all().map_err(|_| Error::ArchiveIo)?;
        root.sync_all().map_err(|_| Error::ArchiveIo)?;
        let lock_key = key(&lock)?;
        let marker = marker_bytes(&binding, root_key)?;
        let marker_file = match create_regular(&root, cstr(b"BINDING\0"), libc::O_WRONLY) {
            Ok(file) => {
                write_all_at(&file, &marker, 0)?;
                file
            }
            Err(OpenFailure::Exists) => {
                let file = open_regular_at(&root, cstr(b"BINDING\0"), libc::O_RDWR, 0)?;
                if read_bounded(&file, MARKER_CAP)? != marker {
                    return Err(Error::Identity);
                }
                file
            }
            Err(OpenFailure::Other(e)) => return Err(e),
        };
        marker_file.sync_all().map_err(|_| Error::ArchiveIo)?;
        root.sync_all().map_err(|_| Error::ArchiveIo)?;
        let segments = child_directory(&root, cstr(b"segments\0"), true)?;
        if key(&segments)?.device != root_key.device {
            return Err(Error::ArchiveIo);
        }
        let archive = Self {
            root,
            segments,
            binding,
            marker,
            root_key,
            lock_key,
            health: Health::NeedsReconcile,
            last_attempt: None,
            read_fault: Cell::new(false),
            _thread_affine: PhantomData,
            lock,
        };
        archive.check_guard()?;
        Ok(archive)
    }
    pub(crate) fn binding(&self) -> &CatalogBinding {
        &self.binding
    }
    pub(crate) fn check_binding(&self, binding: &CatalogBinding) -> Result<()> {
        if binding != &self.binding {
            return Err(Error::Identity);
        }
        self.check_guard()
    }
    pub(crate) fn is_ready(&self) -> bool {
        !self.read_fault.get() && matches!(self.health, Health::Ready(_))
    }
    /// SQL reservation failures before a guard exists cannot leave a cached Ready.
    /// A forgotten outstanding guard MUST remain Pending until full close/open.
    pub(crate) fn invalidate(&mut self) {
        if !matches!(self.health, Health::Pending) {
            self.health = Health::NeedsReconcile;
        }
    }
    pub(crate) fn ready_segment(&self) -> Result<Option<SegmentState>> {
        if self.read_fault.get() {
            return Err(Error::HistoryUnavailable);
        }
        match &self.health {
            Health::Ready(r) => Ok(r.open),
            _ => Err(Error::HistoryUnavailable),
        }
    }
    fn check_guard(&self) -> Result<()> {
        let result = self.check_guard_inner();
        if result.is_err() {
            self.read_fault.set(true);
        }
        result
    }
    fn check_guard_inner(&self) -> Result<()> {
        self.binding.check_file()?;
        if key(&self.root)? != self.root_key || key(&self.lock)? != self.lock_key {
            return Err(Error::Identity);
        }
        same_named(&self.root, cstr(b"LOCK\0"), &self.lock)?;
        same_named(&self.root, cstr(b"segments\0"), &self.segments)?;
        let marker = open_regular_at(&self.root, cstr(b"BINDING\0"), libc::O_RDONLY, 0)?;
        if read_bounded(&marker, MARKER_CAP)? != self.marker {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn segment_dir(&self, segment: u64, create: bool) -> Result<File> {
        let name =
            CString::new(format!("{:016x}", segment / 4096)).map_err(|_| Error::ArchiveIo)?;
        let dir = child_directory(&self.segments, &name, create)?;
        if key(&dir)?.device != self.root_key.device {
            return Err(Error::Identity);
        }
        Ok(dir)
    }
    fn segment_name(segment: u64) -> Result<CString> {
        CString::new(format!("{segment:016x}.cpar")).map_err(|_| Error::ArchiveIo)
    }
    /// No outstanding batch permitted, including a forgotten Rust guard.
    /// Root must supply a FRESH authoritative same-catalog view while this lock
    /// is held, using a nonpoisoned Ledger. No view is supplied by a producer.
    pub(crate) fn reconcile_catalog(&mut self, view: &CatalogView) -> Result<IoReconcile> {
        if matches!(self.health, Health::Pending) {
            return Err(Error::ArchiveBusy);
        }
        self.health = Health::NeedsReconcile;
        self.read_fault.set(true);
        let result = self.reconcile_inner(view);
        if result.is_err() {
            self.health = Health::Quarantined;
        }
        result
    }
    fn reconcile_inner(&mut self, view: &CatalogView) -> Result<IoReconcile> {
        self.check_binding(&view.binding)?;
        if view.archive_limit_bytes == 0
            || view.archive_committed_bytes > view.archive_limit_bytes
            || view.objects.len() > MAX_OPEN_RECORDS
        {
            return Err(Error::State);
        }
        // Resolve an uncertain receipt against the complete catalog BEFORE any
        // truncation. Inconsistent/mixed publication never authorizes tail reuse.
        let resolved = if let Some(attempt) = &self.last_attempt {
            let open = view.open.ok_or(Error::State)?;
            if open.segment != attempt.segment {
                return Err(Error::State);
            }
            if open.committed_end == attempt.new_end {
                if !attempt
                    .entries
                    .iter()
                    .all(|e| view.objects.iter().any(|a| a == e))
                {
                    return Err(Error::State);
                }
                true
            } else if open.committed_end == attempt.old_end {
                false
            } else {
                return Err(Error::State);
            }
        } else {
            false
        };
        let mut discarded = 0;
        let mut open_file = None;
        if let Some(open) = view.open {
            if open.sealed
                || open.committed_end > SEGMENT_BYTES
                || (open.committed_end != 0 && open.committed_end < SEGMENT_HEADER_BYTES)
                || open.committed_end > view.archive_committed_bytes
            {
                return Err(Error::State);
            }
            let mut expected = SEGMENT_HEADER_BYTES;
            let mut ids = BTreeSet::new();
            for entry in &view.objects {
                validate_locator(entry)?;
                if entry.segment != open.segment
                    || entry.committed_end != open.committed_end
                    || entry.record_offset != expected
                    || !ids.insert(entry.id)
                {
                    return Err(Error::State);
                }
                expected = record_end(entry)?;
            }
            if (open.committed_end == 0 && !view.objects.is_empty())
                || (open.committed_end != 0 && expected != open.committed_end)
            {
                return Err(Error::State);
            }
            // A newly reserved end0 may have no file or a partial unindexed tail.
            let dir = match self.segment_dir(open.segment, false) {
                Ok(dir) => Some(dir),
                Err(Error::HistoryUnavailable) if open.committed_end == 0 => None,
                Err(e) => return Err(e),
            };
            if let Some(dir) = dir {
                let name = Self::segment_name(open.segment)?;
                let file = match open_regular_at(&dir, &name, libc::O_RDWR, 0) {
                    Ok(f) => Some(f),
                    Err(Error::HistoryUnavailable) if open.committed_end == 0 => None,
                    Err(e) => return Err(e),
                };
                if let Some(file) = file {
                    if key(&file)?.device != self.root_key.device {
                        return Err(Error::Identity);
                    }
                    let length = file.metadata().map_err(|_| Error::ArchiveIo)?.len();
                    if length > SEGMENT_BYTES {
                        return Err(Error::ArchiveCorrupt);
                    }
                    if length < open.committed_end {
                        return Err(Error::HistoryUnavailable);
                    }
                    if open.committed_end > 0 {
                        verify_header(&file, &self.binding, open.segment)?;
                        for entry in &view.objects {
                            read_object_file(&file, &self.binding, entry)?;
                        }
                    }
                    // Only authoritative, unreferenced tail is discarded, never
                    // a missing-ACK receipt's remembered old end.
                    if length > open.committed_end {
                        discarded = length - open.committed_end;
                        file.set_len(open.committed_end)
                            .map_err(|_| Error::ArchiveIo)?;
                        file.sync_all().map_err(|_| Error::ArchiveIo)?;
                    }
                    same_named(&dir, &name, &file)?;
                    open_file = Some(key(&file)?);
                }
            }
        } else if !view.objects.is_empty() || self.last_attempt.is_some() {
            // With this lifetime lock nobody can move our uncertain open segment.
            return Err(Error::State);
        }
        self.check_guard()?;
        self.health = Health::Ready(ReadyState {
            open: view.open,
            open_file,
            total: view.archive_committed_bytes,
            limit: view.archive_limit_bytes,
        });
        self.last_attempt = None;
        self.read_fault.set(false);
        Ok(if resolved {
            IoReconcile::ResolvedCommitted
        } else if discarded > 0 {
            IoReconcile::DiscardedUnpublishedTail { bytes: discarded }
        } else {
            IoReconcile::Clean
        })
    }
    pub(crate) fn append_leased<'io>(
        &'io mut self,
        reservation: &SegmentReservation,
        inputs: &[ExportInput],
    ) -> Result<DurableBatch<'io>> {
        if self.read_fault.get() {
            return Err(Error::HistoryUnavailable);
        }
        let ready = match &self.health {
            Health::Ready(r) => r.clone(),
            _ => return Err(Error::HistoryUnavailable),
        };
        self.health = Health::NeedsReconcile; // also survives unwinding before guard creation
        let result = self.append_inner(&ready, reservation, inputs);
        match result {
            Ok((attempt, file, dir, name)) => {
                let final_ready = ReadyState {
                    open: Some(SegmentState {
                        segment: attempt.segment,
                        committed_end: attempt.new_end,
                        sealed: false,
                    }),
                    open_file: Some(key(&file)?),
                    total: ready.total + (attempt.new_end - attempt.old_end),
                    limit: ready.limit,
                };
                self.last_attempt = Some(attempt.clone());
                self.health = Health::Pending;
                Ok(DurableBatch {
                    archive: self,
                    attempt,
                    file,
                    dir,
                    name,
                    reservation: reservation.clone(),
                    final_ready: Some(final_ready),
                    settled: false,
                })
            }
            Err(e) => Err(e),
        }
    }
    fn append_inner(
        &mut self,
        ready: &ReadyState,
        r: &SegmentReservation,
        inputs: &[ExportInput],
    ) -> Result<(Attempt, File, File, CString)> {
        self.check_binding(&r.binding)?;
        let open = ready.open.ok_or(Error::State)?;
        if open.sealed
            || open.segment != r.segment
            || open.committed_end != r.old_committed_end
            || r.archive_committed_bytes != ready.total
            || r.archive_limit_bytes != ready.limit
            || inputs.is_empty()
            || inputs.len() > MAX_BATCH
        {
            return Err(Error::State);
        }
        let mut ids = BTreeSet::new();
        let mut previous = None;
        for input in inputs {
            if input.height == 0
                || input.height > i64::MAX as u64
                || input.ordinal >= 128
                || previous.is_some_and(|p| p >= (input.height, input.ordinal))
                || !ids.insert(input.id)
            {
                return Err(Error::State);
            }
            previous = Some((input.height, input.ordinal));
            validate_full(&self.binding, &input.full, input.id, Some(&input.reduced))?;
        }
        let mut end = if r.old_committed_end == 0 {
            SEGMENT_HEADER_BYTES
        } else {
            r.old_committed_end
        };
        let mut entries = Vec::new();
        for input in inputs {
            let length = u32::try_from(input.full.len()).map_err(|_| Error::Capacity)?;
            let next = end
                .checked_add(RECORD_HEADER_BYTES)
                .and_then(|n| n.checked_add(u64::from(length)))
                .ok_or(Error::Capacity)?;
            if next > SEGMENT_BYTES {
                break;
            }
            entries.push(ObjectLocator {
                id: input.id,
                full_length: length,
                segment: r.segment,
                record_offset: end,
                committed_end: 0,
            });
            end = next;
        }
        if entries.is_empty() {
            return Err(Error::Capacity);
        }
        let delta = end.checked_sub(r.old_committed_end).ok_or(Error::State)?;
        if ready.total.checked_add(delta).ok_or(Error::Capacity)? > ready.limit {
            return Err(Error::ArchiveBacklog);
        }
        for e in &mut entries {
            e.committed_end = end;
        }
        let dir = self.segment_dir(r.segment, true)?;
        let name = Self::segment_name(r.segment)?;
        let (file, created) = create_or_open_regular(&dir, &name, libc::O_RDWR)?;
        let current_key = key(&file)?;
        if current_key.device != self.root_key.device
            || file.metadata().map_err(|_| Error::ArchiveIo)?.len() != r.old_committed_end
            || match ready.open_file {
                Some(k) => created || k != current_key,
                None => !created,
            }
        {
            return Err(Error::Identity);
        }
        if r.old_committed_end == 0 {
            write_all_at(&file, &segment_header(&self.binding, r.segment), 0)?;
        } else {
            verify_header(&file, &self.binding, r.segment)?;
        }
        for (entry, input) in entries.iter().zip(inputs) {
            let mut header = [0u8; 68];
            header[..4].copy_from_slice(&entry.full_length.to_le_bytes());
            header[4..].copy_from_slice(&entry.id);
            write_all_at(&file, &header, entry.record_offset)?;
            write_all_at(
                &file,
                &input.full,
                entry.record_offset + RECORD_HEADER_BYTES,
            )?;
        }
        file.sync_all().map_err(|_| Error::ArchiveIo)?;
        // Also sync a reused zero-length file's directory: a previous failed
        // append may have created its entry but not reached directory fsync.
        dir.sync_all().map_err(|_| Error::ArchiveIo)?;
        same_named(&dir, &name, &file)?;
        self.check_guard()?;
        #[cfg(feature = "archive-crash-controls")]
        crash_after_file_sync()?;
        Ok((
            Attempt {
                segment: r.segment,
                old_end: r.old_committed_end,
                new_end: end,
                entries,
            },
            file,
            dir,
            name,
        ))
    }
    pub(crate) fn read_object(
        &self,
        binding: &CatalogBinding,
        locator: &ObjectLocator,
    ) -> Result<Vec<u8>> {
        let result = self.read_object_inner(binding, locator);
        if result.is_err() {
            self.read_fault.set(true);
        }
        result
    }
    fn read_object_inner(
        &self,
        binding: &CatalogBinding,
        locator: &ObjectLocator,
    ) -> Result<Vec<u8>> {
        if !self.is_ready() {
            return Err(Error::HistoryUnavailable);
        }
        self.check_binding(binding)?;
        validate_locator(locator)?;
        if let Health::Ready(ready) = &self.health {
            if let Some(open) = ready.open {
                if locator.segment > open.segment
                    || (locator.segment == open.segment
                        && locator.committed_end != open.committed_end)
                {
                    return Err(Error::State);
                }
            }
        }
        let dir = self.segment_dir(locator.segment, false)?;
        let name = Self::segment_name(locator.segment)?;
        let file = open_regular_at(&dir, &name, libc::O_RDONLY, 0)?;
        if key(&file)?.device != self.root_key.device {
            return Err(Error::Identity);
        }
        let bytes = read_object_file(&file, &self.binding, locator)?;
        same_named(&dir, &name, &file)?;
        self.check_guard()?;
        Ok(bytes)
    }
}

/// This capability cannot outlive or release the exact LocalArchive lock. Root
/// keeps the exact Ledger reborrow beside it in PendingPublication.
pub(crate) struct DurableBatch<'io> {
    archive: &'io mut LocalArchive,
    attempt: Attempt,
    file: File,
    dir: File,
    name: CString,
    reservation: SegmentReservation,
    final_ready: Option<ReadyState>,
    settled: bool,
}
impl DurableBatch<'_> {
    pub(crate) fn binding(&self) -> &CatalogBinding {
        &self.archive.binding
    }
    pub(crate) fn segment(&self) -> u64 {
        self.attempt.segment
    }
    pub(crate) fn old_end(&self) -> u64 {
        self.attempt.old_end
    }
    pub(crate) fn new_end(&self) -> u64 {
        self.attempt.new_end
    }
    pub(crate) fn entries(&self) -> &[ObjectLocator] {
        &self.attempt.entries
    }
    pub(crate) fn objects(&self) -> &[ObjectLocator] {
        &self.attempt.entries
    }
    pub(crate) fn reservation(&self) -> &SegmentReservation {
        &self.reservation
    }
    /// Segment delta, including first header and each record header, not full-only bytes.
    pub(crate) fn raw_bytes(&self) -> u64 {
        self.attempt.new_end - self.attempt.old_end
    }
    /// Optional final fallible preflight BEFORE Root starts SQL publication.
    pub(crate) fn validate_for_publication(&self) -> Result<()> {
        self.archive.check_guard()?;
        same_named(&self.dir, &self.name, &self.file)?;
        if !matches!(self.archive.health, Health::Pending)
            || self.file.metadata().map_err(|_| Error::ArchiveIo)?.len() != self.attempt.new_end
        {
            return Err(Error::ArchiveCorrupt);
        }
        Ok(())
    }
    /// Call ONLY after confirmed SQL commit, never after absent/lost ACK.
    pub(crate) fn settle_committed(mut self) {
        // All arithmetic/IO was checked BEFORE publication. No error after SQL
        // commit may masquerade as an unchanged failed operation. The fallback
        // is fail-closed for a future internal invariant bug, never Ready.
        self.archive.health = match self.final_ready.take() {
            Some(ready) => Health::Ready(ready),
            None => Health::NeedsReconcile,
        };
        self.archive.last_attempt = None;
        self.settled = true;
    }
    /// Root must query this fresh matching view before any publication attempt.
    /// An attempted/uncertain publish consumes Pending; it cannot call abort.
    pub(crate) fn abort_with_view(mut self, view: &CatalogView) -> Result<IoReconcile> {
        if view.open.map(|s| (s.segment, s.committed_end))
            != Some((self.attempt.segment, self.attempt.old_end))
        {
            return Err(Error::State);
        }
        self.archive.health = Health::NeedsReconcile;
        let result = self.archive.reconcile_catalog(view);
        if result.is_ok() {
            self.settled = true;
        }
        result
    }
}
impl Drop for DurableBatch<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.archive.health = Health::NeedsReconcile;
        }
    }
}

// All names below are single components generated by this module, never sender input.
fn cstr(bytes: &'static [u8]) -> &'static CStr {
    // SAFETY: callers use source literals with exactly one trailing NUL.
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}
fn key(file: &File) -> Result<FileKey> {
    let m = file.metadata().map_err(|_| Error::ArchiveIo)?;
    Ok(FileKey {
        device: m.dev(),
        inode: m.ino(),
    })
}
fn regular(file: File) -> Result<File> {
    let m = file.metadata().map_err(|_| Error::ArchiveIo)?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(Error::ArchiveIo);
    }
    Ok(file)
}
fn valid_name(name: &CStr) -> Result<()> {
    let b = name.to_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(Error::ArchiveIo);
    }
    Ok(())
}
fn open_regular_at(dir: &File, name: &CStr, flags: i32, _mode: u32) -> Result<File> {
    valid_name(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(
            if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Error::HistoryUnavailable
            } else {
                Error::ArchiveIo
            },
        );
    }
    // SAFETY: openat returned a new owned descriptor; NONBLOCK precedes fstat so
    // a malicious FIFO cannot block before regular-file validation.
    regular(unsafe { File::from_raw_fd(fd) })
}
enum OpenFailure {
    Exists,
    Other(Error),
}
fn create_regular(dir: &File, name: &CStr, flags: i32) -> core::result::Result<File, OpenFailure> {
    valid_name(name).map_err(OpenFailure::Other)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(
            if io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                OpenFailure::Exists
            } else {
                OpenFailure::Other(Error::ArchiveIo)
            },
        );
    }
    regular(unsafe { File::from_raw_fd(fd) }).map_err(OpenFailure::Other)
}
fn create_or_open_regular(dir: &File, name: &CStr, flags: i32) -> Result<(File, bool)> {
    match create_regular(dir, name, flags) {
        Ok(f) => Ok((f, true)),
        Err(OpenFailure::Exists) => Ok((open_regular_at(dir, name, flags, 0)?, false)),
        Err(OpenFailure::Other(e)) => Err(e),
    }
}
fn child_directory(dir: &File, name: &CStr, create: bool) -> Result<File> {
    valid_name(name)?;
    if create {
        let status = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
        if status != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(Error::ArchiveIo);
        }
    }
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(
            if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Error::HistoryUnavailable
            } else {
                Error::ArchiveIo
            },
        );
    }
    let child = unsafe { File::from_raw_fd(fd) };
    if !child.metadata().map_err(|_| Error::ArchiveIo)?.is_dir() {
        return Err(Error::ArchiveIo);
    }
    same_named(dir, name, &child)?;
    // Reused links may be remnants of an interrupted initializer too. Every
    // create-mode walk establishes child metadata + its parent link before use.
    if create {
        child.sync_all().map_err(|_| Error::ArchiveIo)?;
        dir.sync_all().map_err(|_| Error::ArchiveIo)?;
    }
    Ok(child)
}
fn walk_directory(path: &Path, create: bool) -> Result<File> {
    if !path.is_absolute() {
        return Err(Error::ArchiveIo);
    }
    if path.as_os_str().as_bytes().len() > 4096 {
        return Err(Error::Capacity);
    }
    let fd = unsafe {
        libc::open(
            cstr(b"/\0").as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::ArchiveIo);
    }
    let mut dir = unsafe { File::from_raw_fd(fd) };
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(n) => {
                let name = CString::new(n.as_bytes()).map_err(|_| Error::ArchiveIo)?;
                dir = child_directory(&dir, &name, create)?;
            }
            _ => return Err(Error::ArchiveIo),
        }
    }
    Ok(dir)
}
fn parent_and_name(path: &Path) -> Result<(PathBuf, CString)> {
    if !path.is_absolute() {
        return Err(Error::Identity);
    }
    let parent = path.parent().ok_or(Error::Identity)?.to_path_buf();
    let name = CString::new(path.file_name().ok_or(Error::Identity)?.as_bytes())
        .map_err(|_| Error::Identity)?;
    valid_name(&name)?;
    Ok((parent, name))
}
fn same_named(dir: &File, name: &CStr, file: &File) -> Result<()> {
    valid_name(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(Error::Identity);
    }
    let st = unsafe { st.assume_init() };
    let m = file.metadata().map_err(|_| Error::ArchiveIo)?;
    if st.st_dev != m.dev()
        || st.st_ino != m.ino()
        || st.st_mode & libc::S_IFMT != m.mode() & libc::S_IFMT
    {
        return Err(Error::Identity);
    }
    if m.is_file() && (m.nlink() != 1 || st.st_nlink != 1) {
        return Err(Error::Identity);
    }
    Ok(())
}
fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: u64) -> Result<()> {
    while !bytes.is_empty() {
        match file.read_at(bytes, offset) {
            Ok(0) => return Err(Error::HistoryUnavailable),
            Ok(n) => {
                offset = offset.checked_add(n as u64).ok_or(Error::Capacity)?;
                bytes = &mut bytes[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::ArchiveIo),
        }
    }
    Ok(())
}
fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) -> Result<()> {
    while !bytes.is_empty() {
        match file.write_at(bytes, offset) {
            Ok(0) => return Err(Error::ArchiveIo),
            Ok(n) => {
                offset = offset.checked_add(n as u64).ok_or(Error::Capacity)?;
                bytes = &bytes[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::ArchiveIo),
        }
    }
    Ok(())
}
fn read_bounded(file: &File, cap: usize) -> Result<Vec<u8>> {
    let before = file.metadata().map_err(|_| Error::ArchiveIo)?;
    let n = usize::try_from(before.len()).map_err(|_| Error::Capacity)?;
    if n > cap {
        return Err(Error::ArchiveCorrupt);
    }
    let mut bytes = vec![0u8; n];
    read_exact_at(file, &mut bytes, 0)?;
    let after = file.metadata().map_err(|_| Error::ArchiveIo)?;
    if after.len() != before.len() || after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(Error::Identity);
    }
    Ok(bytes)
}
fn marker_bytes(binding: &CatalogBinding, root: FileKey) -> Result<Vec<u8>> {
    let path = binding.db_path.as_os_str().as_bytes();
    if path.len() > 4096 {
        return Err(Error::Capacity);
    }
    let mut b = Vec::with_capacity(176 + path.len());
    b.extend_from_slice(b"CPBIND03");
    b.extend_from_slice(&3u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&binding.chain);
    b.extend_from_slice(&binding.genesis);
    b.extend_from_slice(&binding.catalog_id);
    for v in [binding.db_device, binding.db_inode, root.device, root.inode] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&(path.len() as u32).to_le_bytes());
    b.extend_from_slice(path);
    Ok(b)
}
fn segment_header(binding: &CatalogBinding, segment: u64) -> [u8; 148] {
    let mut b = [0u8; 148];
    b[..8].copy_from_slice(b"CPARCH03");
    b[8..10].copy_from_slice(&3u16.to_le_bytes());
    b[12..44].copy_from_slice(&binding.chain);
    b[44..108].copy_from_slice(&binding.genesis);
    b[108..140].copy_from_slice(&binding.catalog_id);
    b[140..148].copy_from_slice(&segment.to_le_bytes());
    b
}
fn verify_header(file: &File, binding: &CatalogBinding, segment: u64) -> Result<()> {
    let mut header = [0u8; 148];
    read_exact_at(file, &mut header, 0)?;
    if header != segment_header(binding, segment) {
        return Err(Error::ArchiveCorrupt);
    }
    Ok(())
}
fn record_end(locator: &ObjectLocator) -> Result<u64> {
    locator
        .record_offset
        .checked_add(RECORD_HEADER_BYTES)
        .and_then(|v| v.checked_add(u64::from(locator.full_length)))
        .ok_or(Error::ArchiveCorrupt)
}
fn validate_locator(locator: &ObjectLocator) -> Result<()> {
    if locator.full_length == 0
        || locator.full_length as usize > cp03_history::BODY_MAX
        || locator.committed_end > SEGMENT_BYTES
        || locator.record_offset < SEGMENT_HEADER_BYTES
        || record_end(locator)? > locator.committed_end
    {
        return Err(Error::ArchiveCorrupt);
    }
    Ok(())
}
fn history_error(error: cp03_history::Error) -> Error {
    match error {
        cp03_history::Error::NativeHistoryHash(_) => Error::HistoryHashProvider,
        _ => Error::ArchiveCorrupt,
    }
}
fn validate_full(
    binding: &CatalogBinding,
    full: &[u8],
    id: [u8; 64],
    reduced: Option<&[u8]>,
) -> Result<()> {
    let parsed = cp03_history::body::parse_full(full).map_err(history_error)?;
    if parsed.body_id() != id || parsed.prefix().statement().chain != binding.chain {
        return Err(Error::ArchiveCorrupt);
    }
    if let Some(expected) = reduced {
        if parsed.reduced_bytes().map_err(history_error)? != expected {
            return Err(Error::ArchiveCorrupt);
        }
    }
    // Transport hashes/canonicality only. Historical cryptographic/source checks
    // and exact retained header membership remain Root's store admission path.
    Ok(())
}
fn read_object_file(
    file: &File,
    binding: &CatalogBinding,
    locator: &ObjectLocator,
) -> Result<Vec<u8>> {
    validate_locator(locator)?;
    let before = file.metadata().map_err(|_| Error::ArchiveIo)?;
    if before.len() < locator.committed_end {
        return Err(Error::HistoryUnavailable);
    }
    if before.len() > SEGMENT_BYTES {
        return Err(Error::ArchiveCorrupt);
    }
    verify_header(file, binding, locator.segment)?;
    let mut h = [0u8; 68];
    read_exact_at(file, &mut h, locator.record_offset)?;
    if h[..4] != locator.full_length.to_le_bytes() || h[4..] != locator.id {
        return Err(Error::ArchiveCorrupt);
    }
    let mut full = vec![0; locator.full_length as usize];
    read_exact_at(file, &mut full, locator.record_offset + RECORD_HEADER_BYTES)?;
    validate_full(binding, &full, locator.id, None)?;
    let after = file.metadata().map_err(|_| Error::ArchiveIo)?;
    if after.len() != before.len() || after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(Error::Identity);
    }
    Ok(full)
}
#[cfg(feature = "archive-crash-controls")]
fn crash_after_file_sync() -> Result<()> {
    use std::io::Write;
    if std::env::var_os("CP03_ARCHIVE_CRASH_POINT").is_some_and(|v| v == "before-publication") {
        let mut err = io::stderr().lock();
        err.write_all(b"CP03_ARCHIVE_CRASH_POINT before-publication\n")
            .map_err(|_| Error::ArchiveIo)?;
        err.flush().map_err(|_| Error::ArchiveIo)?;
        if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
            return Err(Error::ArchiveIo);
        }
    }
    Ok(())
}
