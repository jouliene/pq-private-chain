//! Auxiliary common-history framing, not a checkpoint or payment-validity proof.
use crate::{Error, Head, Result, encoding::{field_bytes, fields}};
use compact_arities_v3::statement::MAX;
use std::io::{self, Write};

pub const CONTINUATION_HEADER_BYTES: usize = 436;
const REQUEST: &[u8; 8] = b"CPHREQ01";
const RESPONSE: &[u8; 8] = b"CPHCONT1";

/// Public common range. Only a wallet's own committed joint state can authorize
/// its base; decoding these bytes does not confer that authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationRequest {
    pub block_version: u16,
    pub chain: [u8; 32],
    pub genesis_id: [u8; 64],
    pub base: Head,
    pub target: Head,
}
impl ContinuationRequest {
    pub fn frame_count(&self) -> Result<u64> {
        self.target.height.checked_sub(self.base.height).ok_or(Error::Codec)
    }
    pub fn validate(&self) -> Result<()> {
        if ![3, 4].contains(&self.block_version) { return Err(Error::Codec); }
        let count = self.frame_count()?;
        for h in [&self.base, &self.target] {
            fields(&field_bytes(&h.root))?;
            if h.height > i64::MAX as u64 || h.leaf_count > 1u64 << 40
                || h.fees > MAX || h.liabilities > MAX
                || (h.height == 0 && (h.id != self.genesis_id || h.leaf_count != 0 || h.fees != 0)) {
                return Err(Error::Codec);
            }
        }
        if count == 0 && self.base != self.target { return Err(Error::Identity); }
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONTINUATION_HEADER_BYTES || &bytes[..8] != REQUEST
            || bytes[8..10] != 1u16.to_le_bytes() { return Err(Error::Codec); }
        let value = Self {
            block_version: u16::from_le_bytes(bytes[10..12].try_into().map_err(|_| Error::Codec)?),
            chain: bytes[12..44].try_into().map_err(|_| Error::Codec)?,
            genesis_id: bytes[44..108].try_into().map_err(|_| Error::Codec)?,
            base: decode_cursor(&bytes[108..268])?,
            target: decode_cursor(&bytes[268..428])?,
        };
        value.validate()?;
        if u64::from_le_bytes(bytes[428..436].try_into().map_err(|_| Error::Codec)?) != value.frame_count()? {
            return Err(Error::Codec);
        }
        Ok(value)
    }
    pub fn encode(&self) -> Result<[u8; CONTINUATION_HEADER_BYTES]> { self.header(REQUEST) }
    pub fn response_header(&self) -> Result<[u8; CONTINUATION_HEADER_BYTES]> { self.header(RESPONSE) }
    fn header(&self, magic: &[u8; 8]) -> Result<[u8; CONTINUATION_HEADER_BYTES]> {
        self.validate()?;
        let mut out = [0; CONTINUATION_HEADER_BYTES];
        out[..8].copy_from_slice(magic); out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[10..12].copy_from_slice(&self.block_version.to_le_bytes());
        out[12..44].copy_from_slice(&self.chain); out[44..108].copy_from_slice(&self.genesis_id);
        encode_cursor(&mut out[108..268], self.base); encode_cursor(&mut out[268..428], self.target);
        out[428..436].copy_from_slice(&self.frame_count()?.to_le_bytes());
        Ok(out)
    }
}
fn decode_cursor(b: &[u8]) -> Result<Head> {
    if b.len() != 160 { return Err(Error::Codec); }
    let n = |at| u64::from_le_bytes(b[at..at + 8].try_into().expect("fixed cursor bounds"));
    Ok(Head { height: n(0), id: b[8..72].try_into().map_err(|_| Error::Codec)?,
        leaf_count: n(72), root: fields(&b[80..144])?, fees: n(144), liabilities: n(152) })
}
fn encode_cursor(b: &mut [u8], h: Head) {
    b[..8].copy_from_slice(&h.height.to_le_bytes()); b[8..72].copy_from_slice(&h.id);
    b[72..80].copy_from_slice(&h.leaf_count.to_le_bytes()); b[80..144].copy_from_slice(&field_bytes(&h.root));
    b[144..152].copy_from_slice(&h.fees.to_le_bytes()); b[152..160].copy_from_slice(&h.liabilities.to_le_bytes());
}

/// Selected history values fetched during trusted-local Ledger::open_counted.
/// Counts are SQL result values, not disk pages, allocator traffic or runtime pins.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StartupHistoryReads {
    pub tip_header_rows: u64,
    pub tip_header_bytes: u64,
    pub tip_body_length_rows: u64,
}

/// Exact successful SQL result rows/blob bytes and writer bytes for one range.
/// Metadata/base/target reads are separate from streamed history. SQL fullscan
/// steps refer only to the measured header/reduced-record SELECT statements.
/// These are not physical disk I/O bytes. Failed operations retain these counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationReads {
    pub snapshot_meta_rows: u64,
    pub base_header_rows: u64,
    pub base_header_bytes: u64,
    pub target_header_rows: u64,
    pub target_header_bytes: u64,
    pub history_header_rows: u64,
    pub history_header_bytes: u64,
    pub reduced_record_rows: u64,
    pub reduced_record_bytes: u64,
    pub sqlite_fullscan_steps: u64,
    pub history_frame_bytes: u64,
    pub response_bytes_written: u64,
}
pub(crate) fn add(value: &mut u64, n: usize) -> Result<()> {
    *value = value.checked_add(u64::try_from(n).map_err(|_| Error::Capacity)?).ok_or(Error::Capacity)?;
    Ok(())
}
pub(crate) struct CountedWriter<'a, W> { pub inner: &'a mut W, pub written: u64 }
impl<W: Write> Write for CountedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.written = self.written.checked_add(n as u64)
            .ok_or_else(|| io::Error::other("continuation byte counter overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}
