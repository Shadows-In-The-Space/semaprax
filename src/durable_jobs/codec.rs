//! Deterministic, bounded, fixed-layout encoding of a [`JobTable`]
//! generation snapshot.
//!
//! `semaprax.durable-jobs-generation.v1` uses little-endian integers
//! throughout, the same convention `src/job_runtime.rs`'s checkpoint
//! envelope (`semaprax.job-runtime-checkpoint.v1`) uses. Encoding never
//! consults a clock, an environment variable, or hash-map iteration order:
//! [`JobTable::jobs`] and [`JobTable::side_records`] are `BTreeMap`s, so
//! records are always written in ascending key order regardless of the
//! order callers inserted them in. Two stores driven through the identical
//! sequence of calls therefore produce byte-identical generation files;
//! `store::tests::identical_operation_sequences_produce_byte_identical_generations`
//! is the regression for that claim.
//!
//! Decoding is refused, not partially trusted, on any malformed, truncated,
//! or over-bound input: trailing bytes, a length prefix that would run past
//! the buffer, an unknown state code, or a table exceeding the bounds below
//! all return `None` rather than a best-effort partial table.

use std::collections::BTreeMap;

use super::model::{JobId, JobRecord, JobState, JobTable, Lease, RetryPolicy};

const MAGIC: &[u8; 8] = b"SPXDJ01\0";
pub const MAX_JOBS: usize = 4096;
pub const MAX_SIDE_RECORDS: usize = 4096;
pub const MAX_KEY_BYTES: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 1 << 20;
pub const MAX_ERROR_BYTES: usize = 4096;
pub const MAX_GENERATION_BYTES: usize = 64 << 20;

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
}

/// Encode a full table snapshot. Returns `None` if any bound above would be
/// exceeded, so a caller never silently writes a truncated or oversized
/// generation.
pub fn encode(table: &JobTable) -> Option<Vec<u8>> {
    if table.jobs.len() > MAX_JOBS || table.side_records.len() > MAX_SIDE_RECORDS {
        return None;
    }
    let mut w = Writer(Vec::new());
    w.0.extend_from_slice(MAGIC);
    w.u64(table.next_job_id);
    w.u32(table.jobs.len() as u32);
    for record in table.jobs.values() {
        if record.idempotency_key.len() > MAX_KEY_BYTES
            || record.payload.len() > MAX_PAYLOAD_BYTES
            || record.last_error.len() > MAX_ERROR_BYTES
        {
            return None;
        }
        w.u64(record.id.0);
        w.bytes(&record.idempotency_key);
        w.bytes(&record.payload);
        w.u8(record.state.code());
        w.u32(record.attempt);
        w.u64(record.lease_epoch);
        w.u32(record.retry_policy.max_attempts);
        w.u64(record.retry_policy.base_backoff_ticks);
        w.u64(record.retry_policy.max_backoff_ticks);
        match record.lease {
            Some(lease) => {
                w.u8(1);
                w.u64(lease.worker_id);
                w.u64(lease.generation);
                w.u64(lease.deadline_tick);
            }
            None => w.u8(0),
        }
        w.u64(record.created_at_tick);
        w.bytes(&record.last_error);
    }
    w.u32(table.side_records.len() as u32);
    for (key, value) in &table.side_records {
        if key.len() > MAX_KEY_BYTES || value.len() > MAX_PAYLOAD_BYTES {
            return None;
        }
        w.bytes(key);
        w.bytes(value);
    }
    if w.0.len() > MAX_GENERATION_BYTES {
        return None;
    }
    Some(w.0)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self, max: usize) -> Option<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > max {
            return None;
        }
        Some(self.take(len)?.to_vec())
    }
}

/// Decode a generation snapshot, refusing anything malformed, truncated, or
/// carrying trailing bytes after the last declared field.
pub fn decode(bytes: &[u8]) -> Option<JobTable> {
    if bytes.len() > MAX_GENERATION_BYTES {
        return None;
    }
    let mut r = Reader::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return None;
    }
    let next_job_id = r.u64()?;
    let job_count = r.u32()? as usize;
    if job_count > MAX_JOBS {
        return None;
    }
    let mut jobs = BTreeMap::new();
    for _ in 0..job_count {
        let id = JobId(r.u64()?);
        let idempotency_key = r.bytes(MAX_KEY_BYTES)?;
        let payload = r.bytes(MAX_PAYLOAD_BYTES)?;
        let state = JobState::from_code(r.u8()?)?;
        let attempt = r.u32()?;
        let lease_epoch = r.u64()?;
        let max_attempts = r.u32()?;
        let base_backoff_ticks = r.u64()?;
        let max_backoff_ticks = r.u64()?;
        let lease = match r.u8()? {
            0 => None,
            1 => Some(Lease {
                worker_id: r.u64()?,
                generation: r.u64()?,
                deadline_tick: r.u64()?,
            }),
            _ => return None,
        };
        let created_at_tick = r.u64()?;
        let last_error = r.bytes(MAX_ERROR_BYTES)?;
        let record = JobRecord {
            id,
            idempotency_key,
            payload,
            state,
            attempt,
            lease_epoch,
            retry_policy: RetryPolicy::new(max_attempts, base_backoff_ticks, max_backoff_ticks),
            lease,
            created_at_tick,
            last_error,
        };
        if jobs.insert(id, record).is_some() {
            // Duplicate job id: corrupt, refuse rather than silently
            // overwrite an earlier record with a later one.
            return None;
        }
    }
    let side_count = r.u32()? as usize;
    if side_count > MAX_SIDE_RECORDS {
        return None;
    }
    let mut side_records = BTreeMap::new();
    for _ in 0..side_count {
        let key = r.bytes(MAX_KEY_BYTES)?;
        let value = r.bytes(MAX_PAYLOAD_BYTES)?;
        if side_records.insert(key, value).is_some() {
            return None;
        }
    }
    if r.pos != r.bytes.len() {
        return None; // trailing bytes are refused, never ignored.
    }
    Some(JobTable {
        next_job_id,
        jobs,
        side_records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_jobs::model::JobId;

    fn sample_table() -> JobTable {
        let mut jobs = BTreeMap::new();
        jobs.insert(
            JobId(1),
            JobRecord {
                id: JobId(1),
                idempotency_key: b"key-a".to_vec(),
                payload: b"payload-a".to_vec(),
                state: JobState::Pending,
                attempt: 0,
                lease_epoch: 0,
                retry_policy: RetryPolicy::new(3, 10, 100),
                lease: None,
                created_at_tick: 42,
                last_error: Vec::new(),
            },
        );
        jobs.insert(
            JobId(2),
            JobRecord {
                id: JobId(2),
                idempotency_key: b"key-b".to_vec(),
                payload: b"payload-b".to_vec(),
                state: JobState::Leased,
                attempt: 1,
                lease_epoch: 1,
                retry_policy: RetryPolicy::new(5, 20, 200),
                lease: Some(Lease {
                    worker_id: 7,
                    generation: 3,
                    deadline_tick: 99,
                }),
                created_at_tick: 43,
                last_error: b"boom".to_vec(),
            },
        );
        let mut side_records = BTreeMap::new();
        side_records.insert(b"app-counter".to_vec(), b"1".to_vec());
        JobTable {
            next_job_id: 3,
            jobs,
            side_records,
        }
    }

    #[test]
    fn round_trips_a_table_with_leases_errors_and_side_records() {
        let table = sample_table();
        let bytes = encode(&table).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, table);
    }

    #[test]
    fn encoding_is_deterministic_across_repeated_calls() {
        let table = sample_table();
        let a = encode(&table).unwrap();
        let b = encode(&table).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_table_round_trips() {
        let table = JobTable::default();
        let bytes = encode(&table).unwrap();
        assert_eq!(decode(&bytes).unwrap(), table);
    }

    #[test]
    fn decode_refuses_bad_magic() {
        let mut bytes = encode(&sample_table()).unwrap();
        bytes[0] = b'X';
        assert!(decode(&bytes).is_none());
    }

    #[test]
    fn decode_refuses_truncated_input() {
        let bytes = encode(&sample_table()).unwrap();
        for cut in [0, 1, 8, 9, bytes.len() - 1] {
            assert!(decode(&bytes[..cut]).is_none(), "cut={cut}");
        }
    }

    #[test]
    fn decode_refuses_trailing_bytes() {
        let mut bytes = encode(&sample_table()).unwrap();
        bytes.push(0);
        assert!(decode(&bytes).is_none());
    }

    #[test]
    fn decode_refuses_an_unknown_state_code() {
        let table = sample_table();
        let bytes = encode(&table).unwrap();
        // Locate and corrupt the first record's state-code byte by
        // re-encoding a single-job table with a known offset instead of
        // guessing byte positions in the two-job sample.
        let mut single = BTreeMap::new();
        single.insert(JobId(1), table.jobs[&JobId(1)].clone());
        let solo = JobTable {
            next_job_id: 2,
            jobs: single,
            side_records: BTreeMap::new(),
        };
        let mut solo_bytes = encode(&solo).unwrap();
        // magic(8) + next_job_id(8) + job_count(4) + id(8) + key len(4) + key(5)
        // + payload len(4) + payload(9) = 50, then the state-code byte.
        let state_offset = 8 + 8 + 4 + 8 + 4 + 5 + 4 + 9;
        assert_eq!(solo_bytes[state_offset], JobState::Pending.code());
        solo_bytes[state_offset] = 200;
        assert!(decode(&solo_bytes).is_none());
        let _ = bytes; // keep the two-job sample's encode exercised above too
    }

    #[test]
    fn decode_refuses_a_duplicate_job_id() {
        // Hand-encode two records sharing id 1: valid framing, illegal
        // content.
        let mut w = Writer(Vec::new());
        w.0.extend_from_slice(MAGIC);
        w.u64(2);
        w.u32(2);
        for _ in 0..2 {
            w.u64(1); // same id twice
            w.bytes(b"k");
            w.bytes(b"p");
            w.u8(JobState::Pending.code());
            w.u32(0); // attempt
            w.u64(0); // lease_epoch
            w.u32(3); // max_attempts
            w.u64(10);
            w.u64(100);
            w.u8(0);
            w.u64(0);
            w.bytes(b"");
        }
        w.u32(0);
        assert!(decode(&w.0).is_none());
    }

    #[test]
    fn encode_refuses_a_payload_over_the_bound() {
        let mut table = JobTable::default();
        table.next_job_id = 1;
        table.jobs.insert(
            JobId(0),
            JobRecord {
                id: JobId(0),
                idempotency_key: Vec::new(),
                payload: vec![0u8; MAX_PAYLOAD_BYTES + 1],
                state: JobState::Pending,
                attempt: 0,
                lease_epoch: 0,
                retry_policy: RetryPolicy::new(1, 1, 1),
                lease: None,
                created_at_tick: 0,
                last_error: Vec::new(),
            },
        );
        assert!(encode(&table).is_none());
    }
}
