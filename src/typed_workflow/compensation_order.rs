//! Compensation-order proof: a workflow's compensations must replay in the
//! exact reverse of the order their originating steps committed, and that
//! claim is checked as inert proof data rather than as permission to run
//! anything.
//!
//! [`CommitLog`] records which step (for which run) committed an effect
//! that now needs compensating, strictly in the order [`CommitLog::record`]
//! is called — appended, never sorted, mirroring the repository's cleanup-
//! plan invariant ("Cleanup inventory order is structural metadata... must
//! never be sorted or repaired downstream") applied here to compensation
//! commit order instead. [`CommitLog::compensation_order`] derives the
//! required replay order from that log by reversing it, and returns a
//! [`CompensationOrderProof`]: a plain data value with a deterministic
//! canonical byte encoding ([`CompensationOrderProof::canonical_bytes`])
//! and two checks, [`CompensationOrderProof::verify_prefix`] and
//! [`CompensationOrderProof::verify_complete`], that compare a caller's
//! *actual* replay order against the required one and fail closed on any
//! divergence — out-of-order, missing, extra, or duplicated entries are all
//! refused rather than silently accepted or repaired.
//!
//! Per the repository invariant "a settlement or concurrency model is proof
//! data, not permission to perform a physical finalizer, spawn runtime
//! work, or publish an artifact," nothing in this module executes a
//! compensation, calls [`super::compensation::CompensationLedger::apply`],
//! or accepts a runnable effect of any kind — every function here is a pure
//! function from data to data or to a verification result. A caller is
//! expected to consult [`CompensationOrderProof::verify_prefix`] *before*
//! invoking its own compensation effect for the next step, using this
//! module's answer only as a check, never as the thing that performs the
//! compensation.
//!
//! Like [`super::checkpoint`]'s explicit choice not to define a versioned
//! wire format, [`CompensationOrderProof::canonical_bytes`] is a canonical
//! *encoding* for equality, hashing, and audit comparison — not a
//! self-describing wire format with an independent decoder. Persisting this
//! proof across a process boundary would need its own versioned spec,
//! decoder, and hostile-input tests per the repository's change protocol;
//! that is out of scope here.

use super::graph::StepId;

/// One step's effect becoming durable enough to require compensation,
/// recorded at the instant of commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitRecord {
    pub step: StepId,
    pub run: u64,
}

/// Append-only record of commits, in exactly the order [`CommitLog::record`]
/// was called. Never sorted, never deduplicated: the same `(step, run)`
/// pair may legitimately appear more than once if a step's effect commits
/// more than once within a run, and a caller relying on this log for
/// compensation ordering needs every one of those commits to get its own
/// reverse-ordered slot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitLog {
    commits: Vec<CommitRecord>,
}

impl CommitLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one commit to the end of the log. Never reorders or merges
    /// with an existing entry, even one for the same `(step, run)`.
    pub fn record(&mut self, step: StepId, run: u64) {
        self.commits.push(CommitRecord { step, run });
    }

    /// The commits in exactly the order they were recorded.
    #[must_use]
    pub fn commits(&self) -> &[CommitRecord] {
        &self.commits
    }

    /// Derives the required compensation order: the exact reverse of commit
    /// order. This is a structural reversal of the recorded sequence, never
    /// a sort by [`StepId`] or `run` — two logs holding the same set of
    /// commits but recorded in different call orders produce different
    /// proofs, because the order itself is the fact being proven.
    #[must_use]
    pub fn compensation_order(&self) -> CompensationOrderProof {
        let mut required = self.commits.clone();
        required.reverse();
        CompensationOrderProof { required }
    }
}

/// One divergence between a required compensation order and an actual
/// (proposed or completed) replay order. Fails closed: any of these stops
/// the replay being treated as valid, rather than being patched over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderViolation {
    /// `actual` replayed something other than the record required at
    /// `index`.
    OutOfOrder {
        index: usize,
        expected: CommitRecord,
        actual: CommitRecord,
    },
    /// The replay is longer than the required order: an entry at `index`
    /// (zero-based, at or past the required length) has no corresponding
    /// commit to compensate, whether it is a genuine extra, a duplicate of
    /// an already-replayed entry, or anything else the log never
    /// committed.
    Extraneous(usize),
    /// The replay is a correct but incomplete prefix of the required
    /// order: `completed` records were replayed and matched, but
    /// `required` were needed for this to count as a full, valid
    /// compensation of the run.
    Incomplete { completed: usize, required: usize },
}

/// Inert proof data: the exact sequence of `(step, run)` pairs a
/// compensating replay must follow, derived once by
/// [`CommitLog::compensation_order`]. Carries no authority — it holds no
/// effect, closure, or handle capable of running anything, only the data a
/// caller checks its own replay against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompensationOrderProof {
    required: Vec<CommitRecord>,
}

impl CompensationOrderProof {
    /// The full required replay order, exactly as derived: reverse of
    /// commit order, unsorted, un-deduplicated.
    #[must_use]
    pub fn required(&self) -> &[CommitRecord] {
        &self.required
    }

    /// Deterministic canonical byte encoding of the required order: each
    /// record contributes its step id as 4 big-endian bytes followed by its
    /// run as 8 big-endian bytes, concatenated in required order with no
    /// separator. Two calls against the same proof, in the same process or
    /// a different one, always produce identical bytes; two proofs whose
    /// required orders differ — including two proofs over the same set of
    /// records in a different order — always produce different bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.required.len() * 12);
        for record in &self.required {
            bytes.extend_from_slice(&record.step.0.to_be_bytes());
            bytes.extend_from_slice(&record.run.to_be_bytes());
        }
        bytes
    }

    /// Checks that `attempted` — the records compensated so far, in the
    /// exact order they were actually replayed — is a valid *prefix* of the
    /// required order. Fails closed on the first divergence rather than
    /// scanning for a best match: a replay that gets record zero right and
    /// record one wrong is refused at index one, not silently accepted
    /// because most of it matched.
    pub fn verify_prefix(&self, attempted: &[CommitRecord]) -> Result<(), OrderViolation> {
        for (index, actual) in attempted.iter().enumerate() {
            match self.required.get(index) {
                None => return Err(OrderViolation::Extraneous(index)),
                Some(expected) if expected == actual => {}
                Some(expected) => {
                    return Err(OrderViolation::OutOfOrder {
                        index,
                        expected: *expected,
                        actual: *actual,
                    })
                }
            }
        }
        Ok(())
    }

    /// Checks that `attempted` is the *entire* required order: a valid
    /// prefix per [`Self::verify_prefix`] that additionally accounts for
    /// every required record, no more and no fewer.
    pub fn verify_complete(&self, attempted: &[CommitRecord]) -> Result<(), OrderViolation> {
        self.verify_prefix(attempted)?;
        if attempted.len() < self.required.len() {
            return Err(OrderViolation::Incomplete {
                completed: attempted.len(),
                required: self.required.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
