//! Checkpoints bound to an exact workflow revision.
//!
//! A [`Checkpoint`] records the minimum needed to resume: which revision
//! compiled it, which step to resume at, a monotonic sequence number, and a
//! snapshot of the [`super::compensation::CompensationLedger`] (so resuming
//! cannot re-run a compensation, per that module's guarantee). It never
//! carries live capabilities, grants, secrets, or transport handles — there
//! is no field for any of those, by construction, matching the repository
//! invariant that those are never serialized.
//!
//! This is an in-memory structural model, not a byte-level wire format;
//! [`Checkpoint`] is not `Serialize`/`Deserialize` here and defines no
//! encoding. A schema-versioned on-disk or on-wire checkpoint format is out
//! of scope for this module and would need its own versioned spec,
//! independent decoder, and hostile-input tests per the repository's change
//! protocol for new wire formats.
//!
//! [`Checkpoint::resume`] fails closed on any drift: a revision mismatch or
//! a corrupted snapshot never resumes at the recorded step "anyway" with a
//! warning — it refuses.

use super::compensation::CompensationLedger;
use super::graph::StepId;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RevisionId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    revision: RevisionId,
    step: StepId,
    sequence: u64,
    ledger_snapshot: Vec<(u32, u64)>,
    digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    RevisionDrift,
    Corrupt,
    /// Migration named a step the checkpoint was not actually resting on,
    /// or omitted a mapping for it.
    IncompatibleStep,
}

fn digest_of(
    revision: RevisionId,
    step: StepId,
    sequence: u64,
    ledger_snapshot: &[(u32, u64)],
) -> u64 {
    let mut hasher = DefaultHasher::new();
    revision.hash(&mut hasher);
    step.hash(&mut hasher);
    sequence.hash(&mut hasher);
    ledger_snapshot.hash(&mut hasher);
    hasher.finish()
}

impl Checkpoint {
    #[must_use]
    pub fn new(
        revision: RevisionId,
        step: StepId,
        sequence: u64,
        ledger: &CompensationLedger,
    ) -> Self {
        let ledger_snapshot = ledger.snapshot();
        let digest = digest_of(revision, step, sequence, &ledger_snapshot);
        Self {
            revision,
            step,
            sequence,
            ledger_snapshot,
            digest,
        }
    }

    #[must_use]
    pub fn revision(&self) -> RevisionId {
        self.revision
    }

    #[must_use]
    pub fn step(&self) -> StepId {
        self.step
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    fn is_intact(&self) -> bool {
        self.digest
            == digest_of(
                self.revision,
                self.step,
                self.sequence,
                &self.ledger_snapshot,
            )
    }

    /// Resume at this checkpoint's recorded step, only if `expected_revision`
    /// matches exactly and the snapshot has not drifted from its digest.
    /// Returns the resume step, sequence, and a rebuilt compensation ledger
    /// that already knows about every compensation this run had applied.
    pub fn resume(
        &self,
        expected_revision: RevisionId,
    ) -> Result<(StepId, u64, CompensationLedger), CheckpointError> {
        if self.revision != expected_revision {
            return Err(CheckpointError::RevisionDrift);
        }
        if !self.is_intact() {
            return Err(CheckpointError::Corrupt);
        }
        Ok((
            self.step,
            self.sequence,
            CompensationLedger::restore(&self.ledger_snapshot),
        ))
    }

    /// Migrate this checkpoint from `from` to `to`, remapping its resume
    /// step through `step_map`. Fails closed (never guesses) if this
    /// checkpoint's own revision is not `from`, or if `step_map` has no
    /// entry for this checkpoint's exact step.
    pub fn migrate(
        &self,
        from: RevisionId,
        to: RevisionId,
        step_map: &[(StepId, StepId)],
    ) -> Result<Checkpoint, CheckpointError> {
        if self.revision != from {
            return Err(CheckpointError::RevisionDrift);
        }
        if !self.is_intact() {
            return Err(CheckpointError::Corrupt);
        }
        let Some(&(_, mapped)) = step_map.iter().find(|(old, _)| *old == self.step) else {
            return Err(CheckpointError::IncompatibleStep);
        };
        let ledger_snapshot = self.ledger_snapshot.clone();
        let digest = digest_of(to, mapped, self.sequence, &ledger_snapshot);
        Ok(Checkpoint {
            revision: to,
            step: mapped,
            sequence: self.sequence,
            ledger_snapshot,
            digest,
        })
    }

    /// Test-only corruption injection: returns a checkpoint whose stored
    /// digest no longer matches its content, simulating storage-layer
    /// corruption without needing a real byte-level encoding to bit-flip.
    #[cfg(test)]
    fn corrupted(mut self) -> Self {
        self.digest ^= 1;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_workflow::compensation::CompensationKey;

    #[test]
    fn resume_at_matching_revision_succeeds() {
        let mut ledger = CompensationLedger::new();
        ledger.apply(
            CompensationKey {
                step: StepId(2),
                run: 1,
            },
            || {},
        );
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);

        let (step, sequence, restored) = checkpoint
            .resume(RevisionId(1))
            .expect("matching revision resumes");
        assert_eq!(step, StepId(4));
        assert_eq!(sequence, 3);
        assert!(restored.is_applied(CompensationKey {
            step: StepId(2),
            run: 1
        }));
    }

    #[test]
    fn resume_fails_closed_on_revision_drift() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        assert_eq!(
            checkpoint.resume(RevisionId(2)),
            Err(CheckpointError::RevisionDrift)
        );
    }

    #[test]
    fn resume_fails_closed_on_corruption() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger).corrupted();
        assert_eq!(
            checkpoint.resume(RevisionId(1)),
            Err(CheckpointError::Corrupt)
        );
    }

    #[test]
    fn migrate_to_a_mapped_step_resumes_under_the_new_revision() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        let migrated = checkpoint
            .migrate(RevisionId(1), RevisionId(2), &[(StepId(4), StepId(40))])
            .expect("mapped step migrates");
        let (step, _, _) = migrated
            .resume(RevisionId(2))
            .expect("migrated checkpoint resumes under new revision");
        assert_eq!(step, StepId(40));
        // The old revision no longer resumes this migrated checkpoint.
        assert_eq!(
            migrated.resume(RevisionId(1)),
            Err(CheckpointError::RevisionDrift)
        );
    }

    #[test]
    fn migrate_without_a_mapping_for_the_actual_step_fails_closed() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        let result = checkpoint.migrate(RevisionId(1), RevisionId(2), &[(StepId(5), StepId(50))]);
        assert_eq!(result, Err(CheckpointError::IncompatibleStep));
    }

    #[test]
    fn migrate_from_the_wrong_source_revision_fails_closed() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        let result = checkpoint.migrate(RevisionId(9), RevisionId(2), &[(StepId(4), StepId(40))]);
        assert_eq!(result, Err(CheckpointError::RevisionDrift));
    }
}
