//! Checkpoint-store adapter for the generic durable policy journal v3.
//!
//! The caller owns storage and recovery bytes.  Every `intent` checkpoint is
//! committed before adapter construction; a settlement checkpoint failure
//! leaves that durable intent unresolved and therefore non-retryable.

use crate::agent_lifecycle::{CheckpointStore, CheckpointStoreError};
use crate::model_budget_policy::retry::{AdapterAttemptResult, RetryAttemptJournal};
use crate::model_budget_policy::AttemptReservation;

use crate::live_invocation::policy_journal::{PolicyAttemptOutcome, PolicyJournalError};

use crate::live_invocation::policy_journal_v3::PolicyJournalV3;

pub(crate) struct PolicyCheckpointJournalV3<'a> {
    store: &'a mut dyn CheckpointStore,
    journal: PolicyJournalV3,
    generation: u64,
}

impl<'a> PolicyCheckpointJournalV3<'a> {
    pub(crate) fn new(store: &'a mut dyn CheckpointStore, journal: PolicyJournalV3) -> Self {
        Self {
            store,
            journal,
            generation: 0,
        }
    }

    pub(crate) fn resume(
        store: &'a mut dyn CheckpointStore,
        journal: PolicyJournalV3,
        generation: u64,
    ) -> Self {
        Self {
            store,
            journal,
            generation,
        }
    }

    pub(crate) fn journal(&self) -> &PolicyJournalV3 {
        &self.journal
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    fn persist(&mut self) -> Result<(), String> {
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| "policy_generation_overflow".to_owned())?;
        self.store
            .commit(next, &self.journal.render().map_err(journal_error)?)
            .map_err(store_error)?;
        self.generation = next;
        Ok(())
    }
}

impl RetryAttemptJournal for PolicyCheckpointJournalV3<'_> {
    fn intent(&mut self, reservation: &AttemptReservation) -> Result<(), String> {
        self.journal
            .append_intent(reservation.clone())
            .map_err(journal_error)?;
        self.persist()
    }

    fn settled(
        &mut self,
        reservation: &AttemptReservation,
        result: &AdapterAttemptResult,
    ) -> Result<(), String> {
        let outcome = match result {
            AdapterAttemptResult::Settled {
                response_bytes,
                usage,
            } => PolicyAttemptOutcome::Settled {
                response: response_bytes.clone(),
                usage: *usage,
            },
            AdapterAttemptResult::Failed {
                classification,
                attempted_bytes,
                ..
            } => PolicyAttemptOutcome::Failed {
                class: *classification,
                attempted_bytes: *attempted_bytes,
            },
        };
        self.journal
            .append_outcome(reservation.ordinal, outcome)
            .map_err(journal_error)?;
        self.persist()
    }
}

fn store_error(_: CheckpointStoreError) -> String {
    "policy_checkpoint_failed".to_owned()
}
fn journal_error(error: PolicyJournalError) -> String {
    format!("policy_journal_{error:?}")
}
