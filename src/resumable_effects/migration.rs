//! Pure state migration between compatible `ProgramRoot` revisions (issue
//! #204's implementation-sequence step 7 and its "Checkpoint serialization
//! and state migration" scope bullet), for the exact reference-level
//! `State` types [`super::core::ResumableEffectProgram`] already fixes.
//!
//! # The pattern this mirrors
//!
//! `execution_revision::typed_migration` and `live_invocation::migration`
//! already prove the shape a real checked migration takes for actual HIR
//! locals: evaluate a pure migration function twice, reject disagreement,
//! carry cumulative budget forward. This module proves the identical shape
//! at the reference level, for an arbitrary caller-chosen `State` pair,
//! rather than adding a second, divergent migration story once real
//! checked state types exist to migrate between (the exact duplication
//! `docs/RESUMABLE-EFFECTS-V1.md`'s scope boundary warns against).
//!
//! Only a *suspended* computation is a migration candidate: `Complete` and
//! `Fail` are already-settled terminals with nothing left to carry forward,
//! and a fresh `Continue` never escapes `run`/`resume` as an `Outcome`.
//! Migrating in place (the same `program_root` on both sides) is refused,
//! not silently accepted as a no-op: this module is for moving a suspended
//! computation across a revision boundary, and an unchanged root should
//! resume through the ordinary [`super::core::resume`] driver instead,
//! where journal replay -- not migration -- is the correct evidence path.

use super::core::{EffectScope, Outcome, ResumableEffectProgram, Step};

/// A pure, deterministic migration from one program revision's suspended
/// `State` to a successor revision's own `State`. Must be a pure function
/// of `state` alone: the driver below calls it twice and rejects any
/// disagreement rather than ever trusting a single evaluation.
pub trait StateMigration<From: ResumableEffectProgram, To: ResumableEffectProgram> {
    /// Attempt the migration. `Err` rejects an incompatible state change
    /// with a caller-chosen, stable reason (never a panic).
    fn migrate(&self, state: &From::State) -> Result<To::State, String>;
}

/// A successfully migrated suspended state, plus the old revision's
/// cumulative dispatch count carried forward rather than silently reset to
/// zero at the migration boundary.
#[derive(Clone, Debug)]
pub struct MigratedState<To: ResumableEffectProgram> {
    pub state: To::State,
    /// The old revision's [`Outcome::dispatched`] count immediately before
    /// migration.
    pub carried_dispatched: u32,
}

/// Why a migration attempt was refused before its result was trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationError {
    /// The source outcome's terminal was not `Suspend`; there is nothing
    /// live to migrate.
    NotSuspended,
    /// `old_scope` and `new_scope` named the same `program_root`: this is
    /// not a revision boundary, so [`super::core::resume`] is the correct
    /// path, not migration.
    SameProgramRoot,
    /// The migration function itself rejected this state as incompatible.
    Rejected(String),
    /// The migration function was evaluated twice and disagreed with
    /// itself: it is not the pure function this mechanism requires, so its
    /// result is untrusted regardless of which evaluation might have been
    /// "right".
    Disagreement,
}

/// Migrate a suspended computation's state across a `ProgramRoot` revision
/// boundary. Evaluates `migration.migrate` twice against the identical
/// input and rejects any disagreement before returning either result,
/// mirroring the checked-migration pattern named above. This function
/// itself performs no dispatch and mints no effect authority: its result
/// is a new `State` value a caller must still drive through the ordinary
/// [`super::core::run`]/[`super::core::resume`] machinery, under a freshly
/// derived scope, to actually resume work.
pub fn migrate_suspended<From, To, M>(
    migration: &M,
    outcome: &Outcome<From>,
    old_scope: &EffectScope,
    new_scope: &EffectScope,
) -> Result<MigratedState<To>, MigrationError>
where
    From: ResumableEffectProgram,
    To: ResumableEffectProgram,
    M: StateMigration<From, To>,
{
    let Step::Suspend(state) = &outcome.terminal else {
        return Err(MigrationError::NotSuspended);
    };
    if old_scope.program_root == new_scope.program_root {
        return Err(MigrationError::SameProgramRoot);
    }
    let first = migration.migrate(state).map_err(MigrationError::Rejected)?;
    let second = migration.migrate(state).map_err(MigrationError::Rejected)?;
    if first != second {
        return Err(MigrationError::Disagreement);
    }
    Ok(MigratedState {
        state: first,
        carried_dispatched: outcome.dispatched,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resumable_effects::core::*;
    use std::cell::Cell;

    /// The old revision: a bare counter that always suspends immediately,
    /// small enough to stay local to this test module.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct OldProgram;
    impl ResumableEffectProgram for OldProgram {
        type State = i64;
        type Result = i64;
        type Request = ();
        type Observation = ();
        type CleanupOp = ();
        fn request(&self, _state: &i64) -> Option<()> {
            None
        }
        fn transition(&self, state: &i64, _observation: Option<&()>) -> Step<i64, i64> {
            Step::Suspend(*state)
        }
        fn cleanup_plan(&self, _state: &i64) -> Vec<()> {
            Vec::new()
        }
    }

    /// The new revision: same shape, but its `State` is a `String`
    /// projection, forcing a genuine migration rather than an identity
    /// carry-over.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct NewProgram;
    impl ResumableEffectProgram for NewProgram {
        type State = String;
        type Result = i64;
        type Request = ();
        type Observation = ();
        type CleanupOp = ();
        fn request(&self, _state: &String) -> Option<()> {
            None
        }
        fn transition(&self, state: &String, _observation: Option<&()>) -> Step<String, i64> {
            Step::Complete(state.len() as i64)
        }
        fn cleanup_plan(&self, _state: &String) -> Vec<()> {
            Vec::new()
        }
    }

    struct DeterministicMigration;
    impl StateMigration<OldProgram, NewProgram> for DeterministicMigration {
        fn migrate(&self, state: &i64) -> Result<String, String> {
            Ok(format!("migrated:{state}"))
        }
    }

    struct RejectingMigration;
    impl StateMigration<OldProgram, NewProgram> for RejectingMigration {
        fn migrate(&self, state: &i64) -> Result<String, String> {
            Err(format!("incompatible state change for {state}"))
        }
    }

    /// Returns a different string every call, standing in for a migration
    /// function that is not actually a pure function of its input.
    struct NondeterministicMigration {
        calls: Cell<u32>,
    }
    impl StateMigration<OldProgram, NewProgram> for NondeterministicMigration {
        fn migrate(&self, state: &i64) -> Result<String, String> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            Ok(format!("migrated:{state}:{n}"))
        }
    }

    fn scope(root: &str) -> EffectScope {
        EffectScope {
            program_root: root.to_string(),
            invocation_id: "mig-1".to_string(),
            policy_epoch: 1,
        }
    }

    fn suspended_outcome(value: i64, dispatched: u32) -> Outcome<OldProgram> {
        Outcome {
            terminal: Step::Suspend(value),
            cleanup: Vec::new(),
            dispatched,
        }
    }

    #[test]
    fn a_deterministic_migration_across_a_revision_boundary_succeeds_and_carries_the_dispatch_count(
    ) {
        let outcome = suspended_outcome(42, 3);
        let migrated = migrate_suspended(
            &DeterministicMigration,
            &outcome,
            &scope("root:v1"),
            &scope("root:v2"),
        )
        .expect("a deterministic migration between distinct roots must succeed");
        assert_eq!(migrated.state, "migrated:42");
        assert_eq!(migrated.carried_dispatched, 3);
    }

    #[test]
    fn migration_is_refused_when_the_source_terminal_is_not_suspended() {
        let complete = Outcome::<OldProgram> {
            terminal: Step::Complete(7),
            cleanup: Vec::new(),
            dispatched: 0,
        };
        let err = migrate_suspended(
            &DeterministicMigration,
            &complete,
            &scope("root:v1"),
            &scope("root:v2"),
        )
        .unwrap_err();
        assert_eq!(err, MigrationError::NotSuspended);
    }

    #[test]
    fn migration_is_refused_when_the_program_root_is_unchanged() {
        let outcome = suspended_outcome(1, 0);
        let err = migrate_suspended(
            &DeterministicMigration,
            &outcome,
            &scope("root:v1"),
            &scope("root:v1"),
        )
        .unwrap_err();
        assert_eq!(err, MigrationError::SameProgramRoot);
    }

    #[test]
    fn migration_propagates_an_explicit_rejection_from_the_migration_function() {
        let outcome = suspended_outcome(9, 0);
        let err = migrate_suspended(
            &RejectingMigration,
            &outcome,
            &scope("root:v1"),
            &scope("root:v2"),
        )
        .unwrap_err();
        assert_eq!(
            err,
            MigrationError::Rejected("incompatible state change for 9".to_string())
        );
    }

    #[test]
    fn migration_rejects_a_nondeterministic_migration_functions_disagreement_with_itself() {
        let outcome = suspended_outcome(5, 0);
        let migration = NondeterministicMigration {
            calls: Cell::new(0),
        };
        let err = migrate_suspended(&migration, &outcome, &scope("root:v1"), &scope("root:v2"))
            .unwrap_err();
        assert_eq!(err, MigrationError::Disagreement);
        // Both evaluations must actually have run (never short-circuited
        // after the first) for disagreement to be detectable at all.
        assert_eq!(migration.calls.get(), 2);
    }
}
