//! Pure, bounded migration of an authenticated scalar suspension. Replay uses
//! only the interpreter's admitted effect-free start/resume lane.

use super::{
    decode_source_checkpoint_v2, encode_source_checkpoint_v2, ArgumentValue, ResolvedProgram,
    ResumableContinuation, SourceCheckpointError, SourceCheckpointKey, SourceCheckpointScope,
};
use crate::interpreter::resumable::{
    resume_sequential_resumable_effect, run_sequential_resumable_effect,
    SequentialResumableEvaluation, SequentialResumableStep,
};
use crate::resumable_effects::lowering::{lower_sequential, SequentialResumablePlan};

/// Independently supplied facts for one side of an explicit migration.
pub struct SourceCheckpointMigrationInput<'a> {
    pub program: &'a ResolvedProgram,
    pub key: &'a SourceCheckpointKey,
    pub scope: &'a SourceCheckpointScope,
    pub function_id: &'a str,
    pub arguments: &'a [ArgumentValue],
}

/// Replay limits shared by both revisions. Every start or resume is a segment;
/// resume re-evaluates its prefix, and all that work counts again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCheckpointMigrationBudget {
    /// Must not exceed [`crate::interpreter::MAX_STEPS_LIMIT`]. Zero admits no
    /// replay work and reports `FuelExhausted`.
    pub max_segment_steps: usize,
    pub max_total_steps: usize,
}

/// Canonical v2 bytes and the actual combined old/new replay cost. This is inert
/// proof data; no store, scheduler, host handler or publication is involved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCheckpointMigration {
    pub checkpoint: Vec<u8>,
    pub steps_used: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCheckpointMigrationError {
    OldCheckpoint(SourceCheckpointError),
    NewCheckpoint(SourceCheckpointError),
    UnchangedProgramRoot,
    InvocationMismatch,
    FunctionMismatch,
    TypeMismatch,
    SiteMismatch,
    RequestMismatch { site: usize },
    InvalidBudget,
    FuelExhausted,
    ReplayRejected,
}

/// Migrate a pending scalar suspension to an explicitly supplied new revision.
/// Both keys/scopes and both original argument tuples must be supplied anew.
/// The persistent function, invocation, scalar signature and ordered yield
/// sites must agree; the ProgramRoot must change. Policy epoch and key rotation
/// are explicit caller choices. All historical and pending requests must match
/// bit for bit under both revisions, while the unexecuted suffix may change.
///
/// This function authenticates the old v2 bytes first, then deterministically
/// replays both checked programs with recorded answers only. No handler can be
/// passed, so migration cannot dispatch or answer the pending request. A failed
/// migration returns no replacement checkpoint and changes no external state.
pub fn migrate_source_checkpoint_v2(
    old: SourceCheckpointMigrationInput<'_>,
    new: SourceCheckpointMigrationInput<'_>,
    bytes: &[u8],
    budget: SourceCheckpointMigrationBudget,
) -> Result<SourceCheckpointMigration, SourceCheckpointMigrationError> {
    use SourceCheckpointMigrationError as Error;
    let authenticated = decode_source_checkpoint_v2(
        old.program,
        old.key,
        old.scope,
        old.function_id,
        old.arguments,
        bytes,
    )
    .map_err(Error::OldCheckpoint)?;
    if budget.max_segment_steps > crate::interpreter::MAX_STEPS_LIMIT {
        return Err(Error::InvalidBudget);
    }
    if old.function_id != new.function_id {
        return Err(Error::FunctionMismatch);
    }
    if old.scope.program_root() == new.scope.program_root() {
        return Err(Error::UnchangedProgramRoot);
    }
    if old.scope.invocation_id() != new.scope.invocation_id() {
        return Err(Error::InvocationMismatch);
    }
    let old_plan = plan(&old)?;
    let new_plan = plan(&new)?;
    if old_plan.suspensions.len() != new_plan.suspensions.len() {
        return Err(Error::SiteMismatch);
    }
    for (before, after) in old_plan.suspensions.iter().zip(&new_plan.suspensions) {
        if before.request_type != after.request_type || before.response_type != after.response_type
        {
            return Err(Error::TypeMismatch);
        }
        if before.state != after.state || before.position != after.position {
            return Err(Error::SiteMismatch);
        }
    }
    let old_function = old
        .program
        .functions
        .iter()
        .find(|f| f.id.as_str() == old.function_id)
        .ok_or(Error::FunctionMismatch)?;
    let new_function = new
        .program
        .functions
        .iter()
        .find(|f| f.id.as_str() == new.function_id)
        .ok_or(Error::FunctionMismatch)?;
    if old_function.return_type != new_function.return_type
        || !old_function
            .params
            .iter()
            .map(|p| &p.ty)
            .eq(new_function.params.iter().map(|p| &p.ty))
    {
        return Err(Error::TypeMismatch);
    }
    let mut fuel = Fuel { budget, used: 0 };
    let mut before = start(&old, &mut fuel)?;
    let mut after = start(&new, &mut fuel)?;
    for (site, (request, answer)) in authenticated.history().enumerate() {
        compare(&before, &after, request, site)?;
        before = resume(&old, &before, answer, &mut fuel)?;
        after = resume(&new, &after, answer, &mut fuel)?;
    }
    compare(
        &before,
        &after,
        authenticated.request(),
        authenticated.history().len(),
    )?;
    if before.state() != authenticated.state() || before.binding() != authenticated.binding() {
        return Err(Error::SiteMismatch);
    }
    let checkpoint = encode_source_checkpoint_v2(
        new.program,
        new.key,
        new.scope,
        new.function_id,
        new.arguments,
        &after,
    )
    .map_err(Error::NewCheckpoint)?;
    Ok(SourceCheckpointMigration {
        checkpoint,
        steps_used: fuel.used,
    })
}

fn plan(
    input: &SourceCheckpointMigrationInput<'_>,
) -> Result<SequentialResumablePlan, SourceCheckpointMigrationError> {
    let function = input
        .program
        .functions
        .iter()
        .find(|f| f.id.as_str() == input.function_id)
        .ok_or(SourceCheckpointMigrationError::FunctionMismatch)?;
    lower_sequential(input.program, function)
        .map_err(|_| SourceCheckpointMigrationError::ReplayRejected)
}

fn same_scalar(left: &ArgumentValue, right: &ArgumentValue) -> bool {
    match (left, right) {
        (ArgumentValue::Float32(a), ArgumentValue::Float32(b)) => a.to_bits() == b.to_bits(),
        (ArgumentValue::Float64(a), ArgumentValue::Float64(b)) => a.to_bits() == b.to_bits(),
        _ => left == right,
    }
}

fn compare(
    before: &ResumableContinuation,
    after: &ResumableContinuation,
    request: &ArgumentValue,
    site: usize,
) -> Result<(), SourceCheckpointMigrationError> {
    if before.state() != after.state() {
        return Err(SourceCheckpointMigrationError::SiteMismatch);
    }
    if !same_scalar(before.request(), request) || !same_scalar(after.request(), request) {
        return Err(SourceCheckpointMigrationError::RequestMismatch { site });
    }
    Ok(())
}

struct Fuel {
    budget: SourceCheckpointMigrationBudget,
    used: usize,
}

impl Fuel {
    fn remaining(&self) -> Result<usize, SourceCheckpointMigrationError> {
        let remaining = self
            .budget
            .max_total_steps
            .saturating_sub(self.used)
            .min(self.budget.max_segment_steps);
        if remaining == 0 {
            Err(SourceCheckpointMigrationError::FuelExhausted)
        } else {
            Ok(remaining)
        }
    }

    fn accept(
        &mut self,
        result: SequentialResumableEvaluation,
    ) -> Result<ResumableContinuation, SourceCheckpointMigrationError> {
        self.used = self
            .used
            .checked_add(result.steps_used)
            .filter(|used| *used <= self.budget.max_total_steps)
            .ok_or(SourceCheckpointMigrationError::FuelExhausted)?;
        match result.step {
            SequentialResumableStep::Suspended { continuation } => Ok(continuation),
            SequentialResumableStep::FuelExhausted => {
                Err(SourceCheckpointMigrationError::FuelExhausted)
            }
            _ => Err(SourceCheckpointMigrationError::ReplayRejected),
        }
    }
}

fn start(
    input: &SourceCheckpointMigrationInput<'_>,
    fuel: &mut Fuel,
) -> Result<ResumableContinuation, SourceCheckpointMigrationError> {
    let evaluation = run_sequential_resumable_effect(
        input.program,
        input.function_id,
        input.arguments,
        fuel.remaining()?,
    )
    .map_err(|_| SourceCheckpointMigrationError::ReplayRejected)?;
    fuel.accept(evaluation)
}

fn resume(
    input: &SourceCheckpointMigrationInput<'_>,
    continuation: &ResumableContinuation,
    answer: &ArgumentValue,
    fuel: &mut Fuel,
) -> Result<ResumableContinuation, SourceCheckpointMigrationError> {
    let evaluation = resume_sequential_resumable_effect(
        input.program,
        input.function_id,
        input.arguments,
        continuation,
        answer,
        fuel.remaining()?,
    )
    .map_err(|_| SourceCheckpointMigrationError::ReplayRejected)?;
    fuel.accept(evaluation)
}

#[cfg(test)]
mod tests;
