//! Additive source migration identity and the charged pure-evaluation prefix.
//! The caller still has to bind both retained Projects and the checked
//! migration function; this value and its hash are not source authority.

use super::*;

const HANDOFF_DOMAIN: &[u8] = b"semaprax.live-invocation.source-migration-handoff.v3\0";
const STATE_DOMAIN: &[u8] = b"semaprax.live-invocation.source-migrated-state.v3\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceMigrationCarry {
    pub handoff_digest: String,
    pub previous_schema: String,
    pub previous_invocation: String,
    pub previous_generation: u64,
    pub previous_chain: String,
    pub previous_program_root: String,
    pub destination_program_root: String,
    pub old_state_id: String,
    pub new_state_id: String,
    pub migration_function: String,
    pub migration_closure: String,
    pub task_digest: String,
    pub carried_model_units: i64,
    pub carried_stage_fuel: u64,
    pub carried_turns: u32,
    pub carried_stages: u32,
    pub carried_effects: u32,
    pub carried_attempts: u32,
    pub previous_ceiling: i64,
    pub previous_max_iterations: u32,
    pub previous_max_stages: u32,
    pub previous_max_steps_per_stage: usize,
    pub previous_max_total_steps: usize,
    pub previous_reservation_units: i64,
    pub previous_unit: String,
    pub previous_clock_domain: String,
    pub previous_last_checked_millis: i64,
    pub previous_deadline_millis: i64,
    pub evaluation_steps: usize,
}

impl SourceMigrationCarry {
    pub(crate) fn digest(&self) -> String {
        let material = format!(
            "{{\"schema\":\"semaprax.source-migration-handoff.v3\",\"previous_schema\":{},\"previous_invocation\":{},\"previous_generation\":{},\"previous_chain\":{},\"previous_program_root\":{},\"destination_program_root\":{},\"old_state_id\":{},\"new_state_id\":{},\"migration_function\":{},\"migration_closure\":{},\"task_digest\":{},\"carried_model_units\":{},\"carried_stage_fuel\":{},\"carried_turns\":{},\"carried_stages\":{},\"carried_effects\":{},\"carried_attempts\":{},\"previous_ceiling\":{},\"previous_max_iterations\":{},\"previous_max_stages\":{},\"previous_max_steps_per_stage\":{},\"previous_max_total_steps\":{},\"previous_reservation_units\":{},\"previous_unit\":{},\"previous_clock_domain\":{},\"previous_last_checked_millis\":{},\"previous_deadline_millis\":{},\"evaluation_steps\":{}}}",
            quote_json(&self.previous_schema), quote_json(&self.previous_invocation),
            self.previous_generation, quote_json(&self.previous_chain),
            quote_json(&self.previous_program_root), quote_json(&self.destination_program_root),
            quote_json(&self.old_state_id), quote_json(&self.new_state_id),
            quote_json(&self.migration_function), quote_json(&self.migration_closure),
            quote_json(&self.task_digest), self.carried_model_units, self.carried_stage_fuel,
            self.carried_turns, self.carried_stages, self.carried_effects, self.carried_attempts,
            self.previous_ceiling, self.previous_max_iterations,
            self.previous_max_stages, self.previous_max_steps_per_stage,
            self.previous_max_total_steps, self.previous_reservation_units,
            quote_json(&self.previous_unit), quote_json(&self.previous_clock_domain),
            self.previous_last_checked_millis, self.previous_deadline_millis,
            self.evaluation_steps,
        );
        digest(HANDOFF_DOMAIN, material.as_bytes())
    }

    pub(crate) fn evaluation_fuel(&self) -> Result<u64, SourceJournalError> {
        u64::try_from(self.evaluation_steps)
            .ok()
            .and_then(|steps| steps.checked_mul(2))
            .filter(|fuel| *fuel > 0)
            .ok_or(SourceJournalError::Capacity)
    }
}

pub(crate) fn task_digest(task: &[u8], budget: i64) -> String {
    let material = format!(
        "{{\"task\":{},\"budget\":{}}}",
        quote_json(&hex(task)),
        budget
    );
    digest(
        b"semaprax.live-invocation.source-migration-task.v3\0",
        material.as_bytes(),
    )
}

pub(crate) fn state_digest(state: &[u8]) -> String {
    digest(STATE_DOMAIN, state)
}

pub(super) struct MigrationPrefix {
    pub source_start: usize,
    pub model_units: i64,
    pub stage_fuel: u64,
    pub turns: u32,
    pub stages: u32,
    pub effects: u32,
    pub attempts: u32,
}

/// The migrated preamble is the only addition before the ordinary source
/// causal stream. An unresolved pure intent can be repeated only by another
/// charged intent; a failed or settled evaluation cannot be run again.
pub(super) fn prefix(
    binding: &SourceInvocationBinding,
    entries: &[SourceJournalEntry],
) -> Result<MigrationPrefix, SourceJournalError> {
    let Some(carry) = binding.migration() else {
        return Ok(MigrationPrefix {
            source_start: 0,
            model_units: 0,
            stage_fuel: 0,
            turns: 0,
            stages: 0,
            effects: 0,
            attempts: 0,
        });
    };
    let mut result = MigrationPrefix {
        source_start: entries.len(),
        model_units: carry.carried_model_units,
        stage_fuel: carry.carried_stage_fuel,
        turns: carry.carried_turns,
        stages: carry.carried_stages,
        effects: carry.carried_effects,
        attempts: carry.carried_attempts,
    };
    if !matches!(entries.first(), Some(SourceJournalEntry::MigrationOpened { handoff_digest })
        if handoff_digest == &carry.handoff_digest)
    {
        return Err(SourceJournalError::Order);
    }
    let mut pending: Option<u32> = None;
    let mut next_attempt = 0u32;
    let mut settled = false;
    let mut failed = false;
    for (index, entry) in entries.iter().enumerate().skip(1) {
        match entry {
            SourceJournalEntry::MigrationEvaluationIntent { attempt, fuel }
                if !settled
                    && !failed
                    && *attempt == next_attempt
                    && *fuel as u64 == carry.evaluation_fuel()? =>
            {
                next_attempt = next_attempt
                    .checked_add(1)
                    .ok_or(SourceJournalError::Capacity)?;
                result.stage_fuel = result
                    .stage_fuel
                    .checked_add(*fuel as u64)
                    .ok_or(SourceJournalError::Capacity)?;
                if result.stage_fuel
                    > binding
                        .max_total_steps()
                        .ok_or(SourceJournalError::Binding)? as u64
                {
                    return Err(SourceJournalError::Capacity);
                }
                pending = Some(*attempt);
            }
            SourceJournalEntry::MigrationEvaluationSettled {
                attempt,
                state,
                state_digest,
            } if pending == Some(*attempt)
                && !settled
                && !failed
                && !state.is_empty()
                && state.len() <= MAX_SOURCE_CARRIER_BYTES
                && *state_digest == self::state_digest(state)
                && serde_json::from_slice::<serde_json::Value>(state).is_ok() =>
            {
                settled = true;
                pending = None;
            }
            SourceJournalEntry::MigrationEvaluationFailed { attempt, .. }
                if pending == Some(*attempt) && !settled && !failed =>
            {
                failed = true;
                pending = None;
            }
            SourceJournalEntry::RunOpened if settled => {
                result.source_start = index;
                break;
            }
            _ => return Err(SourceJournalError::Order),
        }
    }
    if failed && result.source_start != entries.len() {
        return Err(SourceJournalError::Order);
    }
    Ok(result)
}

impl SourceInvocationBinding {
    pub(crate) fn bind_migrated_execution(
        seed: SourceInvocationSeed,
        evaluator_profile: &str,
        carry: SourceMigrationCarry,
    ) -> Result<Self, SourceJournalError> {
        let prior_task = task_digest(&seed.task, seed.task_budget);
        if carry.handoff_digest != carry.digest()
            || ![
                &carry.handoff_digest,
                &carry.previous_invocation,
                &carry.previous_chain,
                &carry.previous_program_root,
                &carry.destination_program_root,
                &carry.migration_closure,
                &carry.task_digest,
            ]
            .into_iter()
            .all(|value| looks_like_digest(value))
            || !matches!(
                carry.previous_schema.as_str(),
                SOURCE_EXECUTION_JOURNAL_SCHEMA | SOURCE_MIGRATED_JOURNAL_SCHEMA
            )
            || ![
                &carry.old_state_id,
                &carry.new_state_id,
                &carry.migration_function,
            ]
            .into_iter()
            .all(|value| valid_token(value, 240))
            || carry.previous_program_root == carry.destination_program_root
            || seed.program_root.as_deref() != Some(carry.destination_program_root.as_str())
            || prior_task != carry.task_digest
            || carry.carried_model_units < 0
            || carry.carried_model_units > seed.ceiling
            || seed.ceiling > carry.previous_ceiling
            || seed.max_iterations > carry.previous_max_iterations
            || seed.max_stages > carry.previous_max_stages
            || seed.max_steps_per_stage > carry.previous_max_steps_per_stage
            || seed.max_total_steps > carry.previous_max_total_steps
            || seed.reservation_units != carry.previous_reservation_units
            || seed.unit != carry.previous_unit
            || seed.clock_domain != carry.previous_clock_domain
            || seed.initial_millis < carry.previous_last_checked_millis
            || seed.deadline_millis > carry.previous_deadline_millis
            || carry.previous_last_checked_millis < 0
            || carry.carried_turns >= seed.max_iterations
            || carry.carried_stages >= seed.max_stages
            || carry.carried_effects > carry.carried_turns
            || carry.carried_attempts < carry.carried_effects
        {
            return Err(SourceJournalError::Binding);
        }
        let max_steps_per_stage = seed.max_steps_per_stage;
        let max_total_steps = seed.max_total_steps;
        let mut binding = Self::bind_execution(seed, evaluator_profile)?;
        if carry
            .carried_stage_fuel
            .checked_add(carry.evaluation_fuel()?)
            .is_none_or(|total| total > max_total_steps as u64)
        {
            return Err(SourceJournalError::Capacity);
        }
        binding.invocation = digest(
            MIGRATED_ID_DOMAIN,
            format!("{}\0{}", binding.invocation, carry.handoff_digest).as_bytes(),
        );
        binding.profile = SourceProfile::MigratedV3 {
            evaluator: evaluator_profile.to_owned(),
            max_steps_per_stage,
            max_total_steps,
            carry,
        };
        Ok(binding)
    }
}
