//! The recorded true outcome of one authorized live smoke.
//!
//! A record is produced *after* an operator has actually run the authorized
//! smoke, from an [`AuthorizedLiveRepairSmoke`] that could only exist because a
//! real grant named the exact plan. Three things make it honest evidence:
//!
//! * **Failure is a first-class result.** [`LiveRepairSmokeOutcome`] has
//!   variants for a provider failure, an exhausted budget and a cancellation,
//!   and each records normally. There is no "record only on success" path that
//!   would push an operator toward quietly re-running until it looks good.
//! * **Reported usage cannot exceed what was authorized.** A record claiming
//!   more attempts or more cost than the intersected ceiling is refused, so a
//!   record can never be used to legitimise overspend after the fact.
//! * **A record binds one plan.** [`LiveRepairSmokeRecord::verify_for`] refuses
//!   a different plan, so a successful run of a cheap plan cannot be presented
//!   as evidence for a different one.

use serde_json::{json, Value};

use super::authorization::AuthorizedLiveRepairSmoke;
use super::plan::{limits_json, LiveRepairSmokePlan};
use super::{
    digest, refused, render, replay_document, string_field, u32_field, validate_digest_label,
    validate_label, Result, LIVE_REPAIR_SMOKE_RECORD_SCHEMA,
};

const DOMAIN: &[u8] = b"semaprax.live-repair-smoke-record.v1\0";

/// The measured cost of one live smoke, exactly as the provider reported it.
///
/// Every token field is optional because a provider may legitimately report no
/// usage; "unknown" is recorded as unknown rather than as zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LiveRepairSmokeUsage {
    /// Provider attempts actually dispatched, including retries.
    pub attempts: u32,
    /// Attempts that were served from a recorded settlement instead of a new
    /// dispatch. Resuming a smoke must not redispatch settled work.
    pub replayed_attempts: u32,
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    /// Cost in the operator's own micro-units, never a live price lookup.
    pub cost_micros: i64,
}

impl LiveRepairSmokeUsage {
    fn json(&self) -> Value {
        json!({
            "attempts": self.attempts,
            "cost_micros": self.cost_micros,
            "replayed_attempts": self.replayed_attempts,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
        })
    }

    fn from_json(value: &Value) -> Result<Self> {
        Ok(Self {
            attempts: u32_field(value, "attempts")?,
            replayed_attempts: u32_field(value, "replayed_attempts")?,
            tokens_in: value.get("tokens_in").and_then(Value::as_u64),
            tokens_out: value.get("tokens_out").and_then(Value::as_u64),
            cost_micros: super::i64_field(value, "cost_micros")?,
        })
    }
}

/// What actually happened. Every variant is a valid recorded result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveRepairSmokeOutcome {
    /// The loop reached a corrected candidate. `rejections` is the number of
    /// proposals the checked oracle refused before the accepted one; a value of
    /// zero means the model was right first time, which is a weaker
    /// demonstration of the feedback path and is recorded as such.
    Repaired {
        turns: u32,
        rejections: u32,
        candidate_digest: String,
    },
    /// The provider itself failed. `terminal` is the adapter's own bounded
    /// terminal label; it is never a response body.
    ProviderFailed { turns: u32, terminal: String },
    /// The authorized budget ran out before a corrected candidate existed.
    BudgetExhausted { turns: u32 },
    /// The operator or the host cancelled the run.
    Cancelled { turns: u32 },
    /// Every turn ran, but the checked oracle refused every proposal. The
    /// workflow behaved correctly and the model did not solve the task.
    NotRepaired { turns: u32, rejections: u32 },
}

impl LiveRepairSmokeOutcome {
    #[must_use]
    pub fn turns(&self) -> u32 {
        match self {
            Self::Repaired { turns, .. }
            | Self::ProviderFailed { turns, .. }
            | Self::BudgetExhausted { turns }
            | Self::Cancelled { turns }
            | Self::NotRepaired { turns, .. } => *turns,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Repaired { .. } => "repaired",
            Self::ProviderFailed { .. } => "provider_failed",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::Cancelled { .. } => "cancelled",
            Self::NotRepaired { .. } => "not_repaired",
        }
    }

    /// Whether the smoke reached a corrected candidate. A record is evidence
    /// either way; this only says which way.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Repaired { .. })
    }

    fn json(&self) -> Value {
        let mut value = json!({"kind": self.kind(), "turns": self.turns()});
        let object = value
            .as_object_mut()
            .expect("the outcome object was just constructed");
        match self {
            Self::Repaired {
                rejections,
                candidate_digest,
                ..
            } => {
                object.insert("candidate_digest".to_owned(), json!(candidate_digest));
                object.insert("rejections".to_owned(), json!(rejections));
            }
            Self::NotRepaired { rejections, .. } => {
                object.insert("rejections".to_owned(), json!(rejections));
            }
            Self::ProviderFailed { terminal, .. } => {
                object.insert("terminal".to_owned(), json!(terminal));
            }
            Self::BudgetExhausted { .. } | Self::Cancelled { .. } => {}
        }
        value
    }

    fn from_json(value: &Value) -> Result<Self> {
        let turns = u32_field(value, "turns")?;
        match value.get("kind").and_then(Value::as_str) {
            Some("repaired") => Ok(Self::Repaired {
                turns,
                rejections: u32_field(value, "rejections")?,
                candidate_digest: string_field(value, "candidate_digest")?,
            }),
            Some("not_repaired") => Ok(Self::NotRepaired {
                turns,
                rejections: u32_field(value, "rejections")?,
            }),
            Some("provider_failed") => Ok(Self::ProviderFailed {
                turns,
                terminal: string_field(value, "terminal")?,
            }),
            Some("budget_exhausted") => Ok(Self::BudgetExhausted { turns }),
            Some("cancelled") => Ok(Self::Cancelled { turns }),
            _ => Err(refused("replayed smoke record has an unknown outcome kind")),
        }
    }

    fn validate(&self, max_calls: u32) -> Result<()> {
        let turns = self.turns();
        if turns > max_calls {
            return Err(refused(
                "recorded turn count exceeds the authorized call ceiling",
            ));
        }
        match self {
            Self::Repaired {
                candidate_digest,
                rejections,
                ..
            } => {
                validate_digest_label(candidate_digest)?;
                if *rejections >= turns {
                    return Err(refused(
                        "a repaired smoke cannot report at least as many rejections as turns",
                    ));
                }
                // A repair that used fewer turns than planned is fine: the
                // plan's turn count is the demonstration's ceiling, not a
                // quota. A repair with no turn at all is not.
                if turns == 0 {
                    return Err(refused("a repaired smoke cannot report zero turns"));
                }
            }
            Self::NotRepaired { rejections, .. } => {
                if *rejections > turns {
                    return Err(refused(
                        "an unrepaired smoke cannot report more rejections than turns",
                    ));
                }
            }
            Self::ProviderFailed { terminal, .. } => {
                validate_label(terminal, "recorded provider terminal is out of bounds")?;
            }
            Self::BudgetExhausted { .. } | Self::Cancelled { .. } => {}
        }
        Ok(())
    }
}

/// The complete evidence document for one executed live smoke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRepairSmokeRecord {
    plan_digest: String,
    grant_digest: String,
    operator_reference: String,
    outcome: LiveRepairSmokeOutcome,
    usage: LiveRepairSmokeUsage,
    json: String,
    digest: String,
}

impl LiveRepairSmokeRecord {
    /// Record the true outcome of one authorized smoke.
    ///
    /// Refuses a record whose reported usage exceeds the intersected ceiling
    /// the operator actually authorized, and a record whose turn count exceeds
    /// the authorized `max_calls`. Refusing here is deliberate: an overspending
    /// record is a bug or a lie, and either way it must not become evidence.
    pub fn record(
        authorized: &AuthorizedLiveRepairSmoke,
        outcome: LiveRepairSmokeOutcome,
        usage: LiveRepairSmokeUsage,
    ) -> Result<Self> {
        let effective = authorized.effective_budget();
        outcome.validate(effective.max_calls)?;
        let dispatched = usage
            .attempts
            .checked_sub(usage.replayed_attempts)
            .ok_or_else(|| {
                refused("recorded replayed attempts exceed the total recorded attempts")
            })?;
        if usage.attempts > effective.max_calls {
            return Err(refused(
                "recorded attempts exceed the authorized call ceiling",
            ));
        }
        if usage.cost_micros < 0 {
            return Err(refused("recorded cost is negative"));
        }
        if usage.cost_micros > effective.max_cost_micros {
            return Err(refused("recorded cost exceeds the authorized cost ceiling"));
        }
        if let (Some(tokens_in), Some(tokens_out)) = (usage.tokens_in, usage.tokens_out) {
            let aggregate = tokens_in.saturating_add(tokens_out);
            if aggregate > effective.max_aggregate_tokens {
                return Err(refused(
                    "recorded aggregate tokens exceed the authorized aggregate ceiling",
                ));
            }
        }

        let plan_digest = authorized.plan().digest().to_owned();
        let grant_digest = authorized.grant().digest().to_owned();
        let operator_reference = authorized.grant().operator_reference().to_owned();
        let value = json!({
            "authorized_budget": limits_json(&effective),
            "dispatched": dispatched > 0,
            "evidence_class": "operator_authorized_local_live_provider_smoke",
            "grant_digest": grant_digest,
            "hosted_ci_evidence": false,
            "newly_dispatched_attempts": dispatched,
            "nonclaims": [
                "one_local_operator_run_is_not_hosted_ci_or_production_support",
                "a_record_binds_only_the_exact_plan_digest_named_here",
                "a_recorded_repair_is_not_candidate_approval_or_publication_authority",
                "reported_usage_is_the_providers_own_report_not_an_independent_audit",
            ],
            "operator_reference": operator_reference,
            "outcome": outcome.json(),
            "plan_digest": plan_digest,
            "provider_id": authorized.plan().provider_id(),
            "publication_authority": false,
            "schema": LIVE_REPAIR_SMOKE_RECORD_SCHEMA,
            "source_mutation": false,
            "succeeded": outcome.succeeded(),
            "usage": usage.json(),
        });
        let json = render(&value)?;
        let digest = digest(DOMAIN, json.as_bytes());
        Ok(Self {
            plan_digest,
            grant_digest,
            operator_reference,
            outcome,
            usage,
            json,
            digest,
        })
    }

    /// Reparse a record that crossed a session boundary.
    pub fn replay(expected_digest: &str, bytes: &[u8]) -> Result<Self> {
        let value = replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_RECORD_SCHEMA,
            expected_digest,
            bytes,
        )?;
        let plan_digest = string_field(&value, "plan_digest")?;
        let grant_digest = string_field(&value, "grant_digest")?;
        validate_digest_label(&plan_digest)?;
        validate_digest_label(&grant_digest)?;
        let outcome = LiveRepairSmokeOutcome::from_json(
            value
                .get("outcome")
                .ok_or_else(|| refused("replayed smoke record is missing its outcome"))?,
        )?;
        let usage = LiveRepairSmokeUsage::from_json(
            value
                .get("usage")
                .ok_or_else(|| refused("replayed smoke record is missing its usage"))?,
        )?;
        Ok(Self {
            plan_digest,
            grant_digest,
            operator_reference: string_field(&value, "operator_reference")?,
            outcome,
            usage,
            json: String::from_utf8(bytes.to_vec())
                .map_err(|_| refused("replayed smoke record is not UTF-8"))?,
            digest: expected_digest.to_owned(),
        })
    }

    /// Refuse a record that belongs to a different plan.
    pub fn verify_for(&self, plan: &LiveRepairSmokePlan) -> Result<()> {
        if self.plan_digest != plan.digest() {
            return Err(refused(
                "smoke record names a different plan than the one presented",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
    #[must_use]
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    #[must_use]
    pub fn operator_reference(&self) -> &str {
        &self.operator_reference
    }
    #[must_use]
    pub fn outcome(&self) -> &LiveRepairSmokeOutcome {
        &self.outcome
    }
    #[must_use]
    pub fn usage(&self) -> LiveRepairSmokeUsage {
        self.usage
    }
    /// Provider attempts that were newly dispatched rather than replayed from
    /// a recorded settlement. An interrupted-and-resumed smoke reports the same
    /// total attempts with a higher replayed count and no extra dispatch.
    #[must_use]
    pub fn newly_dispatched_attempts(&self) -> u32 {
        self.usage
            .attempts
            .saturating_sub(self.usage.replayed_attempts)
    }
    #[must_use]
    pub fn to_json(&self) -> &str {
        &self.json
    }
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
