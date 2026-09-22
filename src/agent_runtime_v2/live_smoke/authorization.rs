//! The separate operator act that turns a plan into something that may spend
//! real money, and the authorized value that act produces.
//!
//! Nothing in the compiler, the runtime or any evidence capsule can mint an
//! [`OperatorLiveSmokeGrant`]. Its only constructors are
//! [`OperatorLiveSmokeGrant::grant`] -- an explicit host call carrying an
//! operator reference, a justification and approved ceilings -- and
//! [`OperatorLiveSmokeGrant::replay`], which re-derives the same value from its
//! own canonical bytes and digest. Evidence carries no authority here, exactly
//! as the repository invariant requires.

use serde_json::json;

use super::plan::{limits_from_json, limits_json, LiveRepairSmokePlan};
use super::{
    digest, refused, render, replay_document, string_field, validate_digest_label, validate_label,
    Result, LIVE_REPAIR_SMOKE_GRANT_SCHEMA, MAX_JUSTIFICATION_BYTES,
};
use crate::model_budget_policy::{intersect, ModelBudgetLimits};

const DOMAIN: &[u8] = b"semaprax.live-repair-smoke-operator-grant.v1\0";

/// One operator's explicit, bounded approval to run exactly one planned live
/// smoke.
///
/// The grant names one plan digest. Presenting it alongside a different plan
/// is refused by [`AuthorizedLiveRepairSmoke::authorize`], so an approval
/// obtained for a cheap plan can never be replayed onto an expensive one, and
/// a plan re-bound after any fact changed carries a new digest that no existing
/// grant names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorLiveSmokeGrant {
    plan_digest: String,
    operator_reference: String,
    justification: String,
    approved: ModelBudgetLimits,
    json: String,
    digest: String,
}

impl OperatorLiveSmokeGrant {
    /// Mint one grant for one exact plan.
    ///
    /// `approved` may only narrow. Every dimension is compared against the
    /// plan's already-derived effective ceiling and a wider value is refused
    /// with the offending dimension named, rather than silently clamped: an
    /// operator who believes they approved more than the deployment admits
    /// should be told, not quietly corrected.
    pub fn grant(
        plan: &LiveRepairSmokePlan,
        operator_reference: &str,
        justification: &str,
        approved: ModelBudgetLimits,
    ) -> Result<Self> {
        validate_label(
            operator_reference,
            "smoke operator reference is out of bounds",
        )?;
        if justification.is_empty()
            || justification.len() > MAX_JUSTIFICATION_BYTES
            || justification.chars().any(char::is_control)
            || justification.trim() != justification
        {
            return Err(refused("smoke operator justification is out of bounds"));
        }
        require_not_wider(approved, plan.effective_budget())?;
        if approved.max_calls < plan.expected_turns() {
            return Err(refused(
                "approved call ceiling is below the plan's expected turn count",
            ));
        }
        if approved.max_cost_micros <= 0 {
            return Err(refused("approved cost ceiling admits no paid attempt"));
        }

        let plan_digest = plan.digest().to_owned();
        validate_digest_label(&plan_digest)?;
        let value = json!({
            "approved_budget": limits_json(&approved),
            "credential": "never_carried_here",
            "justification": justification,
            "nonclaims": [
                "a_grant_binds_only_the_exact_plan_digest_named_here",
                "a_grant_is_not_a_credential_endpoint_or_transport_authority",
                "a_grant_never_widens_the_source_or_deployment_ceiling",
                "a_grant_is_not_candidate_approval_or_publication_authority",
            ],
            "operator_reference": operator_reference,
            "plan_digest": plan_digest,
            "schema": LIVE_REPAIR_SMOKE_GRANT_SCHEMA,
        });
        let json = render(&value)?;
        let digest = digest(DOMAIN, json.as_bytes());
        Ok(Self {
            plan_digest,
            operator_reference: operator_reference.to_owned(),
            justification: justification.to_owned(),
            approved,
            json,
            digest,
        })
    }

    /// Reparse a grant that crossed a process or session boundary.
    pub fn replay(expected_digest: &str, bytes: &[u8]) -> Result<Self> {
        let value = replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_GRANT_SCHEMA,
            expected_digest,
            bytes,
        )?;
        let plan_digest = string_field(&value, "plan_digest")?;
        validate_digest_label(&plan_digest)?;
        let approved = limits_from_json(
            value
                .get("approved_budget")
                .ok_or_else(|| refused("replayed smoke grant is missing its approved budget"))?,
        )?;
        Ok(Self {
            plan_digest,
            operator_reference: string_field(&value, "operator_reference")?,
            justification: string_field(&value, "justification")?,
            approved,
            json: String::from_utf8(bytes.to_vec())
                .map_err(|_| refused("replayed smoke grant is not UTF-8"))?,
            digest: expected_digest.to_owned(),
        })
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
    #[must_use]
    pub fn operator_reference(&self) -> &str {
        &self.operator_reference
    }
    #[must_use]
    pub fn justification(&self) -> &str {
        &self.justification
    }
    #[must_use]
    pub fn approved_budget(&self) -> ModelBudgetLimits {
        self.approved
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

/// A plan joined to the grant that authorizes exactly it.
///
/// This is the only value in the contract from which a
/// [`super::LiveRepairSmokeRecord`] can be produced. Its effective budget is
/// the intersection of the plan's derived ceiling and the operator's approval,
/// computed through the same `intersect` the rest of the runtime uses.
#[derive(Clone, Debug)]
pub struct AuthorizedLiveRepairSmoke {
    plan: LiveRepairSmokePlan,
    grant: OperatorLiveSmokeGrant,
    effective: ModelBudgetLimits,
}

impl AuthorizedLiveRepairSmoke {
    /// Join one plan to one grant.
    ///
    /// Refuses when the grant names a different plan. This is the check that
    /// makes "approval for A does not authorize B" true for the spending
    /// boundary, mirroring the candidate-digest check that makes it true for
    /// the publication boundary.
    pub fn authorize(plan: &LiveRepairSmokePlan, grant: &OperatorLiveSmokeGrant) -> Result<Self> {
        if grant.plan_digest() != plan.digest() {
            return Err(refused(
                "operator grant names a different plan than the one presented",
            ));
        }
        let effective = intersect(
            plan.effective_budget(),
            grant.approved_budget(),
            ModelBudgetLimits::unbounded(),
        )
        .map_err(|_| refused("authorized smoke budget is contradictory or zero-impossible"))?
        .limits();
        if effective.max_calls < plan.expected_turns() {
            return Err(refused(
                "authorized call ceiling is below the plan's expected turn count",
            ));
        }
        Ok(Self {
            plan: plan.clone(),
            grant: grant.clone(),
            effective,
        })
    }

    #[must_use]
    pub fn plan(&self) -> &LiveRepairSmokePlan {
        &self.plan
    }
    #[must_use]
    pub fn grant(&self) -> &OperatorLiveSmokeGrant {
        &self.grant
    }
    /// The one ceiling this authorized smoke may spend against.
    #[must_use]
    pub fn effective_budget(&self) -> ModelBudgetLimits {
        self.effective
    }
}

/// Refuse a candidate ceiling that is wider than the reference on any single
/// dimension, naming that dimension.
fn require_not_wider(candidate: ModelBudgetLimits, reference: ModelBudgetLimits) -> Result<()> {
    if candidate.max_calls > reference.max_calls {
        return Err(wider("max_calls"));
    }
    if candidate.max_retries > reference.max_retries {
        return Err(wider("max_retries"));
    }
    if candidate.max_providers > reference.max_providers {
        return Err(wider("max_providers"));
    }
    if candidate.max_context_tokens > reference.max_context_tokens {
        return Err(wider("max_context_tokens"));
    }
    if candidate.max_output_tokens > reference.max_output_tokens {
        return Err(wider("max_output_tokens"));
    }
    if candidate.max_aggregate_tokens > reference.max_aggregate_tokens {
        return Err(wider("max_aggregate_tokens"));
    }
    if candidate.max_cost_micros > reference.max_cost_micros {
        return Err(wider("max_cost_micros"));
    }
    if candidate.max_latency_millis > reference.max_latency_millis {
        return Err(wider("max_latency_millis"));
    }
    Ok(())
}

fn wider(dimension: &str) -> Vec<crate::diagnostic::Diagnostic> {
    refused(&format!(
        "operator grant would widen the effective ceiling for {dimension}"
    ))
}
