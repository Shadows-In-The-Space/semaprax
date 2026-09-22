//! One complete, digest-identified description of a live smoke run.
//!
//! A plan is the join of a checked [`LiveRepairSmokeTarget`] and one already
//! bound [`SourceModelBinding`]. Its effective budget is **derived** through
//! the existing `policy_binding` intersection rather than accepted from a
//! caller, so a plan physically cannot carry a ceiling wider than the source
//! Agent and the deployment policy already admitted.

use serde_json::{json, Value};

use super::target::LiveRepairSmokeTarget;
use super::{
    digest, refused, render, replay_document, string_field, u32_field, validate_digest_label,
    validate_label, Result, LIVE_REPAIR_SMOKE_PLAN_SCHEMA, MAX_SMOKE_TURNS, MIN_SMOKE_TURNS,
};
use crate::agent_runtime_v2::SourceModelBinding;
use crate::model_budget_policy::ModelBudgetLimits;

const DOMAIN: &[u8] = b"semaprax.live-repair-smoke-plan.v1\0";

/// A complete, self-describing plan for one operator-gated live smoke.
///
/// Constructing a plan performs no I/O and dispatches nothing. It is the
/// document an operator reads *before* deciding whether to spend money, and
/// the exact digest any grant and any record must name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRepairSmokePlan {
    target: LiveRepairSmokeTarget,
    model_binding_digest: String,
    policy_binding_digest: String,
    provider_id: String,
    model_id: String,
    adapter_identity: String,
    adapter_version: String,
    provider_profile: String,
    source_revision: String,
    proposal_schema_digest: String,
    max_request_bytes: u64,
    max_response_bytes: u64,
    expected_turns: u32,
    effective: ModelBudgetLimits,
    json: String,
    digest: String,
}

impl LiveRepairSmokePlan {
    /// Bind one plan.
    ///
    /// `invocation_policy` may only narrow: it is the third argument to the
    /// existing three-way `intersect`, reached through
    /// [`SourceModelBinding::policy_binding`]. `expected_turns` must be at
    /// least [`MIN_SMOKE_TURNS`] -- a smoke that cannot reach a second turn
    /// cannot exercise the wrong-then-corrected feedback loop this workflow
    /// exists to demonstrate -- and must fit inside the derived `max_calls`.
    pub fn bind(
        target: LiveRepairSmokeTarget,
        binding: &SourceModelBinding,
        invocation_policy: ModelBudgetLimits,
        expected_turns: u32,
    ) -> Result<Self> {
        if !(MIN_SMOKE_TURNS..=MAX_SMOKE_TURNS).contains(&expected_turns) {
            return Err(refused(
                "smoke turn count is outside the two-to-sixteen live smoke range",
            ));
        }
        let policy = binding.policy_binding(invocation_policy).map_err(refused)?;
        let effective = policy.effective().limits();
        if effective.max_calls < expected_turns {
            return Err(refused(
                "smoke turn count exceeds the effective model call ceiling",
            ));
        }
        if effective.max_cost_micros <= 0 {
            return Err(refused(
                "smoke effective cost ceiling admits no paid attempt",
            ));
        }

        let adapter = binding.adapter_identity();
        validate_label(
            &adapter.provider_id,
            "smoke provider identity is out of bounds",
        )?;
        validate_label(&adapter.model_id, "smoke model identity is out of bounds")?;
        let model_binding_digest = binding.digest().to_owned();
        let policy_binding_digest = policy.digest().to_owned();
        validate_digest_label(&model_binding_digest)?;
        validate_digest_label(&policy_binding_digest)?;

        let max_request_bytes = binding.max_request_bytes() as u64;
        let max_response_bytes = binding.max_response_bytes() as u64;
        let source_revision = binding.source_revision().to_owned();
        let proposal_schema_digest = binding.proposal_schema_digest().to_owned();

        let value = json!({
            "adapter_identity": adapter.adapter_identity,
            "adapter_version": adapter.adapter_version,
            "dispatch_authority": false,
            "effective_budget": limits_json(&effective),
            "expected_turns": expected_turns,
            "max_request_bytes": max_request_bytes,
            "max_response_bytes": max_response_bytes,
            "model_binding_digest": model_binding_digest,
            "model_id": adapter.model_id,
            "nonclaims": [
                "a_plan_is_not_operator_authorization_to_spend",
                "a_plan_performs_no_provider_network_or_filesystem_work",
                "a_plan_carries_no_credential_endpoint_prompt_or_response_body",
                "a_plan_grants_no_source_write_or_publication_authority",
            ],
            "policy_binding_digest": policy_binding_digest,
            "profile": adapter.provider_profile,
            "proposal_schema_digest": proposal_schema_digest,
            "provider_id": adapter.provider_id,
            "schema": LIVE_REPAIR_SMOKE_PLAN_SCHEMA,
            "source_revision": source_revision,
            "target": serde_json::from_str::<Value>(target.to_json())
                .map_err(|_| refused("smoke target document is not readable"))?,
            "target_digest": target.digest(),
        });
        let json = render(&value)?;
        let digest = digest(DOMAIN, json.as_bytes());
        Ok(Self {
            target,
            model_binding_digest,
            policy_binding_digest,
            provider_id: adapter.provider_id.clone(),
            model_id: adapter.model_id.clone(),
            adapter_identity: adapter.adapter_identity.clone(),
            adapter_version: adapter.adapter_version.clone(),
            provider_profile: adapter.provider_profile.clone(),
            source_revision,
            proposal_schema_digest,
            max_request_bytes,
            max_response_bytes,
            expected_turns,
            effective,
            json,
            digest,
        })
    }

    /// Reparse a plan document produced by an earlier session, re-deriving its
    /// nested target from the same bytes.
    pub fn replay(expected_digest: &str, bytes: &[u8]) -> Result<Self> {
        let value = replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_PLAN_SCHEMA,
            expected_digest,
            bytes,
        )?;
        let target_value = value
            .get("target")
            .ok_or_else(|| refused("replayed smoke plan is missing its target"))?;
        let target_bytes = render(target_value)?;
        let target_digest = string_field(&value, "target_digest")?;
        let target = LiveRepairSmokeTarget::replay(&target_digest, target_bytes.as_bytes())?;
        let effective = limits_from_json(
            value
                .get("effective_budget")
                .ok_or_else(|| refused("replayed smoke plan is missing its effective budget"))?,
        )?;
        let model_binding_digest = string_field(&value, "model_binding_digest")?;
        let policy_binding_digest = string_field(&value, "policy_binding_digest")?;
        validate_digest_label(&model_binding_digest)?;
        validate_digest_label(&policy_binding_digest)?;
        let expected_turns = u32_field(&value, "expected_turns")?;
        if !(MIN_SMOKE_TURNS..=MAX_SMOKE_TURNS).contains(&expected_turns) {
            return Err(refused(
                "replayed smoke plan has an out-of-range turn count",
            ));
        }
        Ok(Self {
            target,
            model_binding_digest,
            policy_binding_digest,
            provider_id: string_field(&value, "provider_id")?,
            model_id: string_field(&value, "model_id")?,
            adapter_identity: string_field(&value, "adapter_identity")?,
            adapter_version: string_field(&value, "adapter_version")?,
            provider_profile: string_field(&value, "profile")?,
            source_revision: string_field(&value, "source_revision")?,
            proposal_schema_digest: string_field(&value, "proposal_schema_digest")?,
            max_request_bytes: super::u64_field(&value, "max_request_bytes")?,
            max_response_bytes: super::u64_field(&value, "max_response_bytes")?,
            expected_turns,
            effective,
            json: String::from_utf8(bytes.to_vec())
                .map_err(|_| refused("replayed smoke plan is not UTF-8"))?,
            digest: expected_digest.to_owned(),
        })
    }

    #[must_use]
    pub fn target(&self) -> &LiveRepairSmokeTarget {
        &self.target
    }
    #[must_use]
    pub fn model_binding_digest(&self) -> &str {
        &self.model_binding_digest
    }
    #[must_use]
    pub fn policy_binding_digest(&self) -> &str {
        &self.policy_binding_digest
    }
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }
    #[must_use]
    pub fn adapter_identity(&self) -> &str {
        &self.adapter_identity
    }
    #[must_use]
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }
    #[must_use]
    pub fn provider_profile(&self) -> &str {
        &self.provider_profile
    }
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }
    #[must_use]
    pub fn proposal_schema_digest(&self) -> &str {
        &self.proposal_schema_digest
    }
    #[must_use]
    pub fn max_request_bytes(&self) -> u64 {
        self.max_request_bytes
    }
    #[must_use]
    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
    #[must_use]
    pub fn expected_turns(&self) -> u32 {
        self.expected_turns
    }
    #[must_use]
    pub fn effective_budget(&self) -> ModelBudgetLimits {
        self.effective
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

pub(crate) fn limits_json(limits: &ModelBudgetLimits) -> Value {
    json!({
        "max_aggregate_tokens": limits.max_aggregate_tokens,
        "max_calls": limits.max_calls,
        "max_context_tokens": limits.max_context_tokens,
        "max_cost_micros": limits.max_cost_micros,
        "max_latency_millis": limits.max_latency_millis,
        "max_output_tokens": limits.max_output_tokens,
        "max_providers": limits.max_providers,
        "max_retries": limits.max_retries,
    })
}

pub(crate) fn limits_from_json(value: &Value) -> Result<ModelBudgetLimits> {
    Ok(ModelBudgetLimits {
        max_calls: u32_field(value, "max_calls")?,
        max_retries: u32_field(value, "max_retries")?,
        max_providers: u32_field(value, "max_providers")?,
        max_context_tokens: super::u64_field(value, "max_context_tokens")?,
        max_output_tokens: super::u64_field(value, "max_output_tokens")?,
        max_aggregate_tokens: super::u64_field(value, "max_aggregate_tokens")?,
        max_cost_micros: super::i64_field(value, "max_cost_micros")?,
        max_latency_millis: super::i64_field(value, "max_latency_millis")?,
    })
}
