//! The dispatch-free readiness receipt.
//!
//! This is the route a fresh operator can always run: it needs no credential,
//! opens no socket, spends nothing, and answers exactly one question -- "is
//! this planned live smoke ready, and if not, which prerequisite is missing?"
//!
//! The receipt states `dispatched: false` and `provider_dispatch_count: 0` as
//! literal facts of the document, so a preflight receipt found in a log can
//! never be misread as evidence that a live run happened.

use std::sync::Arc;

use serde_json::{json, Value};

use super::authorization::OperatorLiveSmokeGrant;
use super::plan::{limits_json, LiveRepairSmokePlan};
use super::{digest, render, Result, LIVE_REPAIR_SMOKE_PREFLIGHT_SCHEMA};
use crate::project::{ProjectCandidate, ProjectRevision};

const DOMAIN: &[u8] = b"semaprax.live-repair-smoke-preflight.v1\0";

/// One named readiness condition and whether it currently holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRepairSmokePrerequisite {
    id: &'static str,
    satisfied: bool,
    detail: String,
}

impl LiveRepairSmokePrerequisite {
    #[must_use]
    pub fn id(&self) -> &str {
        self.id
    }
    #[must_use]
    pub fn satisfied(&self) -> bool {
        self.satisfied
    }
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    fn json(&self) -> Value {
        json!({"detail": self.detail, "id": self.id, "satisfied": self.satisfied})
    }
}

/// The complete readiness receipt for one plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRepairSmokePreflight {
    plan_digest: String,
    prerequisites: Vec<LiveRepairSmokePrerequisite>,
    ready: bool,
    json: String,
    digest: String,
}

impl LiveRepairSmokePreflight {
    /// Evaluate every prerequisite for `plan` against the live retained
    /// `project` and an optional operator grant.
    ///
    /// Passing `None` for `grant` is the ordinary, documented offline case: the
    /// receipt then reports `operator_grant_present: false` and `ready: false`,
    /// which is the honest state of an unexecuted live smoke.
    ///
    /// Every individual prerequisite failure is reported, not returned as an
    /// error, so an operator sees the whole picture from one run. Only a
    /// malformed document refuses.
    pub fn derive(
        plan: &LiveRepairSmokePlan,
        project: &Arc<ProjectRevision>,
        grant: Option<&OperatorLiveSmokeGrant>,
    ) -> Result<Self> {
        let mut prerequisites = Vec::new();

        let unchanged = plan.target().require_unchanged(project);
        prerequisites.push(condition(
            "retained_source_bytes_unchanged",
            unchanged.is_ok(),
            "the planned source path, its exact bytes and the project revision still match the plan",
            "the retained project or its planned source bytes drifted after the plan was bound",
        ));

        let target_resolves = resolves(project, plan.target().repair_target());
        prerequisites.push(condition(
            "repair_target_resolves_in_the_retained_project",
            target_resolves,
            "the planned repair target names a declaration of the retained revision",
            "the planned repair target no longer names a declaration of the retained revision",
        ));

        let effective = plan.effective_budget();
        prerequisites.push(condition(
            "effective_budget_admits_the_expected_turns",
            effective.max_calls >= plan.expected_turns() && effective.max_cost_micros > 0,
            "the derived effective ceiling admits every planned turn and a nonzero cost",
            "the derived effective ceiling cannot carry the planned turns or admits no cost",
        ));

        prerequisites.push(condition(
            "provider_adapter_selection_is_bound",
            !plan.provider_id().is_empty()
                && !plan.model_id().is_empty()
                && !plan.adapter_identity().is_empty(),
            "one deployment-admitted provider, model and adapter identity is bound",
            "no provider, model and adapter identity is bound",
        ));

        prerequisites.push(condition(
            "operator_grant_present",
            grant.is_some(),
            "an explicit operator grant was supplied to this preflight",
            "no operator grant was supplied; this live smoke is planned but not authorized",
        ));

        prerequisites.push(condition(
            "operator_grant_binds_this_exact_plan",
            grant.is_some_and(|grant| grant.plan_digest() == plan.digest()),
            "the supplied operator grant names this exact plan digest",
            "no operator grant names this exact plan digest",
        ));

        let ready = prerequisites
            .iter()
            .all(LiveRepairSmokePrerequisite::satisfied);
        let plan_digest = plan.digest().to_owned();
        let value = json!({
            "credentials_read": false,
            "dispatched": false,
            "effective_budget": limits_json(&effective),
            "evidence_class": "dispatch_free_local_readiness_evaluation",
            "expected_turns": plan.expected_turns(),
            "filesystem_write": false,
            "model_id": plan.model_id(),
            "network_observation": false,
            "nonclaims": [
                "a_preflight_receipt_is_not_evidence_that_a_live_run_occurred",
                "a_preflight_receipt_is_not_operator_authorization_to_spend",
                "readiness_is_not_a_prediction_that_the_provider_will_succeed",
                "no_source_mutation_git_write_or_publication_authority",
            ],
            "plan_digest": plan_digest,
            "prerequisites": prerequisites
                .iter()
                .map(LiveRepairSmokePrerequisite::json)
                .collect::<Vec<_>>(),
            "provider_dispatch_count": 0,
            "provider_id": plan.provider_id(),
            "publication_authority": false,
            "ready": ready,
            "schema": LIVE_REPAIR_SMOKE_PREFLIGHT_SCHEMA,
            "source_mutation": false,
        });
        let json = render(&value)?;
        let digest = digest(DOMAIN, json.as_bytes());
        Ok(Self {
            plan_digest,
            prerequisites,
            ready,
            json,
            digest,
        })
    }

    /// Whether every prerequisite holds. `false` is the expected state of a
    /// live smoke that has been built and documented but deliberately not run.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.ready
    }
    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
    #[must_use]
    pub fn prerequisites(&self) -> &[LiveRepairSmokePrerequisite] {
        &self.prerequisites
    }
    /// The first unsatisfied prerequisite, if any -- the one an operator has
    /// to act on next.
    #[must_use]
    pub fn blocking(&self) -> Option<&LiveRepairSmokePrerequisite> {
        self.prerequisites
            .iter()
            .find(|prerequisite| !prerequisite.satisfied)
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

fn condition(
    id: &'static str,
    satisfied: bool,
    satisfied_detail: &str,
    unsatisfied_detail: &str,
) -> LiveRepairSmokePrerequisite {
    LiveRepairSmokePrerequisite {
        id,
        satisfied,
        detail: if satisfied {
            satisfied_detail.to_owned()
        } else {
            unsatisfied_detail.to_owned()
        },
    }
}

fn resolves(project: &Arc<ProjectRevision>, target: &str) -> bool {
    let Ok(root) = ProjectCandidate::open(Arc::clone(project), project.project_revision()) else {
        return false;
    };
    root.semantic_delta(root.candidate_digest(), target).is_ok()
}

impl LiveRepairSmokePlan {
    /// Convenience entry point: evaluate readiness without an operator grant.
    ///
    /// This is the command a fresh operator runs first. It never dispatches.
    pub fn preflight(&self, project: &Arc<ProjectRevision>) -> Result<LiveRepairSmokePreflight> {
        LiveRepairSmokePreflight::derive(self, project, None)
    }

    /// Evaluate readiness with an operator grant in hand.
    pub fn authorized_preflight(
        &self,
        project: &Arc<ProjectRevision>,
        grant: &OperatorLiveSmokeGrant,
    ) -> Result<LiveRepairSmokePreflight> {
        LiveRepairSmokePreflight::derive(self, project, Some(grant))
    }
}
