//! Review export and the separately approved publication boundary for one
//! repaired candidate.
//!
//! The repair workflow's default run stops at a reviewed candidate: it mutates
//! no authoritative source and touches no Git. Publishing is a *different act*
//! in a *different session*, and this module is the only route from a repaired
//! candidate to it.
//!
//! Two values, in strict order:
//!
//! 1. [`RepairCandidateReview`] is the export an operator or a reviewer reads:
//!    the exact source diff, the semantic delta, the impact summary, the
//!    validation results, the declared blind spots and the journal binding --
//!    all independently regenerated from the candidate rather than copied from
//!    whatever the model claimed. Producing it grants nothing.
//! 2. [`RepairCandidateApproval`] is minted only by
//!    [`RepairCandidateApproval::approve`], a distinct human act over one exact
//!    review. It names one candidate digest.
//!
//! [`prepare_approved_repair_publication`] and
//! [`apply_approved_repair_publication`] require that approval and then
//! delegate to the unmodified `project::prepare_candidate_publication` /
//! `project::apply_candidate_publication` boundary, which performs its own
//! independent replay and remains the only authority that pivots `ACTIVE`.
//! Because the approval carries candidate A's digest, presenting candidate B
//! with it is refused here *and* again by that boundary's own
//! `approved_candidate_digest` check.
//!
//! See `docs/LIVE-REPAIR-SMOKE-V1.md`.

use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::diagnostic::Diagnostic;
use crate::project::{
    apply_candidate_publication, prepare_candidate_publication, ProjectCandidate,
    ProjectCandidatePublication,
};
use crate::workspace_analysis::WorkspaceImpactOptions;

pub const REPAIR_CANDIDATE_REVIEW_SCHEMA: &str = "semaprax.repair-candidate-review.v1";
pub const REPAIR_CANDIDATE_APPROVAL_SCHEMA: &str = "semaprax.repair-candidate-approval.v1";
pub const MAX_REPAIR_CANDIDATE_REVIEW_BYTES: usize = 256 * 1024;
pub const MAX_REPAIR_CANDIDATE_APPROVAL_BYTES: usize = 16 * 1024;
/// A repair report describes one bounded repair, not a release.
pub const MAX_REPAIR_VALIDATIONS: usize = 32;
pub const MAX_REPAIR_BLIND_SPOTS: usize = 32;

const REVIEW_DOMAIN: &[u8] = b"semaprax.repair-candidate-review.v1\0";
const APPROVAL_DOMAIN: &[u8] = b"semaprax.repair-candidate-approval.v1\0";
const MAX_LABEL_BYTES: usize = 256;

type Result<T> = std::result::Result<T, Vec<Diagnostic>>;

fn refused(detail: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::io(
        "SPX-G583",
        format!("repair candidate approval refused: {detail}"),
    )]
}

fn sha256(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn render(value: &Value, limit: usize) -> Result<String> {
    let mut json =
        serde_json::to_string(value).map_err(|_| refused("document is not renderable JSON"))?;
    json.push('\n');
    if json.len() > limit {
        return Err(refused("document exceeds its transport bound"));
    }
    Ok(json)
}

fn label(value: &str, detail: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(refused(detail));
    }
    Ok(())
}

/// One executed validation and its result, as observed by the host oracle.
///
/// The model never authors these: it cannot run a shell command and cannot
/// alter the oracle. A failed validation is recorded, not suppressed -- a
/// review that carries failures is still a valid review, it is simply one a
/// reviewer should refuse to approve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairValidationOutcome {
    check_id: String,
    status: RepairValidationStatus,
    detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairValidationStatus {
    Passed,
    Failed,
    Skipped,
}

impl RepairValidationStatus {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "passed" => Ok(Self::Passed),
            "failed" => Ok(Self::Failed),
            "skipped" => Ok(Self::Skipped),
            _ => Err(refused("validation status is outside its closed set")),
        }
    }
}

impl RepairValidationOutcome {
    pub fn new(check_id: &str, status: RepairValidationStatus, detail: &str) -> Result<Self> {
        label(check_id, "validation check identity is out of bounds")?;
        if detail.len() > MAX_LABEL_BYTES || detail.chars().any(char::is_control) {
            return Err(refused("validation detail is out of bounds"));
        }
        Ok(Self {
            check_id: check_id.to_owned(),
            status,
            detail: detail.to_owned(),
        })
    }

    #[must_use]
    pub fn check_id(&self) -> &str {
        &self.check_id
    }
    #[must_use]
    pub fn status(&self) -> RepairValidationStatus {
        self.status
    }
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    fn json(&self) -> Value {
        json!({"check_id": self.check_id, "detail": self.detail, "status": self.status.name()})
    }

    fn from_json(value: &Value) -> Result<Self> {
        let status = RepairValidationStatus::parse(
            value
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| refused("replayed validation is missing its status"))?,
        )?;
        Self::new(
            value
                .get("check_id")
                .and_then(Value::as_str)
                .ok_or_else(|| refused("replayed validation is missing its check identity"))?,
            status,
            value.get("detail").and_then(Value::as_str).unwrap_or(""),
        )
    }
}

/// The complete reviewable export for one repaired candidate.
///
/// Every digest here is regenerated from the candidate at derive time. A
/// review therefore cannot describe a candidate other than the one it was
/// derived from, and cannot be weakened by a caller passing a friendlier
/// report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairCandidateReview {
    candidate_digest: String,
    base_project_revision: String,
    candidate_project_revision: String,
    repair_target: String,
    changed_paths: Vec<String>,
    source_review_digest: String,
    semantic_delta_digest: String,
    impact_summary_digest: String,
    journal_digest: String,
    validations: Vec<RepairValidationOutcome>,
    blind_spots: Vec<String>,
    json: String,
    digest: String,
}

impl RepairCandidateReview {
    /// Regenerate the whole review from `candidate`.
    ///
    /// `journal_digest` binds the causal journal the repair run produced, so a
    /// reviewer can tie the candidate back to the exact recorded conversation
    /// and effect observations that produced it. `blind_spots` are the host's
    /// own declared gaps -- what this review does *not* establish.
    pub fn derive(
        candidate: &ProjectCandidate,
        repair_target: &str,
        journal_digest: &str,
        validations: &[RepairValidationOutcome],
        blind_spots: &[String],
    ) -> Result<Self> {
        label(repair_target, "repair target is out of bounds")?;
        label(journal_digest, "journal digest label is out of bounds")?;
        if validations.len() > MAX_REPAIR_VALIDATIONS {
            return Err(refused("review carries more validations than permitted"));
        }
        if blind_spots.len() > MAX_REPAIR_BLIND_SPOTS {
            return Err(refused("review carries more blind spots than permitted"));
        }
        for blind_spot in blind_spots {
            label(blind_spot, "blind spot label is out of bounds")?;
        }

        let candidate_digest = candidate.candidate_digest().to_owned();
        let source_review = candidate.source_review(&candidate_digest)?;
        let semantic_delta = candidate.semantic_delta(&candidate_digest, repair_target)?;
        let impact_summary = candidate.impact_summary(
            &candidate_digest,
            repair_target,
            WorkspaceImpactOptions::default(),
        )?;

        let review_value: Value = serde_json::from_str(&source_review)
            .map_err(|_| refused("candidate source review is not readable JSON"))?;
        let base_project_revision = review_value
            .get("base_project_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("candidate source review has no base project revision"))?
            .to_owned();
        let candidate_project_revision = review_value
            .get("candidate_project_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("candidate source review has no candidate project revision"))?
            .to_owned();
        let changed_paths = review_value
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| refused("candidate source review has no changed-file inventory"))?
            .iter()
            .map(|file| {
                file.get("path")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| refused("candidate source review row has no path"))
            })
            .collect::<Result<Vec<_>>>()?;
        if changed_paths.is_empty() {
            return Err(refused(
                "a repair review requires at least one changed source",
            ));
        }

        let source_review_digest = sha256(REVIEW_DOMAIN, source_review.as_bytes());
        let semantic_delta_digest = sha256(REVIEW_DOMAIN, semantic_delta.as_bytes());
        let impact_summary_digest = sha256(REVIEW_DOMAIN, impact_summary.as_bytes());

        let value = json!({
            "approval_authority": false,
            "base_project_revision": base_project_revision,
            "blind_spots": blind_spots,
            "candidate_digest": candidate_digest,
            "candidate_project_revision": candidate_project_revision,
            "changed_paths": changed_paths,
            "evidence_class": "independently_regenerated_repair_candidate_review",
            "impact_summary_digest": impact_summary_digest,
            "journal_digest": journal_digest,
            "nonclaims": [
                "a_review_is_not_approval_and_approval_is_a_separate_act",
                "a_review_grants_no_source_write_git_or_publication_authority",
                "regenerated_digests_describe_this_candidate_only",
                "declared_blind_spots_are_not_an_exhaustive_risk_assessment",
            ],
            "publication_authority": false,
            "repair_target": repair_target,
            "schema": REPAIR_CANDIDATE_REVIEW_SCHEMA,
            "semantic_delta_digest": semantic_delta_digest,
            "source_mutation": false,
            "source_review_digest": source_review_digest,
            "validations": validations
                .iter()
                .map(RepairValidationOutcome::json)
                .collect::<Vec<_>>(),
        });
        let json = render(&value, MAX_REPAIR_CANDIDATE_REVIEW_BYTES)?;
        let digest = sha256(REVIEW_DOMAIN, json.as_bytes());
        Ok(Self {
            candidate_digest,
            base_project_revision,
            candidate_project_revision,
            repair_target: repair_target.to_owned(),
            changed_paths,
            source_review_digest,
            semantic_delta_digest,
            impact_summary_digest,
            journal_digest: journal_digest.to_owned(),
            validations: validations.to_vec(),
            blind_spots: blind_spots.to_vec(),
            json,
            digest,
        })
    }

    /// Reparse a review document produced by an earlier session.
    pub fn replay(expected_digest: &str, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_REPAIR_CANDIDATE_REVIEW_BYTES {
            return Err(refused("replayed review is empty or exceeds its bound"));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| refused("replayed review is not JSON"))?;
        if value.get("schema").and_then(Value::as_str) != Some(REPAIR_CANDIDATE_REVIEW_SCHEMA) {
            return Err(refused("replayed review has a different schema"));
        }
        if render(&value, MAX_REPAIR_CANDIDATE_REVIEW_BYTES)?.as_bytes() != bytes {
            return Err(refused("replayed review is not canonical JSON"));
        }
        if sha256(REVIEW_DOMAIN, bytes) != expected_digest {
            return Err(refused("replayed review digest is stale"));
        }
        let text = |key: &str| -> Result<String> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| refused("replayed review is missing a required field"))
        };
        let strings = |key: &str| -> Result<Vec<String>> {
            value
                .get(key)
                .and_then(Value::as_array)
                .ok_or_else(|| refused("replayed review is missing a required array"))?
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| refused("replayed review array holds a non-string"))
                })
                .collect()
        };
        let validations = value
            .get("validations")
            .and_then(Value::as_array)
            .ok_or_else(|| refused("replayed review is missing its validations"))?
            .iter()
            .map(RepairValidationOutcome::from_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            candidate_digest: text("candidate_digest")?,
            base_project_revision: text("base_project_revision")?,
            candidate_project_revision: text("candidate_project_revision")?,
            repair_target: text("repair_target")?,
            changed_paths: strings("changed_paths")?,
            source_review_digest: text("source_review_digest")?,
            semantic_delta_digest: text("semantic_delta_digest")?,
            impact_summary_digest: text("impact_summary_digest")?,
            journal_digest: text("journal_digest")?,
            validations,
            blind_spots: strings("blind_spots")?,
            json: String::from_utf8(bytes.to_vec())
                .map_err(|_| refused("replayed review is not UTF-8"))?,
            digest: expected_digest.to_owned(),
        })
    }

    /// Whether every recorded validation passed. A reviewer is free to approve
    /// anyway; this only reports what the oracle observed.
    #[must_use]
    pub fn all_validations_passed(&self) -> bool {
        !self.validations.is_empty()
            && self
                .validations
                .iter()
                .all(|validation| validation.status == RepairValidationStatus::Passed)
    }

    #[must_use]
    pub fn candidate_digest(&self) -> &str {
        &self.candidate_digest
    }
    #[must_use]
    pub fn base_project_revision(&self) -> &str {
        &self.base_project_revision
    }
    #[must_use]
    pub fn candidate_project_revision(&self) -> &str {
        &self.candidate_project_revision
    }
    #[must_use]
    pub fn repair_target(&self) -> &str {
        &self.repair_target
    }
    #[must_use]
    pub fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }
    #[must_use]
    pub fn source_review_digest(&self) -> &str {
        &self.source_review_digest
    }
    #[must_use]
    pub fn semantic_delta_digest(&self) -> &str {
        &self.semantic_delta_digest
    }
    #[must_use]
    pub fn impact_summary_digest(&self) -> &str {
        &self.impact_summary_digest
    }
    #[must_use]
    pub fn journal_digest(&self) -> &str {
        &self.journal_digest
    }
    #[must_use]
    pub fn validations(&self) -> &[RepairValidationOutcome] {
        &self.validations
    }
    #[must_use]
    pub fn blind_spots(&self) -> &[String] {
        &self.blind_spots
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

/// Authority-free evidence that a reviewer approved one exact repaired
/// candidate.
///
/// Minted only by [`Self::approve`]. Deriving a review, running a smoke or
/// holding a candidate never implies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairCandidateApproval {
    review_digest: String,
    candidate_digest: String,
    base_project_revision: String,
    approver_reference: String,
    json: String,
    digest: String,
}

impl RepairCandidateApproval {
    pub fn approve(review: &RepairCandidateReview, approver_reference: &str) -> Result<Self> {
        label(approver_reference, "approver reference is out of bounds")?;
        let value = json!({
            "approver_reference": approver_reference,
            "base_project_revision": review.base_project_revision,
            "candidate_digest": review.candidate_digest,
            "nonclaims": [
                "an_approval_binds_only_the_exact_candidate_digest_named_here",
                "a_rederived_candidate_with_a_different_digest_is_not_authorized",
                "review_and_approval_are_distinct_acts",
                "an_approval_is_not_itself_the_publication_invocation",
            ],
            "repair_target": review.repair_target,
            "review_digest": review.digest,
            "schema": REPAIR_CANDIDATE_APPROVAL_SCHEMA,
        });
        let json = render(&value, MAX_REPAIR_CANDIDATE_APPROVAL_BYTES)?;
        let digest = sha256(APPROVAL_DOMAIN, json.as_bytes());
        Ok(Self {
            review_digest: review.digest.clone(),
            candidate_digest: review.candidate_digest.clone(),
            base_project_revision: review.base_project_revision.clone(),
            approver_reference: approver_reference.to_owned(),
            json,
            digest,
        })
    }

    /// Reparse an approval that crossed a session boundary. This is the shape
    /// of the "new independently approved session": the approving session hands
    /// over canonical bytes and a digest, and the publishing session re-derives
    /// the value rather than trusting an in-process object.
    pub fn replay(expected_digest: &str, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_REPAIR_CANDIDATE_APPROVAL_BYTES {
            return Err(refused("replayed approval is empty or exceeds its bound"));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| refused("replayed approval is not JSON"))?;
        if value.get("schema").and_then(Value::as_str) != Some(REPAIR_CANDIDATE_APPROVAL_SCHEMA) {
            return Err(refused("replayed approval has a different schema"));
        }
        if render(&value, MAX_REPAIR_CANDIDATE_APPROVAL_BYTES)?.as_bytes() != bytes {
            return Err(refused("replayed approval is not canonical JSON"));
        }
        if sha256(APPROVAL_DOMAIN, bytes) != expected_digest {
            return Err(refused("replayed approval digest is stale"));
        }
        let text = |key: &str| -> Result<String> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| refused("replayed approval is missing a required field"))
        };
        Ok(Self {
            review_digest: text("review_digest")?,
            candidate_digest: text("candidate_digest")?,
            base_project_revision: text("base_project_revision")?,
            approver_reference: text("approver_reference")?,
            json: String::from_utf8(bytes.to_vec())
                .map_err(|_| refused("replayed approval is not UTF-8"))?,
            digest: expected_digest.to_owned(),
        })
    }

    /// Refuse a candidate this approval does not name. This is the check that
    /// makes "approval for candidate A cannot publish candidate B" true at this
    /// route's own boundary, before the delegated publication boundary re-checks
    /// it independently.
    pub fn require_candidate(&self, candidate: &ProjectCandidate) -> Result<()> {
        if candidate.candidate_digest() != self.candidate_digest {
            return Err(refused(
                "approval names a different candidate than the one presented",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn review_digest(&self) -> &str {
        &self.review_digest
    }
    #[must_use]
    pub fn candidate_digest(&self) -> &str {
        &self.candidate_digest
    }
    #[must_use]
    pub fn base_project_revision(&self) -> &str {
        &self.base_project_revision
    }
    #[must_use]
    pub fn approver_reference(&self) -> &str {
        &self.approver_reference
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

/// Read-only preparation of one approved repaired candidate's publication.
///
/// Refuses before touching the workspace when the approval names a different
/// candidate, then delegates to the unmodified managed-workspace boundary.
pub fn prepare_approved_repair_publication(
    approval: &RepairCandidateApproval,
    candidate: &ProjectCandidate,
    workspace_root: &Path,
    project_manifest: &Path,
    expected_workspace_revision: &str,
) -> Result<ProjectCandidatePublication> {
    approval.require_candidate(candidate)?;
    prepare_candidate_publication(
        candidate,
        approval.candidate_digest(),
        workspace_root,
        project_manifest,
        expected_workspace_revision,
    )
}

/// The separately authorized publishing invocation for one approved repaired
/// candidate. The live invocation performed here remains the only authority
/// that pivots `ACTIVE`.
pub fn apply_approved_repair_publication(
    approval: &RepairCandidateApproval,
    candidate: &ProjectCandidate,
    workspace_root: &Path,
    project_manifest: &Path,
    expected_workspace_revision: &str,
    submitted_publication: &[u8],
) -> Result<String> {
    approval.require_candidate(candidate)?;
    apply_candidate_publication(
        candidate,
        approval.candidate_digest(),
        workspace_root,
        project_manifest,
        expected_workspace_revision,
        submitted_publication,
    )
}
