//! The exact retained-Project facts one live smoke is bound to.
//!
//! Binding happens against a retained [`ProjectRevision`], never against host
//! strings a caller asserts. The source path is looked up inside the retained
//! source inventory and the repair target is resolved through the ordinary
//! candidate semantic-delta route, so a target that names nothing in the
//! project is refused before any plan, grant or provider adapter exists.

use std::sync::Arc;

use serde_json::{json, Value};

use super::{
    digest, refused, render, replay_document, string_field, validate_digest_label, validate_label,
    Result, LIVE_REPAIR_SMOKE_TARGET_SCHEMA,
};
use crate::project::{ProjectCandidate, ProjectRevision};

const DOMAIN: &[u8] = b"semaprax.live-repair-smoke-target.v1\0";

/// One retained Project selection a live smoke may run against.
///
/// Every field is a checked fact copied out of the retained revision, not a
/// caller assertion. Holding this value grants nothing; it is the *subject* a
/// plan is written about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveRepairSmokeTarget {
    project_revision: String,
    workspace_revision: String,
    source_path: String,
    source_digest: String,
    source_bytes: u64,
    agent_id: String,
    step_id: String,
    repair_target: String,
    observed_failure: String,
    json: String,
    digest: String,
}

impl LiveRepairSmokeTarget {
    /// Bind one smoke target to the retained revision.
    ///
    /// `source_path` is a Project-relative identity resolved inside
    /// [`ProjectRevision::sources`]. A path that is absolute, contains a
    /// traversal segment, does not end in `.spx`, or simply is not part of the
    /// retained inventory is refused -- there is no route here by which a model
    /// or a host config can reach a file outside the project.
    ///
    /// `observed_failure` names the *real* failed check or test this smoke
    /// exists to repair. It is recorded as an identity so a later reader can
    /// tell which failure the run was actually about; it is never executed.
    pub fn bind(
        project: &Arc<ProjectRevision>,
        source_path: &str,
        agent_id: &str,
        step_id: &str,
        repair_target: &str,
        observed_failure: &str,
    ) -> Result<Self> {
        validate_label(agent_id, "smoke agent identity is out of bounds")?;
        validate_label(step_id, "smoke step identity is out of bounds")?;
        validate_label(repair_target, "smoke repair target is out of bounds")?;
        validate_label(observed_failure, "smoke observed failure is out of bounds")?;
        validate_source_path(source_path)?;

        let source = project
            .sources()
            .iter()
            .find(|source| source.path() == source_path)
            .ok_or_else(|| {
                refused("smoke source path is not part of the retained Project inventory")
            })?;

        // Resolve the repair target through the ordinary candidate route. This
        // is the same admission `OfflineRepairEnvelope::new` performs, reused
        // rather than reimplemented, and it proves the target names a real
        // declaration of this exact revision before a paid call is ever
        // planned.
        let root = ProjectCandidate::open(Arc::clone(project), project.project_revision())?;
        root.semantic_delta(root.candidate_digest(), repair_target)?;

        let source_bytes = u64::try_from(source.source().len())
            .map_err(|_| refused("smoke source size is out of range"))?;
        let project_revision = project.project_revision().to_owned();
        let workspace_revision = project.workspace_revision().to_owned();
        let source_digest = source.source_digest().to_owned();
        validate_digest_label(&project_revision)?;

        let value = json!({
            "agent_id": agent_id,
            "observed_failure": observed_failure,
            "project_revision": project_revision,
            "repair_target": repair_target,
            "schema": LIVE_REPAIR_SMOKE_TARGET_SCHEMA,
            "source_bytes": source_bytes,
            "source_digest": source_digest,
            "source_path": source_path,
            "step_id": step_id,
            "workspace_revision": workspace_revision,
        });
        let json = render(&value)?;
        let digest = digest(DOMAIN, json.as_bytes());
        Ok(Self {
            project_revision,
            workspace_revision,
            source_path: source_path.to_owned(),
            source_digest,
            source_bytes,
            agent_id: agent_id.to_owned(),
            step_id: step_id.to_owned(),
            repair_target: repair_target.to_owned(),
            observed_failure: observed_failure.to_owned(),
            json,
            digest,
        })
    }

    /// Reparse a target document produced by an earlier session.
    pub fn replay(expected_digest: &str, bytes: &[u8]) -> Result<Self> {
        let value = replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_TARGET_SCHEMA,
            expected_digest,
            bytes,
        )?;
        let project_revision = string_field(&value, "project_revision")?;
        validate_digest_label(&project_revision)?;
        let source_bytes = value
            .get("source_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| refused("replayed smoke target is missing its source size"))?;
        let target = Self {
            project_revision,
            workspace_revision: string_field(&value, "workspace_revision")?,
            source_path: string_field(&value, "source_path")?,
            source_digest: string_field(&value, "source_digest")?,
            source_bytes,
            agent_id: string_field(&value, "agent_id")?,
            step_id: string_field(&value, "step_id")?,
            repair_target: string_field(&value, "repair_target")?,
            observed_failure: string_field(&value, "observed_failure")?,
            json: String::from_utf8(bytes.to_vec())
                .map_err(|_| refused("replayed smoke target is not UTF-8"))?,
            digest: expected_digest.to_owned(),
        };
        validate_source_path(&target.source_path)?;
        validate_label(
            &target.agent_id,
            "replayed smoke agent identity is out of bounds",
        )?;
        validate_label(
            &target.step_id,
            "replayed smoke step identity is out of bounds",
        )?;
        validate_label(
            &target.repair_target,
            "replayed smoke repair target is out of bounds",
        )?;
        Ok(target)
    }

    /// Recheck this target against a live retained revision. A drifted source
    /// byte digest, a moved project revision or a vanished source path fails
    /// closed: a paid call is never made against facts that have already
    /// changed underneath the plan.
    pub fn require_unchanged(&self, project: &ProjectRevision) -> Result<()> {
        if project.project_revision() != self.project_revision {
            return Err(refused("smoke target project revision drifted"));
        }
        if project.workspace_revision() != self.workspace_revision {
            return Err(refused("smoke target workspace revision drifted"));
        }
        let source = project
            .sources()
            .iter()
            .find(|source| source.path() == self.source_path)
            .ok_or_else(|| refused("smoke target source path is no longer retained"))?;
        if source.source_digest() != self.source_digest {
            return Err(refused("smoke target source bytes drifted"));
        }
        if u64::try_from(source.source().len()).unwrap_or(u64::MAX) != self.source_bytes {
            return Err(refused("smoke target source size drifted"));
        }
        Ok(())
    }

    #[must_use]
    pub fn project_revision(&self) -> &str {
        &self.project_revision
    }
    #[must_use]
    pub fn workspace_revision(&self) -> &str {
        &self.workspace_revision
    }
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    #[must_use]
    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    #[must_use]
    pub fn step_id(&self) -> &str {
        &self.step_id
    }
    #[must_use]
    pub fn repair_target(&self) -> &str {
        &self.repair_target
    }
    #[must_use]
    pub fn observed_failure(&self) -> &str {
        &self.observed_failure
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

/// Project-relative source identity rules. Deliberately stricter than "not
/// absolute": a smoke target must be an ordinary checked `.spx` source of the
/// retained project, with no traversal, no root anchor and no drive prefix.
fn validate_source_path(path: &str) -> Result<()> {
    validate_label(path, "smoke source path is out of bounds")?;
    if path.len() > 240 || !path.ends_with(".spx") {
        return Err(refused("smoke source path is not a bounded .spx identity"));
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains(':') {
        return Err(refused("smoke source path is not Project-relative"));
    }
    if path
        .split(['/', '\\'])
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(refused("smoke source path contains a traversal segment"));
    }
    if !crate::workspace::evidence_path_is_valid(path) {
        return Err(refused("smoke source path is not a valid evidence path"));
    }
    Ok(())
}
