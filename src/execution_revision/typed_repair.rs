//! Private-host offline repair previews reached through the checked typed loop.
//!
//! A source proposal supplies a checked literal value and kind inside a bounded
//! host-owned envelope. Applying its derived [`SemanticChange`] creates an
//! ephemeral [`ProjectCandidate`]. This module intentionally exposes neither a
//! source path nor a publication operation.

use std::sync::Arc;

use crate::agent_lifecycle::iterative::effects::{TypedEffectHandler, TypedEffectRequest};
use crate::diagnostic::Diagnostic;
use crate::interpreter::retained_call::RetainedValue;
use crate::project::{ProjectCandidate, ProjectRevision, SemanticChange};
use crate::workspace_analysis::WorkspaceImpactOptions;

const MAX_TARGET_BYTES: usize = 256;
const MAX_REPLACEMENT_MAGNITUDE: i64 = 1_000_000;

type Result<T> = std::result::Result<T, Vec<Diagnostic>>;

fn refused(detail: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::io(
        "SPX-G583",
        format!("offline repair preview refused: {detail}"),
    )]
}

/// A host-fixed target and bounded expression envelope for one retained project
/// revision. The model supplies the literal value and its checked scalar kind;
/// it cannot choose a path, target, or arbitrary semantic-change JSON.
pub struct OfflineRepairEnvelope {
    project: Arc<ProjectRevision>,
    target: String,
}

impl OfflineRepairEnvelope {
    pub fn new(project: Arc<ProjectRevision>, target: impl Into<String>) -> Result<Self> {
        let target = target.into();
        if target.is_empty() || target.len() > MAX_TARGET_BYTES {
            return Err(refused("target_bounds"));
        }
        let root = ProjectCandidate::open(Arc::clone(&project), project.project_revision())?;
        // This verifies the target against the retained project before any
        // source-model activity can reach the host effect.
        root.semantic_delta(root.candidate_digest(), &target)?;
        Ok(Self { project, target })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn preview(&self, replacement: i64, bool_literal: bool) -> Result<OfflineRepairPreview> {
        if replacement.unsigned_abs() > MAX_REPLACEMENT_MAGNITUDE as u64 {
            return Err(refused("replacement_bounds"));
        }
        let root =
            ProjectCandidate::open(Arc::clone(&self.project), self.project.project_revision())?;
        let body = if bool_literal {
            serde_json::json!({"kind":"bool","value":true})
        } else {
            serde_json::json!({"kind":"i64","value":replacement})
        };
        let change = SemanticChange::new(
            self.project.project_revision(),
            &serde_json::json!({"kind":"replace_function_body","target":self.target,"body":body}),
        )?;
        let candidate = root.apply(root.candidate_digest(), &change)?;
        let candidate_digest = candidate.candidate_digest().to_owned();
        let source_review = candidate.source_review(&candidate_digest)?;
        let semantic_delta = candidate.semantic_delta(&candidate_digest, &self.target)?;
        let impact_summary = candidate.impact_summary(
            &candidate_digest,
            &self.target,
            WorkspaceImpactOptions::default(),
        )?;
        Ok(OfflineRepairPreview {
            replacement,
            bool_literal,
            candidate,
            source_review,
            semantic_delta,
            impact_summary,
        })
    }
}

/// Read-only evidence produced after a selected candidate has passed ordinary
/// candidate admission. Dropping this value discards the candidate.
pub struct OfflineRepairPreview {
    replacement: i64,
    bool_literal: bool,
    candidate: ProjectCandidate,
    source_review: String,
    semantic_delta: String,
    impact_summary: String,
}

impl OfflineRepairPreview {
    pub fn replacement(&self) -> i64 {
        self.replacement
    }
    pub fn bool_literal(&self) -> bool {
        self.bool_literal
    }
    pub fn candidate(&self) -> &ProjectCandidate {
        &self.candidate
    }
    pub fn source_review(&self) -> &str {
        &self.source_review
    }
    pub fn semantic_delta(&self) -> &str {
        &self.semantic_delta
    }
    pub fn impact_summary(&self) -> &str {
        &self.impact_summary
    }
}

/// The exact candidate diagnostics retained by the private host. The typed
/// result carries the first numeric `SPX-GNNN` suffix because the established
/// typed effect transport is scalar-only; it does not serialize diagnostic
/// messages into the source-model prompt.
pub struct OfflineRepairRejection {
    replacement: i64,
    bool_literal: bool,
    feedback_code: i64,
    diagnostics: Vec<Diagnostic>,
}

impl OfflineRepairRejection {
    pub fn replacement(&self) -> i64 {
        self.replacement
    }
    pub fn bool_literal(&self) -> bool {
        self.bool_literal
    }
    pub fn feedback_code(&self) -> i64 {
        self.feedback_code
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// A typed-effect handler for one declared private-host repair operation.
/// Its only result is a stable numeric diagnostic feedback code: zero means a
/// candidate preview was produced. A rejected preview is an ordinary effect
/// result, so the next checked source proposal receives the feedback.
pub struct OfflineRepairHandler {
    envelope: OfflineRepairEnvelope,
    malformed_operation_id: String,
    corrected_operation_id: String,
    effect_id: String,
    replacement_argument_id: String,
    feedback_result_id: String,
    latest_preview: Option<OfflineRepairPreview>,
    latest_rejection: Option<OfflineRepairRejection>,
    rejection_count: u32,
}

impl OfflineRepairHandler {
    pub fn new(
        envelope: OfflineRepairEnvelope,
        malformed_operation_id: impl Into<String>,
        corrected_operation_id: impl Into<String>,
        effect_id: impl Into<String>,
        replacement_argument_id: impl Into<String>,
        feedback_result_id: impl Into<String>,
    ) -> Result<Self> {
        let malformed_operation_id = malformed_operation_id.into();
        let corrected_operation_id = corrected_operation_id.into();
        let effect_id = effect_id.into();
        let replacement_argument_id = replacement_argument_id.into();
        let feedback_result_id = feedback_result_id.into();
        if [
            &malformed_operation_id,
            &corrected_operation_id,
            &effect_id,
            &replacement_argument_id,
            &feedback_result_id,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_TARGET_BYTES)
        {
            return Err(refused("effect_identity"));
        }
        if malformed_operation_id == corrected_operation_id {
            return Err(refused("effect_identity"));
        }
        Ok(Self {
            envelope,
            malformed_operation_id,
            corrected_operation_id,
            effect_id,
            replacement_argument_id,
            feedback_result_id,
            latest_preview: None,
            latest_rejection: None,
            rejection_count: 0,
        })
    }

    pub fn latest_preview(&self) -> Option<&OfflineRepairPreview> {
        self.latest_preview.as_ref()
    }
    pub fn latest_rejection(&self) -> Option<&OfflineRepairRejection> {
        self.latest_rejection.as_ref()
    }
    pub fn rejection_count(&self) -> u32 {
        self.rejection_count
    }

    fn rejection(
        &mut self,
        replacement: i64,
        bool_literal: bool,
        diagnostics: Vec<Diagnostic>,
    ) -> i64 {
        let feedback_code = diagnostics
            .iter()
            .find_map(|diagnostic| {
                diagnostic
                    .code
                    .strip_prefix("SPX-G")
                    .and_then(|value| value.parse::<i64>().ok())
            })
            .unwrap_or(583);
        self.latest_rejection = Some(OfflineRepairRejection {
            replacement,
            bool_literal,
            feedback_code,
            diagnostics,
        });
        self.rejection_count = self.rejection_count.saturating_add(1);
        feedback_code
    }
}

impl TypedEffectHandler for OfflineRepairHandler {
    fn execute(
        &mut self,
        request: &TypedEffectRequest<'_>,
    ) -> Option<Vec<(String, RetainedValue)>> {
        let bool_literal = if request.operation_id() == self.malformed_operation_id {
            true
        } else if request.operation_id() == self.corrected_operation_id {
            false
        } else {
            return None;
        };
        if request.effect_id() != self.effect_id {
            return None;
        }
        let [(replacement_id, RetainedValue::I64(replacement))] = request.arguments() else {
            return None;
        };
        if replacement_id != &self.replacement_argument_id {
            return None;
        }
        self.latest_preview = None;
        let feedback = match self.envelope.preview(*replacement, bool_literal) {
            Ok(preview) => {
                self.latest_preview = Some(preview);
                0
            }
            Err(diagnostics) => self.rejection(*replacement, bool_literal, diagnostics),
        };
        Some(vec![(
            self.feedback_result_id.clone(),
            RetainedValue::I64(feedback),
        )])
    }
}
