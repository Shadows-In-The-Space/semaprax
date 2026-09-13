//! Opaque, in-memory Project sessions for the embedding API.
//!
//! This module accepts caller-owned manifest/source bytes and delegates all
//! Project admission, refresh atomicity, and transaction replay to the
//! persistent semantic service. It neither opens a path nor accepts a callback
//! that could acquire ambient host authority.

use std::collections::BTreeSet;

use crate::diagnostic::{Diagnostic, Severity};
use crate::project::{
    ProjectFrontendCache, ProjectFrontendSource, ProjectManifest, SemanticTransactionArtifactsV2,
    SemanticWorkspaceService, MAX_SOURCES, MAX_TOTAL_SOURCE_BYTES,
};

use super::{
    EmbeddingCancellation, CANCELLATION_DIAGNOSTIC_CODE, PANIC_NORMALIZED_DIAGNOSTIC_CODE,
};

/// One caller-owned Project source. `path` is a manifest inventory label, not a
/// path the embedding API will open.
pub struct ProjectSourceInput {
    path: String,
    source: String,
}

impl ProjectSourceInput {
    /// Retain a bounded source proposal, using the Project kernel's own input
    /// validation and diagnostic vocabulary.
    pub fn new(path: &str, source: &str) -> Result<Self, Vec<Diagnostic>> {
        ProjectFrontendSource::new(path, source)?;
        Ok(Self {
            path: path.to_owned(),
            source: source.to_owned(),
        })
    }
}

/// Complete pathless input for opening or refreshing a [`ProjectSession`].
///
/// Construction validates individual sources and manifest syntax. Full Project
/// admission, including inventory and aggregate limits, happens on each open
/// or refresh against fresh compiler-owned values.
pub struct ProjectSessionInput {
    manifest: String,
    sources: Vec<ProjectSourceInput>,
}

impl ProjectSessionInput {
    pub fn new(manifest: &str, sources: Vec<ProjectSourceInput>) -> Result<Self, Vec<Diagnostic>> {
        preflight_sources(&sources)?;
        ProjectManifest::parse(manifest)?;
        Ok(Self {
            manifest: manifest.to_owned(),
            sources,
        })
    }

    fn admit(&self) -> Result<(ProjectManifest, Vec<ProjectFrontendSource>), Vec<Diagnostic>> {
        let manifest = ProjectManifest::parse(&self.manifest)?;
        let sources = self
            .sources
            .iter()
            .map(|source| ProjectFrontendSource::new(&source.path, &source.source))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((manifest, sources))
    }
}

/// A caller-owned incremental Project session. Compiler internals never cross
/// this boundary. Dropping it discards only its in-memory service and cache.
///
/// The handle intentionally is neither `Clone` nor a concurrency promise.
/// Refresh and candidate validation require `&mut self`; a caught service panic
/// poisons the handle so no later call can imply its retained state is sound.
pub struct ProjectSession {
    service: SemanticWorkspaceService,
    poisoned: bool,
}

/// Closed result of opening a Project session. The session itself is returned
/// separately and only when `ok` is true.
#[derive(Debug, Clone)]
pub struct ProjectSessionOpenOutcome {
    pub ok: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub workspace_revision: Option<String>,
    pub project_revision: Option<String>,
    pub open_work: Option<String>,
    pub open_work_digest: Option<String>,
}

/// Closed result of a source refresh. A failed result never represents an
/// adopted refresh; a panic additionally poisons the session.
#[derive(Debug, Clone)]
pub struct ProjectSessionRefreshOutcome {
    pub ok: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub old_workspace_revision: Option<String>,
    pub workspace_revision: Option<String>,
    pub receipt: Option<String>,
    pub receipt_digest: Option<String>,
    pub generation_reused: Option<bool>,
}

/// Canonical, authority-free products of candidate validation or replay.
#[derive(Debug, Clone)]
pub struct ProjectCandidateOutcome {
    pub ok: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub candidate: Option<String>,
    pub candidate_digest: Option<String>,
    pub impact: Option<String>,
    pub impact_digest: Option<String>,
    pub review: Option<String>,
    pub review_digest: Option<String>,
    pub result: Option<String>,
    pub result_digest: Option<String>,
    pub evidence: Option<String>,
    pub preserved_target_source: Option<String>,
}

/// Closed result of an exact active-generation semantic query.
#[derive(Debug, Clone)]
pub struct ProjectQueryOutcome {
    pub ok: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub result_json: Option<String>,
    pub result_digest: Option<String>,
    pub workspace_revision: Option<String>,
}

/// Open an opaque Project session from caller-provided bytes. No filesystem,
/// process, network, environment, or publication capability is available.
pub fn open_project_session(
    input: &ProjectSessionInput,
) -> (Option<ProjectSession>, ProjectSessionOpenOutcome) {
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (manifest, sources) = input.admit()?;
        let mut frontend = ProjectFrontendCache::new_with_semantic_cache();
        let revision = frontend.build(&manifest, &sources)?.into_revision();
        SemanticWorkspaceService::open_with_semantic_cache(revision, frontend)
    }));
    match opened {
        Ok(Ok(service)) => {
            let generation = service.active_generation();
            let outcome = ProjectSessionOpenOutcome {
                ok: true,
                diagnostics: Vec::new(),
                workspace_revision: Some(generation.workspace_revision().to_owned()),
                project_revision: Some(generation.revision().project_revision().to_owned()),
                open_work: Some(service.open_work().to_json().to_owned()),
                open_work_digest: Some(service.open_work().receipt_digest().to_owned()),
            };
            (
                Some(ProjectSession {
                    service,
                    poisoned: false,
                }),
                outcome,
            )
        }
        Ok(Err(diagnostics)) => (None, open_failure(diagnostics)),
        Err(_) => (
            None,
            open_failure(panic_diagnostics("opening a Project session")),
        ),
    }
}

/// Open only when cancellation has not already been requested. Opening has no
/// partial adoption before the service is returned, so a pre-cancelled call
/// performs no Project admission or cache work.
pub fn open_project_session_with_cancellation(
    input: &ProjectSessionInput,
    cancellation: &EmbeddingCancellation,
) -> (Option<ProjectSession>, ProjectSessionOpenOutcome) {
    if cancellation.is_cancelled() {
        return (None, open_failure(cancellation_diagnostics()));
    }
    open_project_session(input)
}

impl ProjectSession {
    /// The live workspace revision, absent after a caught stateful-operation
    /// panic. Callers must reopen rather than treat a poisoned handle as stale.
    pub fn workspace_revision(&self) -> Option<&str> {
        (!self.poisoned).then(|| self.service.active_generation().workspace_revision())
    }

    /// The live Project revision, absent after a caught stateful-operation
    /// panic.
    pub fn project_revision(&self) -> Option<&str> {
        (!self.poisoned).then(|| {
            self.service
                .active_generation()
                .revision()
                .project_revision()
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Stage and atomically adopt caller-owned sources through the existing
    /// service. A normal failure retains the former generation; a caught panic
    /// fails closed by poisoning this handle.
    pub fn refresh(
        &mut self,
        input: &ProjectSessionInput,
        expected_old_workspace_revision: &str,
    ) -> ProjectSessionRefreshOutcome {
        if self.poisoned {
            return refresh_failure(poisoned_diagnostics());
        }
        match self.stateful("refreshing a Project session", |service| {
            let (manifest, sources) = input.admit()?;
            service.refresh_owned_sources(&manifest, &sources, expected_old_workspace_revision)
        }) {
            Ok(receipt) => ProjectSessionRefreshOutcome {
                ok: true,
                diagnostics: Vec::new(),
                old_workspace_revision: Some(receipt.old_workspace_revision().to_owned()),
                workspace_revision: Some(receipt.workspace_revision().to_owned()),
                receipt: Some(receipt.to_json().to_owned()),
                receipt_digest: Some(receipt.receipt_digest().to_owned()),
                generation_reused: Some(receipt.generation_reused()),
            },
            Err(diagnostics) => refresh_failure(diagnostics),
        }
    }

    /// Begin an atomic refresh only when cancellation was already observed as
    /// clear. The persistent service has no safe mid-refresh cancellation
    /// point: once admitted staging starts, this façade lets its existing
    /// all-or-nothing refresh finish rather than claiming interruption.
    pub fn refresh_with_cancellation(
        &mut self,
        input: &ProjectSessionInput,
        expected_old_workspace_revision: &str,
        cancellation: &EmbeddingCancellation,
    ) -> ProjectSessionRefreshOutcome {
        if cancellation.is_cancelled() {
            return refresh_failure(cancellation_diagnostics());
        }
        self.refresh(input, expected_old_workspace_revision)
    }

    /// Execute a canonical query against the active immutable generation.
    /// Query has no mutable service effect, so its panic cannot leave an
    /// externally observable partial adoption; it is nevertheless normalized.
    pub fn query(&self, query_bytes: &[u8]) -> ProjectQueryOutcome {
        if self.poisoned {
            return query_failure(poisoned_diagnostics());
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.service.query(query_bytes)
        })) {
            Ok(Ok(result)) => ProjectQueryOutcome {
                ok: true,
                diagnostics: Vec::new(),
                result_json: Some(result.to_json().to_owned()),
                result_digest: Some(result.result_digest().to_owned()),
                workspace_revision: Some(result.workspace_revision().to_owned()),
            },
            Ok(Err(diagnostics)) => query_failure(diagnostics),
            Err(_) => query_failure(panic_diagnostics("querying a Project session")),
        }
    }

    /// Validate a v2 transaction. Candidate bytes are report-only and confer no
    /// publication or commit capability. This mutates bounded service history,
    /// so a caught panic poisons the session.
    pub fn validate_candidate_v2(&mut self, transaction_bytes: &[u8]) -> ProjectCandidateOutcome {
        if self.poisoned {
            return candidate_failure(poisoned_diagnostics());
        }
        match self.stateful("validating a Project candidate", |service| {
            service.validate_transaction_v2(transaction_bytes)
        }) {
            Ok(artifacts) => candidate_success(&artifacts),
            Err(diagnostics) => candidate_failure(diagnostics),
        }
    }

    /// Replay frozen v2 transaction evidence against the current generation.
    /// Replay is read-only in the service, and receives no host authority.
    pub fn replay_candidate_v2(
        &mut self,
        transaction_bytes: &[u8],
        evidence_bytes: &[u8],
    ) -> ProjectCandidateOutcome {
        if self.poisoned {
            return candidate_failure(poisoned_diagnostics());
        }
        match self.stateful("replaying a Project candidate", |service| {
            service.replay_transaction_v2(transaction_bytes, evidence_bytes)
        }) {
            Ok(artifacts) => candidate_success(&artifacts),
            Err(diagnostics) => candidate_failure(diagnostics),
        }
    }

    fn stateful<T>(
        &mut self,
        operation: &str,
        action: impl FnOnce(&mut SemanticWorkspaceService) -> Result<T, Vec<Diagnostic>>,
    ) -> Result<T, Vec<Diagnostic>> {
        if self.poisoned {
            return Err(poisoned_diagnostics());
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut self.service))) {
            Ok(result) => result,
            Err(_) => {
                self.poisoned = true;
                Err(panic_diagnostics(operation))
            }
        }
    }
}

fn preflight_sources(sources: &[ProjectSourceInput]) -> Result<(), Vec<Diagnostic>> {
    if sources.len() > MAX_SOURCES {
        return Err(frontend_capacity(
            "frontend source inventory exceeds its module bound",
        ));
    }
    let mut total = 0usize;
    let mut paths = BTreeSet::new();
    for source in sources {
        total = total
            .checked_add(source.source.len())
            .ok_or_else(|| frontend_capacity("frontend source accounting overflow"))?;
        if total > MAX_TOTAL_SOURCE_BYTES {
            return Err(frontend_capacity(
                "frontend source inventory exceeds its byte bound",
            ));
        }
        if !paths.insert(source.path.as_str()) {
            return Err(frontend_invalid("frontend sources contain duplicate paths"));
        }
    }
    Ok(())
}

fn frontend_invalid(message: &'static str) -> Vec<Diagnostic> {
    vec![Diagnostic::io("SPX-G255", message)]
}

fn frontend_capacity(message: impl Into<String>) -> Vec<Diagnostic> {
    vec![Diagnostic::io("SPX-G256", message)]
}

fn candidate_success(artifacts: &SemanticTransactionArtifactsV2) -> ProjectCandidateOutcome {
    ProjectCandidateOutcome {
        ok: true,
        diagnostics: Vec::new(),
        candidate: Some(artifacts.candidate().to_json().to_owned()),
        candidate_digest: Some(artifacts.candidate().candidate_digest().to_owned()),
        impact: Some(artifacts.impact().to_owned()),
        impact_digest: Some(artifacts.impact_digest().to_owned()),
        review: Some(artifacts.review().to_owned()),
        review_digest: Some(artifacts.review_digest().to_owned()),
        result: Some(artifacts.result().to_owned()),
        result_digest: Some(artifacts.result_digest().to_owned()),
        evidence: Some(artifacts.evidence().to_owned()),
        preserved_target_source: artifacts.preserved_target_source().map(str::to_owned),
    }
}

fn open_failure(diagnostics: Vec<Diagnostic>) -> ProjectSessionOpenOutcome {
    ProjectSessionOpenOutcome {
        ok: false,
        diagnostics,
        workspace_revision: None,
        project_revision: None,
        open_work: None,
        open_work_digest: None,
    }
}

fn refresh_failure(diagnostics: Vec<Diagnostic>) -> ProjectSessionRefreshOutcome {
    ProjectSessionRefreshOutcome {
        ok: false,
        diagnostics,
        old_workspace_revision: None,
        workspace_revision: None,
        receipt: None,
        receipt_digest: None,
        generation_reused: None,
    }
}

fn query_failure(diagnostics: Vec<Diagnostic>) -> ProjectQueryOutcome {
    ProjectQueryOutcome {
        ok: false,
        diagnostics,
        result_json: None,
        result_digest: None,
        workspace_revision: None,
    }
}

fn candidate_failure(diagnostics: Vec<Diagnostic>) -> ProjectCandidateOutcome {
    ProjectCandidateOutcome {
        ok: false,
        diagnostics,
        candidate: None,
        candidate_digest: None,
        impact: None,
        impact_digest: None,
        review: None,
        review_digest: None,
        result: None,
        result_digest: None,
        evidence: None,
        preserved_target_source: None,
    }
}

fn panic_diagnostics(operation: &str) -> Vec<Diagnostic> {
    vec![Diagnostic {
        code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
        severity: Severity::Error,
        message: format!(
            "the embedding boundary caught a panic while {operation}; the operation failed closed"
        ),
        path: None,
        span: None,
        help: Some("this names an embedding-boundary defect; reopen the session and report it against the compiler".to_owned()),
    }]
}

fn poisoned_diagnostics() -> Vec<Diagnostic> {
    vec![Diagnostic {
        code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
        severity: Severity::Error,
        message: "the Project session was poisoned after an embedding-boundary panic and cannot be reused".to_owned(),
        path: None,
        span: None,
        help: Some("drop this handle and open a new Project session from explicit source bytes".to_owned()),
    }]
}

fn cancellation_diagnostics() -> Vec<Diagnostic> {
    vec![Diagnostic::io(
        CANCELLATION_DIAGNOSTIC_CODE,
        "embedding Project request was cancelled before it began",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{
        ProjectCandidate, SemanticQuery, SemanticTransactionReplaceExpression,
        SemanticTransactionV2,
    };
    use serde_json::{json, Value};

    const MANIFEST: &str = include_str!("../../examples/calculator-project/semaprax.toml");
    const APP: &str = include_str!("../../examples/calculator-project/src/app.spx");
    const CORE: &str = include_str!("../../examples/calculator-project/src/core.spx");
    const TESTS: &str = include_str!("../../examples/calculator-project/src/tests.spx");

    fn input(app: &str) -> ProjectSessionInput {
        ProjectSessionInput::new(
            MANIFEST,
            vec![
                ProjectSourceInput::new("src/app.spx", app).unwrap(),
                ProjectSourceInput::new("src/core.spx", CORE).unwrap(),
                ProjectSourceInput::new("src/tests.spx", TESTS).unwrap(),
            ],
        )
        .unwrap()
    }

    fn pathless_label_input() -> ProjectSessionInput {
        let manifest = MANIFEST.replace("src/app.spx", "aa-no-filesystem/app.spx");
        ProjectSessionInput::new(
            &manifest,
            vec![
                ProjectSourceInput::new("aa-no-filesystem/app.spx", APP).unwrap(),
                ProjectSourceInput::new("src/core.spx", CORE).unwrap(),
                ProjectSourceInput::new("src/tests.spx", TESTS).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn opens_from_explicit_bytes() {
        let input = pathless_label_input();
        let (session, outcome) = open_project_session(&input);
        assert!(outcome.ok, "{:?}", outcome.diagnostics);
        assert!(session.is_some());
        assert!(outcome
            .open_work
            .as_deref()
            .unwrap()
            .contains("semantic-workspace-service-work"));
        assert!(outcome.workspace_revision.is_some());
        assert!(outcome.project_revision.is_some());
    }

    #[test]
    fn refresh_keeps_the_old_generation_on_stale_or_invalid_input() {
        let (session, opened) = open_project_session(&input(APP));
        assert!(opened.ok, "{:?}", opened.diagnostics);
        let mut session = session.unwrap();
        let before = session.workspace_revision().unwrap().to_owned();
        let stale = session.refresh(&input(APP), "0".repeat(64).as_str());
        assert!(!stale.ok);
        assert_eq!(session.workspace_revision(), Some(before.as_str()));
        let invalid = ProjectSessionInput::new(
            MANIFEST,
            vec![ProjectSourceInput::new("src/app.spx", "invalid source").unwrap()],
        )
        .unwrap();
        let failed = session.refresh(&invalid, &before);
        assert!(!failed.ok);
        assert_eq!(session.workspace_revision(), Some(before.as_str()));
    }

    #[test]
    fn changed_refresh_adopts_once_and_makes_old_candidate_evidence_stale() {
        let (session, opened) = open_project_session(&input(APP));
        assert!(opened.ok, "{:?}", opened.diagnostics);
        let mut session = session.unwrap();
        let revision = session.workspace_revision().unwrap().to_owned();
        let project = session.service.active_generation().revision();
        let root =
            ProjectCandidate::open(std::sync::Arc::clone(project), project.project_revision())
                .unwrap();
        let catalog: Value =
            serde_json::from_str(&root.expression_catalog("calculator.add").unwrap()).unwrap();
        let row = catalog["expressions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["replaceable"] == true)
            .unwrap();
        let source = project
            .sources()
            .iter()
            .find(|source| source.path() == catalog["source"]["path"].as_str().unwrap())
            .unwrap()
            .source();
        let start = row["source_span"]["start"].as_u64().unwrap() as usize;
        let end = row["source_span"]["end"].as_u64().unwrap() as usize;
        let transaction = SemanticTransactionV2::replace_expression(
            &revision,
            SemanticTransactionReplaceExpression::new(
                "calculator.add",
                row["expression_id"].as_str().unwrap(),
                &source[start..end],
                json!({"kind": "i64", "value": 42}),
            ),
        )
        .unwrap();
        let validated = session.validate_candidate_v2(transaction.to_json().as_bytes());
        assert!(validated.ok, "{:?}", validated.diagnostics);
        let changed = APP.replace("multiply(6, 7)", "multiply(6, 8)");
        let refreshed = session.refresh(&input(&changed), &revision);
        assert!(refreshed.ok, "{:?}", refreshed.diagnostics);
        assert_ne!(session.workspace_revision(), Some(revision.as_str()));
        let stale = session.replay_candidate_v2(
            transaction.to_json().as_bytes(),
            validated.evidence.as_deref().unwrap().as_bytes(),
        );
        assert!(!stale.ok);
    }

    #[test]
    fn session_input_rejects_duplicate_paths_before_retaining_session_input() {
        let duplicated = vec![
            ProjectSourceInput::new("src/app.spx", APP).unwrap(),
            ProjectSourceInput::new("src/app.spx", APP).unwrap(),
        ];
        let errors = match ProjectSessionInput::new(MANIFEST, duplicated) {
            Ok(_) => panic!("expected duplicate source labels to fail"),
            Err(errors) => errors,
        };
        assert_eq!(errors[0].code, "SPX-G255");
    }

    #[test]
    fn session_input_preflights_the_project_source_count_bound() {
        let sources = (0..=MAX_SOURCES)
            .map(|index| ProjectSourceInput::new(&format!("source-{index}.spx"), "x").unwrap())
            .collect();
        let errors = match ProjectSessionInput::new(MANIFEST, sources) {
            Ok(_) => panic!("expected source count preflight to fail"),
            Err(errors) => errors,
        };
        assert_eq!(errors[0].code, "SPX-G256");
    }

    #[test]
    fn cancelled_project_open_does_no_admission_work() {
        let cancellation = EmbeddingCancellation::new();
        cancellation.cancel();
        let (session, outcome) = open_project_session_with_cancellation(&input(APP), &cancellation);
        assert!(session.is_none());
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics[0].code, CANCELLATION_DIAGNOSTIC_CODE);
    }

    #[test]
    fn cancelled_refresh_preserves_generation_and_handle_remains_usable() {
        let (session, opened) = open_project_session(&input(APP));
        assert!(opened.ok);
        let mut session = session.unwrap();
        let before = session.workspace_revision().unwrap().to_owned();
        let cancellation = EmbeddingCancellation::new();
        cancellation.cancel();
        let result = session.refresh_with_cancellation(&input(APP), &before, &cancellation);
        assert!(!result.ok);
        assert_eq!(result.diagnostics[0].code, CANCELLATION_DIAGNOSTIC_CODE);
        assert_eq!(session.workspace_revision(), Some(before.as_str()));
        assert!(session.refresh(&input(APP), &before).ok);
    }

    #[test]
    fn malformed_candidate_and_query_fail_closed_without_authority() {
        let (session, opened) = open_project_session(&input(APP));
        assert!(opened.ok, "{:?}", opened.diagnostics);
        let mut session = session.unwrap();
        let candidate = session.validate_candidate_v2(b"not canonical transaction bytes");
        assert!(!candidate.ok);
        assert!(candidate.candidate.is_none());
        let query = session.query(b"not canonical query bytes");
        assert!(!query.ok);
        assert!(query.result_json.is_none());
    }

    #[test]
    fn query_and_v2_candidate_replay_return_canonical_reports() {
        let (session, opened) = open_project_session(&input(APP));
        assert!(opened.ok, "{:?}", opened.diagnostics);
        let mut session = session.unwrap();
        let revision = session.workspace_revision().unwrap().to_owned();
        let query = SemanticQuery::symbol(&revision, "calculator.add").unwrap();
        let queried = session.query(query.to_json().as_bytes());
        assert!(queried.ok, "{:?}", queried.diagnostics);
        assert_eq!(
            queried.workspace_revision.as_deref(),
            Some(revision.as_str())
        );

        let project = session.service.active_generation().revision();
        let root =
            ProjectCandidate::open(std::sync::Arc::clone(project), project.project_revision())
                .unwrap();
        let catalog: Value =
            serde_json::from_str(&root.expression_catalog("calculator.add").unwrap()).unwrap();
        let row = catalog["expressions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["replaceable"] == true)
            .unwrap();
        let source = project
            .sources()
            .iter()
            .find(|source| source.path() == catalog["source"]["path"].as_str().unwrap())
            .unwrap()
            .source();
        let start = row["source_span"]["start"].as_u64().unwrap() as usize;
        let end = row["source_span"]["end"].as_u64().unwrap() as usize;
        let transaction = SemanticTransactionV2::replace_expression(
            &revision,
            SemanticTransactionReplaceExpression::new(
                "calculator.add",
                row["expression_id"].as_str().unwrap(),
                &source[start..end],
                json!({"kind": "i64", "value": 42}),
            ),
        )
        .unwrap();
        let validated = session.validate_candidate_v2(transaction.to_json().as_bytes());
        assert!(validated.ok, "{:?}", validated.diagnostics);
        let replayed = session.replay_candidate_v2(
            transaction.to_json().as_bytes(),
            validated.evidence.as_deref().unwrap().as_bytes(),
        );
        assert!(replayed.ok, "{:?}", replayed.diagnostics);
        assert_eq!(replayed.candidate, validated.candidate);
        assert_eq!(replayed.result, validated.result);
        let mismatched = session.replay_candidate_v2(transaction.to_json().as_bytes(), b"mismatch");
        assert!(!mismatched.ok);
    }

    #[test]
    fn caught_stateful_panic_poison_the_session_and_future_calls_fail_closed() {
        let (session, opened) = open_project_session(&input(APP));
        assert!(opened.ok, "{:?}", opened.diagnostics);
        let mut session = session.unwrap();
        let panic = session.stateful(
            "test-only session operation",
            |_| -> Result<(), Vec<Diagnostic>> {
                panic!("intentional embedding boundary test panic")
            },
        );
        let errors = panic.unwrap_err();
        assert_eq!(errors[0].code, PANIC_NORMALIZED_DIAGNOSTIC_CODE);
        assert!(session.is_poisoned());
        assert!(session.workspace_revision().is_none());
        let refused = session.refresh(&input(APP), "0".repeat(64).as_str());
        assert!(!refused.ok);
        assert_eq!(
            refused.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
    }
}
