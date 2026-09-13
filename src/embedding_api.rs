//! Embedding API v1: small, versioned Rust entry points for analyzing one
//! caller-supplied SEMAPRAX compilation unit, built for issue #203 ("publish
//! a small stable Semaprax embedding API with explicit host capabilities").
//!
//! # Relationship to `src/semantic_embedding/` (issue #203's other tranche)
//!
//! [`crate::semantic_embedding`] also cites issue #203, but it is a vector-
//! embedding boundary (turning bytes into an `f32` vector for retrieval), an
//! entirely different sense of the word "embedding" from the one issue #203
//! actually asks for: *embedding the compiler itself* into a host process
//! ("editors, build systems, services, and applications embed parsing,
//! checking, interpretation, semantic query, candidate validation, and
//! selected execution without spawning the CLI"). That module's own doc
//! says so plainly ("Issue #203 asks for a much larger surface... None of
//! that lives in this module"). This module is the first real slice of
//! *that* surface: compiler/session-shaped, not vector-shaped.
//!
//! # What this module is
//!
//! [`check_source`], [`format_source`], [`graph_source`], and
//! [`context_source`] parse caller-supplied source strings for four
//! stateless analysis operations. Each returns a closed, versioned outcome —
//! never the internal [`crate::ast::Program`] or [`crate::hir::Analysis`]
//! (whose `resolved` field carries [`crate::hir::ResolvedProgram`]). Both
//! stay compiler-owned, exactly as issue #203's "Validated internals remain
//! compiler-owned" acceptance criterion requires: an embedder gets reports,
//! canonical projections, and a revision hash, never a value whose shape
//! this crate is free to change without notice.
//!
//! No capability is required for any of these operations: each is a pure
//! function of caller bytes and its declared query bounds (module-level
//! "in scope" bullets "Source/Project load", "Check", and
//! "Format, graph/query/context"). It opens no file, spawns no process, and
//! reaches no network — `unit_name` only labels diagnostics and is never read
//! as a path (`unit_name_is_never_read_from_disk` below proves this against a
//! path that does not exist on this machine). A future slice that reaches
//! Deterministic interpreter execution uses its own explicit
//! [`ExecutionCapability`], mirroring
//! [`crate::live_invocation::model_invoke::ModelInvokeCapability`] and
//! [`crate::semantic_embedding::capability::EmbeddingCapability`]'s shape;
//! it grants only the prepared, pathless evaluator and no host effect provider.
//!
//! # What this module is not
//!
//! Its stateless unit operations do not retain a handle. For an explicit,
//! multi-file Project handle, [`open_project_session`] owns only an in-memory
//! [`ProjectSession`] backed by the existing semantic service; it accepts no
//! ambient source provider and exposes no compiler internals. It is not a C
//! ABI. See `docs/EMBEDDING-API-V2.md` for the complete scope statement and
//! nonclaims this module is honestly bounded by.
//!
//! # Panic normalization
//!
//! A parser or analyzer defect must never unwind across this API boundary
//! into a host's own call stack. [`check_source`] therefore runs the actual
//! analysis inside [`std::panic::catch_unwind`] and converts a caught panic
//! into a [`crate::diagnostic::Diagnostic`] carrying
//! [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`], a code reserved for exactly this
//! case and never produced by parsing or analyzing real source. Because a
//! real compiler defect could not be manufactured honestly for this test
//! suite, the panic path is proven with an internal test-only
//! [`SourceChecker`] double that panics on purpose
//! (`embedding_boundary_normalizes_a_panic_into_a_diagnostic_never_
//! propagating_the_unwind`) — the same seam-substitution pattern
//! `src/semantic_embedding/fixture.rs`'s `ScriptedEmbeddingProvider` uses to
//! prove paths the real fixture cannot reach.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::diagnostic::{Diagnostic, Severity};

mod analysis_request;
mod execution;
mod negotiation;
pub use negotiation::{
    context_v2_source_with_cancellation, negotiate_features, EmbeddingFeatures, SUPPORTED_FEATURES,
    UNSUPPORTED_FEATURE_DIAGNOSTIC_CODE,
};
mod project_session;

pub use analysis_request::{
    check_source_with_request, context_source_with_request, context_v2_source_with_request,
    format_source_with_request, graph_source_with_request, AnalysisOptions, AnalysisRequest,
    MAX_ANALYSIS_SOURCE_BYTES, MAX_ANALYSIS_SYMBOL_BYTES, MAX_ANALYSIS_UNIT_NAME_BYTES,
    SOURCE_LIMIT_DIAGNOSTIC_CODE,
};
pub use execution::{
    execute_entry_source, ExecutionCancellation, ExecutionCapability, ExecutionOptions,
    ExecutionOutcome, ExecutionReport,
};
pub use project_session::{
    open_project_session, open_project_session_with_cancellation, ProjectCandidateOutcome,
    ProjectQueryOutcome, ProjectSession, ProjectSessionInput, ProjectSessionOpenOutcome,
    ProjectSessionRefreshOutcome, ProjectSourceInput,
};

/// A diagnostic code reserved for [`check_source`]'s panic-normalization
/// path. No parser or analyzer diagnostic uses this code; it names an
/// embedding-boundary defect, never a property of the checked program.
pub const PANIC_NORMALIZED_DIAGNOSTIC_CODE: &str = "SPX-EMB001";
/// Stable refusal for a host compiled against a different embedding API major.
pub const VERSION_MISMATCH_DIAGNOSTIC_CODE: &str = "SPX-EMB002";
/// Stable refusal for an embedding request cancelled before its result is used.
pub const CANCELLATION_DIAGNOSTIC_CODE: &str = "SPX-EMB003";

/// Monotonic host-owned cancellation signal for pure embedding requests.
///
/// An [`AnalysisRequest`] samples it before every stateless analysis operation
/// and again before returning a successful report. It is not a promise to
/// interrupt parser/resolver internals mid-operation.
#[derive(Default)]
pub struct EmbeddingCancellation {
    cancelled: AtomicBool,
}

impl EmbeddingCancellation {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// This embedding surface's own compatibility version — unrelated to any
/// checked program's semantics. See "Compatibility policy" in
/// `docs/EMBEDDING-API-V2.md`.
pub const EMBEDDING_API_VERSION: EmbeddingApiVersion = EmbeddingApiVersion {
    major: 2,
    minor: 0,
    patch: 0,
};

/// A semantic version for this Rust embedding surface. Two builds are
/// compatible for this module's calls exactly when their `major` values
/// are equal; `minor`/`patch` are informational only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingApiVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl EmbeddingApiVersion {
    /// Whether a caller that was built against `requested_major` can rely on
    /// this build's `check_source` contract. Only the major version is
    /// checked: `minor`/`patch` differences never change accepted inputs or
    /// [`CheckOutcome`]'s shape (see the compatibility policy in
    /// `docs/EMBEDDING-API-V2.md`), while a differing major version is
    /// explicitly refused rather than silently assumed compatible.
    pub fn is_compatible_with(&self, requested_major: u16) -> bool {
        self.major == requested_major
    }

    /// Refuse a mismatched major with a stable embedding-boundary diagnostic.
    pub fn require_compatible(&self, requested_major: u16) -> Result<(), Diagnostic> {
        self.is_compatible_with(requested_major)
            .then_some(())
            .ok_or_else(|| {
                Diagnostic::io(
                    VERSION_MISMATCH_DIAGNOSTIC_CODE,
                    format!(
                        "embedding API major {requested_major} is incompatible with host major {}",
                        self.major
                    ),
                )
            })
    }
}

/// The closed outcome of checking one caller-supplied compilation unit.
/// Deliberately does not carry [`crate::ast::Program`] or any other
/// internal compiler value: only diagnostics and the canonical revision
/// hash [`crate::graph::revision`] already publishes for the same purpose
/// elsewhere in this crate.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// Echoes the `unit_name` the caller passed in; never read from disk.
    pub unit_name: String,
    /// `true` exactly when no diagnostic in `diagnostics` is
    /// [`Severity::Error`] — matching the `severity.is_error()` rule the CLI
    /// `check` command and [`crate::hir::analyze`] both already use.
    pub ok: bool,
    /// Every diagnostic the parser and analyzer produced, warnings
    /// included. Unlike the crate-root [`crate::check`] helper (which
    /// discards non-error diagnostics on success), this module always
    /// returns the full set so a host does not silently lose warnings.
    pub diagnostics: Vec<Diagnostic>,
    /// [`crate::graph::revision`] of the checked program, present only when
    /// `ok` is `true` — an unresolvable program has no canonical revision to
    /// report.
    pub revision: Option<String>,
}

/// One parsed-and-analyzed unit, before being rendered into the public
/// [`CheckOutcome`]. Kept private so no internal compiler type crosses this
/// module's boundary.
struct UnitAnalysis {
    diagnostics: Vec<Diagnostic>,
    ok: bool,
    revision: Option<String>,
}

/// Internal seam behind [`check_source`], not part of the public API.
/// Exists only so the panic-normalization boundary in [`check_with`] can be
/// exercised by a test double that panics on purpose, without depending on
/// discovering an actual parser/analyzer defect.
trait SourceChecker {
    fn analyze(&self, unit_name: &str, source: &str) -> Result<UnitAnalysis, Diagnostic>;
}

/// The only [`SourceChecker`] this crate ships for real use: the ordinary
/// parse-then-analyze pipeline, over caller-supplied bytes only.
struct StandardChecker;

impl SourceChecker for StandardChecker {
    fn analyze(&self, unit_name: &str, source: &str) -> Result<UnitAnalysis, Diagnostic> {
        // `crate::parse` reads only `source`; `unit_name` labels diagnostics
        // and is never opened as a path (see `parser::Parser::new`, and
        // `unit_name_is_never_read_from_disk` below).
        let program = crate::parse(source, unit_name)?;
        let diagnostics = crate::hir::analyze(&program).diagnostics;
        let ok = !diagnostics.iter().any(|item| item.severity.is_error());
        let revision = ok.then(|| crate::graph::revision(&program));
        Ok(UnitAnalysis {
            diagnostics,
            ok,
            revision,
        })
    }
}

fn check_with(checker: &dyn SourceChecker, unit_name: &str, source: &str) -> CheckOutcome {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        checker.analyze(unit_name, source)
    }));
    match outcome {
        Ok(Ok(analysis)) => CheckOutcome {
            unit_name: unit_name.to_owned(),
            ok: analysis.ok,
            diagnostics: analysis.diagnostics,
            revision: analysis.revision,
        },
        Ok(Err(parse_failure)) => CheckOutcome {
            unit_name: unit_name.to_owned(),
            ok: false,
            diagnostics: vec![parse_failure],
            revision: None,
        },
        Err(_panic_payload) => CheckOutcome {
            unit_name: unit_name.to_owned(),
            ok: false,
            diagnostics: vec![Diagnostic {
                code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                severity: Severity::Error,
                message: format!(
                    "the embedding check boundary caught a panic while analyzing {unit_name:?} \
                     and normalized it to this diagnostic instead of letting the unwind cross \
                     the embedding API boundary"
                ),
                path: Some(unit_name.to_owned()),
                span: None,
                help: Some(
                    "this names an embedding-boundary defect, not a property of the checked \
                     source; report it against the compiler"
                        .to_owned(),
                ),
            }],
            revision: None,
        },
    }
}

/// Check one caller-supplied SEMAPRAX compilation unit.
///
/// `source` is the exact bytes to check; `unit_name` only labels
/// diagnostics and never names a path this function reads. No capability is
/// required: this is a pure, read-only function of its two arguments, and
/// it panics never (a panic inside the pipeline is caught and normalized
/// into [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`] instead of unwinding out of
/// this call). See the module documentation for what this deliberately does
/// not do (session lifecycle, multi-file Project load, execution, a C ABI).
pub fn check_source(unit_name: &str, source: &str) -> CheckOutcome {
    analysis_request::check_source(unit_name, source)
}

/// The closed outcome of canonically formatting one caller-supplied
/// compilation unit. Mirrors [`CheckOutcome`]'s shape deliberately: a
/// `unit_name` echo, an `ok` flag, and the full diagnostic set on failure —
/// never an internal [`crate::ast::Program`].
#[derive(Debug, Clone)]
pub struct FormatOutcome {
    /// Echoes the `unit_name` the caller passed in; never read from disk.
    pub unit_name: String,
    /// `true` exactly when `source` parsed successfully. Formatting itself
    /// never fails once parsing succeeds: [`crate::format::canonical`]
    /// operates on the parsed [`crate::ast::Program`] and does not require
    /// semantic (HIR) validity.
    pub ok: bool,
    /// The parser's diagnostic on failure; always empty when `ok` is `true`.
    pub diagnostics: Vec<Diagnostic>,
    /// The canonical source projection, present only when `ok` is `true`.
    pub canonical_source: Option<String>,
}

/// Internal seam behind [`format_source`], not part of the public API.
/// Exists only so the panic-normalization boundary in [`format_with`] can be
/// exercised by a test double that panics on purpose, mirroring
/// [`SourceChecker`]'s identical role for [`check_with`].
trait SourceFormatter {
    fn format(&self, unit_name: &str, source: &str) -> Result<String, Diagnostic>;
}

/// The only [`SourceFormatter`] this crate ships for real use: parse
/// caller-supplied bytes, then render the canonical projection.
struct StandardFormatter;

impl SourceFormatter for StandardFormatter {
    fn format(&self, unit_name: &str, source: &str) -> Result<String, Diagnostic> {
        // `crate::parse` reads only `source`; `unit_name` labels diagnostics
        // and is never opened as a path, exactly as in `StandardChecker`.
        let program = crate::parse(source, unit_name)?;
        Ok(crate::format::canonical(&program))
    }
}

fn format_with(formatter: &dyn SourceFormatter, unit_name: &str, source: &str) -> FormatOutcome {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        formatter.format(unit_name, source)
    }));
    match outcome {
        Ok(Ok(canonical_source)) => FormatOutcome {
            unit_name: unit_name.to_owned(),
            ok: true,
            diagnostics: Vec::new(),
            canonical_source: Some(canonical_source),
        },
        Ok(Err(parse_failure)) => FormatOutcome {
            unit_name: unit_name.to_owned(),
            ok: false,
            diagnostics: vec![parse_failure],
            canonical_source: None,
        },
        Err(_panic_payload) => FormatOutcome {
            unit_name: unit_name.to_owned(),
            ok: false,
            diagnostics: vec![Diagnostic {
                code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                severity: Severity::Error,
                message: format!(
                    "the embedding format boundary caught a panic while formatting {unit_name:?} \
                     and normalized it to this diagnostic instead of letting the unwind cross \
                     the embedding API boundary"
                ),
                path: Some(unit_name.to_owned()),
                span: None,
                help: Some(
                    "this names an embedding-boundary defect, not a property of the checked \
                     source; report it against the compiler"
                        .to_owned(),
                ),
            }],
            canonical_source: None,
        },
    }
}

/// Canonically format one caller-supplied SEMAPRAX compilation unit.
///
/// `source` is the exact bytes to format; `unit_name` only labels
/// diagnostics and never names a path this function reads. No capability is
/// required: this is a pure, read-only function of its two arguments, and it
/// panics never (a panic inside the formatter is caught and normalized into
/// [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`] instead of unwinding out of this
/// call). Unlike [`check_source`], a successful format does not require the
/// source to be semantically valid — only syntactically parseable — because
/// [`crate::format::canonical`] renders the parsed AST directly and performs
/// no HIR resolution.
pub fn format_source(unit_name: &str, source: &str) -> FormatOutcome {
    analysis_request::format_source(unit_name, source)
}

/// The closed outcome of rendering one caller-supplied compilation unit's
/// canonical semantic graph — the same JSON [`crate::graph::to_json`]
/// already produces for its other callers, unchanged. Mirrors
/// [`CheckOutcome`]/[`FormatOutcome`]'s shape: a `unit_name` echo, an `ok`
/// flag, and a diagnostic set — with one deliberate difference from
/// `check_source`'s contract, documented on [`GraphOutcome::diagnostics`].
#[derive(Debug, Clone)]
pub struct GraphOutcome {
    /// Echoes the `unit_name` the caller passed in; never read from disk.
    pub unit_name: String,
    /// `true` exactly when `source` parsed and resolved successfully.
    pub ok: bool,
    /// The failing diagnostic(s) when `ok` is `false`; always empty when
    /// `ok` is `true`. Unlike [`CheckOutcome::diagnostics`], a successful
    /// render never carries a warning: `graph_source` forwards to the
    /// already-public [`crate::graph::to_json`], which resolves through
    /// [`crate::hir::resolve`] — and `resolve` returns only `Ok(resolved)`
    /// on success, dropping the diagnostics it collected along the way (see
    /// its own implementation: `resolved.ok_or(diagnostics)`). This module
    /// does not reimplement resolution to recover them, so a host that also
    /// wants warnings on a program whose graph rendered successfully must
    /// call [`check_source`] for the same `source` as well —
    /// `a_declaration_missing_id_still_graphs_ok_but_the_warning_is_not_
    /// carried_forward` below locks this difference in on purpose, so a
    /// future change here does not silently start (or stop) carrying it.
    pub diagnostics: Vec<Diagnostic>,
    /// The canonical semantic graph JSON, present only when `ok` is `true`.
    pub graph_json: Option<String>,
}

/// Internal seam behind [`graph_source`], not part of the public API.
/// Mirrors [`SourceChecker`]/[`SourceFormatter`]'s identical role: lets the
/// panic-normalization boundary in [`graph_with`] be exercised by a test
/// double that panics on purpose.
trait SourceGrapher {
    fn graph(&self, unit_name: &str, source: &str) -> Result<String, Vec<Diagnostic>>;
}

/// The only [`SourceGrapher`] this crate ships for real use: parse
/// caller-supplied bytes, then render the canonical semantic graph exactly
/// as [`crate::graph::to_json`] already does for its other callers.
struct StandardGrapher;

impl SourceGrapher for StandardGrapher {
    fn graph(&self, unit_name: &str, source: &str) -> Result<String, Vec<Diagnostic>> {
        // `crate::parse` reads only `source`; `unit_name` labels diagnostics
        // and is never opened as a path, exactly as in `StandardChecker`.
        let program = crate::parse(source, unit_name).map_err(|diagnostic| vec![diagnostic])?;
        crate::graph::to_json(&program)
    }
}

fn graph_with(grapher: &dyn SourceGrapher, unit_name: &str, source: &str) -> GraphOutcome {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        grapher.graph(unit_name, source)
    }));
    match outcome {
        Ok(Ok(graph_json)) => GraphOutcome {
            unit_name: unit_name.to_owned(),
            ok: true,
            diagnostics: Vec::new(),
            graph_json: Some(graph_json),
        },
        Ok(Err(diagnostics)) => GraphOutcome {
            unit_name: unit_name.to_owned(),
            ok: false,
            diagnostics,
            graph_json: None,
        },
        Err(_panic_payload) => GraphOutcome {
            unit_name: unit_name.to_owned(),
            ok: false,
            diagnostics: vec![Diagnostic {
                code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                severity: Severity::Error,
                message: format!(
                    "the embedding graph boundary caught a panic while rendering the semantic \
                     graph for {unit_name:?} and normalized it to this diagnostic instead of \
                     letting the unwind cross the embedding API boundary"
                ),
                path: Some(unit_name.to_owned()),
                span: None,
                help: Some(
                    "this names an embedding-boundary defect, not a property of the checked \
                     source; report it against the compiler"
                        .to_owned(),
                ),
            }],
            graph_json: None,
        },
    }
}

/// Render one caller-supplied SEMAPRAX compilation unit's canonical
/// semantic graph — the same JSON [`crate::graph::to_json`] already
/// produces for its other callers.
///
/// `source` is the exact bytes to check and render; `unit_name` only labels
/// diagnostics and never names a path this function reads. No capability is
/// required: rendering the graph is a pure, read-only function of its two
/// arguments, and it panics never (a panic inside parsing or resolution is
/// caught and normalized into [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`] instead of
/// unwinding out of this call). Unlike [`check_source`], a successful
/// render's `diagnostics` is always empty — see [`GraphOutcome::diagnostics`]
/// for why — so a host that also wants warnings should call [`check_source`]
/// on the same `source`.
pub fn graph_source(unit_name: &str, source: &str) -> GraphOutcome {
    analysis_request::graph_source(unit_name, source)
}

/// One closed semantic facet admitted by [`ContextOptions`]. The names and
/// meanings match the v1 agent-context projection, but this distinct public
/// enum keeps the embedding API from exposing the graph module's broader,
/// evolving option surface as its own compatibility contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextFilter {
    Contracts,
    Ownership,
    Effects,
    Types,
}

impl ContextFilter {
    fn into_graph_filter(self) -> crate::graph::AgentContextFilter {
        match self {
            Self::Contracts => crate::graph::AgentContextFilter::Contracts,
            Self::Ownership => crate::graph::AgentContextFilter::Ownership,
            Self::Effects => crate::graph::AgentContextFilter::Effects,
            Self::Types => crate::graph::AgentContextFilter::Types,
        }
    }
}

/// Validated bounds and facets for one [`context_source`] query.
///
/// The default is the graph v1 context default: a depth of one, a 64 KiB
/// output limit, 256 facts, and contracts/ownership/effects/types. The
/// constructor delegates every range, duplicate-filter, and empty-filter
/// refusal to the canonical graph validator before a source unit is parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextOptions {
    depth: usize,
    max_bytes: usize,
    max_nodes: usize,
    filters: Vec<ContextFilter>,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            depth: 1,
            max_bytes: 64 * 1024,
            max_nodes: 256,
            filters: vec![
                ContextFilter::Contracts,
                ContextFilter::Ownership,
                ContextFilter::Effects,
                ContextFilter::Types,
            ],
        }
    }
}

impl ContextOptions {
    /// Construct options for a bounded v1 semantic-context query.
    ///
    /// The returned error is the canonical graph option diagnostic; this API
    /// neither loosens limits nor invents a parallel diagnostic vocabulary.
    pub fn new(
        depth: usize,
        max_bytes: usize,
        max_nodes: usize,
        filters: impl IntoIterator<Item = ContextFilter>,
    ) -> Result<Self, Diagnostic> {
        let options = Self {
            depth,
            max_bytes,
            max_nodes,
            filters: filters.into_iter().collect(),
        };
        options.to_graph_options()?;
        Ok(options)
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    #[must_use]
    pub fn filters(&self) -> &[ContextFilter] {
        &self.filters
    }

    fn to_graph_options(&self) -> Result<crate::graph::AgentContextOptions, Diagnostic> {
        crate::graph::AgentContextOptions::new(
            self.depth,
            self.max_bytes,
            self.max_nodes,
            self.filters
                .iter()
                .copied()
                .map(ContextFilter::into_graph_filter),
        )
    }
}

/// The closed outcome of a bounded semantic-context query over one
/// caller-supplied compilation unit. It returns canonical JSON only, never a
/// parsed AST, resolved HIR, or graph-owned query state.
#[derive(Debug, Clone)]
pub struct ContextOutcome {
    /// Echoes the `unit_name` the caller passed in; never read from disk.
    pub unit_name: String,
    /// Echoes the requested function display name or persistent declaration
    /// ID; it is data for graph selection and never a filesystem path.
    pub symbol: String,
    /// `true` when the unit parsed and resolved and the bounded query ran,
    /// including the ordinary no-match result (`context_json` is `None`).
    pub ok: bool,
    /// Parse, resolution, graph, or option diagnostics on failure. Successful
    /// context output follows `graph::agent_context_json` and therefore does
    /// not carry non-error analysis warnings; call [`check_source`] as well
    /// when a host needs those warnings.
    pub diagnostics: Vec<Diagnostic>,
    /// The canonical `semaprax.agent-context.v1` JSON, or `None` when no
    /// function matches `symbol` or when `ok` is false.
    pub context_json: Option<String>,
}

/// Internal seam behind [`context_source`], used only to prove that a panic
/// is normalized before it can cross the host boundary.
trait SourceContexter {
    fn context(
        &self,
        unit_name: &str,
        source: &str,
        symbol: &str,
        options: &ContextOptions,
    ) -> Result<Option<String>, Vec<Diagnostic>>;
}

/// The real context path parses explicit bytes then forwards to the canonical
/// bounded v1 graph-query implementation.
struct StandardContexter;

impl SourceContexter for StandardContexter {
    fn context(
        &self,
        unit_name: &str,
        source: &str,
        symbol: &str,
        options: &ContextOptions,
    ) -> Result<Option<String>, Vec<Diagnostic>> {
        let graph_options = options.to_graph_options().map_err(|item| vec![item])?;
        let program = crate::parse(source, unit_name).map_err(|item| vec![item])?;
        crate::graph::agent_context_json(&program, symbol, &graph_options)
    }
}

fn context_with(
    contexter: &dyn SourceContexter,
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextOptions,
) -> ContextOutcome {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        contexter.context(unit_name, source, symbol, options)
    }));
    match outcome {
        Ok(Ok(context_json)) => ContextOutcome {
            unit_name: unit_name.to_owned(),
            symbol: symbol.to_owned(),
            ok: true,
            diagnostics: Vec::new(),
            context_json,
        },
        Ok(Err(diagnostics)) => ContextOutcome {
            unit_name: unit_name.to_owned(),
            symbol: symbol.to_owned(),
            ok: false,
            diagnostics,
            context_json: None,
        },
        Err(_panic_payload) => ContextOutcome {
            unit_name: unit_name.to_owned(),
            symbol: symbol.to_owned(),
            ok: false,
            diagnostics: vec![Diagnostic {
                code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                severity: Severity::Error,
                message: format!(
                    "the embedding context boundary caught a panic while querying {symbol:?} \
                     in {unit_name:?} and normalized it to this diagnostic instead of letting \
                     the unwind cross the embedding API boundary"
                ),
                path: Some(unit_name.to_owned()),
                span: None,
                help: Some(
                    "this names an embedding-boundary defect, not a property of the checked \
                     source; report it against the compiler"
                        .to_owned(),
                ),
            }],
            context_json: None,
        },
    }
}

/// Return a deterministic, byte- and node-bounded v1 semantic-context view
/// for one caller-supplied compilation unit.
///
/// `source`, `unit_name`, and `symbol` are caller-supplied data. This function
/// opens no path, reads no ambient host state, and has no capability because it
/// is a pure read-only analysis operation. It never lets a compiler panic
/// unwind into the caller; such a panic becomes
/// [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`]. A no-match is successful and returns
/// `ContextOutcome { ok: true, context_json: None, .. }`.
pub fn context_source(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextOptions,
) -> ContextOutcome {
    analysis_request::context_source(unit_name, source, symbol, options)
}

/// Run a bounded v1 context request with explicit cooperative cancellation.
///
/// Cancellation is sampled before parsing and once more before a successful
/// JSON report is returned. The graph kernel has no mid-traversal cancellation
/// hook, so cancellation after work begins can discard a completed report but
/// cannot claim that parser/resolver work was interrupted.
pub fn context_source_with_cancellation(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextOptions,
    cancellation: &EmbeddingCancellation,
) -> ContextOutcome {
    analysis_request::context_source_with_cancellation(
        unit_name,
        source,
        symbol,
        options,
        cancellation,
    )
}

/// Closed traversal direction admitted by [`ContextV2Options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextDirection {
    Forward,
    Reverse,
    Both,
}

impl ContextDirection {
    fn into_graph_direction(self) -> crate::graph::AgentContextDirection {
        match self {
            Self::Forward => crate::graph::AgentContextDirection::Forward,
            Self::Reverse => crate::graph::AgentContextDirection::Reverse,
            Self::Both => crate::graph::AgentContextDirection::Both,
        }
    }
}

/// Validated v2 context options. V2 keeps [`ContextOptions`]'s exact bounds
/// and facets while adding an explicit traversal direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextV2Options {
    base: ContextOptions,
    direction: ContextDirection,
}

impl Default for ContextV2Options {
    fn default() -> Self {
        Self {
            base: ContextOptions::default(),
            direction: ContextDirection::Forward,
        }
    }
}

impl ContextV2Options {
    /// Construct options for a bounded v2 semantic-context query.
    pub fn new(
        depth: usize,
        max_bytes: usize,
        max_nodes: usize,
        filters: impl IntoIterator<Item = ContextFilter>,
        direction: ContextDirection,
    ) -> Result<Self, Diagnostic> {
        Ok(Self {
            base: ContextOptions::new(depth, max_bytes, max_nodes, filters)?,
            direction,
        })
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.base.depth()
    }

    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.base.max_bytes()
    }

    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.base.max_nodes()
    }

    #[must_use]
    pub fn filters(&self) -> &[ContextFilter] {
        self.base.filters()
    }

    #[must_use]
    pub const fn direction(&self) -> ContextDirection {
        self.direction
    }

    fn to_graph_options(&self) -> Result<crate::graph::AgentContextV2Options, Diagnostic> {
        crate::graph::AgentContextV2Options::new(
            self.base.depth,
            self.base.max_bytes,
            self.base.max_nodes,
            self.base
                .filters
                .iter()
                .copied()
                .map(ContextFilter::into_graph_filter),
            self.direction.into_graph_direction(),
        )
    }
}

/// Internal seam behind [`context_v2_source`], used only to prove v2 panic
/// normalization at the embedding boundary.
trait SourceV2Contexter {
    fn context(
        &self,
        unit_name: &str,
        source: &str,
        symbol: &str,
        options: &ContextV2Options,
    ) -> Result<Option<String>, Vec<Diagnostic>>;
}

struct StandardV2Contexter;

impl SourceV2Contexter for StandardV2Contexter {
    fn context(
        &self,
        unit_name: &str,
        source: &str,
        symbol: &str,
        options: &ContextV2Options,
    ) -> Result<Option<String>, Vec<Diagnostic>> {
        let graph_options = options.to_graph_options().map_err(|item| vec![item])?;
        let program = crate::parse(source, unit_name).map_err(|item| vec![item])?;
        crate::graph::agent_context_v2_json(&program, symbol, &graph_options)
    }
}

fn context_v2_with(
    contexter: &dyn SourceV2Contexter,
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextV2Options,
) -> ContextOutcome {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        contexter.context(unit_name, source, symbol, options)
    }));
    match outcome {
        Ok(Ok(context_json)) => ContextOutcome {
            unit_name: unit_name.to_owned(),
            symbol: symbol.to_owned(),
            ok: true,
            diagnostics: Vec::new(),
            context_json,
        },
        Ok(Err(diagnostics)) => ContextOutcome {
            unit_name: unit_name.to_owned(),
            symbol: symbol.to_owned(),
            ok: false,
            diagnostics,
            context_json: None,
        },
        Err(_panic_payload) => ContextOutcome {
            unit_name: unit_name.to_owned(),
            symbol: symbol.to_owned(),
            ok: false,
            diagnostics: vec![Diagnostic {
                code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                severity: Severity::Error,
                message: format!(
                    "the embedding v2 context boundary caught a panic while querying {symbol:?} \
                     in {unit_name:?} and normalized it to this diagnostic instead of letting \
                     the unwind cross the embedding API boundary"
                ),
                path: Some(unit_name.to_owned()),
                span: None,
                help: Some(
                    "this names an embedding-boundary defect, not a property of the checked \
                     source; report it against the compiler"
                        .to_owned(),
                ),
            }],
            context_json: None,
        },
    }
}

/// Return a deterministic, byte- and node-bounded v2 semantic-context view
/// with explicit forward, reverse, or bidirectional traversal.
///
/// This is the v2 counterpart to [`context_source`]. It is equally pure and
/// pathless: all source, selection, bounds, facets, and direction arrive from
/// the caller, and a compiler panic becomes
/// [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`] rather than unwinding into the host.
pub fn context_v2_source(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextV2Options,
) -> ContextOutcome {
    analysis_request::context_v2_source(unit_name, source, symbol, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "module app.hello;\n\n@id(\"app.main\")\nfn main() -> i64\n{\n    42\n}\n";

    #[test]
    fn valid_source_checks_ok_with_no_diagnostics_and_a_revision() {
        let outcome = check_source("hello.spx", HELLO);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(outcome.diagnostics.is_empty());
        assert!(outcome.revision.is_some());
        assert_eq!(outcome.unit_name, "hello.spx");
    }

    #[test]
    fn a_declaration_missing_id_still_checks_ok_but_keeps_its_warning() {
        // `crate::check` (the crate-root helper) discards non-error
        // diagnostics on success; this module must not repeat that, or a
        // host embedding it would silently lose every warning on a
        // successful check.
        let source = "module app.warned;\n\nfn main() -> i64\n{\n    42\n}\n";
        let outcome = check_source("warned.spx", source);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|item| item.code == "SPX-S103"),
            "expected the missing-@id warning to survive a successful check, got {:?}",
            outcome.diagnostics
        );
        assert!(outcome
            .diagnostics
            .iter()
            .all(|item| !item.severity.is_error()));
    }

    #[test]
    fn malformed_source_fails_with_the_specific_parser_diagnostic() {
        // A module with no function at all is refused by the parser with
        // SPX-P101, before any HIR analysis runs.
        let outcome = check_source("empty.spx", "module app.empty;\n");
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(outcome.diagnostics[0].code, "SPX-P101");
        assert!(outcome.diagnostics[0].severity.is_error());
        assert!(outcome.revision.is_none());
        // Distinguish this genuine parser refusal from the unrelated
        // panic-normalization path: neither code's text appears in the
        // other's diagnostic.
        assert_ne!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
        assert!(!outcome.diagnostics[0]
            .message
            .contains(PANIC_NORMALIZED_DIAGNOSTIC_CODE));
    }

    #[test]
    fn unit_name_is_never_read_from_disk() {
        // A path that certainly does not exist on this machine must not
        // cause an I/O failure: `unit_name` only labels diagnostics.
        let outcome = check_source("/definitely/does/not/exist/on/this/machine/unit.spx", HELLO);
        assert!(
            outcome.ok,
            "checking must depend only on `source`, not on whether `unit_name` \
             names a real file; got {:?}",
            outcome.diagnostics
        );
    }

    struct PanickingChecker;

    impl SourceChecker for PanickingChecker {
        fn analyze(&self, _unit_name: &str, _source: &str) -> Result<UnitAnalysis, Diagnostic> {
            panic!("deliberate test panic: proving it never crosses the embedding boundary");
        }
    }

    #[test]
    fn embedding_boundary_normalizes_a_panic_into_a_diagnostic_never_propagating_the_unwind() {
        let outcome = check_with(&PanickingChecker, "panicking.spx", "irrelevant");
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
        assert!(outcome.diagnostics[0].severity.is_error());
        assert!(outcome.revision.is_none());
        // Distinguish this internal-defect path from a genuine parser
        // refusal: the panic diagnostic never mentions a real parser code.
        assert!(!outcome.diagnostics[0].message.contains("SPX-P101"));
    }

    #[test]
    fn version_negotiation_accepts_matching_major_and_refuses_a_different_one() {
        assert!(EMBEDDING_API_VERSION.is_compatible_with(2));
        assert!(!EMBEDDING_API_VERSION.is_compatible_with(1));
        assert!(!EMBEDDING_API_VERSION.is_compatible_with(0));
        assert!(EMBEDDING_API_VERSION.require_compatible(2).is_ok());
        let refusal = EMBEDDING_API_VERSION.require_compatible(1).unwrap_err();
        assert_eq!(refusal.code, VERSION_MISMATCH_DIAGNOSTIC_CODE);
    }

    #[test]
    fn valid_source_formats_to_its_own_canonical_projection() {
        let outcome = format_source("hello.spx", HELLO);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(outcome.diagnostics.is_empty());
        let canonical_source = outcome
            .canonical_source
            .expect("ok outcome must carry canonical_source");
        assert_eq!(outcome.unit_name, "hello.spx");
        // Formatting is idempotent: reformatting an already-canonical unit
        // must reproduce byte-identical output.
        let reformatted = format_source("hello.spx", &canonical_source);
        assert!(reformatted.ok);
        assert_eq!(reformatted.canonical_source, Some(canonical_source));
    }

    #[test]
    fn a_declaration_missing_id_still_formats_ok() {
        // Formatting does not require semantic (HIR) validity, unlike
        // `check_source`: a syntactically valid program missing `@id`
        // (which only `check_source` would warn about) still formats.
        let source = "module app.warned;\n\nfn main() -> i64\n{\n    42\n}\n";
        let outcome = format_source("warned.spx", source);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(outcome.diagnostics.is_empty());
        assert!(outcome.canonical_source.is_some());
    }

    #[test]
    fn malformed_source_fails_format_with_the_specific_parser_diagnostic() {
        let outcome = format_source("empty.spx", "module app.empty;\n");
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(outcome.diagnostics[0].code, "SPX-P101");
        assert!(outcome.diagnostics[0].severity.is_error());
        assert!(outcome.canonical_source.is_none());
        assert_ne!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
    }

    #[test]
    fn format_unit_name_is_never_read_from_disk() {
        let outcome = format_source("/definitely/does/not/exist/on/this/machine/unit.spx", HELLO);
        assert!(
            outcome.ok,
            "formatting must depend only on `source`, not on whether `unit_name` \
             names a real file; got {:?}",
            outcome.diagnostics
        );
    }

    struct PanickingFormatter;

    impl SourceFormatter for PanickingFormatter {
        fn format(&self, _unit_name: &str, _source: &str) -> Result<String, Diagnostic> {
            panic!("deliberate test panic: proving it never crosses the embedding boundary");
        }
    }

    #[test]
    fn embedding_format_boundary_normalizes_a_panic_into_a_diagnostic_never_propagating_the_unwind()
    {
        let outcome = format_with(&PanickingFormatter, "panicking.spx", "irrelevant");
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
        assert!(outcome.diagnostics[0].severity.is_error());
        assert!(outcome.canonical_source.is_none());
        assert!(!outcome.diagnostics[0].message.contains("SPX-P101"));
    }

    #[test]
    fn valid_source_graph_matches_graph_to_json_exactly() {
        let outcome = graph_source("hello.spx", HELLO);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(outcome.diagnostics.is_empty());
        assert_eq!(outcome.unit_name, "hello.spx");
        let graph_json = outcome
            .graph_json
            .expect("ok outcome must carry graph_json");
        // Cross-check against `crate::graph::to_json` directly: this facade
        // is a thin forwarding wrapper, not a reimplementation, so its
        // output must be byte-identical to calling the wrapped function
        // directly on the same parsed program. A stub or a divergent
        // reimplementation would fail this exact equality.
        let program = crate::parse(HELLO, "hello.spx").expect("HELLO must parse");
        let expected = crate::graph::to_json(&program).expect("HELLO must resolve");
        assert_eq!(graph_json, expected);
    }

    #[test]
    fn malformed_source_fails_graph_with_the_specific_parser_diagnostic() {
        let outcome = graph_source("empty.spx", "module app.empty;\n");
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(outcome.diagnostics[0].code, "SPX-P101");
        assert!(outcome.diagnostics[0].severity.is_error());
        assert!(outcome.graph_json.is_none());
        assert_ne!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
    }

    #[test]
    fn graph_unit_name_is_never_read_from_disk() {
        let outcome = graph_source("/definitely/does/not/exist/on/this/machine/unit.spx", HELLO);
        assert!(
            outcome.ok,
            "graph rendering must depend only on `source`, not on whether `unit_name` \
             names a real file; got {:?}",
            outcome.diagnostics
        );
    }

    struct PanickingGrapher;

    impl SourceGrapher for PanickingGrapher {
        fn graph(&self, _unit_name: &str, _source: &str) -> Result<String, Vec<Diagnostic>> {
            panic!("deliberate test panic: proving it never crosses the embedding boundary");
        }
    }

    #[test]
    fn embedding_graph_boundary_normalizes_a_panic_into_a_diagnostic_never_propagating_the_unwind()
    {
        let outcome = graph_with(&PanickingGrapher, "panicking.spx", "irrelevant");
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
        assert!(outcome.diagnostics[0].severity.is_error());
        assert!(outcome.graph_json.is_none());
        assert!(!outcome.diagnostics[0].message.contains("SPX-P101"));
    }

    #[test]
    fn a_declaration_missing_id_still_graphs_ok_but_the_warning_is_not_carried_forward() {
        // Establishes the contrast `GraphOutcome::diagnostics` documents:
        // `check_source` keeps a successful check's warnings (its own test
        // above proves this), but `graph_source` forwards through
        // `hir::resolve`, which discards them on success.
        let source = "module app.warned;\n\nfn main() -> i64\n{\n    42\n}\n";
        let checked = check_source("warned.spx", source);
        assert!(
            checked
                .diagnostics
                .iter()
                .any(|item| item.code == "SPX-S103"),
            "check_source's own contract regressed; this test assumes it still keeps SPX-S103, \
             got {:?}",
            checked.diagnostics
        );
        let graphed = graph_source("warned.spx", source);
        assert!(graphed.ok, "expected ok, got {:?}", graphed.diagnostics);
        assert!(
            graphed.diagnostics.is_empty(),
            "documented limitation regressed: graph_source now carries a successful-render \
             diagnostic it previously discarded; if intentional, update \
             GraphOutcome::diagnostics' doc comment to match, got {:?}",
            graphed.diagnostics
        );
        assert!(graphed.graph_json.is_some());
    }

    #[test]
    fn valid_source_context_matches_the_canonical_bounded_query_exactly() {
        let options = ContextOptions::default();
        let outcome = context_source("hello.spx", HELLO, "app.main", &options);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(outcome.diagnostics.is_empty());
        assert_eq!(outcome.unit_name, "hello.spx");
        assert_eq!(outcome.symbol, "app.main");
        let context_json = outcome
            .context_json
            .expect("matching query must carry context JSON");
        let program = crate::parse(HELLO, "hello.spx").expect("HELLO must parse");
        let expected = crate::graph::agent_context_json(
            &program,
            "app.main",
            &crate::graph::AgentContextOptions::default(),
        )
        .expect("HELLO must resolve")
        .expect("app.main must match");
        assert_eq!(context_json, expected);
    }

    #[test]
    fn context_no_match_is_a_successful_empty_result() {
        let outcome = context_source(
            "hello.spx",
            HELLO,
            "app.does_not_exist",
            &ContextOptions::default(),
        );
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert!(outcome.diagnostics.is_empty());
        assert_eq!(outcome.symbol, "app.does_not_exist");
        assert_eq!(outcome.context_json, None);
    }

    #[test]
    fn cancelled_context_never_starts_or_returns_a_report() {
        let cancellation = EmbeddingCancellation::new();
        cancellation.cancel();
        let outcome = context_source_with_cancellation(
            "hello.spx",
            HELLO,
            "app.main",
            &ContextOptions::default(),
            &cancellation,
        );
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics[0].code, CANCELLATION_DIAGNOSTIC_CODE);
        assert!(outcome.context_json.is_none());
    }

    #[test]
    fn context_options_use_the_canonical_bounds_and_refusals() {
        let error = ContextOptions::new(0, 1, 1, [ContextFilter::Types])
            .expect_err("one byte must be below the canonical context minimum");
        assert_eq!(error.code, "SPX-G004");
        let error = ContextOptions::new(0, 2048, 1, [ContextFilter::Types, ContextFilter::Types])
            .expect_err("duplicate filters must be refused by the canonical validator");
        assert_eq!(error.code, "SPX-G004");
    }

    #[test]
    fn malformed_source_fails_context_with_the_specific_parser_diagnostic() {
        let outcome = context_source(
            "empty.spx",
            "module app.empty;\n",
            "app.main",
            &ContextOptions::default(),
        );
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(outcome.diagnostics[0].code, "SPX-P101");
        assert!(outcome.context_json.is_none());
    }

    #[test]
    fn context_unit_name_is_never_read_from_disk() {
        let outcome = context_source(
            "/definitely/does/not/exist/on/this/machine/unit.spx",
            HELLO,
            "app.main",
            &ContextOptions::default(),
        );
        assert!(
            outcome.ok,
            "context must depend only on `source`, not on whether `unit_name` names a file; got {:?}",
            outcome.diagnostics
        );
    }

    struct PanickingContexter;

    impl SourceContexter for PanickingContexter {
        fn context(
            &self,
            _unit_name: &str,
            _source: &str,
            _symbol: &str,
            _options: &ContextOptions,
        ) -> Result<Option<String>, Vec<Diagnostic>> {
            panic!("deliberate test panic: proving it never crosses the embedding boundary");
        }
    }

    #[test]
    fn embedding_context_boundary_normalizes_a_panic_into_a_diagnostic() {
        let outcome = context_with(
            &PanickingContexter,
            "panicking.spx",
            "irrelevant",
            "app.main",
            &ContextOptions::default(),
        );
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
        assert!(outcome.context_json.is_none());
    }

    #[test]
    fn v2_context_matches_the_canonical_bidirectional_query_exactly() {
        let options = ContextV2Options::new(
            1,
            64 * 1024,
            256,
            [
                ContextFilter::Contracts,
                ContextFilter::Ownership,
                ContextFilter::Effects,
                ContextFilter::Types,
            ],
            ContextDirection::Both,
        )
        .expect("valid v2 options");
        let outcome = context_v2_source("hello.spx", HELLO, "app.main", &options);
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        let context_json = outcome
            .context_json
            .expect("matching v2 query must carry context JSON");
        let program = crate::parse(HELLO, "hello.spx").expect("HELLO must parse");
        let expected_options = crate::graph::AgentContextV2Options::new(
            1,
            64 * 1024,
            256,
            [
                crate::graph::AgentContextFilter::Contracts,
                crate::graph::AgentContextFilter::Ownership,
                crate::graph::AgentContextFilter::Effects,
                crate::graph::AgentContextFilter::Types,
            ],
            crate::graph::AgentContextDirection::Both,
        )
        .expect("valid graph v2 options");
        let expected = crate::graph::agent_context_v2_json(&program, "app.main", &expected_options)
            .expect("HELLO must resolve")
            .expect("app.main must match");
        assert_eq!(context_json, expected);
        assert_eq!(options.direction(), ContextDirection::Both);
    }

    #[test]
    fn v2_context_no_match_is_a_successful_empty_result() {
        let outcome = context_v2_source(
            "hello.spx",
            HELLO,
            "app.does_not_exist",
            &ContextV2Options::default(),
        );
        assert!(outcome.ok, "expected ok, got {:?}", outcome.diagnostics);
        assert_eq!(outcome.context_json, None);
    }

    struct PanickingV2Contexter;

    impl SourceV2Contexter for PanickingV2Contexter {
        fn context(
            &self,
            _unit_name: &str,
            _source: &str,
            _symbol: &str,
            _options: &ContextV2Options,
        ) -> Result<Option<String>, Vec<Diagnostic>> {
            panic!("deliberate test panic: proving it never crosses the embedding boundary");
        }
    }

    #[test]
    fn embedding_v2_context_boundary_normalizes_a_panic_into_a_diagnostic() {
        let outcome = context_v2_with(
            &PanickingV2Contexter,
            "panicking.spx",
            "irrelevant",
            "app.main",
            &ContextV2Options::default(),
        );
        assert!(!outcome.ok);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            PANIC_NORMALIZED_DIAGNOSTIC_CODE
        );
        assert!(outcome.context_json.is_none());
    }
}
