//! Bounded, reusable request values for the pathless analysis facade.
//!
//! This module owns only admission around the existing compiler kernels. It
//! never retains an AST, cache, or source bytes, and never opens `unit_name`.

use super::{
    check_with, context_v2_with, context_with, format_with, graph_with, CheckOutcome,
    ContextOptions, ContextOutcome, ContextV2Options, EmbeddingCancellation, FormatOutcome,
    GraphOutcome, StandardChecker, StandardContexter, StandardFormatter, StandardGrapher,
    StandardV2Contexter, CANCELLATION_DIAGNOSTIC_CODE,
};
use crate::diagnostic::Diagnostic;

/// Stable refusal for source or label capacity beyond the embedding facade's
/// admitted request bounds.
pub const SOURCE_LIMIT_DIAGNOSTIC_CODE: &str = "SPX-EMB005";

/// Largest source payload any pathless analysis call accepts.
pub const MAX_ANALYSIS_SOURCE_BYTES: usize = 16 * 1024 * 1024;
/// Largest diagnostic-only unit label any pathless analysis call accepts.
pub const MAX_ANALYSIS_UNIT_NAME_BYTES: usize = 4 * 1024;
/// Largest context symbol selector any pathless context call accepts.
pub const MAX_ANALYSIS_SYMBOL_BYTES: usize = 4 * 1024;

/// Caller-selected input bounds for one or more pathless analysis requests.
///
/// Values can only tighten the facade-wide hard caps. This type carries no
/// compiler state and is `Copy`, so callers may reuse it concurrently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisOptions {
    max_source_bytes: usize,
    max_unit_name_bytes: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_source_bytes: MAX_ANALYSIS_SOURCE_BYTES,
            max_unit_name_bytes: MAX_ANALYSIS_UNIT_NAME_BYTES,
        }
    }
}

impl AnalysisOptions {
    /// Select stricter source and label limits, never limits above this
    /// facade's fixed admission caps.
    pub fn new(max_source_bytes: usize, max_unit_name_bytes: usize) -> Result<Self, Diagnostic> {
        if max_source_bytes > MAX_ANALYSIS_SOURCE_BYTES
            || max_unit_name_bytes > MAX_ANALYSIS_UNIT_NAME_BYTES
        {
            return Err(capacity_diagnostic(
                "requested analysis limits exceed this embedding API's hard caps",
            ));
        }
        Ok(Self {
            max_source_bytes,
            max_unit_name_bytes,
        })
    }

    #[must_use]
    pub const fn max_source_bytes(self) -> usize {
        self.max_source_bytes
    }

    #[must_use]
    pub const fn max_unit_name_bytes(self) -> usize {
        self.max_unit_name_bytes
    }
}

/// Borrowed, immutable inputs for one pathless analysis operation.
///
/// The request neither copies nor retains caller bytes. It is safe to reuse
/// from multiple threads; cancellation is cooperative, sampled before work
/// and once more before a successful report is returned. The compiler kernels
/// have no mid-parse interruption hook, so the second sample may discard an
/// already-computed pure report rather than interrupting parser work.
#[derive(Clone, Copy)]
pub struct AnalysisRequest<'a> {
    unit_name: &'a str,
    source: &'a str,
    options: AnalysisOptions,
    cancellation: Option<&'a EmbeddingCancellation>,
}

impl<'a> AnalysisRequest<'a> {
    /// Build a request using the facade's fixed hard limits.
    #[must_use]
    pub const fn new(unit_name: &'a str, source: &'a str) -> Self {
        Self {
            unit_name,
            source,
            options: AnalysisOptions {
                max_source_bytes: MAX_ANALYSIS_SOURCE_BYTES,
                max_unit_name_bytes: MAX_ANALYSIS_UNIT_NAME_BYTES,
            },
            cancellation: None,
        }
    }

    /// Apply caller-selected limits to this request.
    #[must_use]
    pub const fn with_options(mut self, options: AnalysisOptions) -> Self {
        self.options = options;
        self
    }

    /// Attach a caller-owned cooperative cancellation signal.
    #[must_use]
    pub const fn with_cancellation(mut self, cancellation: &'a EmbeddingCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    #[must_use]
    pub const fn unit_name(self) -> &'a str {
        self.unit_name
    }

    #[must_use]
    pub const fn source(self) -> &'a str {
        self.source
    }

    #[must_use]
    pub const fn options(self) -> AnalysisOptions {
        self.options
    }

    fn preflight(self) -> Result<(), Diagnostic> {
        if self.is_cancelled() {
            return Err(cancelled_diagnostic());
        }
        preflight_hard_source_and_label(self.unit_name, self.source)?;
        if self.unit_name.len() > self.options.max_unit_name_bytes {
            return Err(capacity_diagnostic(
                "embedding analysis unit label exceeds the admitted byte limit",
            ));
        }
        if self.source.len() > self.options.max_source_bytes {
            return Err(capacity_diagnostic(
                "embedding analysis source exceeds the admitted byte limit",
            ));
        }
        Ok(())
    }

    fn preflight_context(self, symbol: &str) -> Result<(), Diagnostic> {
        self.preflight()?;
        if symbol.len() > MAX_ANALYSIS_SYMBOL_BYTES {
            return Err(capacity_diagnostic(
                "embedding context symbol exceeds the admitted byte limit",
            ));
        }
        Ok(())
    }

    fn bounded_unit_name(self) -> String {
        bounded_echo(self.unit_name, self.options.max_unit_name_bytes)
    }

    fn is_cancelled(self) -> bool {
        match self.cancellation {
            Some(item) => item.is_cancelled(),
            None => false,
        }
    }
}

pub(crate) fn check_source(unit_name: &str, source: &str) -> CheckOutcome {
    check_source_with_request(AnalysisRequest::new(unit_name, source))
}

/// Check a bounded request using the existing pathless check kernel.
pub fn check_source_with_request(request: AnalysisRequest<'_>) -> CheckOutcome {
    match request.preflight() {
        Ok(()) => close_check_after_cancellation(
            request,
            check_with(&StandardChecker, request.unit_name, request.source),
        ),
        Err(diagnostic) => failed_check(request, diagnostic),
    }
}

pub(crate) fn format_source(unit_name: &str, source: &str) -> FormatOutcome {
    format_source_with_request(AnalysisRequest::new(unit_name, source))
}

/// Format a bounded request using the existing pathless formatter.
pub fn format_source_with_request(request: AnalysisRequest<'_>) -> FormatOutcome {
    match request.preflight() {
        Ok(()) => close_format_after_cancellation(
            request,
            format_with(&StandardFormatter, request.unit_name, request.source),
        ),
        Err(diagnostic) => failed_format(request, diagnostic),
    }
}

pub(crate) fn graph_source(unit_name: &str, source: &str) -> GraphOutcome {
    graph_source_with_request(AnalysisRequest::new(unit_name, source))
}

/// Render a graph for a bounded request using the existing pathless kernel.
pub fn graph_source_with_request(request: AnalysisRequest<'_>) -> GraphOutcome {
    match request.preflight() {
        Ok(()) => close_graph_after_cancellation(
            request,
            graph_with(&StandardGrapher, request.unit_name, request.source),
        ),
        Err(diagnostic) => failed_graph(request, diagnostic),
    }
}

pub(crate) fn context_source(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextOptions,
) -> ContextOutcome {
    context_source_with_request(AnalysisRequest::new(unit_name, source), symbol, options)
}

/// Query v1 context for a bounded request using the existing pathless kernel.
pub fn context_source_with_request(
    request: AnalysisRequest<'_>,
    symbol: &str,
    options: &ContextOptions,
) -> ContextOutcome {
    match request.preflight_context(symbol) {
        Ok(()) => close_context_after_cancellation(
            request,
            symbol,
            context_with(
                &StandardContexter,
                request.unit_name,
                request.source,
                symbol,
                options,
            ),
        ),
        Err(diagnostic) => failed_context(request, symbol, diagnostic),
    }
}

pub(crate) fn context_source_with_cancellation(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextOptions,
    cancellation: &EmbeddingCancellation,
) -> ContextOutcome {
    context_source_with_request(
        AnalysisRequest::new(unit_name, source).with_cancellation(cancellation),
        symbol,
        options,
    )
}

pub(crate) fn context_v2_source(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextV2Options,
) -> ContextOutcome {
    context_v2_source_with_request(AnalysisRequest::new(unit_name, source), symbol, options)
}

/// Query v2 context for a bounded request using the existing pathless kernel.
pub fn context_v2_source_with_request(
    request: AnalysisRequest<'_>,
    symbol: &str,
    options: &ContextV2Options,
) -> ContextOutcome {
    match request.preflight_context(symbol) {
        Ok(()) => close_context_after_cancellation(
            request,
            symbol,
            context_v2_with(
                &StandardV2Contexter,
                request.unit_name,
                request.source,
                symbol,
                options,
            ),
        ),
        Err(diagnostic) => failed_context(request, symbol, diagnostic),
    }
}

pub(super) fn preflight_hard_source_and_label(
    unit_name: &str,
    source: &str,
) -> Result<(), Diagnostic> {
    if unit_name.len() > MAX_ANALYSIS_UNIT_NAME_BYTES {
        return Err(capacity_diagnostic(
            "embedding analysis unit label exceeds the admitted byte limit",
        ));
    }
    if source.len() > MAX_ANALYSIS_SOURCE_BYTES {
        return Err(capacity_diagnostic(
            "embedding analysis source exceeds the admitted byte limit",
        ));
    }
    Ok(())
}

pub(super) fn bounded_hard_unit_name(unit_name: &str) -> String {
    bounded_echo(unit_name, MAX_ANALYSIS_UNIT_NAME_BYTES)
}

fn capacity_diagnostic(message: &str) -> Diagnostic {
    Diagnostic::io(SOURCE_LIMIT_DIAGNOSTIC_CODE, message)
}

fn cancelled_diagnostic() -> Diagnostic {
    Diagnostic::io(
        CANCELLATION_DIAGNOSTIC_CODE,
        "embedding analysis request was cancelled before a report was returned",
    )
}

fn bounded_echo(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn failed_check(request: AnalysisRequest<'_>, diagnostic: Diagnostic) -> CheckOutcome {
    CheckOutcome {
        unit_name: request.bounded_unit_name(),
        ok: false,
        diagnostics: vec![diagnostic],
        revision: None,
    }
}
fn failed_format(request: AnalysisRequest<'_>, diagnostic: Diagnostic) -> FormatOutcome {
    FormatOutcome {
        unit_name: request.bounded_unit_name(),
        ok: false,
        diagnostics: vec![diagnostic],
        canonical_source: None,
    }
}
fn failed_graph(request: AnalysisRequest<'_>, diagnostic: Diagnostic) -> GraphOutcome {
    GraphOutcome {
        unit_name: request.bounded_unit_name(),
        ok: false,
        diagnostics: vec![diagnostic],
        graph_json: None,
    }
}
fn failed_context(
    request: AnalysisRequest<'_>,
    symbol: &str,
    diagnostic: Diagnostic,
) -> ContextOutcome {
    ContextOutcome {
        unit_name: request.bounded_unit_name(),
        symbol: bounded_echo(symbol, MAX_ANALYSIS_SYMBOL_BYTES),
        ok: false,
        diagnostics: vec![diagnostic],
        context_json: None,
    }
}

fn close_check_after_cancellation(
    request: AnalysisRequest<'_>,
    outcome: CheckOutcome,
) -> CheckOutcome {
    if outcome.ok && request.is_cancelled() {
        failed_check(request, cancelled_diagnostic())
    } else {
        outcome
    }
}
fn close_format_after_cancellation(
    request: AnalysisRequest<'_>,
    outcome: FormatOutcome,
) -> FormatOutcome {
    if outcome.ok && request.is_cancelled() {
        failed_format(request, cancelled_diagnostic())
    } else {
        outcome
    }
}
fn close_graph_after_cancellation(
    request: AnalysisRequest<'_>,
    outcome: GraphOutcome,
) -> GraphOutcome {
    if outcome.ok && request.is_cancelled() {
        failed_graph(request, cancelled_diagnostic())
    } else {
        outcome
    }
}
fn close_context_after_cancellation(
    request: AnalysisRequest<'_>,
    symbol: &str,
    outcome: ContextOutcome,
) -> ContextOutcome {
    if outcome.ok && request.is_cancelled() {
        failed_context(request, symbol, cancelled_diagnostic())
    } else {
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "module app.hello;\n\n@id(\"app.main\")\nfn main() -> i64\n{\n    42\n}\n";

    #[test]
    fn strict_source_limit_refuses_before_parser_for_every_kernel() {
        let options = AnalysisOptions::new(3, 8).unwrap();
        let request = AnalysisRequest::new("unit", "invalid").with_options(options);
        let outcomes = [
            check_source_with_request(request).diagnostics,
            format_source_with_request(request).diagnostics,
            graph_source_with_request(request).diagnostics,
            context_source_with_request(request, "main", &ContextOptions::default()).diagnostics,
            context_v2_source_with_request(request, "main", &ContextV2Options::default())
                .diagnostics,
        ];
        for diagnostics in outcomes {
            assert_eq!(diagnostics[0].code, SOURCE_LIMIT_DIAGNOSTIC_CODE);
        }
        assert_eq!(
            AnalysisOptions::new(MAX_ANALYSIS_SOURCE_BYTES + 1, 1)
                .unwrap_err()
                .code,
            SOURCE_LIMIT_DIAGNOSTIC_CODE
        );
    }

    #[test]
    fn rejected_labels_and_symbols_are_utf8_safe_and_output_bounded() {
        let oversized = "é".repeat(MAX_ANALYSIS_UNIT_NAME_BYTES + 1);
        let label_failure = check_source_with_request(
            AnalysisRequest::new(&oversized, "invalid")
                .with_options(AnalysisOptions::new(MAX_ANALYSIS_SOURCE_BYTES, 3).unwrap()),
        );
        assert_eq!(
            label_failure.diagnostics[0].code,
            SOURCE_LIMIT_DIAGNOSTIC_CODE
        );
        assert!(label_failure.unit_name.len() <= 3);
        assert!(label_failure
            .unit_name
            .is_char_boundary(label_failure.unit_name.len()));

        let symbol = "é".repeat(MAX_ANALYSIS_SYMBOL_BYTES + 1);
        for outcome in [
            context_source_with_request(
                AnalysisRequest::new("unit", "invalid"),
                &symbol,
                &ContextOptions::default(),
            ),
            context_v2_source_with_request(
                AnalysisRequest::new("unit", "invalid"),
                &symbol,
                &ContextV2Options::default(),
            ),
        ] {
            assert_eq!(outcome.diagnostics[0].code, SOURCE_LIMIT_DIAGNOSTIC_CODE);
            assert!(outcome.symbol.len() <= MAX_ANALYSIS_SYMBOL_BYTES);
            assert!(outcome.symbol.is_char_boundary(outcome.symbol.len()));
        }
    }

    #[test]
    fn cancellation_refuses_before_parse_and_a_request_is_reusable_across_threads() {
        let cancellation = EmbeddingCancellation::new();
        cancellation.cancel();
        let cancelled =
            AnalysisRequest::new("bad.spx", "not parseable").with_cancellation(&cancellation);
        assert_eq!(
            check_source_with_request(cancelled).diagnostics[0].code,
            CANCELLATION_DIAGNOSTIC_CODE
        );

        let request = AnalysisRequest::new("hello.spx", HELLO);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| check_source_with_request(request));
            let second = scope.spawn(|| check_source_with_request(request));
            let first = first.join().unwrap();
            let second = second.join().unwrap();
            assert!(first.ok);
            assert!(second.ok);
            assert_eq!(first.revision, second.revision);
        });
    }
}
