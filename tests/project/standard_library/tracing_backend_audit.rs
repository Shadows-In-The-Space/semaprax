//! Issue #193: `std.tracing` is the W3C Trace Context `traceparent`/
//! `tracestate` decision layer, added following the shape
//! `webhook_backend_audit.rs` and `email_backend_audit.rs` established for
//! their sibling policy packages. Every package advertising a backend must
//! actually exercise its conformance on that backend, so this reuses exactly
//! the machinery `examples_and_conformance_return_zero_on_interpreter_native_and_wasm`
//! uses for every package, filtered down to this one, cheap enough to run
//! standalone without the full ~40-package sweep that needs well over 10 GB
//! on this host (see `AGENTS.md`/`CLAUDE.md`).
use super::*;

#[test]
fn tracing_executes_on_all_three_backends() {
    if cfg!(windows) {
        return;
    }
    run_examples_and_conformance(
        packages()
            .into_iter()
            .filter(|p| p.module == "std.tracing")
            .collect(),
    );
}
