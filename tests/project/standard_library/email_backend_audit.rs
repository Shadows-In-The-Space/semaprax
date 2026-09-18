//! Issue #193: `std.email` is the outbound-email decision layer, added in the
//! same session that `log_redact_backend_audit.rs` established this shape for
//! its sibling policy package. Every package advertising a backend must
//! actually exercise its conformance on that backend, so this reuses exactly
//! the machinery
//! `examples_and_conformance_return_zero_on_interpreter_native_and_wasm`
//! uses for every package, filtered down to this one, cheap enough to run
//! standalone without the full ~40-package sweep that needs well over 10 GB
//! on this host (see `AGENTS.md`/`CLAUDE.md`).
use super::*;

#[test]
fn email_executes_on_all_three_backends() {
    if cfg!(windows) {
        return;
    }
    run_examples_and_conformance(
        packages()
            .into_iter()
            .filter(|p| p.module == "std.email")
            .collect(),
    );
}
