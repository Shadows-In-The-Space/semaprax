//! The task-service reference application carried end to end.
//!
//! `examples/task-service-project` is issue #194's reference application: it
//! composes the bundled `std.auth` and `std.jobs` dependencies into a full
//! register/log-in/create-update-record/enqueue-complete-job/query-status/
//! log-out scenario, plus row-level-unauthorized and invalid-input rejection,
//! in deterministic fixture mode. Its own README and
//! `docs/COMPLETION-MATRIX.md` record that this project was, until this
//! module, "manually observed to pass" only -- no test under `tests/` or
//! `src/**/tests.rs` executed `check`/`test`/`run` over it, so nothing
//! regressed it in CI. This module is that regression gate.
//!
//! Canonical formatting for every module under `examples/task-service-project`
//! is already covered by `tests/examples.rs::every_example_below_the_top_level_is_canonical`,
//! so this module does not repeat that check.

use std::path::{Path, PathBuf};

use semaprax::project;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/task-service-project")
}

/// `check`, `test`, and `run` all pass on the interpreter, and the manifest's
/// bundled dependencies resolve to the compiler's own `std.auth`/`std.jobs`
/// source rather than anything vendored by hand.
///
/// Negative control (performed manually, not committed): flipping
/// `task_service.core.task_owner_authorized`'s `&&` to `||` makes
/// `task_service.tests.unauthorized_is_rejected` false, so
/// `task_service.tests.main` returns `1` and this assertion on
/// `execute_test()`'s outcome fails. Restoring the source turns the gate
/// green again. This proves the gate actually exercises the row-level
/// authorization the reference application exists to demonstrate, rather
/// than passing regardless of the project's behavior.
#[test]
fn check_test_and_run_pass_on_the_interpreter() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.auth/0.1.0"),
            "the workspace does not carry the bundled std.auth source"
        );
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.jobs/0.1.0"),
            "the workspace does not carry the bundled std.jobs source"
        );
        let options = project::ProjectExecutionOptions::default();
        assert_eq!(
            snapshot.execute_entry(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the acceptance scenario entry did not report success"
        );
        assert_eq!(
            snapshot.execute_test(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the project's own named test cases (success, unauthorized, \
             invalid, duplicate-enqueue) did not all pass"
        );
        Ok(())
    })
    .unwrap();
}

/// The manifest's declared `[exports].web` roots are real public functions
/// reachable in the retained revision's semantic graph, the same shape
/// `tests/useful_data/agent_response_project.rs` asserts for its sibling
/// reference project.
#[test]
fn the_declared_web_exports_are_reachable_public_functions() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let public = snapshot.retain_revision();
        let ids = public
            .public_api_program()
            .functions
            .iter()
            .map(|function| function.id.clone())
            .collect::<Vec<_>>();
        // Guard against the vacuous pass: an empty selection would make the
        // loop below assert nothing at all. This project declares exactly
        // two roots in its `[exports].web`.
        assert_eq!(
            snapshot.manifest().web_exports().len(),
            2,
            "the reference application must still declare its two web export roots"
        );
        for selected in snapshot.manifest().web_exports() {
            assert!(
                ids.iter().any(|id| id.as_str() == selected.as_str()),
                "missing selected export root {selected}"
            );
            assert!(snapshot.semantic_graph().contains(selected));
        }
        Ok(())
    })
    .unwrap();
}
