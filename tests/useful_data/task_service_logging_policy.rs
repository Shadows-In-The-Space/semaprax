//! The task-service structured-log admission regression for issue #193.
//!
//! This is deliberately an interpreter-only project check. The sibling
//! `task_service_project` module owns the full backend matrix; this narrower
//! test pins the new dependency closure, stable identity, and pure no-I/O
//! structured-log policy without duplicating its native and Wasm evidence.

use std::path::Path;

use semaprax::project::{self, ProjectExecutionOptions, ProjectExecutionOutcome};

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/task-service-project")
}

#[test]
fn task_service_admits_only_bounded_redacted_structured_log_policy() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let manifest = snapshot.workspace_manifest();
        for package in [
            "dependencies/std.log/0.1.0",
            "dependencies/std.log.redact/0.1.0",
        ] {
            assert!(
                manifest.contains(package),
                "the service workspace must carry its explicit {package} source"
            );
        }
        assert!(snapshot
            .semantic_graph()
            .contains("task_service.core.structured_log_policy_is_admitted"));
        let options = ProjectExecutionOptions::default();
        assert_eq!(
            snapshot.execute_test(&options)?.outcome(),
            &ProjectExecutionOutcome::Returned(0),
            "the structured-log policy conformance must pass without a host writer or delivery"
        );
        Ok(())
    })
    .unwrap();
}
