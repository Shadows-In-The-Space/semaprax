use super::*;
use std::path::Path;

const SOURCE: &str = r#"
module test.migration;
@id("app.ask")
fn ask(seed: i64) -> i64 yields i64 -> i64
{
    let first = yield seed + 1;
    let second = yield first + 2;
    second + 3
}
@id("app.main")
fn main() -> i64 { 0 }
"#;

fn program(source: &str) -> ResolvedProgram {
    crate::hir::resolve(&crate::parse(source, Path::new("migration.spx")).unwrap()).unwrap()
}

fn budget() -> SourceCheckpointMigrationBudget {
    SourceCheckpointMigrationBudget {
        max_segment_steps: 10_000,
        max_total_steps: 100_000,
    }
}

fn input<'a>(
    program: &'a ResolvedProgram,
    key: &'a SourceCheckpointKey,
    scope: &'a SourceCheckpointScope,
    arguments: &'a [ArgumentValue],
) -> SourceCheckpointMigrationInput<'a> {
    SourceCheckpointMigrationInput {
        program,
        key,
        scope,
        function_id: "app.ask",
        arguments,
    }
}

fn suspended(step: SequentialResumableEvaluation) -> ResumableContinuation {
    let SequentialResumableStep::Suspended { continuation } = step.step else {
        panic!("expected suspension")
    };
    continuation
}

struct Fixture {
    old: ResolvedProgram,
    old_key: SourceCheckpointKey,
    new_key: SourceCheckpointKey,
    old_scope: SourceCheckpointScope,
    new_scope: SourceCheckpointScope,
    arguments: [ArgumentValue; 1],
    checkpoint: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let old = program(SOURCE);
        let old_key = SourceCheckpointKey::new([1; 32]);
        let new_key = SourceCheckpointKey::new([2; 32]);
        let old_scope = SourceCheckpointScope::new("root-old", "invocation", 1).unwrap();
        let new_scope = SourceCheckpointScope::new("root-new", "invocation", 2).unwrap();
        let arguments = [ArgumentValue::Int(4)];
        let first = suspended(
            run_sequential_resumable_effect(&old, "app.ask", &arguments, 10_000).unwrap(),
        );
        let second = suspended(
            resume_sequential_resumable_effect(
                &old,
                "app.ask",
                &arguments,
                &first,
                &ArgumentValue::Int(10),
                10_000,
            )
            .unwrap(),
        );
        let checkpoint =
            encode_source_checkpoint_v2(&old, &old_key, &old_scope, "app.ask", &arguments, &second)
                .unwrap();
        Self {
            old,
            old_key,
            new_key,
            old_scope,
            new_scope,
            arguments,
            checkpoint,
        }
    }

    fn migrate(
        &self,
        new: &ResolvedProgram,
        budget: SourceCheckpointMigrationBudget,
    ) -> Result<SourceCheckpointMigration, SourceCheckpointMigrationError> {
        migrate_source_checkpoint_v2(
            input(&self.old, &self.old_key, &self.old_scope, &self.arguments),
            input(new, &self.new_key, &self.new_scope, &self.arguments),
            &self.checkpoint,
            budget,
        )
    }
}

#[test]
fn migrates_changed_suffix_rotates_key_and_replays_history_without_dispatch() {
    let fixture = Fixture::new();
    let new = program(&SOURCE.replace("second + 3", "second + 30"));
    let migrated = fixture.migrate(&new, budget()).unwrap();
    assert_eq!(migrated, fixture.migrate(&new, budget()).unwrap());
    assert!(migrated.steps_used > 0);
    let recovered = decode_source_checkpoint_v2(
        &new,
        &fixture.new_key,
        &fixture.new_scope,
        "app.ask",
        &fixture.arguments,
        &migrated.checkpoint,
    )
    .unwrap();
    assert_eq!(recovered.request(), &ArgumentValue::Int(12));
    let result = resume_sequential_resumable_effect(
        &new,
        "app.ask",
        &fixture.arguments,
        &recovered,
        &ArgumentValue::Int(20),
        10_000,
    )
    .unwrap();
    assert!(matches!(
        result.step,
        SequentialResumableStep::Completed {
            result: ArgumentValue::Int(50),
            ..
        }
    ));
    assert_eq!(
        encode_source_checkpoint_v2(
            &new,
            &fixture.new_key,
            &fixture.new_scope,
            "app.ask",
            &fixture.arguments,
            &recovered
        )
        .unwrap(),
        migrated.checkpoint
    );
    assert_eq!(
        decode_source_checkpoint_v2(
            &new,
            &fixture.old_key,
            &fixture.new_scope,
            "app.ask",
            &fixture.arguments,
            &migrated.checkpoint
        )
        .unwrap_err(),
        SourceCheckpointError::AuthenticationMismatch
    );
}

#[test]
fn historical_and_pending_request_drift_are_distinct_refusals() {
    let fixture = Fixture::new();
    for (source, site) in [
        (SOURCE.replace("seed + 1", "seed + 9"), 0),
        (SOURCE.replace("first + 2", "first + 9"), 1),
    ] {
        assert_eq!(
            fixture.migrate(&program(&source), budget()).unwrap_err(),
            SourceCheckpointMigrationError::RequestMismatch { site }
        );
    }
}

#[test]
fn authenticates_old_key_scope_program_and_arguments_before_migration() {
    let fixture = Fixture::new();
    let new = program(&SOURCE.replace("second + 3", "second + 30"));
    let wrong_arguments = [ArgumentValue::Int(5)];
    for old in [
        input(
            &fixture.old,
            &fixture.new_key,
            &fixture.old_scope,
            &fixture.arguments,
        ),
        input(
            &fixture.old,
            &fixture.old_key,
            &fixture.new_scope,
            &fixture.arguments,
        ),
        input(
            &new,
            &fixture.old_key,
            &fixture.old_scope,
            &fixture.arguments,
        ),
        input(
            &fixture.old,
            &fixture.old_key,
            &fixture.old_scope,
            &wrong_arguments,
        ),
    ] {
        assert!(matches!(
            migrate_source_checkpoint_v2(
                old,
                input(
                    &new,
                    &fixture.new_key,
                    &fixture.new_scope,
                    &fixture.arguments
                ),
                &fixture.checkpoint,
                budget()
            ),
            Err(SourceCheckpointMigrationError::OldCheckpoint(_))
        ));
    }
}

#[test]
fn rejects_changed_site_count_channel_function_or_invocation() {
    let fixture = Fixture::new();
    let fewer_sites =
        program(&SOURCE.replace("let second = yield first + 2;", "let second = first + 2;"));
    assert_eq!(
        fixture.migrate(&fewer_sites, budget()).unwrap_err(),
        SourceCheckpointMigrationError::SiteMismatch
    );
    let moved_site = program(&SOURCE.replace(
        "let first = yield seed + 1;",
        "let extra = seed;\n    let first = yield extra + 1;",
    ));
    assert_eq!(
        fixture.migrate(&moved_site, budget()).unwrap_err(),
        SourceCheckpointMigrationError::SiteMismatch
    );
    let mut new = input(
        &fixture.old,
        &fixture.new_key,
        &fixture.new_scope,
        &fixture.arguments,
    );
    new.function_id = "app.other";
    assert_eq!(
        migrate_source_checkpoint_v2(
            input(
                &fixture.old,
                &fixture.old_key,
                &fixture.old_scope,
                &fixture.arguments
            ),
            new,
            &fixture.checkpoint,
            budget()
        )
        .unwrap_err(),
        SourceCheckpointMigrationError::FunctionMismatch
    );
    let scope = SourceCheckpointScope::new("root-new", "other-invocation", 2).unwrap();
    assert_eq!(
        migrate_source_checkpoint_v2(
            input(
                &fixture.old,
                &fixture.old_key,
                &fixture.old_scope,
                &fixture.arguments
            ),
            input(&fixture.old, &fixture.new_key, &scope, &fixture.arguments),
            &fixture.checkpoint,
            budget()
        )
        .unwrap_err(),
        SourceCheckpointMigrationError::InvocationMismatch
    );
    let typed = program(
        &SOURCE
            .replace("i64", "i32")
            .replace("+ 1", "+ 1i32")
            .replace("+ 2", "+ 2i32")
            .replace("+ 3", "+ 3i32")
            .replace("fn main() -> i32 { 0 }", "fn main() -> i64 { 0 }"),
    );
    assert_eq!(
        fixture.migrate(&typed, budget()).unwrap_err(),
        SourceCheckpointMigrationError::TypeMismatch
    );
}

#[test]
fn cumulative_and_per_segment_fuel_are_enforced_at_exact_boundaries() {
    let fixture = Fixture::new();
    let new = program(&SOURCE.replace("second + 3", "second + 30"));
    let cost = fixture.migrate(&new, budget()).unwrap().steps_used;
    let exact = SourceCheckpointMigrationBudget {
        max_total_steps: cost,
        ..budget()
    };
    assert!(fixture.migrate(&new, exact).is_ok());
    assert_eq!(
        fixture
            .migrate(
                &new,
                SourceCheckpointMigrationBudget {
                    max_total_steps: cost - 1,
                    ..exact
                }
            )
            .unwrap_err(),
        SourceCheckpointMigrationError::FuelExhausted
    );
    for max_segment_steps in [0, 1] {
        assert_eq!(
            fixture
                .migrate(
                    &new,
                    SourceCheckpointMigrationBudget {
                        max_segment_steps,
                        ..budget()
                    }
                )
                .unwrap_err(),
            SourceCheckpointMigrationError::FuelExhausted
        );
    }
    let first =
        run_sequential_resumable_effect(&fixture.old, "app.ask", &fixture.arguments, 10_000)
            .unwrap();
    let start_cost = first.steps_used;
    let second = resume_sequential_resumable_effect(
        &fixture.old,
        "app.ask",
        &fixture.arguments,
        &suspended(first),
        &ArgumentValue::Int(10),
        10_000,
    )
    .unwrap();
    let segment_cost = start_cost.max(second.steps_used);
    assert!(segment_cost > 1);
    assert!(fixture
        .migrate(
            &new,
            SourceCheckpointMigrationBudget {
                max_segment_steps: segment_cost,
                ..budget()
            }
        )
        .is_ok());
    assert_eq!(
        fixture
            .migrate(
                &new,
                SourceCheckpointMigrationBudget {
                    max_segment_steps: segment_cost - 1,
                    ..budget()
                }
            )
            .unwrap_err(),
        SourceCheckpointMigrationError::FuelExhausted
    );
}

#[test]
fn segment_budget_limit_is_explicit_even_when_total_would_mask_it() {
    let fixture = Fixture::new();
    let new = program(&SOURCE.replace("second + 3", "second + 30"));
    assert!(fixture
        .migrate(
            &new,
            SourceCheckpointMigrationBudget {
                max_segment_steps: crate::interpreter::MAX_STEPS_LIMIT,
                ..budget()
            }
        )
        .is_ok());
    assert_eq!(
        fixture
            .migrate(
                &new,
                SourceCheckpointMigrationBudget {
                    max_segment_steps: crate::interpreter::MAX_STEPS_LIMIT + 1,
                    ..budget()
                }
            )
            .unwrap_err(),
        SourceCheckpointMigrationError::InvalidBudget
    );
}

#[test]
fn explicit_destination_scope_can_select_a_decreasing_policy_epoch() {
    let mut fixture = Fixture::new();
    fixture.new_scope = SourceCheckpointScope::new("root-new", "invocation", 0).unwrap();
    let new = program(&SOURCE.replace("second + 3", "second + 30"));
    let migrated = fixture.migrate(&new, budget()).unwrap();
    let recovered = decode_source_checkpoint_v2(
        &new,
        &fixture.new_key,
        &fixture.new_scope,
        "app.ask",
        &fixture.arguments,
        &migrated.checkpoint,
    )
    .unwrap();
    assert_eq!(recovered.request(), &ArgumentValue::Int(12));
    let wrong_epoch = SourceCheckpointScope::new("root-new", "invocation", 1).unwrap();
    assert_eq!(
        decode_source_checkpoint_v2(
            &new,
            &fixture.new_key,
            &wrong_epoch,
            "app.ask",
            &fixture.arguments,
            &migrated.checkpoint,
        )
        .unwrap_err(),
        SourceCheckpointError::ScopeMismatch
    );
}

#[test]
fn signed_fabricated_history_is_rejected_even_if_the_new_program_matches_it() {
    use crate::interpreter::resumable::checkpoint;
    use sha2::{Digest, Sha256};
    let mut fixture = Fixture::new();
    let authenticated = decode_source_checkpoint_v2(
        &fixture.old,
        &fixture.old_key,
        &fixture.old_scope,
        "app.ask",
        &fixture.arguments,
        &fixture.checkpoint,
    )
    .unwrap();
    let inner = checkpoint::encode("app.ask", &authenticated).unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&inner).unwrap();
    document["history"][0]["request"]["value"] = serde_json::json!(13);
    document.as_object_mut().unwrap().remove("digest");
    let mut hasher = Sha256::new();
    hasher.update(b"semaprax.source-resumable-sequential-checkpoint-digest.v1\0");
    hasher.update(document.to_string().as_bytes());
    document["digest"] = serde_json::json!(format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    ));
    // Structural decoding and v2 signing intentionally do not execute source.
    let fabricated = checkpoint::decode(
        &fixture.old,
        "app.ask",
        &fixture.arguments,
        format!("{document}\n").as_bytes(),
    )
    .unwrap();
    fixture.checkpoint = encode_source_checkpoint_v2(
        &fixture.old,
        &fixture.old_key,
        &fixture.old_scope,
        "app.ask",
        &fixture.arguments,
        &fabricated,
    )
    .unwrap();
    assert!(decode_source_checkpoint_v2(
        &fixture.old,
        &fixture.old_key,
        &fixture.old_scope,
        "app.ask",
        &fixture.arguments,
        &fixture.checkpoint,
    )
    .is_ok());
    let new = program(&SOURCE.replace("seed + 1", "seed + 9"));
    assert_eq!(
        fixture.migrate(&new, budget()).unwrap_err(),
        SourceCheckpointMigrationError::RequestMismatch { site: 0 }
    );
}

#[test]
fn changed_destination_arguments_require_compatible_requests_and_bind_new_output() {
    let fixture = Fixture::new();
    let arguments = [ArgumentValue::Int(3)];
    let compatible = program(&SOURCE.replace("seed + 1", "seed + 2"));
    let migrated = migrate_source_checkpoint_v2(
        input(
            &fixture.old,
            &fixture.old_key,
            &fixture.old_scope,
            &fixture.arguments,
        ),
        input(
            &compatible,
            &fixture.new_key,
            &fixture.new_scope,
            &arguments,
        ),
        &fixture.checkpoint,
        budget(),
    )
    .unwrap();
    assert!(decode_source_checkpoint_v2(
        &compatible,
        &fixture.new_key,
        &fixture.new_scope,
        "app.ask",
        &arguments,
        &migrated.checkpoint,
    )
    .is_ok());
    assert_eq!(
        decode_source_checkpoint_v2(
            &compatible,
            &fixture.new_key,
            &fixture.new_scope,
            "app.ask",
            &fixture.arguments,
            &migrated.checkpoint,
        )
        .unwrap_err(),
        SourceCheckpointError::SuspensionMismatch
    );
    assert_eq!(
        migrate_source_checkpoint_v2(
            input(
                &fixture.old,
                &fixture.old_key,
                &fixture.old_scope,
                &fixture.arguments
            ),
            input(
                &fixture.old,
                &fixture.new_key,
                &fixture.new_scope,
                &arguments
            ),
            &fixture.checkpoint,
            budget(),
        )
        .unwrap_err(),
        SourceCheckpointMigrationError::RequestMismatch { site: 0 }
    );
}

#[test]
fn scalar_comparison_preserves_nan_payload_and_signed_zero() {
    let nan = ArgumentValue::Float64(f64::from_bits(0x7ff8_0000_0000_0042));
    assert!(same_scalar(&nan, &nan));
    assert!(!same_scalar(
        &nan,
        &ArgumentValue::Float64(f64::from_bits(0x7ff8_0000_0000_0043))
    ));
    assert!(!same_scalar(
        &ArgumentValue::Float64(0.0),
        &ArgumentValue::Float64(-0.0)
    ));
    assert!(!same_scalar(
        &ArgumentValue::Float32(0.0),
        &ArgumentValue::Float32(-0.0)
    ));
}

#[test]
fn migration_preserves_nan_history_and_refuses_signed_zero_request_drift() {
    let source = r#"
module test.float_migration;
@id("app.ask")
fn ask(seed: f64) -> f64 yields f64 -> f64
{
    let first = yield seed;
    let second = yield first;
    second + 1.0
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let old = program(source);
    let new = program(&source.replace("second + 1.0", "second + 2.0"));
    let old_key = SourceCheckpointKey::new([3; 32]);
    let new_key = SourceCheckpointKey::new([4; 32]);
    let old_scope = SourceCheckpointScope::new("old", "invocation", 1).unwrap();
    let new_scope = SourceCheckpointScope::new("new", "invocation", 2).unwrap();
    let arguments = [ArgumentValue::Float64(f64::from_bits(
        0x7ff8_0000_0000_0042,
    ))];
    let first =
        suspended(run_sequential_resumable_effect(&old, "app.ask", &arguments, 10_000).unwrap());
    let second = suspended(
        resume_sequential_resumable_effect(
            &old,
            "app.ask",
            &arguments,
            &first,
            &ArgumentValue::Float64(-0.0),
            10_000,
        )
        .unwrap(),
    );
    let bytes =
        encode_source_checkpoint_v2(&old, &old_key, &old_scope, "app.ask", &arguments, &second)
            .unwrap();
    let result = migrate_source_checkpoint_v2(
        input(&old, &old_key, &old_scope, &arguments),
        input(&new, &new_key, &new_scope, &arguments),
        &bytes,
        budget(),
    )
    .unwrap();
    let continuation = decode_source_checkpoint_v2(
        &new,
        &new_key,
        &new_scope,
        "app.ask",
        &arguments,
        &result.checkpoint,
    )
    .unwrap();
    assert!(same_scalar(
        continuation.request(),
        &ArgumentValue::Float64(-0.0)
    ));
    assert!(same_scalar(
        continuation.history().next().unwrap().0,
        &arguments[0]
    ));
    let drift = program(&source.replace("yield first", "yield 0.0"));
    assert_eq!(
        migrate_source_checkpoint_v2(
            input(&old, &old_key, &old_scope, &arguments),
            input(&drift, &new_key, &new_scope, &arguments),
            &bytes,
            budget()
        )
        .unwrap_err(),
        SourceCheckpointMigrationError::RequestMismatch { site: 1 }
    );
}

#[test]
fn same_root_requires_recovery_instead_of_migration() {
    let fixture = Fixture::new();
    assert_eq!(
        migrate_source_checkpoint_v2(
            input(
                &fixture.old,
                &fixture.old_key,
                &fixture.old_scope,
                &fixture.arguments
            ),
            input(
                &fixture.old,
                &fixture.new_key,
                &fixture.old_scope,
                &fixture.arguments
            ),
            &fixture.checkpoint,
            budget(),
        )
        .unwrap_err(),
        SourceCheckpointMigrationError::UnchangedProgramRoot
    );
}
