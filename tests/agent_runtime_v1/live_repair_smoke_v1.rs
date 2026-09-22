//! Live Repair Smoke v1 and the repair candidate's separately approved
//! publication boundary.
//!
//! These cases drive the real library entry points against a host-selected
//! temporary Project. Nothing here calls a provider: the whole point of the
//! contract under test is that a live call stays behind an explicit operator
//! grant, and every case below runs with no credential of any kind.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use semaprax::agent_deployment::migrate_agent_definition_v1;
use semaprax::agent_lifecycle::iterative::effects::{
    EffectArgument, EffectBudget, EffectOperation, EffectResult, EffectScalar,
};
use semaprax::agent_lifecycle::iterative::IterativeBudget;
use semaprax::agent_lifecycle::LifecycleTask;
use semaprax::agent_runtime_v2::{
    bind_agent_runtime_v2_live, prepare_approved_repair_publication, AuthorizedLiveRepairSmoke,
    LiveRepairSmokeOutcome, LiveRepairSmokePlan, LiveRepairSmokeRecord, LiveRepairSmokeTarget,
    LiveRepairSmokeUsage, OfflineRepairEnvelope, OfflineRepairPreview, OperatorLiveSmokeGrant,
    RepairCandidateApproval, RepairCandidateReview, RepairValidationOutcome,
    RepairValidationStatus, SourceModelAdapterIdentity, SourceModelBinding,
};
use semaprax::execution_revision::ProgramRootRef;
use semaprax::model_budget_policy::ModelBudgetLimits;
use semaprax::project::{with_authenticated_project, ProjectRevision};

const TARGET: &str = "fixture.repair.value";
const SOURCE_PATH: &str = "src/app.spx";
const AGENT_ID: &str = "fixture.agent";
const STEP_ID: &str = "fixture.agent.type.step";
const SELECTOR: &str = "fixture.agent.type.proposal.sequence";
const OBSERVED_FAILURE: &str = "fixture.tests.repair_value_returns_seven";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary copy of the committed offline-repair Project whose deployment
/// admits a nonzero monetary ceiling. The committed fixture declares a free
/// local provider (`max_usd_microunits: 0`), which is exactly right for the
/// offline demonstration and exactly wrong for a *live* smoke: a plan whose
/// effective cost ceiling is zero admits no paid attempt and is refused. The
/// copy changes that one number and nothing else.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "semaprax-live-repair-smoke-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();

        let committed =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/offline-repair-project");
        let app = fs::read_to_string(committed.join("src/app.spx")).unwrap();
        let paid = app.replace(
            "\\\"max_usd_microunits\\\":0,",
            "\\\"max_usd_microunits\\\":250000,",
        );
        assert_ne!(
            paid, app,
            "the fixture must actually raise the deployment's monetary ceiling"
        );
        fs::write(root.join("src/app.spx"), &paid).unwrap();
        fs::write(
            root.join("src/tests.spx"),
            fs::read_to_string(committed.join("src/tests.spx")).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("semaprax.toml"),
            fs::read_to_string(committed.join("semaprax.toml")).unwrap(),
        )
        .unwrap();
        // The platform temporary directory is reached through a symbolic link
        // on macOS, and Project authentication refuses a non-real ancestor.
        let root = root.canonicalize().unwrap();
        Self { root }
    }

    fn manifest(&self) -> PathBuf {
        self.root.join("semaprax.toml")
    }

    fn source_path(&self) -> PathBuf {
        self.root.join(SOURCE_PATH)
    }

    fn project(&self) -> Arc<ProjectRevision> {
        with_authenticated_project(&self.manifest(), |snapshot| Ok(snapshot.retain_revision()))
            .unwrap_or_else(|diagnostics| {
                panic!("fixture project did not authenticate: {diagnostics:#?}")
            })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn operations() -> Vec<EffectOperation> {
    ["fixture.read", "fixture.read.second"]
        .into_iter()
        .map(|operation_id| EffectOperation {
            operation_id: operation_id.to_owned(),
            effect_id: "read".to_owned(),
            arguments: vec![EffectArgument {
                argument_id: "query".to_owned(),
                proposal_field_id: "fixture.agent.type.proposal.budget".to_owned(),
                kind: EffectScalar::I64,
            }],
            results: vec![EffectResult {
                result_id: "value".to_owned(),
                kind: EffectScalar::I64,
            }],
        })
        .collect()
}

fn adapter_identity() -> SourceModelAdapterIdentity {
    SourceModelAdapterIdentity {
        provider_id: "fake.local".to_owned(),
        model_id: "fake-basic".to_owned(),
        adapter_identity: "scripted-streaming-adapter".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        provider_profile: "fixture".to_owned(),
    }
}

/// Reach the real `SourceModelBinding` through the same public route the
/// production repair CLI uses, rather than fabricating one.
fn model_binding(project: &Arc<ProjectRevision>) -> SourceModelBinding {
    let root = project.program_root().expect("fixture ProgramRoot");
    let (_, deployment) = migrate_agent_definition_v1(
        project.agent_definitions()[0]
            .definition()
            .canonical_source(),
        "test.live.repair.smoke",
    )
    .unwrap_or_else(|diagnostics| panic!("fixture deployment migration refused: {diagnostics:#?}"));
    let runtime = bind_agent_runtime_v2_live(
        Arc::clone(project),
        ProgramRootRef::V1(&root),
        root.program_root_digest(),
        SOURCE_PATH,
        AGENT_ID,
        STEP_ID,
        SELECTOR,
        operations(),
        &deployment,
        LifecycleTask {
            objective: b"repair the checked fixture value".to_vec(),
            budget: 12,
        },
        IterativeBudget::default(),
        EffectBudget {
            max_calls: 2,
            max_argument_bytes: 4096,
            max_result_bytes: 4096,
            max_total_bytes: 8192,
        },
    )
    .unwrap_or_else(|diagnostics| panic!("fixture runtime binding refused: {diagnostics:#?}"));
    runtime
        .source_model_binding(adapter_identity())
        .unwrap_or_else(|diagnostics| panic!("fixture model binding refused: {diagnostics:#?}"))
}

fn target(project: &Arc<ProjectRevision>) -> LiveRepairSmokeTarget {
    LiveRepairSmokeTarget::bind(
        project,
        SOURCE_PATH,
        AGENT_ID,
        STEP_ID,
        TARGET,
        OBSERVED_FAILURE,
    )
    .unwrap_or_else(|diagnostics| panic!("smoke target refused: {diagnostics:#?}"))
}

fn plan_with_turns(
    project: &Arc<ProjectRevision>,
    binding: &SourceModelBinding,
    turns: u32,
) -> LiveRepairSmokePlan {
    LiveRepairSmokePlan::bind(
        target(project),
        binding,
        ModelBudgetLimits::unbounded(),
        turns,
    )
    .unwrap_or_else(|diagnostics| panic!("smoke plan refused: {diagnostics:#?}"))
}

fn grant_for(plan: &LiveRepairSmokePlan) -> OperatorLiveSmokeGrant {
    OperatorLiveSmokeGrant::grant(
        plan,
        "operator:test-harness",
        "run one bounded live repair smoke",
        plan.effective_budget(),
    )
    .unwrap_or_else(|diagnostics| panic!("operator grant refused: {diagnostics:#?}"))
}

// ---------------------------------------------------------------------------
// Target binding: the model cannot reach outside the project.
// ---------------------------------------------------------------------------

#[test]
fn smoke_target_binds_only_paths_inside_the_retained_project() {
    let fixture = Fixture::new();
    let project = fixture.project();

    let bound = target(&project);
    assert_eq!(bound.source_path(), SOURCE_PATH);
    assert_eq!(bound.repair_target(), TARGET);
    assert_eq!(bound.project_revision(), project.project_revision());

    for rejected in [
        "/etc/passwd",
        "../outside.spx",
        "src/../../escape.spx",
        "src/missing.spx",
        "src/app.txt",
        "C:/windows/app.spx",
    ] {
        assert!(
            LiveRepairSmokeTarget::bind(
                &project,
                rejected,
                AGENT_ID,
                STEP_ID,
                TARGET,
                OBSERVED_FAILURE
            )
            .is_err(),
            "{rejected} must not be selectable as a smoke source"
        );
    }
}

#[test]
fn smoke_target_refuses_a_repair_target_the_project_does_not_declare() {
    let fixture = Fixture::new();
    let project = fixture.project();
    assert!(LiveRepairSmokeTarget::bind(
        &project,
        SOURCE_PATH,
        AGENT_ID,
        STEP_ID,
        "fixture.repair.value.that.does.not.exist",
        OBSERVED_FAILURE
    )
    .is_err());
}

#[test]
fn smoke_target_fails_closed_when_the_checked_source_drifts() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let bound = target(&project);
    bound
        .require_unchanged(&project)
        .expect("the freshly bound target matches its own revision");

    let original = fs::read_to_string(fixture.source_path()).unwrap();
    let mutated = original.replacen(
        "@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    0\n}",
        "@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    5\n}",
        1,
    );
    assert_ne!(mutated, original, "the drift edit must change the source");
    fs::write(fixture.source_path(), &mutated).unwrap();

    let drifted = fixture.project();
    assert!(
        bound.require_unchanged(&drifted).is_err(),
        "a plan bound to earlier source bytes must not run against drifted source"
    );
}

#[test]
fn smoke_target_round_trips_through_its_canonical_document() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let bound = target(&project);
    let replayed = LiveRepairSmokeTarget::replay(bound.digest(), bound.to_json().as_bytes())
        .expect("a canonical target document replays");
    assert_eq!(replayed, bound);

    let tampered = bound.to_json().replace(OBSERVED_FAILURE, "fixture.other");
    assert!(LiveRepairSmokeTarget::replay(bound.digest(), tampered.as_bytes()).is_err());
}

// ---------------------------------------------------------------------------
// Plan: the budget is derived, never asserted.
// ---------------------------------------------------------------------------

#[test]
fn smoke_plan_derives_its_effective_budget_and_bounds_its_turns() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);

    let plan = plan_with_turns(&project, &binding, 2);
    assert_eq!(plan.expected_turns(), 2);
    assert_eq!(plan.model_binding_digest(), binding.digest());
    assert_eq!(plan.provider_id(), "fake.local");
    assert!(
        plan.effective_budget().max_cost_micros > 0,
        "the fixture deployment admits a paid attempt"
    );
    assert!(
        plan.to_json().contains("\"dispatch_authority\":false"),
        "a plan document states plainly that it is not authority to dispatch"
    );

    assert!(
        LiveRepairSmokePlan::bind(
            target(&project),
            &binding,
            ModelBudgetLimits::unbounded(),
            1
        )
        .is_err(),
        "a one-turn smoke cannot demonstrate the wrong-then-corrected loop"
    );
    assert!(
        LiveRepairSmokePlan::bind(
            target(&project),
            &binding,
            ModelBudgetLimits::unbounded(),
            999
        )
        .is_err(),
        "a smoke is bounded, not open-ended"
    );
}

#[test]
fn smoke_plan_refuses_a_turn_count_the_effective_call_ceiling_cannot_carry() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let narrowed = ModelBudgetLimits {
        max_calls: 2,
        ..ModelBudgetLimits::unbounded()
    };
    assert!(LiveRepairSmokePlan::bind(target(&project), &binding, narrowed, 2).is_ok());
    assert!(
        LiveRepairSmokePlan::bind(target(&project), &binding, narrowed, 3).is_err(),
        "the invocation ceiling narrows the plan and the plan must honour it"
    );
}

#[test]
fn smoke_plan_round_trips_through_its_canonical_document() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let replayed = LiveRepairSmokePlan::replay(plan.digest(), plan.to_json().as_bytes())
        .expect("a canonical plan document replays");
    assert_eq!(replayed.digest(), plan.digest());
    assert_eq!(replayed.expected_turns(), plan.expected_turns());
    assert_eq!(replayed.target(), plan.target());
    assert_eq!(replayed.effective_budget(), plan.effective_budget());
}

// ---------------------------------------------------------------------------
// Preflight: the documented route that a fresh operator can always run.
// ---------------------------------------------------------------------------

#[test]
fn preflight_without_an_operator_grant_is_not_ready_and_dispatches_nothing() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);

    let preflight = plan.preflight(&project).expect("preflight renders");
    assert!(
        !preflight.ready(),
        "an unauthorized live smoke is planned, not ready"
    );
    assert_eq!(
        preflight.blocking().map(|entry| entry.id()),
        Some("operator_grant_present"),
        "the missing operator grant is the blocking prerequisite"
    );
    let document = preflight.to_json();
    assert!(document.contains("\"dispatched\":false"));
    assert!(document.contains("\"provider_dispatch_count\":0"));
    assert!(document.contains("\"credentials_read\":false"));
    assert!(document.contains("\"network_observation\":false"));
    assert!(document.contains("\"source_mutation\":false"));
    assert!(document.contains("\"publication_authority\":false"));

    // The four facts a preflight *can* establish without a grant all hold.
    for id in [
        "retained_source_bytes_unchanged",
        "repair_target_resolves_in_the_retained_project",
        "effective_budget_admits_the_expected_turns",
        "provider_adapter_selection_is_bound",
    ] {
        let entry = preflight
            .prerequisites()
            .iter()
            .find(|entry| entry.id() == id)
            .unwrap_or_else(|| panic!("{id} is reported"));
        assert!(entry.satisfied(), "{id} must hold for the fixture");
    }
}

#[test]
fn preflight_with_the_matching_operator_grant_is_ready() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let grant = grant_for(&plan);

    let preflight = plan
        .authorized_preflight(&project, &grant)
        .expect("preflight renders");
    assert!(preflight.ready(), "{}", preflight.to_json());
    assert!(preflight.blocking().is_none());
    assert!(
        preflight.to_json().contains("\"dispatched\":false"),
        "even a ready preflight has still dispatched nothing"
    );
}

#[test]
fn preflight_reports_drifted_source_rather_than_silently_proceeding() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let grant = grant_for(&plan);

    let original = fs::read_to_string(fixture.source_path()).unwrap();
    fs::write(
        fixture.source_path(),
        original.replacen(
            "@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    0\n}",
            "@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    3\n}",
            1,
        ),
    )
    .unwrap();
    let drifted = fixture.project();

    let preflight = plan
        .authorized_preflight(&drifted, &grant)
        .expect("preflight renders");
    assert!(!preflight.ready());
    assert_eq!(
        preflight.blocking().map(|entry| entry.id()),
        Some("retained_source_bytes_unchanged")
    );
}

// ---------------------------------------------------------------------------
// Operator grant: a grant for plan A never authorizes plan B.
// ---------------------------------------------------------------------------

#[test]
fn an_operator_grant_for_one_plan_does_not_authorize_another() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan_a = plan_with_turns(&project, &binding, 2);
    let plan_b = plan_with_turns(&project, &binding, 3);
    assert_ne!(
        plan_a.digest(),
        plan_b.digest(),
        "the two plans must be distinguishable"
    );

    let grant = grant_for(&plan_a);
    assert!(AuthorizedLiveRepairSmoke::authorize(&plan_a, &grant).is_ok());
    assert!(
        AuthorizedLiveRepairSmoke::authorize(&plan_b, &grant).is_err(),
        "approval for plan A must not authorize spending on plan B"
    );

    let preflight_b = plan_b
        .authorized_preflight(&project, &grant)
        .expect("preflight renders");
    assert!(!preflight_b.ready());
    assert_eq!(
        preflight_b.blocking().map(|entry| entry.id()),
        Some("operator_grant_binds_this_exact_plan")
    );
}

#[test]
fn an_operator_grant_may_narrow_but_never_widen_the_effective_ceiling() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let effective = plan.effective_budget();

    let narrowed = ModelBudgetLimits {
        max_cost_micros: effective.max_cost_micros / 2,
        ..effective
    };
    let narrow_grant = OperatorLiveSmokeGrant::grant(&plan, "operator:test", "narrow", narrowed)
        .expect("narrowing is always permitted");
    let authorized = AuthorizedLiveRepairSmoke::authorize(&plan, &narrow_grant).unwrap();
    assert_eq!(
        authorized.effective_budget().max_cost_micros,
        narrowed.max_cost_micros,
        "the intersection takes the operator's tighter bound"
    );

    let widened = ModelBudgetLimits {
        max_cost_micros: effective.max_cost_micros.saturating_add(1),
        ..effective
    };
    assert!(
        OperatorLiveSmokeGrant::grant(&plan, "operator:test", "widen", widened).is_err(),
        "an operator cannot approve more than the source and deployment admit"
    );

    let more_calls = ModelBudgetLimits {
        max_calls: effective.max_calls.saturating_add(1),
        ..effective
    };
    assert!(
        OperatorLiveSmokeGrant::grant(&plan, "operator:test", "widen calls", more_calls).is_err()
    );
}

#[test]
fn an_operator_grant_round_trips_and_refuses_tampered_bytes() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let grant = grant_for(&plan);

    let replayed = OperatorLiveSmokeGrant::replay(grant.digest(), grant.to_json().as_bytes())
        .expect("a canonical grant replays");
    assert_eq!(replayed, grant);

    let tampered = grant
        .to_json()
        .replace("operator:test-harness", "operator:someone-else");
    assert!(OperatorLiveSmokeGrant::replay(grant.digest(), tampered.as_bytes()).is_err());
}

// ---------------------------------------------------------------------------
// Record: failure is a valid recorded result, overspend is not recordable.
// ---------------------------------------------------------------------------

#[test]
fn a_provider_failure_is_a_valid_recorded_smoke_result() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let authorized = AuthorizedLiveRepairSmoke::authorize(&plan, &grant_for(&plan)).unwrap();

    let record = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::ProviderFailed {
            turns: 1,
            terminal: "provider_unavailable".to_owned(),
        },
        LiveRepairSmokeUsage {
            attempts: 1,
            replayed_attempts: 0,
            tokens_in: Some(120),
            tokens_out: Some(0),
            cost_micros: 100,
        },
    )
    .expect("a failed live smoke records normally");
    assert!(!record.outcome().succeeded());
    assert_eq!(record.newly_dispatched_attempts(), 1);
    assert!(record.to_json().contains("\"succeeded\":false"));
    assert!(record
        .to_json()
        .contains("\"one_local_operator_run_is_not_hosted_ci_or_production_support\""));
}

#[test]
fn a_record_cannot_claim_usage_beyond_what_the_operator_authorized() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let authorized = AuthorizedLiveRepairSmoke::authorize(&plan, &grant_for(&plan)).unwrap();
    let ceiling = authorized.effective_budget();

    let over_cost = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::NotRepaired {
            turns: 2,
            rejections: 2,
        },
        LiveRepairSmokeUsage {
            attempts: 2,
            replayed_attempts: 0,
            tokens_in: None,
            tokens_out: None,
            cost_micros: ceiling.max_cost_micros.saturating_add(1),
        },
    );
    assert!(over_cost.is_err(), "an overspending record is not evidence");

    let over_calls = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::NotRepaired {
            turns: 2,
            rejections: 2,
        },
        LiveRepairSmokeUsage {
            attempts: ceiling.max_calls.saturating_add(1),
            replayed_attempts: 0,
            tokens_in: None,
            tokens_out: None,
            cost_micros: 0,
        },
    );
    assert!(over_calls.is_err());
}

#[test]
fn a_resumed_smoke_records_replayed_work_without_a_second_dispatch() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let authorized = AuthorizedLiveRepairSmoke::authorize(&plan, &grant_for(&plan)).unwrap();

    let interrupted = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::Cancelled { turns: 1 },
        LiveRepairSmokeUsage {
            attempts: 1,
            replayed_attempts: 0,
            tokens_in: None,
            tokens_out: None,
            cost_micros: 10,
        },
    )
    .expect("an interrupted smoke records");
    assert_eq!(interrupted.newly_dispatched_attempts(), 1);

    let resumed = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::NotRepaired {
            turns: 2,
            rejections: 2,
        },
        LiveRepairSmokeUsage {
            attempts: 2,
            replayed_attempts: 1,
            tokens_in: None,
            tokens_out: None,
            cost_micros: 20,
        },
    )
    .expect("a resumed smoke records");
    assert_eq!(
        resumed.newly_dispatched_attempts(),
        1,
        "the replayed first attempt must not count as a second dispatch"
    );
    assert_eq!(resumed.usage().attempts, 2);
    assert!(resumed
        .to_json()
        .contains("\"newly_dispatched_attempts\":1"));

    let impossible = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::Cancelled { turns: 1 },
        LiveRepairSmokeUsage {
            attempts: 1,
            replayed_attempts: 2,
            tokens_in: None,
            tokens_out: None,
            cost_micros: 0,
        },
    );
    assert!(
        impossible.is_err(),
        "a record cannot replay more attempts than it made"
    );
}

#[test]
fn a_repaired_smoke_record_binds_the_exact_corrected_candidate() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan = plan_with_turns(&project, &binding, 2);
    let authorized = AuthorizedLiveRepairSmoke::authorize(&plan, &grant_for(&plan)).unwrap();

    let (_review, preview) = review_for(&project, 7);
    let candidate_digest = preview.candidate().candidate_digest().to_owned();

    let record = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::Repaired {
            turns: 2,
            rejections: 1,
            candidate_digest: candidate_digest.clone(),
        },
        LiveRepairSmokeUsage {
            attempts: 2,
            replayed_attempts: 0,
            tokens_in: Some(200),
            tokens_out: Some(40),
            cost_micros: 900,
        },
    )
    .expect("a successful live smoke records");
    assert!(record.outcome().succeeded());
    assert!(
        record.to_json().contains(&candidate_digest),
        "the record names the exact corrected candidate"
    );
    assert!(record.to_json().contains("\"rejections\":1"));

    assert!(
        LiveRepairSmokeRecord::record(
            &authorized,
            LiveRepairSmokeOutcome::Repaired {
                turns: 2,
                rejections: 2,
                candidate_digest: candidate_digest.clone(),
            },
            LiveRepairSmokeUsage::default(),
        )
        .is_err(),
        "a repair cannot have rejected every one of its own turns"
    );
    assert!(
        LiveRepairSmokeRecord::record(
            &authorized,
            LiveRepairSmokeOutcome::Repaired {
                turns: 2,
                rejections: 1,
                candidate_digest: "not-a-candidate-digest".to_owned(),
            },
            LiveRepairSmokeUsage::default(),
        )
        .is_err(),
        "a record cannot name a candidate that is not a canonical digest"
    );
}

#[test]
fn a_record_from_one_plan_is_not_evidence_for_another() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let binding = model_binding(&project);
    let plan_a = plan_with_turns(&project, &binding, 2);
    let plan_b = plan_with_turns(&project, &binding, 3);
    let authorized = AuthorizedLiveRepairSmoke::authorize(&plan_a, &grant_for(&plan_a)).unwrap();

    let record = LiveRepairSmokeRecord::record(
        &authorized,
        LiveRepairSmokeOutcome::BudgetExhausted { turns: 2 },
        LiveRepairSmokeUsage {
            attempts: 2,
            replayed_attempts: 0,
            tokens_in: None,
            tokens_out: None,
            cost_micros: 5,
        },
    )
    .unwrap();
    assert!(record.verify_for(&plan_a).is_ok());
    assert!(record.verify_for(&plan_b).is_err());

    let replayed = LiveRepairSmokeRecord::replay(record.digest(), record.to_json().as_bytes())
        .expect("a canonical record replays");
    assert_eq!(replayed, record);
}

// ---------------------------------------------------------------------------
// Review and approval: default runs change nothing, and approval binds one
// exact candidate.
// ---------------------------------------------------------------------------

fn review_for(
    project: &Arc<ProjectRevision>,
    replacement: i64,
) -> (RepairCandidateReview, OfflineRepairPreview) {
    let envelope = OfflineRepairEnvelope::new(Arc::clone(project), TARGET)
        .unwrap_or_else(|diagnostics| panic!("repair envelope refused: {diagnostics:#?}"));
    let preview = envelope
        .preview(replacement, false)
        .unwrap_or_else(|diagnostics| panic!("repair preview refused: {diagnostics:#?}"));
    let validations = [
        RepairValidationOutcome::new(
            "fixture.tests.repair_value_returns_seven",
            RepairValidationStatus::Passed,
            "the checked oracle accepted the corrected candidate",
        )
        .unwrap(),
        RepairValidationOutcome::new(
            "fixture.tests.unrelated_property",
            RepairValidationStatus::Skipped,
            "not exercised by this repair",
        )
        .unwrap(),
    ];
    let blind_spots = vec![
        "no_runtime_or_backend_execution_evidence".to_owned(),
        "no_external_consumer_compatibility_assessment".to_owned(),
    ];
    let review = RepairCandidateReview::derive(
        preview.candidate(),
        TARGET,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        &validations,
        &blind_spots,
    )
    .unwrap_or_else(|diagnostics| panic!("repair review refused: {diagnostics:#?}"));
    (review, preview)
}

#[test]
fn a_repair_review_exports_diff_impact_validations_and_blind_spots_without_touching_source() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let before = fs::read(fixture.source_path()).unwrap();

    let (review, _preview) = review_for(&project, 7);
    assert_eq!(review.repair_target(), TARGET);
    assert_eq!(review.changed_paths(), [SOURCE_PATH.to_owned()]);
    assert_eq!(review.blind_spots().len(), 2);
    assert_eq!(review.validations().len(), 2);
    assert!(
        !review.all_validations_passed(),
        "a skipped validation is not a pass"
    );
    assert_ne!(
        review.source_review_digest(),
        review.semantic_delta_digest()
    );
    assert!(review.to_json().contains("\"publication_authority\":false"));
    assert!(review.to_json().contains("\"source_mutation\":false"));

    assert_eq!(
        fs::read(fixture.source_path()).unwrap(),
        before,
        "a default reviewed run leaves authoritative source untouched"
    );
    assert!(
        !fixture.root.join(".git").exists(),
        "a default reviewed run creates no Git state"
    );

    let replayed = RepairCandidateReview::replay(review.digest(), review.to_json().as_bytes())
        .expect("a canonical review replays");
    assert_eq!(replayed, review);
}

#[test]
fn approval_for_candidate_a_cannot_publish_candidate_b() {
    let fixture = Fixture::new();
    let project = fixture.project();

    let (review_a, preview_a) = review_for(&project, 7);
    let (_review_b, preview_b) = review_for(&project, 9);
    let candidate_a = preview_a.candidate();
    let candidate_b = preview_b.candidate();
    assert_ne!(
        candidate_a.candidate_digest(),
        candidate_b.candidate_digest(),
        "the two repairs must produce distinguishable candidates"
    );

    // The approving session hands over canonical bytes; the publishing session
    // re-derives the approval rather than trusting an in-process object.
    let approval = RepairCandidateApproval::approve(&review_a, "reviewer:test-harness")
        .unwrap_or_else(|diagnostics| panic!("approval refused: {diagnostics:#?}"));
    let carried = RepairCandidateApproval::replay(approval.digest(), approval.to_json().as_bytes())
        .expect("a canonical approval crosses the session boundary");
    assert_eq!(carried, approval);

    carried
        .require_candidate(candidate_a)
        .expect("the approval names candidate A");
    assert!(
        carried.require_candidate(candidate_b).is_err(),
        "approval for candidate A must not admit candidate B"
    );

    let before = fs::read(fixture.source_path()).unwrap();
    let published = prepare_approved_repair_publication(
        &carried,
        candidate_b,
        &fixture.root,
        &fixture.manifest(),
        project.workspace_revision(),
    );
    assert!(
        published.is_err(),
        "the publication route must refuse the unapproved candidate"
    );
    assert_eq!(
        fs::read(fixture.source_path()).unwrap(),
        before,
        "a refused publication leaves authoritative source untouched"
    );
}

#[test]
fn an_approval_is_a_distinct_act_from_deriving_a_review() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let (review, preview) = review_for(&project, 7);
    let candidate = preview.candidate();

    // Holding a review grants nothing: there is no route from a review alone to
    // the publication boundary, only from an approval that names the candidate.
    let approval = RepairCandidateApproval::approve(&review, "reviewer:test-harness").unwrap();
    assert_eq!(approval.candidate_digest(), candidate.candidate_digest());
    assert_eq!(approval.review_digest(), review.digest());
    assert!(approval
        .to_json()
        .contains("\"review_and_approval_are_distinct_acts\""));

    let tampered = approval
        .to_json()
        .replace("reviewer:test-harness", "reviewer:not-this-one");
    assert!(RepairCandidateApproval::replay(approval.digest(), tampered.as_bytes()).is_err());
}
