//! Local frozen iterative lifecycle parity through the production loop kernel.
//!
//! The explicit test selector changes all four deterministic stage dispatches,
//! including authorization. Proposal admission, fresh grant binding/consumption,
//! injected reads, transitions and settlement use the existing driver unchanged.
//! Native/Wasm do not meter interpreter fuel or expose its cleanup-event trace;
//! neither metric nor byte-identical cross-engine evidence is claimed here.
//! This adds no public backend selector, live provider or checkpoint support.

use super::*;
use crate::agent_lifecycle::authorization::StageBackend;
use crate::agent_lifecycle::iterative::driver::{EffectContext, IterativeDriver};
use crate::agent_lifecycle::iterative::{
    compile_agent_lifecycle_v2, CompiledIterativeLifecycle, IterativeBudget, IterativeRun,
    IterativeStatus,
};

fn source() -> String {
    let start = MODULE.find("@id(\"fixture.agent.fn.reduce\")").unwrap();
    let end = MODULE[start..].find("@id(\"app.main\")").unwrap() + start;
    let reducer = r#"
@id("fixture.agent.type.step")
variant Step {
    @id("fixture.agent.step.continue") Continue {
        @id("fixture.agent.step.continue.objective") objective: Bytes,
        @id("fixture.agent.step.continue.budget") budget: i64,
        @id("fixture.agent.step.continue.epoch") epoch: i64,
    },
    @id("fixture.agent.step.complete") Complete {
        @id("fixture.agent.step.complete.summary") summary: Bytes,
        @id("fixture.agent.step.complete.budget") budget: i64,
        @id("fixture.agent.step.complete.status") status: i64,
    },
    @id("fixture.agent.step.suspend") Suspend {
        @id("fixture.agent.step.suspend.objective") objective: Bytes,
        @id("fixture.agent.step.suspend.budget") budget: i64,
        @id("fixture.agent.step.suspend.epoch") epoch: i64,
    },
    @id("fixture.agent.step.fail") Fail {
        @id("fixture.agent.step.fail.code") code: i64,
    },
}
@id("fixture.agent.fn.reduce")
fn reduce(state: own State, budget: i64, urgent: bool, sequence: usize, outcome: own Outcome) -> Step {
    if state.epoch < 2 {
        Step::Continue { objective: outcome.value, budget: state.budget - budget, epoch: state.epoch + 1 }
    } else {
        Step::Complete { summary: outcome.value, budget: state.budget - budget, status: state.epoch }
    }
}
"#;
    format!("{}{}{}", &MODULE[..start], reducer, &MODULE[end..])
}

fn compile(source: &str) -> CompiledIterativeLifecycle {
    compile_agent_lifecycle_v2(
        source,
        "frozen-lifecycle-parity.spx",
        &DEFINITION.replace("RUNTIME", RUNTIME_V1),
        "fixture.agent.type.step",
    )
    .expect("checked iterative fixture")
}

fn proposals(compiled: &CompiledIterativeLifecycle) -> Vec<String> {
    let digest = compiled.proposal_schema().schema().digest();
    (1..=2).map(|sequence| format!(
        "{{\"schema\":\"semaprax.agent-proposal.v1\",\"agent_id\":\"fixture.agent\",\"proposal_schema_digest\":\"{digest}\",\"value\":{{\"fields\":{{\"fixture.agent.type.proposal.budget\":\"1\",\"fixture.agent.type.proposal.urgent\":false,\"fixture.agent.type.proposal.sequence\":\"{sequence}\"}}}}}}\n"
    )).collect()
}

fn task() -> LifecycleTask {
    LifecycleTask {
        objective: b"task".to_vec(),
        budget: 10,
    }
}

fn legs(source: &str) -> [(&str, StageBackend<'_>); 4] {
    [
        ("interpreter", StageBackend::Interpreter),
        ("native O0", StageBackend::Native),
        ("native O2", StageBackend::NativeAtOptimization("-O2")),
        ("Core Wasm", StageBackend::Wasm { source }),
    ]
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    stages: Vec<(&'static str, usize, usize)>,
    contexts: Vec<(usize, String, String, String, String)>,
    reads: Vec<(String, i64, Vec<u8>)>,
    transitions: Vec<(usize, String, String)>,
}

struct Probe<'a> {
    trace: Trace,
    cancellation: &'a AgentCancellation,
    cancel_on_read: bool,
}

impl IterativeDriver for Probe<'_> {
    fn before_stage(
        &mut self,
        role: &'static str,
        turn: usize,
        max_steps: usize,
    ) -> Result<(), Vec<Diagnostic>> {
        self.trace.stages.push((role, turn, max_steps));
        Ok(())
    }

    fn before_effect(&mut self, context: EffectContext<'_>) -> Result<(), Vec<Diagnostic>> {
        assert_eq!(context.turn, self.trace.reads.len());
        assert_eq!(
            context.authorization.binding(),
            authorization::binding(
                context.policy,
                context.state,
                context.proposal_canonical,
                &crate::hir::DeclarationId::new("fixture.agent.type.decision.granted"),
                context.authorization.seal(),
            )
        );
        self.trace.contexts.push((
            context.turn,
            context.policy.to_owned(),
            encode_value(context.state),
            context.proposal_canonical.to_owned(),
            context.authorization.binding().to_owned(),
        ));
        Ok(())
    }

    fn read(&mut self, request: &AuthorizedRequest) -> Result<Option<Vec<u8>>, Vec<Diagnostic>> {
        assert_eq!(request.budget(), 1);
        assert_eq!(request.seal(), b"AZ");
        assert_eq!(self.trace.contexts.last().unwrap().4, request.binding());
        assert!(self
            .trace
            .reads
            .iter()
            .all(|(binding, _, _)| binding != request.binding()));
        let turn = self.trace.reads.len() as u8;
        self.trace.reads.push((
            request.binding().to_owned(),
            request.budget(),
            request.seal().to_vec(),
        ));
        if self.cancel_on_read {
            self.cancellation.cancel();
        }
        // Binary data makes the real injected result observable in both the
        // next authorization's State and the final terminal Report.
        Ok(Some(vec![0, 255, turn]))
    }

    fn after_transition(
        &mut self,
        turn: usize,
        kind: &str,
        value: &RetainedValue,
    ) -> Result<(), Vec<Diagnostic>> {
        self.trace
            .transitions
            .push((turn, kind.to_owned(), encode_value(value)));
        Ok(())
    }
}

fn run(
    compiled: &CompiledIterativeLifecycle,
    proposals: &[String],
    budget: IterativeBudget,
    backend: StageBackend<'_>,
    cancelled: bool,
    cancel_on_read: bool,
) -> (IterativeRun, Trace) {
    let cancellation = AgentCancellation::new();
    if cancelled {
        cancellation.cancel();
    }
    let mut probe = Probe {
        trace: Trace::default(),
        cancellation: &cancellation,
        cancel_on_read,
    };
    let run = compiled
        .run_with_driver_on(
            &task(),
            proposals,
            &mut probe,
            budget,
            &cancellation,
            backend,
        )
        .unwrap_or_else(|errors| {
            panic!(
                "frozen lifecycle failed after {:?}: {errors:?}",
                probe.trace.stages.last()
            )
        });
    assert_eq!(run.effects(), probe.trace.reads.len());
    assert_eq!(run.iterations(), probe.trace.transitions.len());
    assert_eq!(run.stages().len(), probe.trace.stages.len());
    assert_eq!(
        run.authorization_bindings(),
        probe
            .trace
            .reads
            .iter()
            .map(|r| r.0.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        run.evidence_digest(),
        digest(
            b"semaprax.agent-iterative-evidence.v2\0",
            run.evidence().as_bytes()
        )
    );
    (run, probe.trace)
}

// Evidence really settles on each run, but its stage rows include backend-
// specific interpreter step counts. Compare all other evidence fields exactly;
// never normalize the actual artifact or advertise byte-identical evidence.
fn semantic_evidence(run: &IterativeRun) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(run.evidence()).unwrap();
    for row in value["stages"].as_array_mut().unwrap() {
        let row = row.as_array_mut().unwrap();
        assert_eq!(row.len(), 4);
        assert!(row[3].is_u64());
        row.pop();
    }
    value
}

fn assert_parity(expected: &(IterativeRun, Trace), actual: &(IterativeRun, Trace), leg: &str) {
    assert_eq!(actual.0.status(), expected.0.status(), "{leg}");
    assert_eq!(actual.0.value(), expected.0.value(), "{leg}");
    assert_eq!(actual.1, expected.1, "{leg}");
    assert_eq!(
        semantic_evidence(&actual.0),
        semantic_evidence(&expected.0),
        "{leg}"
    );
}

#[test]
fn frozen_lifecycle_completes_with_fresh_grants_and_real_read_results_on_every_backend() {
    if !native_wasm_tools_available() {
        eprintln!("local lifecycle parity requires clang and node");
        return;
    }
    let source = source();
    let compiled = compile(&source);
    let proposals = proposals(&compiled);
    let budget = IterativeBudget::default();
    let expected = run(
        &compiled,
        &proposals,
        budget,
        StageBackend::Interpreter,
        false,
        false,
    );
    assert_eq!(expected.0.status(), IterativeStatus::Complete);
    assert_eq!(
        (
            expected.0.iterations(),
            expected.0.effects(),
            expected.0.stages().len()
        ),
        (2, 2, 7)
    );
    assert_eq!(
        expected
            .1
            .stages
            .iter()
            .map(|s| (s.0, s.1))
            .collect::<Vec<_>>(),
        [
            ("initialize", 0),
            ("observe", 0),
            ("authorize", 0),
            ("reduce", 0),
            ("observe", 1),
            ("authorize", 1),
            ("reduce", 1),
        ]
    );
    assert_ne!(
        expected.0.authorization_bindings()[0],
        expected.0.authorization_bindings()[1]
    );
    assert_eq!(expected.1.transitions[0].1, "Continue");
    assert_eq!(expected.1.transitions[1].1, "Complete");
    assert_eq!(expected.1.contexts[1].2, expected.1.transitions[0].2);
    let RetainedValue::Record(report) = expected.0.value().unwrap() else {
        panic!("terminal report")
    };
    assert_eq!(
        report
            .fields
            .iter()
            .map(|f| f.value.clone())
            .collect::<Vec<_>>(),
        [
            RetainedValue::Bytes(vec![0, 255, 1]),
            RetainedValue::I64(8),
            RetainedValue::I64(2),
        ]
    );
    for (index, context) in expected.1.contexts.iter().enumerate() {
        assert_eq!(
            context.3,
            compiled
                .proposal_schema()
                .decode(&proposals[index])
                .unwrap()
                .canonical_json()
        );
    }
    // The production/default route retains exactly the old interpreter evidence.
    let cancellation = AgentCancellation::new();
    let mut probe = Probe {
        trace: Trace::default(),
        cancellation: &cancellation,
        cancel_on_read: false,
    };
    let ordinary = compiled
        .run_with_driver(&task(), &proposals, &mut probe, budget, &cancellation)
        .unwrap();
    assert_eq!(ordinary.evidence(), expected.0.evidence());
    assert_eq!(probe.trace, expected.1);
    for (leg, backend) in legs(&source).into_iter().skip(1) {
        let actual = run(&compiled, &proposals, budget, backend, false, false);
        assert_parity(&expected, &actual, leg);
        assert!(actual.0.stages().iter().all(|stage| stage.steps_used == 0));
    }
}

#[test]
fn frozen_lifecycle_negative_boundaries_agree_without_unbudgeted_or_malformed_dispatch() {
    if !native_wasm_tools_available() {
        eprintln!("local lifecycle parity requires clang and node");
        return;
    }
    let source = source();
    let compiled = compile(&source);
    let valid = proposals(&compiled);
    let budget = IterativeBudget::default();
    for (name, proposals, budget, cancelled, cancel_on_read, status, counts) in [
        (
            "cancel before initialize",
            valid.clone(),
            budget,
            true,
            false,
            IterativeStatus::Cancelled,
            (0, 0, 0),
        ),
        (
            "cancel after read",
            valid.clone(),
            budget,
            false,
            true,
            IterativeStatus::Cancelled,
            (0, 1, 3),
        ),
        (
            "malformed first proposal",
            vec!["{}".into()],
            budget,
            false,
            false,
            IterativeStatus::ModelFailed,
            (0, 0, 2),
        ),
        (
            "malformed next proposal",
            vec![valid[0].clone(), "{}".into()],
            budget,
            false,
            false,
            IterativeStatus::ModelFailed,
            (1, 1, 5),
        ),
        (
            "reserve reduce before read",
            valid.clone(),
            IterativeBudget {
                max_stages: 3,
                ..budget
            },
            false,
            false,
            IterativeStatus::BudgetExhausted,
            (0, 0, 3),
        ),
        (
            "iteration ceiling",
            valid.clone(),
            IterativeBudget {
                max_iterations: 1,
                ..budget
            },
            false,
            false,
            IterativeStatus::BudgetExhausted,
            (1, 1, 4),
        ),
    ] {
        let expected = run(
            &compiled,
            &proposals,
            budget,
            StageBackend::Interpreter,
            cancelled,
            cancel_on_read,
        );
        assert_eq!(expected.0.status(), status, "{name}");
        assert_eq!(
            (
                expected.0.iterations(),
                expected.0.effects(),
                expected.0.stages().len()
            ),
            counts,
            "{name}"
        );
        assert!(expected.0.value().is_none(), "{name}");
        for (leg, backend) in legs(&source).into_iter().skip(1) {
            let actual = run(
                &compiled,
                &proposals,
                budget,
                backend,
                cancelled,
                cancel_on_read,
            );
            assert_parity(&expected, &actual, &format!("{name}: {leg}"));
        }
    }
}

#[test]
fn interpreter_fuel_exhaustion_stays_explicitly_outside_cross_backend_parity() {
    let compiled = compile(&source());
    let run = run(
        &compiled,
        &proposals(&compiled),
        IterativeBudget {
            max_steps_per_stage: 1,
            ..IterativeBudget::default()
        },
        StageBackend::Interpreter,
        false,
        false,
    );
    assert_eq!(run.0.status(), IterativeStatus::BudgetExhausted);
    assert_eq!(
        (run.0.iterations(), run.0.effects(), run.0.stages().len()),
        (0, 0, 1)
    );
    assert_eq!(run.0.stages()[0].outcome(), "fuel_exhausted");
}
