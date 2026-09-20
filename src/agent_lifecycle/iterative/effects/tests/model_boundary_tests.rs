use super::*;

struct ParityModelHandler {
    proposal: String,
    calls: usize,
    malformed: bool,
}

impl crate::agent_lifecycle::iterative::model::ModelHostHandler for ParityModelHandler {
    fn dispatch(
        &mut self,
        request: &crate::agent_lifecycle::iterative::model::ModelHostRequest,
        sink: &mut crate::agent_lifecycle::iterative::model::ModelResponseSink,
    ) -> Result<(), crate::agent_lifecycle::iterative::model::ModelHostError> {
        assert_eq!(request.attempt(), 0);
        assert!(!request.context().is_empty());
        assert!(!request.proposal_schema_digest().is_empty());
        self.calls += 1;
        if self.malformed {
            sink.write(&[0xff])
        } else {
            sink.write(self.proposal.as_bytes())
        }
        .map_err(|_| crate::agent_lifecycle::iterative::model::ModelHostError::Failed)
    }
}

fn model_target_run_on(
    compiled: &CompiledTypedEffects,
    backend: crate::agent_lifecycle::authorization::StageBackend<'_>,
    limits: crate::agent_lifecycle::iterative::model::ModelLimits,
    cancellation: &AgentCancellation,
    malformed: bool,
) -> (
    Result<TargetEffectRun, Vec<Diagnostic>>,
    Vec<Vec<u8>>,
    Vec<crate::agent_lifecycle::iterative::model::ModelEvidence>,
    crate::agent_lifecycle::iterative::model::ModelAccounting,
    usize,
    ParityTargetHandler,
) {
    let proposal = crate::agent_lifecycle::tests::proposal(&compiled.lifecycle.inner, "1", "0");
    let mut model_handler = ParityModelHandler {
        proposal,
        calls: 0,
        malformed,
    };
    let binding = crate::agent_lifecycle::iterative::model::ModelSourceBinding::new(
        "fixture.agent.model.target-parity",
    )
    .unwrap();
    let mut source = crate::agent_lifecycle::iterative::model::TargetModelSource::new(
        binding,
        limits,
        cancellation,
        &mut model_handler,
    );
    let mut target = ParityTargetHandler {
        calls: 0,
        request_wires: Vec::new(),
    };
    let run = compiled.run_target_live_on(
        &LifecycleTask {
            objective: vec![],
            budget: 10,
        },
        &mut source,
        &mut target,
        IterativeBudget::default(),
        budgets(),
        cancellation,
        backend,
    );
    let requests = source.request_wires().to_vec();
    let evidence = source.evidence().to_vec();
    let accounting = source.accounting();
    drop(source);
    (
        run,
        requests,
        evidence,
        accounting,
        model_handler.calls,
        target,
    )
}

fn model_limits() -> crate::agent_lifecycle::iterative::model::ModelLimits {
    crate::agent_lifecycle::iterative::model::ModelLimits {
        max_calls: 4,
        max_request_bytes: 64 * 1024,
        max_response_bytes: 16 * 1024,
        max_total_bytes: 96 * 1024,
        max_fuel: 4,
    }
}

#[test]
fn model_and_effect_host_boundaries_replay_identically_across_stage_backends() {
    if !target_backend_tools_available() {
        eprintln!("skipping target model bridge: clang or node unavailable");
        return;
    }
    let module_source = typed_effect_source();
    let compiled = compile_from_source(&module_source);
    let cancellation = AgentCancellation::new();
    let expected = model_target_run_on(
        &compiled,
        crate::agent_lifecycle::authorization::StageBackend::Interpreter,
        model_limits(),
        &cancellation,
        false,
    );
    let expected_run = expected.0.as_ref().unwrap();
    assert_eq!(expected_run.lifecycle().status(), IterativeStatus::Complete);
    assert_eq!((expected.4, expected.5.calls), (3, 3));
    assert_eq!(expected.1.len(), 3);
    assert_eq!(expected.2.len(), 3);
    assert_eq!(expected.3.calls(), 3);
    assert_eq!(
        expected
            .2
            .iter()
            .map(|evidence| evidence.grant_id())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3,
        "per-turn model grants must be distinct"
    );
    for (wire, evidence) in expected.1.iter().zip(&expected.2) {
        crate::agent_lifecycle::iterative::model::ModelEvidence::decode(&evidence.canonical_wire())
            .unwrap()
            .replay_wire(wire)
            .unwrap();
        let mut forged_request = wire.clone();
        *forged_request.last_mut().unwrap() ^= 1;
        assert!(evidence.replay_wire(&forged_request).is_err());
        let mut forged_evidence = evidence.canonical_wire();
        *forged_evidence.last_mut().unwrap() ^= 1;
        assert!(
            crate::agent_lifecycle::iterative::model::ModelEvidence::decode(&forged_evidence)
                .is_err()
        );
    }

    for (label, backend) in [
        (
            "native -O0",
            crate::agent_lifecycle::authorization::StageBackend::Native,
        ),
        (
            "native -O2",
            crate::agent_lifecycle::authorization::StageBackend::NativeAtOptimization("-O2"),
        ),
        (
            "Core Wasm",
            crate::agent_lifecycle::authorization::StageBackend::Wasm {
                source: &module_source,
            },
        ),
    ] {
        let cancellation = AgentCancellation::new();
        let actual = model_target_run_on(&compiled, backend, model_limits(), &cancellation, false);
        let actual_run = actual
            .0
            .as_ref()
            .unwrap_or_else(|errors| panic!("{label}: {errors:?}"));
        assert_eq!(
            actual_run.lifecycle().status(),
            expected_run.lifecycle().status(),
            "{label}"
        );
        assert_eq!(
            actual_run.lifecycle().value(),
            expected_run.lifecycle().value(),
            "{label}"
        );
        assert_eq!(actual.1, expected.1, "{label}: model requests");
        assert_eq!(actual.2, expected.2, "{label}: model evidence");
        assert_eq!(actual.3, expected.3, "{label}: model accounting");
        assert_eq!(
            actual.5.request_wires, expected.5.request_wires,
            "{label}: effect requests"
        );
        assert_eq!(
            actual_run.accounting(),
            expected_run.accounting(),
            "{label}: effect accounting"
        );
    }
}

#[test]
fn model_boundary_refuses_fuel_and_malformed_response_before_effect_dispatch() {
    if !target_backend_tools_available() {
        eprintln!("skipping target model refusal parity: clang or node unavailable");
        return;
    }
    let module_source = typed_effect_source();
    let compiled = compile_from_source(&module_source);
    for (limits, malformed, expected) in [
        (
            crate::agent_lifecycle::iterative::model::ModelLimits {
                max_fuel: 0,
                ..model_limits()
            },
            false,
            crate::agent_lifecycle::iterative::model::ModelSettlement::FuelExhausted,
        ),
        (
            model_limits(),
            true,
            crate::agent_lifecycle::iterative::model::ModelSettlement::MalformedResponse,
        ),
    ] {
        let cancellation = AgentCancellation::new();
        let reference = model_target_run_on(
            &compiled,
            crate::agent_lifecycle::authorization::StageBackend::Interpreter,
            limits,
            &cancellation,
            malformed,
        );
        assert!(reference.0.is_err());
        assert_eq!(reference.2.len(), 1);
        assert_eq!(reference.2[0].settlement(), expected);
        assert_eq!(reference.2[0].dispatched(), malformed);
        assert_eq!(reference.4, usize::from(malformed));
        assert_eq!(reference.5.calls, 0);

        for (label, backend) in [
            (
                "native -O0",
                crate::agent_lifecycle::authorization::StageBackend::Native,
            ),
            (
                "native -O2",
                crate::agent_lifecycle::authorization::StageBackend::NativeAtOptimization("-O2"),
            ),
            (
                "Core Wasm",
                crate::agent_lifecycle::authorization::StageBackend::Wasm {
                    source: &module_source,
                },
            ),
        ] {
            let cancellation = AgentCancellation::new();
            let actual = model_target_run_on(&compiled, backend, limits, &cancellation, malformed);
            assert_eq!(
                actual.0.as_ref().err().map(|errors| errors
                    .iter()
                    .map(|error| (&error.code, &error.message))
                    .collect::<Vec<_>>()),
                reference.0.as_ref().err().map(|errors| errors
                    .iter()
                    .map(|error| (&error.code, &error.message))
                    .collect::<Vec<_>>()),
                "{label}: model refusal"
            );
            assert_eq!(actual.1, reference.1, "{label}: model requests");
            assert_eq!(actual.2, reference.2, "{label}: model evidence");
            assert_eq!(actual.3, reference.3, "{label}: model accounting");
            assert_eq!(actual.4, reference.4, "{label}: model calls");
            assert_eq!(actual.5.calls, 0, "{label}: effects must not dispatch");
            assert_eq!(
                actual.5.request_wires, reference.5.request_wires,
                "{label}: effect requests"
            );
        }
    }

    let cancellation = AgentCancellation::new();
    cancellation.cancel();
    let reference = model_target_run_on(
        &compiled,
        crate::agent_lifecycle::authorization::StageBackend::Interpreter,
        model_limits(),
        &cancellation,
        false,
    );
    assert_eq!(
        reference.0.unwrap().lifecycle().status(),
        IterativeStatus::Cancelled
    );
    assert!(reference.1.is_empty());
    assert!(reference.2.is_empty());
    assert_eq!(reference.3, Default::default());
    assert_eq!((reference.4, reference.5.calls), (0, 0));
    for (label, backend) in [
        (
            "native -O0",
            crate::agent_lifecycle::authorization::StageBackend::Native,
        ),
        (
            "native -O2",
            crate::agent_lifecycle::authorization::StageBackend::NativeAtOptimization("-O2"),
        ),
        (
            "Core Wasm",
            crate::agent_lifecycle::authorization::StageBackend::Wasm {
                source: &module_source,
            },
        ),
    ] {
        let cancellation = AgentCancellation::new();
        cancellation.cancel();
        let actual = model_target_run_on(&compiled, backend, model_limits(), &cancellation, false);
        assert_eq!(
            actual.0.unwrap().lifecycle().status(),
            IterativeStatus::Cancelled,
            "{label}"
        );
        assert_eq!(actual.1, reference.1, "{label}: model requests");
        assert_eq!(actual.2, reference.2, "{label}: model evidence");
        assert_eq!(actual.3, reference.3, "{label}: model accounting");
        assert_eq!(actual.4, reference.4, "{label}: model calls");
        assert_eq!(actual.5.calls, reference.5.calls, "{label}: effect calls");
        assert_eq!(
            actual.5.request_wires, reference.5.request_wires,
            "{label}: effect requests"
        );
    }
}
