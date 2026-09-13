//! Offline private-host repair uses the ordinary checked source/effect loop.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use super::typed_fixture;
use semaprax::agent_deployment::migrate_agent_definition_v1;
use semaprax::agent_lifecycle::iterative::compile_source_agent_lifecycle_v2;
use semaprax::agent_lifecycle::iterative::effects::{
    EffectArgument, EffectBudget, EffectOperation, EffectResult, EffectScalar,
};
use semaprax::agent_lifecycle::iterative::source_live::{SourceLivePolicy, SourceProposalPolicy};
use semaprax::agent_lifecycle::{CheckpointStore, CheckpointStoreError, LifecycleTask};
use semaprax::agent_runtime::AgentCancellation;
use semaprax::agent_runtime_v2::{
    bind_agent_runtime_v2_live, OfflineRepairEnvelope, OfflineRepairHandler,
    SourceModelAdapterIdentity,
};
use semaprax::execution_revision::ProgramRootRef;
use semaprax::live_invocation::{InvocationClock, SourceInvocationClock};
use semaprax::project::with_authenticated_project;
use semaprax::provider_adapter_sdk::fixture_adapters::{usage, ScriptedStreamingAdapter};
use semaprax::provider_adapter_sdk::{
    AdapterInvocationCapability, AdapterPoll, AdapterRefusal, AdapterRequest, ProviderAdapter,
    StreamingSourceProposalAdapter,
};

struct Clock;
impl InvocationClock for Clock {
    fn now_millis(&self) -> i64 {
        1
    }
}
impl SourceInvocationClock for Clock {
    fn clock_domain(&self) -> &str {
        "typed-offline-repair.v1"
    }
}

#[derive(Default)]
struct Store {
    documents: Vec<String>,
}
impl CheckpointStore for Store {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.documents.push(document.to_owned());
        Ok(())
    }
}

struct RecordingAdapter {
    inner: ScriptedStreamingAdapter,
    requests: Rc<RefCell<Vec<Vec<u8>>>>,
    starts: Rc<Cell<usize>>,
    required_feedback: Option<String>,
}
impl ProviderAdapter for RecordingAdapter {
    fn capabilities(&self) -> &semaprax::provider_adapter_sdk::AdapterCapabilities {
        self.inner.capabilities()
    }
    fn start(
        &mut self,
        capability: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        self.starts.set(self.starts.get() + 1);
        self.requests
            .borrow_mut()
            .push(request.request_bytes.clone());
        if self.required_feedback.as_ref().is_some_and(|feedback| {
            serde_json::from_slice::<serde_json::Value>(&request.request_bytes)
                .ok()
                .and_then(|prompt| prompt["previous_effect_hex"].as_str().map(str::to_owned))
                .as_deref()
                != Some(feedback)
        }) {
            return Err(AdapterRefusal("missing checked repair feedback".to_owned()));
        }
        self.inner.start(capability, request)
    }
    fn poll(&mut self) -> AdapterPoll {
        self.inner.poll()
    }
    fn cancel(&mut self, reason: &str) {
        self.inner.cancel(reason);
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

fn identity() -> SourceModelAdapterIdentity {
    SourceModelAdapterIdentity {
        provider_id: "fake.local".to_owned(),
        model_id: "fake-basic".to_owned(),
        adapter_identity: "scripted-streaming-adapter".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        provider_profile: "fixture".to_owned(),
    }
}

fn policy(binding: &semaprax::agent_runtime_v2::SourceModelBinding) -> SourceLivePolicy {
    SourceLivePolicy {
        deployment_binding: binding.digest().to_owned(),
        response_limit: binding.max_response_bytes(),
        ceiling: 2,
        reservation_units: 1,
        unit: "offline_repair_unit_v1".to_owned(),
        clock_domain: "typed-offline-repair.v1".to_owned(),
        initial_millis: 0,
        deadline_millis: 1_000,
        max_total_steps: 2_000_000,
        program_root: None,
    }
}

fn checkpoint_policy<'a>(
    binding: &'a semaprax::agent_runtime_v2::SourceModelBinding,
) -> SourceProposalPolicy<'a> {
    SourceProposalPolicy {
        deployment_binding: binding.digest(),
        response_limit: binding.max_response_bytes(),
        reservation_units: 1,
    }
}

fn feedback_code(diagnostics: &[semaprax::diagnostic::Diagnostic]) -> i64 {
    diagnostics
        .iter()
        .find_map(|diagnostic| {
            diagnostic
                .code
                .strip_prefix("SPX-G")
                .and_then(|code| code.parse::<i64>().ok())
        })
        .unwrap_or(583)
}

#[test]
fn offline_repair_keeps_candidate_diagnostics_private_and_feeds_checked_correction() {
    let fixture = typed_fixture();
    let source_path = fixture.0.join("src/app.spx");
    let source = std::fs::read_to_string(&source_path).unwrap();
    let source = source.replace("state.epoch < 3", "state.epoch < 2")
        + "\n@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    0\n}\n";
    assert_ne!(source, std::fs::read_to_string(&source_path).unwrap());
    std::fs::write(&source_path, source).unwrap();
    let disk_before = std::fs::read(&source_path).unwrap();

    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let (_, deployment) = migrate_agent_definition_v1(
            project.agent_definitions()[0]
                .definition()
                .canonical_source(),
            "fixture.offline.repair",
        )?;
        let compiled = compile_source_agent_lifecycle_v2(
            project.sources()[0].source(),
            project.sources()[0].path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        let runtime = bind_agent_runtime_v2_live(
            project.clone(),
            ProgramRootRef::V1(&root),
            root.program_root_digest(),
            "src/app.spx",
            "fixture.agent",
            "fixture.agent.type.step",
            "fixture.agent.type.proposal.sequence",
            operations(),
            &deployment,
            LifecycleTask {
                objective: b"repair the private candidate".to_vec(),
                budget: 12,
            },
            semaprax::agent_lifecycle::iterative::IterativeBudget::default(),
            EffectBudget {
                max_calls: 2,
                max_argument_bytes: 4096,
                max_result_bytes: 4096,
                max_total_bytes: 8192,
            },
        )?;
        assert!(OfflineRepairEnvelope::new(project.clone(), "fixture.missing").is_err());
        let denied_envelope = OfflineRepairEnvelope::new(project.clone(), "fixture.repair.value")?;
        assert!(OfflineRepairHandler::new(
            denied_envelope,
            "",
            "fixture.read.second",
            "read",
            "query",
            "value",
        )
        .is_err());
        let ambiguous_envelope =
            OfflineRepairEnvelope::new(project.clone(), "fixture.repair.value")?;
        assert!(OfflineRepairHandler::new(
            ambiguous_envelope,
            "fixture.read",
            "fixture.read",
            "read",
            "query",
            "value",
        )
        .is_err());
        let envelope = OfflineRepairEnvelope::new(project.clone(), "fixture.repair.value")?;
        assert!(envelope.preview(i64::MAX, false).is_err());
        let malformed_diagnostics = match envelope.preview(0, true) {
            Ok(_) => panic!("Bool main body is a malformed candidate"),
            Err(diagnostics) => diagnostics,
        };
        let expected_feedback = format!(
            "{{\"schema\":\"semaprax.agent-effect-fields.v1\",\"fields\":[[\"value\",\"{}\"]]}}\n",
            feedback_code(&malformed_diagnostics)
        )
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        let mut handler = OfflineRepairHandler::new(
            envelope,
            "fixture.read",
            "fixture.read.second",
            "read",
            "query",
            "value",
        )?;
        let documents = [
            ("0", false, "0", None),
            ("7", false, "1", Some(expected_feedback.clone())),
        ]
        .into_iter()
        .map(|(budget, urgent, sequence, required_feedback)| {
            (
                crate::agent_lifecycle_v1::proposal(
                    schema.schema().digest(),
                    budget,
                    urgent,
                    sequence,
                ),
                required_feedback,
            )
        })
        .collect::<Vec<_>>();
        let requests = Rc::new(RefCell::new(Vec::new()));
        let starts = Rc::new(Cell::new(0));
        let documents = RefCell::new(VecDeque::from(documents));
        let factory_requests = Rc::clone(&requests);
        let factory_starts = Rc::clone(&starts);
        let mut factory = move || {
            let (document, required_feedback) = documents.borrow_mut().pop_front().unwrap();
            Box::new(RecordingAdapter {
                inner: ScriptedStreamingAdapter::new(
                    document
                        .as_bytes()
                        .chunks(3)
                        .map(ToOwned::to_owned)
                        .collect(),
                    document.into_bytes(),
                    usage(1, 1, 0),
                    true,
                ),
                requests: Rc::clone(&factory_requests),
                starts: Rc::clone(&factory_starts),
                required_feedback,
            }) as Box<dyn ProviderAdapter>
        };
        let binding = runtime.source_model_binding(identity())?;
        let cancellation = AgentCancellation::new();
        let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut factory,
            AdapterInvocationCapability::grant("private offline repair fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
            checkpoint_policy(&binding),
        )?;
        let mut store = Store::default();
        let complete = runtime
            .run_live_bound_model_durable(
                &mut source,
                &mut handler,
                policy(&binding),
                &Clock,
                &cancellation,
                None,
                &mut store,
            )
            .map_err(|failure| failure.failure().diagnostics.clone())?;
        assert_eq!(complete.run().model_dispatches, 2);
        assert_eq!(complete.run().effect_dispatches, 2);
        assert_eq!(starts.get(), 2);
        assert_eq!(
            handler.rejection_count(),
            1,
            "latest candidate rejection: {:?}",
            handler
                .latest_rejection()
                .map(|rejection| rejection.diagnostics())
        );
        let rejection = handler
            .latest_rejection()
            .expect("malformed preview feedback");
        assert_eq!(rejection.replacement(), 0);
        assert!(rejection.bool_literal());
        assert!(rejection.feedback_code() > 0);
        assert_eq!(
            rejection.diagnostics()[0].code,
            malformed_diagnostics[0].code
        );
        assert_eq!(
            rejection.feedback_code(),
            feedback_code(&malformed_diagnostics)
        );
        let withheld_message = rejection.diagnostics()[0].message.clone();
        let preview = handler
            .latest_preview()
            .expect("corrected candidate preview");
        assert_eq!(preview.replacement(), 7);
        assert!(!preview.bool_literal());
        assert!(preview.source_review().contains("source_authority\":false"));
        assert!(preview.semantic_delta().contains("fixture.repair.value"));
        assert!(preview
            .impact_summary()
            .contains("publication_authority\":false"));
        assert!(preview
            .candidate()
            .revision()
            .sources()
            .iter()
            .any(|source| {
                source.path() == "src/app.spx"
                    && source
                        .source()
                        .contains("fn repair_value() -> i64\n{\n    7")
            }));
        let feedback_hex = format!(
            "{{\"schema\":\"semaprax.agent-effect-fields.v1\",\"fields\":[[\"value\",\"{}\"]]}}\n",
            rejection.feedback_code()
        )
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        assert_eq!(feedback_hex, expected_feedback);
        let prompt: serde_json::Value = serde_json::from_slice(&requests.borrow()[1]).unwrap();
        assert_eq!(
            prompt["previous_effect_hex"].as_str(),
            Some(feedback_hex.as_str())
        );
        let mut withheld = prompt;
        withheld["previous_effect_hex"] = serde_json::Value::Null;
        let mut guard = RecordingAdapter {
            inner: ScriptedStreamingAdapter::new(vec![], vec![], usage(0, 0, 0), true),
            requests: Rc::new(RefCell::new(Vec::new())),
            starts: Rc::new(Cell::new(0)),
            required_feedback: Some(feedback_hex.clone()),
        };
        assert!(guard
            .start(
                &AdapterInvocationCapability::grant("withheld feedback negative"),
                &AdapterRequest {
                    request_bytes: serde_json::to_vec(&withheld).unwrap(),
                    max_response_bytes: binding.max_response_bytes()
                },
            )
            .is_err());
        assert!(!String::from_utf8_lossy(&requests.borrow()[1]).contains(&withheld_message));
        assert!(store
            .documents
            .iter()
            .any(|document| document.contains("attempt_intent")));
        assert!(store
            .documents
            .last()
            .unwrap()
            .contains("\"kind\":\"terminal_snapshot\""));
        assert_eq!(std::fs::read(&source_path).unwrap(), disk_before);

        let checkpoint = store.documents.last().unwrap().clone();
        let (_, replay_deployment) = migrate_agent_definition_v1(
            project.agent_definitions()[0]
                .definition()
                .canonical_source(),
            "fixture.offline.repair",
        )?;
        let replay = bind_agent_runtime_v2_live(
            project.clone(),
            ProgramRootRef::V1(&root),
            root.program_root_digest(),
            "src/app.spx",
            "fixture.agent",
            "fixture.agent.type.step",
            "fixture.agent.type.proposal.sequence",
            operations(),
            &replay_deployment,
            LifecycleTask {
                objective: b"repair the private candidate".to_vec(),
                budget: 12,
            },
            semaprax::agent_lifecycle::iterative::IterativeBudget::default(),
            EffectBudget {
                max_calls: 2,
                max_argument_bytes: 4096,
                max_result_bytes: 4096,
                max_total_bytes: 8192,
            },
        )?;
        let replay_binding = replay.source_model_binding(identity())?;
        let constructed = Rc::new(Cell::new(false));
        let observed = Rc::clone(&constructed);
        let mut replay_factory = move || -> Box<dyn ProviderAdapter> {
            observed.set(true);
            panic!("a terminal repair checkpoint must not construct a provider adapter")
        };
        let mut replay_source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut replay_factory,
            AdapterInvocationCapability::grant("terminal private offline repair replay"),
            schema,
            replay_binding.clone(),
            replay_binding.invocation_capability(),
            checkpoint_policy(&replay_binding),
        )?;
        let replay_envelope = OfflineRepairEnvelope::new(project, "fixture.repair.value")?;
        let mut replay_handler = OfflineRepairHandler::new(
            replay_envelope,
            "fixture.read",
            "fixture.read.second",
            "read",
            "query",
            "value",
        )?;
        let mut replay_store = Store::default();
        let replay = replay
            .run_live_bound_model_durable(
                &mut replay_source,
                &mut replay_handler,
                policy(&replay_binding),
                &Clock,
                &AgentCancellation::new(),
                Some(&checkpoint),
                &mut replay_store,
            )
            .map_err(|failure| failure.failure().diagnostics.clone())?;
        assert!(replay.run().checked_run.is_none());
        assert_eq!(replay.run().model_dispatches, 0);
        assert_eq!(replay.run().effect_dispatches, 0);
        assert!(!constructed.get());
        assert!(replay_handler.latest_preview().is_none());
        assert!(replay_handler.latest_rejection().is_none());
        Ok(())
    })
    .unwrap();
}
