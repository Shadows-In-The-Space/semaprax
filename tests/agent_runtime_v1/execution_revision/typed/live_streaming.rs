//! Direct Runtime v2 consumption of the ordinary streaming source adapter.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use semaprax::agent_deployment::migrate_agent_definition_v1;
use semaprax::agent_lifecycle::iterative::effects::EffectBudget;
use semaprax::agent_lifecycle::iterative::{
    compile_source_agent_lifecycle_v2, IterativeBudget, IterativeStatus,
};
use semaprax::agent_lifecycle::LifecycleTask;
use semaprax::agent_runtime::AgentCancellation;
use semaprax::agent_runtime_v2::{bind_agent_runtime_v2_live, SourceModelAdapterIdentity};
use semaprax::execution_revision::ProgramRootRef;
use semaprax::project::with_authenticated_project;
use semaprax::provider_adapter_sdk::fixture_adapters::{
    usage, ScriptedAdapter, ScriptedStreamingAdapter,
};
use semaprax::provider_adapter_sdk::{
    AdapterCapabilities, AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterSettlement,
    CancellationSemantics, EndpointPolicy, ProviderAdapter, SourceAdapterFactory,
    StreamingSourceProposalAdapter, StructuredOutputMode, TokenAccountingSource,
};

use super::{operations, typed_fixture, Handler};

fn bind(
    project: std::sync::Arc<semaprax::project::ProjectRevision>,
    root: &semaprax::project::ProgramRoot,
) -> Result<semaprax::agent_runtime_v2::AgentRuntimeV2, Vec<semaprax::diagnostic::Diagnostic>> {
    let (_, deployment) = migrate_agent_definition_v1(
        project.agent_definitions()[0]
            .definition()
            .canonical_source(),
        "fixture.streaming.runtime",
    )?;
    bind_agent_runtime_v2_live(
        project,
        ProgramRootRef::V1(root),
        root.program_root_digest(),
        "src/app.spx",
        "fixture.agent",
        "fixture.agent.type.step",
        "fixture.agent.type.proposal.sequence",
        operations(),
        &deployment,
        LifecycleTask {
            objective: b"streamed typed task".to_vec(),
            budget: 12,
        },
        IterativeBudget::default(),
        EffectBudget {
            max_calls: 3,
            max_argument_bytes: 4096,
            max_result_bytes: 4096,
            max_total_bytes: 8192,
        },
    )
}

fn make_factory(documents: Vec<String>) -> impl SourceAdapterFactory {
    let documents = RefCell::new(VecDeque::from(documents));
    move || {
        let document = documents
            .borrow_mut()
            .pop_front()
            .expect("one fresh adapter per attempted source proposal");
        Box::new(ScriptedStreamingAdapter::new(
            document
                .as_bytes()
                .chunks(5)
                .map(ToOwned::to_owned)
                .collect(),
            document.into_bytes(),
            usage(1, 1, 1),
            true,
        )) as Box<dyn ProviderAdapter>
    }
}

fn streaming_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        adapter_identity: "direct-runtime-hostile".to_owned(),
        adapter_version: "1".to_owned(),
        provider_profile: "fixture".to_owned(),
        structured_output_modes: vec![StructuredOutputMode::RawText],
        supports_streaming: true,
        token_accounting_source: TokenAccountingSource::LocalEstimate,
        cancellation_semantics: CancellationSemantics::BestEffortRequestStop,
        retryable_failure_classes: vec![],
        endpoint_policy: EndpointPolicy::HostInjected,
        max_request_bytes: 65_536,
        max_response_bytes: 65_536,
        max_context_tokens: 8192,
        max_output_tokens: 2048,
    }
}

fn mismatch_factory(document: String) -> impl SourceAdapterFactory {
    move || {
        Box::new(ScriptedAdapter::new(
            streaming_capabilities(),
            vec![
                AdapterPoll::Event(AdapterEvent::Delta(document.as_bytes().to_vec())),
                AdapterPoll::Event(AdapterEvent::Completed),
                AdapterPoll::Settled(AdapterSettlement {
                    response_bytes: b"different-settlement".to_vec(),
                    usage: usage(1, 1, 1),
                }),
            ],
            true,
        )) as Box<dyn ProviderAdapter>
    }
}

#[test]
fn direct_runtime_v2_streams_checked_source_proposals_before_effect_authorization() {
    let fixture = typed_fixture();
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let runtime = bind(project.clone(), &root)?;
        let retained_source = &project.sources()[0];
        let compiled = compile_source_agent_lifecycle_v2(
            retained_source.source(),
            retained_source.path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        assert_eq!(
            schema.schema().digest(),
            runtime.proposal_schema().schema().digest()
        );
        assert_eq!(
            schema.source_revision(),
            runtime.proposal_schema().source_revision()
        );
        let documents = ["0", "1", "0"]
            .into_iter()
            .map(|sequence| {
                crate::agent_lifecycle_v1::proposal(schema.schema().digest(), "5", false, sequence)
            })
            .collect();
        let mut adapter_factory = make_factory(documents);
        let binding = runtime.source_model_binding(SourceModelAdapterIdentity {
            provider_id: "fake.local".to_owned(),
            model_id: "fake-basic".to_owned(),
            adapter_identity: "scripted-streaming-adapter".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            provider_profile: "fixture".to_owned(),
        })?;
        let mut source = StreamingSourceProposalAdapter::new_bound(
            &mut adapter_factory,
            AdapterInvocationCapability::grant("offline direct-runtime fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
        )?;
        let mut handler = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let evidence = runtime
            .run_live_bound_model(&mut source, &mut handler, &AgentCancellation::new())
            .map_err(|failure| failure.diagnostics().to_vec())?;
        assert_eq!(
            evidence.run().lifecycle().status(),
            IterativeStatus::Complete
        );
        assert_eq!(
            handler.calls,
            ["fixture.read", "fixture.read.second", "fixture.read"]
        );
        assert_eq!(evidence.model_evidence().attempts().len(), 3);
        assert_eq!(
            evidence.model_evidence().attempts()[0].terminal(),
            "admitted"
        );
        let admitted_root = evidence.evidence_root().digest().to_owned();

        // The same scripted response bytes cannot be joined to a substituted
        // host adapter label: the retained binding digest changes the v4 root
        // and the adapter never starts under the wrong label.
        let substituted = bind(snapshot.retain_revision(), &root)?;
        let substituted_binding = substituted.source_model_binding(SourceModelAdapterIdentity {
            provider_id: "fake.local".to_owned(),
            model_id: "fake-basic".to_owned(),
            adapter_identity: "substituted-streaming-adapter".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            provider_profile: "fixture".to_owned(),
        })?;
        let document =
            crate::agent_lifecycle_v1::proposal(schema.schema().digest(), "5", false, "0");
        let mut adapter_factory = make_factory(vec![document]);
        let mut source = StreamingSourceProposalAdapter::new_bound(
            &mut adapter_factory,
            AdapterInvocationCapability::grant("offline substituted fixture"),
            schema,
            substituted_binding.clone(),
            substituted_binding.invocation_capability(),
        )?;
        let mut never = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let substitution =
            substituted.run_live_bound_model(&mut source, &mut never, &AgentCancellation::new());
        assert!(substitution.is_err());
        let substitution = substitution.err().expect("substitution is refused");
        assert_eq!(substitution.model_evidence().attempts().len(), 1);
        assert_ne!(substitution.evidence_root().digest(), admitted_root);
        assert!(never.calls.is_empty());

        // A source with an earlier attempt cannot carry that evidence into a
        // new invocation, and the refusal does not add another observation.
        let reused = bind(snapshot.retain_revision(), &root)?;
        let reuse = reused.run_live_bound_model(&mut source, &mut never, &AgentCancellation::new());
        assert!(reuse.is_err());
        let reuse = reuse.err().expect("reused source is refused");
        assert!(reuse.model_evidence().attempts().is_empty());
        assert_eq!(source.model_evidence().attempts().len(), 1);

        let hostile = bind(snapshot.retain_revision(), &root)?;
        let mut adapter_factory = make_factory(vec!["!".to_owned()]);
        let mut source = StreamingSourceProposalAdapter::new(
            &mut adapter_factory,
            AdapterInvocationCapability::grant("offline hostile fixture"),
            schema,
        );
        let mut never = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        assert!(hostile
            .run_live(&mut source, &mut never, &AgentCancellation::new())
            .is_err());
        assert!(never.calls.is_empty());

        let cancelled = bind(snapshot.retain_revision(), &root)?;
        let constructed = std::rc::Rc::new(Cell::new(false));
        let observed = std::rc::Rc::clone(&constructed);
        let mut adapter_factory = move || -> Box<dyn ProviderAdapter> {
            observed.set(true);
            panic!("a pre-cancelled runtime must not construct an adapter")
        };
        let cancellation = AgentCancellation::new();
        cancellation.cancel();
        let mut source = StreamingSourceProposalAdapter::new(
            &mut adapter_factory,
            AdapterInvocationCapability::grant("offline cancellation fixture"),
            schema,
        )
        .with_cancellation(&cancellation);
        let mut never = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let cancelled = cancelled.run_live(&mut source, &mut never, &cancellation)?;
        assert_eq!(
            cancelled.run().lifecycle().status(),
            IterativeStatus::Cancelled
        );
        drop(source);
        assert!(!constructed.get());
        assert!(never.calls.is_empty());

        let mismatch = bind(snapshot.retain_revision(), &root)?;
        let document =
            crate::agent_lifecycle_v1::proposal(schema.schema().digest(), "5", false, "0");
        let mut adapter_factory = mismatch_factory(document);
        let mut source = StreamingSourceProposalAdapter::new(
            &mut adapter_factory,
            AdapterInvocationCapability::grant("offline mismatch fixture"),
            schema,
        );
        let mut never = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        assert!(mismatch
            .run_live(&mut source, &mut never, &AgentCancellation::new())
            .is_err());
        assert!(never.calls.is_empty());
        Ok(())
    })
    .unwrap();
}
