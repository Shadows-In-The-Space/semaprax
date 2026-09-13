//! Store-backed source-model streaming regressions.

use super::*;
use semaprax::agent_lifecycle::iterative::source_live::{SourceLivePolicy, SourceProposalPolicy};
use semaprax::agent_lifecycle::{CheckpointStore, CheckpointStoreError};
use semaprax::live_invocation::{InvocationClock, SourceInvocationClock};

struct Clock;

impl InvocationClock for Clock {
    fn now_millis(&self) -> i64 {
        1
    }
}

impl SourceInvocationClock for Clock {
    fn clock_domain(&self) -> &str {
        "typed-streaming-durable-test.v1"
    }
}

#[derive(Default)]
struct Store {
    documents: Vec<String>,
    fail_attempt_intent: bool,
    cancel_at_attempt_intent: Option<AgentCancellation>,
}

impl CheckpointStore for Store {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.documents.push(document.to_owned());
        if document.contains("\"kind\":\"attempt_intent\"") {
            if let Some(cancellation) = &self.cancel_at_attempt_intent {
                cancellation.cancel();
            }
        }
        if self.fail_attempt_intent && document.contains("\"kind\":\"attempt_intent\"") {
            return Err(CheckpointStoreError);
        }
        Ok(())
    }
}

#[test]
fn durable_bound_source_checks_cancellation_after_intent_ack_before_factory_start() {
    let fixture = typed_fixture();
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let compiled = compile_source_agent_lifecycle_v2(
            project.sources()[0].source(),
            project.sources()[0].path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        let runtime = bind(project, &root)?;
        let binding = runtime.source_model_binding(identity())?;
        let constructions = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let mut factory = counted_factory(
            documents(schema),
            Rc::clone(&constructions),
            Rc::clone(&starts),
        );
        let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut factory,
            AdapterInvocationCapability::grant("durable cancellation boundary fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
            checkpoint_policy(&binding),
        )?;
        let cancellation = AgentCancellation::new();
        let mut store = Store {
            cancel_at_attempt_intent: Some(cancellation.clone()),
            ..Store::default()
        };
        let mut handler = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let failure = runtime
            .run_live_bound_model_durable(
                &mut source,
                &mut handler,
                policy(&binding),
                &Clock,
                &cancellation,
                None,
                &mut store,
            )
            .err()
            .expect("post-ack cancellation records a closed source failure");
        assert_eq!(constructions.get(), 0);
        assert_eq!(starts.get(), 0);
        assert!(handler.calls.is_empty());
        assert_eq!(failure.failure().model_dispatches, 1);
        assert!(store
            .documents
            .last()
            .expect("closed failure is acknowledged")
            .contains("\"kind\":\"attempt_failed\""));
        Ok(())
    })
    .unwrap();
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
        ceiling: 3,
        reservation_units: 1,
        unit: "typed_streaming_unit_v1".to_owned(),
        clock_domain: "typed-streaming-durable-test.v1".to_owned(),
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

fn documents(schema: &semaprax::agent_proposal::CompiledAgentProposalSchema) -> Vec<String> {
    ["0", "1", "0"]
        .into_iter()
        .map(|sequence| {
            crate::agent_lifecycle_v1::proposal(schema.schema().digest(), "5", false, sequence)
        })
        .collect()
}

#[test]
fn durable_bound_source_requires_intent_ack_and_never_redispatches_uncertain_recovery() {
    let fixture = typed_fixture();
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let compiled = compile_source_agent_lifecycle_v2(
            project.sources()[0].source(),
            project.sources()[0].path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        let runtime = bind(project.clone(), &root)?;
        let binding = runtime.source_model_binding(identity())?;
        let constructions = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let mut factory = counted_factory(
            documents(schema),
            Rc::clone(&constructions),
            Rc::clone(&starts),
        );
        let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut factory,
            AdapterInvocationCapability::grant("durable intent ack fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
            checkpoint_policy(&binding),
        )?;
        let mut handler = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let clock = Clock;
        let cancellation = AgentCancellation::new();
        let mut store = Store {
            fail_attempt_intent: true,
            ..Store::default()
        };
        let failure = runtime
            .run_live_bound_model_durable(
                &mut source,
                &mut handler,
                policy(&binding),
                &clock,
                &cancellation,
                None,
                &mut store,
            )
            .err()
            .expect("unacknowledged intent stops before provider construction");
        assert_eq!(constructions.get(), 0);
        assert_eq!(starts.get(), 0);
        assert!(handler.calls.is_empty());
        assert_eq!(failure.failure().model_dispatches, 0);
        let uncertain = store
            .documents
            .last()
            .expect("store received the possibly committed intent")
            .clone();

        let runtime = bind(snapshot.retain_revision(), &root)?;
        let binding = runtime.source_model_binding(identity())?;
        let constructions = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let mut factory = counted_factory(
            documents(schema),
            Rc::clone(&constructions),
            Rc::clone(&starts),
        );
        let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut factory,
            AdapterInvocationCapability::grant("durable uncertain recovery fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
            checkpoint_policy(&binding),
        )?;
        let mut never = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let mut recovered_store = Store::default();
        assert!(runtime
            .run_live_bound_model_durable(
                &mut source,
                &mut never,
                policy(&binding),
                &clock,
                &AgentCancellation::new(),
                Some(&uncertain),
                &mut recovered_store,
            )
            .is_err());
        assert_eq!(constructions.get(), 0);
        assert_eq!(starts.get(), 0);
        assert!(never.calls.is_empty());
        assert!(recovered_store.documents.is_empty());
        Ok(())
    })
    .unwrap();
}

#[test]
fn durable_bound_source_completes_typed_effects_and_terminal_replay_is_idle() {
    let fixture = typed_fixture();
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let compiled = compile_source_agent_lifecycle_v2(
            project.sources()[0].source(),
            project.sources()[0].path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        let runtime = bind(project.clone(), &root)?;
        let binding = runtime.source_model_binding(identity())?;
        let constructions = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let mut factory = counted_factory(
            documents(schema),
            Rc::clone(&constructions),
            Rc::clone(&starts),
        );
        let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut factory,
            AdapterInvocationCapability::grant("durable complete fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
            checkpoint_policy(&binding),
        )?;
        let clock = Clock;
        let cancellation = AgentCancellation::new();
        let mut handler = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let mut store = Store::default();
        let complete = runtime
            .run_live_bound_model_durable(
                &mut source,
                &mut handler,
                policy(&binding),
                &clock,
                &cancellation,
                None,
                &mut store,
            )
            .map_err(|failure| failure.failure().diagnostics.clone())?;
        assert_eq!(
            complete.run().checked_run.as_ref().unwrap().status(),
            IterativeStatus::Complete
        );
        assert_eq!(
            handler.calls,
            ["fixture.read", "fixture.read.second", "fixture.read"]
        );
        assert_eq!(constructions.get(), 3);
        assert_eq!(starts.get(), 3);
        let checkpoint = store
            .documents
            .last()
            .expect("terminal journal is acknowledged")
            .clone();

        let runtime = bind(snapshot.retain_revision(), &root)?;
        let binding = runtime.source_model_binding(identity())?;
        let constructions = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let mut factory = counted_factory(
            documents(schema),
            Rc::clone(&constructions),
            Rc::clone(&starts),
        );
        let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
            &mut factory,
            AdapterInvocationCapability::grant("durable terminal replay fixture"),
            schema,
            binding.clone(),
            binding.invocation_capability(),
            checkpoint_policy(&binding),
        )?;
        let mut never = Handler {
            calls: Vec::new(),
            wrong: false,
        };
        let mut replay_store = Store::default();
        let replay = runtime
            .run_live_bound_model_durable(
                &mut source,
                &mut never,
                policy(&binding),
                &clock,
                &AgentCancellation::new(),
                Some(&checkpoint),
                &mut replay_store,
            )
            .map_err(|failure| failure.failure().diagnostics.clone())?;
        assert!(replay.run().checked_run.is_none());
        assert_eq!(replay.run().model_dispatches, 0);
        assert_eq!(replay.run().effect_dispatches, 0);
        assert!(never.calls.is_empty());
        assert_eq!(constructions.get(), 0);
        assert_eq!(starts.get(), 0);
        Ok(())
    })
    .unwrap();
}
