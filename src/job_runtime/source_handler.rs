//! Retained checked source-handler binding for the host-driven job runtime.
//!
//! This module does not add a job state machine, checkpoint wire format, or
//! host capability. It binds one effect-free, explicit-ID source callable to
//! an immutable [`ProjectRevision`] and executes it only through the existing
//! retained-call interpreter seam. The existing [`super::JobRuntime`] remains
//! the only enqueue/claim/complete/recover owner.

use std::path::Path;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use crate::agent_interaction_schema::{
    compile_agent_interaction_schema_from_retained_source, CompiledInteractionSchema,
};
use crate::agent_lifecycle_typed_carrier::{to_retained, InteractionTypeGraph};
use crate::diagnostic::quote_json;
use crate::hir::{self, ResolvedProgram, ResolvedType};
use crate::interpreter::retained_call::{
    evaluate_retained_call, prepare_retained_call, PreparedRetainedCall, RetainedCallOutcome,
    RetainedValue,
};
use crate::interpreter::MAX_STEPS_LIMIT;
use crate::project::ProjectRevision;

use super::{
    DriveOutcome, HostJobHandler, HostJobOutcome, JobCheckpointStore, JobHeartbeat, JobRuntime,
    JobRuntimeError,
};

/// Versioned identity domain for a retained checked source job handler.
pub const SOURCE_JOB_HANDLER_BINDING_SCHEMA: &str = "semaprax.job-source-handler-binding.v1";
pub const MAX_SOURCE_JOB_HANDLER_ID_BYTES: usize = 256;
pub const MAX_SOURCE_JOB_HANDLER_PATH_BYTES: usize = 512;
pub const MAX_SOURCE_JOB_HANDLER_TYPE_ID_BYTES: usize = 256;

const BINDING_DOMAIN: &[u8] = b"semaprax.job-source-handler-binding.v1\0";

/// A fail-closed refusal before any job can be claimed or source callable run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceJobHandlerRefusal {
    InvalidInput,
    StaleProgramRoot,
    SourceNotRetained,
    SourceRevisionMismatch,
    SchemaMismatch,
    HandlerMissing,
    HandlerSignature,
    HandlerAdmission,
    BindingDigestMismatch,
    RuntimeSchemaMismatch,
    RuntimeHandlerDescriptorMismatch,
}

/// Failure while composing the checked source handler with [`JobRuntime`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceJobDriveError {
    Binding(SourceJobHandlerRefusal),
    Runtime(JobRuntimeError),
}

/// One checked, immutable source-handler deployment identity.
///
/// Construction derives the payload schema from bytes already retained in the
/// exact Project, derives the same typed carrier graph from that checked HIR,
/// and admits one non-`main` explicit-ID callable through
/// `interpreter::retained_call`. No source path is opened at execution time.
pub struct SourceJobHandlerBinding {
    project: Arc<ProjectRevision>,
    program_root: String,
    source_path: String,
    source_revision: String,
    handler_id: String,
    payload_type_id: String,
    payload_schema: CompiledInteractionSchema,
    payload_graph: InteractionTypeGraph,
    program: ResolvedProgram,
    prepared: PreparedRetainedCall,
    max_steps: usize,
    canonical: String,
    deployment_identity: String,
}

impl SourceJobHandlerBinding {
    /// Derive a source-handler binding from one immutable retained Project.
    ///
    /// `expected_program_root` is caller-retained deployment input. It must
    /// exactly equal a fresh root derived from `project`; a stale root fails
    /// before a source callable, lease, or host handler can run.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        project: Arc<ProjectRevision>,
        expected_program_root: &str,
        source_path: &str,
        handler_id: &str,
        payload_type_id: &str,
        max_steps: usize,
    ) -> Result<Self, SourceJobHandlerRefusal> {
        if !bounded_text(source_path, MAX_SOURCE_JOB_HANDLER_PATH_BYTES)
            || !bounded_text(handler_id, MAX_SOURCE_JOB_HANDLER_ID_BYTES)
            || !bounded_text(payload_type_id, MAX_SOURCE_JOB_HANDLER_TYPE_ID_BYTES)
            || !(1..=MAX_STEPS_LIMIT).contains(&max_steps)
        {
            return Err(SourceJobHandlerRefusal::InvalidInput);
        }
        let root = project
            .program_root()
            .map_err(|_| SourceJobHandlerRefusal::StaleProgramRoot)?;
        if root.program_root_digest() != expected_program_root {
            return Err(SourceJobHandlerRefusal::StaleProgramRoot);
        }
        let source = project
            .sources()
            .iter()
            .find(|source| source.path() == source_path)
            .ok_or(SourceJobHandlerRefusal::SourceNotRetained)?;
        // Retain these immutable facts before moving `project` into the
        // binding below. The source reference only borrows the project.
        let retained_source_path = source.path().to_owned();
        let retained_source_revision = source.source_revision().to_owned();
        let checked = crate::check(source.source(), source.path())
            .map_err(|_| SourceJobHandlerRefusal::SourceRevisionMismatch)?;
        if crate::graph::revision(&checked) != source.source_revision() {
            return Err(SourceJobHandlerRefusal::SourceRevisionMismatch);
        }
        let program =
            hir::resolve(&checked).map_err(|_| SourceJobHandlerRefusal::HandlerAdmission)?;
        hir::validate(&program).map_err(|_| SourceJobHandlerRefusal::HandlerAdmission)?;
        let payload_schema = compile_agent_interaction_schema_from_retained_source(
            source.source(),
            Path::new(source.path()),
            payload_type_id,
        )
        .map_err(|_| SourceJobHandlerRefusal::SchemaMismatch)?;
        if payload_schema.source_revision() != source.source_revision() {
            return Err(SourceJobHandlerRefusal::SchemaMismatch);
        }
        let payload_graph = InteractionTypeGraph::derive(&program, payload_type_id)
            .map_err(|_| SourceJobHandlerRefusal::SchemaMismatch)?;
        let handler = program
            .functions
            .iter()
            .find(|function| function.id.as_str() == handler_id)
            .ok_or(SourceJobHandlerRefusal::HandlerMissing)?;
        if !handler_signature_matches(handler, payload_type_id) {
            return Err(SourceJobHandlerRefusal::HandlerSignature);
        }
        let prepared = prepare_retained_call(&program, handler_id)
            .map_err(|_| SourceJobHandlerRefusal::HandlerAdmission)?;
        if prepared.function_id() != handler_id || prepared.parameter_count() != 1 {
            return Err(SourceJobHandlerRefusal::HandlerAdmission);
        }
        let canonical = canonical_binding(
            root.program_root_digest(),
            project.project_revision(),
            &retained_source_path,
            &retained_source_revision,
            handler_id,
            payload_type_id,
            payload_schema.schema().digest(),
            max_steps,
        );
        let deployment_identity = digest(&canonical);
        Ok(Self {
            project,
            program_root: root.program_root_digest().to_owned(),
            source_path: retained_source_path,
            source_revision: retained_source_revision,
            handler_id: handler_id.to_owned(),
            payload_type_id: payload_type_id.to_owned(),
            payload_schema,
            payload_graph,
            program,
            prepared,
            max_steps,
            canonical,
            deployment_identity,
        })
    }

    #[must_use]
    pub fn deployment_identity(&self) -> &str {
        &self.deployment_identity
    }

    #[must_use]
    pub fn canonical_json(&self) -> &str {
        &self.canonical
    }

    #[must_use]
    pub fn payload_schema(&self) -> &CompiledInteractionSchema {
        &self.payload_schema
    }

    #[must_use]
    pub fn handler_id(&self) -> &str {
        &self.handler_id
    }

    #[must_use]
    pub fn project_revision(&self) -> &ProjectRevision {
        &self.project
    }

    #[must_use]
    pub fn program_root(&self) -> &str {
        &self.program_root
    }

    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    #[must_use]
    pub fn payload_type_id(&self) -> &str {
        &self.payload_type_id
    }

    /// Bind an otherwise valid job submission to this exact retained source
    /// handler deployment. The existing opaque descriptor field is already
    /// persisted by `JobRuntime`; no checkpoint wire format is changed.
    ///
    /// Callers must use this before enqueueing a checked source job. The
    /// checked drive path refuses any restored submission whose descriptor is
    /// not this binding's exact identity before it can claim a lease.
    #[must_use]
    pub fn bind_submission(&self, mut submission: super::JobSubmission) -> super::JobSubmission {
        submission.payload_descriptor = self.deployment_identity.as_bytes().to_vec();
        submission
    }

    /// Acquire the checked handler only when the caller retained the exact
    /// deployment identity produced by this binding.
    fn handler(
        &self,
        expected_deployment_identity: &str,
    ) -> Result<BoundSourceJobHandler<'_>, SourceJobHandlerRefusal> {
        if expected_deployment_identity != self.deployment_identity {
            return Err(SourceJobHandlerRefusal::BindingDigestMismatch);
        }
        Ok(BoundSourceJobHandler { binding: self })
    }

    fn execute(&self, admitted_payload: &[u8]) -> HostJobOutcome {
        let decoded = match self.payload_schema.decode(admitted_payload) {
            Ok(value) => value,
            Err(_) => return HostJobOutcome::PermanentFailure,
        };
        let retained = match to_retained(&self.payload_graph, &decoded) {
            Ok(value) => value,
            Err(_) => return HostJobOutcome::PermanentFailure,
        };
        match evaluate_retained_call(&self.program, &self.prepared, &[retained], self.max_steps) {
            Ok(evaluation) => map_outcome(evaluation.outcome),
            Err(_) => HostJobOutcome::PermanentFailure,
        }
    }
}

/// A capability-free borrowed adapter that executes exactly the source
/// callable already bound by [`SourceJobHandlerBinding`].
struct BoundSourceJobHandler<'a> {
    binding: &'a SourceJobHandlerBinding,
}

impl HostJobHandler for BoundSourceJobHandler<'_> {
    fn execute(
        &mut self,
        admitted_payload: &[u8],
        _heartbeat: &mut dyn JobHeartbeat,
    ) -> HostJobOutcome {
        // The checked retained-call route is effect-free and bounded by
        // interpreter fuel rather than wall/tick time, so it never needs to
        // extend its own lease; it ignores the heartbeat handle rather than
        // manufacturing a use for it.
        self.binding.execute(admitted_payload)
    }
}

/// Drive the existing durable runtime with one checked source handler.
///
/// This checks the persisted submission descriptor, caller-held deployment
/// identity, and exact runtime payload schema before `JobRuntime` can claim
/// the job. The runtime still owns every checkpoint, lease, evidence, reducer,
/// and uncertainty transition.
#[allow(clippy::too_many_arguments)]
pub fn drive_checked_source_job(
    runtime: &mut JobRuntime<'_>,
    checkpoints: &mut impl JobCheckpointStore,
    binding: &SourceJobHandlerBinding,
    expected_deployment_identity: &str,
    worker_id: u32,
    now_tick: u64,
    lease_ticks: u64,
) -> Result<DriveOutcome, SourceJobDriveError> {
    if runtime.payload_descriptor() != binding.deployment_identity().as_bytes() {
        return Err(SourceJobDriveError::Binding(
            SourceJobHandlerRefusal::RuntimeHandlerDescriptorMismatch,
        ));
    }
    if runtime.schema_digest() != binding.payload_schema.schema().digest() {
        return Err(SourceJobDriveError::Binding(
            SourceJobHandlerRefusal::RuntimeSchemaMismatch,
        ));
    }
    let mut handler = binding
        .handler(expected_deployment_identity)
        .map_err(SourceJobDriveError::Binding)?;
    runtime
        .drive_once(checkpoints, &mut handler, worker_id, now_tick, lease_ticks)
        .map_err(SourceJobDriveError::Runtime)
}

fn handler_signature_matches(function: &hir::ResolvedFunction, payload_type_id: &str) -> bool {
    matches!(
        (function.params.as_slice(), &function.return_type),
        (
            [parameter],
            ResolvedType::I64,
        ) if matches!(
            &parameter.ty,
            ResolvedType::Nominal { declaration, arguments }
                if declaration.as_str() == payload_type_id && arguments.is_empty()
        )
    )
}

fn map_outcome(outcome: RetainedCallOutcome) -> HostJobOutcome {
    match outcome {
        RetainedCallOutcome::Returned(RetainedValue::I64(0)) => HostJobOutcome::Succeeded,
        RetainedCallOutcome::Returned(RetainedValue::I64(1)) => HostJobOutcome::RetryableFailure,
        RetainedCallOutcome::Returned(RetainedValue::I64(2)) => HostJobOutcome::PermanentFailure,
        // The checked callable is effect-free. A language or capacity failure
        // therefore cannot report an external delivery result; classify it as
        // terminal rather than inventing a source-visible uncertainty value.
        RetainedCallOutcome::Returned(_)
        | RetainedCallOutcome::LanguageFailure(_)
        | RetainedCallOutcome::FuelExhausted
        | RetainedCallOutcome::CallDepthExceeded
        | RetainedCallOutcome::GuardError(_) => HostJobOutcome::PermanentFailure,
    }
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.as_bytes().contains(&0)
}

fn canonical_binding(
    program_root: &str,
    project_revision: &str,
    source_path: &str,
    source_revision: &str,
    handler_id: &str,
    payload_type_id: &str,
    schema_digest: &str,
    max_steps: usize,
) -> String {
    format!(
        "{{\"schema\":{},\"program_root\":{},\"project_revision\":{},\"source\":{{\"path\":{},\"revision\":{}}},\"handler\":{{\"id\":{},\"result_profile\":\"i64-status-v1\"}},\"payload\":{{\"type_id\":{},\"schema_digest\":{}}},\"limits\":{{\"max_steps\":{}}}}}",
        quote_json(SOURCE_JOB_HANDLER_BINDING_SCHEMA),
        quote_json(program_root),
        quote_json(project_revision),
        quote_json(source_path),
        quote_json(source_revision),
        quote_json(handler_id),
        quote_json(payload_type_id),
        quote_json(schema_digest),
        max_steps,
    )
}

fn digest(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update(canonical.as_bytes());
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

#[cfg(test)]
#[path = "source_handler_tests.rs"]
mod tests;
