//! `semaprax workflow inspect|validate|checkpoint|dispatch`: read-only fronts
//! over `semaprax::typed_workflow`, issue #208's last in-scope item.
//!
//! `src/typed_workflow` was complete internally -- graph schema, dataflow
//! checking, human gates, bounded Parallel/Join, retries, compensation,
//! checkpoints, model routing, and decide-and-record dispatch -- but nothing
//! outside the module referenced it: there was no way to author, inspect,
//! validate, or run a workflow from outside a Rust unit test. This front
//! closes that gap for the read side and for one narrow, already
//! decide-and-record slice of the write side.
//!
//! Every verb here only decodes and reads bytes the caller already has on
//! disk; every rule is owned by `semaprax::typed_workflow`
//! (`graph_wire::parse_graph`, `graph::WorkflowGraph::validate`,
//! `checkpoint::Checkpoint::decode`, `declared_dispatch::{parse_policy,
//! parse_request, decide}`) and re-derived from the exact bytes under test,
//! matching `cli::audit`'s and `cli::release`'s shape exactly.
//!
//! **`workflow dispatch` is the only verb here that resembles "running"
//! anything, and it is decide-and-record only**, consistent with the engine
//! itself (`typed_workflow::engine::DispatchExecutor`, `79f18bfb`): given a
//! declared allow-list and a declared request, it decides whether the
//! request is in scope and reports that decision. It never invokes an
//! agent, runs a tool, spawns a job, runs a build, or publishes anything --
//! there is nothing in this front, or in the pure function it calls, capable
//! of doing so. The full workflow engine (`typed_workflow::engine::run`) is
//! deliberately **not** exposed here at all: running it needs a mutable
//! `GateLedger` and `CommitLog` threaded across calls, which has no wire
//! format and no durable identity of its own, and driving that from one-shot
//! CLI arguments would mean this front inventing state-threading semantics
//! the owning module never designed -- exactly the kind of second,
//! uncoordinated place for the answer to differ that this repository's
//! adapters are built to avoid. A workflow's *definition* can be inspected
//! and validated, a *checkpoint*'s state can be read, and one *declared
//! dispatch* decision can be recorded; actually executing a graph stays a
//! Rust-embedding concern.

use std::path::{Path, PathBuf};

use semaprax::diagnostic::Diagnostic;
use semaprax::typed_workflow::checkpoint::Checkpoint;
use semaprax::typed_workflow::declared_dispatch::{self, DispatchError};
use semaprax::typed_workflow::graph::{DeclaredStepKind, StepKind};
use semaprax::typed_workflow::graph_wire;

const USAGE: &str = "workflow accepts `inspect <workflow.json>`, \
                      `validate <workflow.json>`, `checkpoint <checkpoint.json>`, or \
                      `dispatch <policy.json> <request.json>`; see `semaprax help workflow`";

/// Largest document this front reads for any one verb. The owning decoders
/// (`graph_wire::parse_graph`, `declared_dispatch::parse_policy`/
/// `parse_request`) enforce their own, smaller bounds independently on the
/// same bytes; this only keeps a hostile file from being read into memory
/// before either ever sees it.
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;

/// This front's own code, for "the requested document could not be read (or
/// decoded as a checkpoint) at all" -- never used for a graph-decode,
/// dispatch-decode, or validation failure, which always keep the owning
/// check's own code.
fn document_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z923", message)
}

/// This front's own code for "the checked thing did not pass its check": an
/// invalid workflow graph, or a dispatch request refused by its policy.
/// Distinct from [`document_error`] (which never got to check anything) and
/// from the owning decoders' own codes (which never even parsed).
fn check_failed(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z924", message)
}

pub(crate) enum WorkflowCommand {
    Inspect(PathBuf),
    Validate(PathBuf),
    Checkpoint(PathBuf),
    Dispatch(PathBuf, PathBuf),
}

fn is_flag(argument: &str) -> bool {
    argument.starts_with("--")
}

/// `inspect <workflow.json>`, `validate <workflow.json>`,
/// `checkpoint <checkpoint.json>`, or `dispatch <policy.json> <request.json>`,
/// and nothing else. An unknown subcommand, a missing operand, an extra
/// operand, or an option-shaped positional operand fails closed with the
/// usage line and exit code 2 before any path is opened.
pub(crate) fn parse(args: &[String]) -> Result<WorkflowCommand, u8> {
    let rejected = match args {
        [subcommand, path] if subcommand == "inspect" && !path.is_empty() && !is_flag(path) => {
            return Ok(WorkflowCommand::Inspect(PathBuf::from(path)));
        }
        [subcommand, path] if subcommand == "validate" && !path.is_empty() && !is_flag(path) => {
            return Ok(WorkflowCommand::Validate(PathBuf::from(path)));
        }
        [subcommand, path] if subcommand == "checkpoint" && !path.is_empty() && !is_flag(path) => {
            return Ok(WorkflowCommand::Checkpoint(PathBuf::from(path)));
        }
        [subcommand, policy, request]
            if subcommand == "dispatch"
                && !policy.is_empty()
                && !is_flag(policy)
                && !request.is_empty()
                && !is_flag(request) =>
        {
            return Ok(WorkflowCommand::Dispatch(
                PathBuf::from(policy),
                PathBuf::from(request),
            ));
        }
        [subcommand, ..]
            if !matches!(
                subcommand.as_str(),
                "inspect" | "validate" | "checkpoint" | "dispatch"
            ) =>
        {
            format!("unknown workflow subcommand `{subcommand}`; {USAGE}")
        }
        _ => USAGE.to_owned(),
    };
    eprintln!("{rejected}");
    Err(2)
}

fn read_bounded(path: &Path, what: &str) -> Result<Vec<u8>, Diagnostic> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        document_error(format!("cannot read {what} {}: {error}", path.display()))
    })?;
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(document_error(format!(
            "{} is {} bytes, over the {MAX_DOCUMENT_BYTES}-byte bound for a {what}",
            path.display(),
            metadata.len()
        )));
    }
    std::fs::read(path)
        .map_err(|error| document_error(format!("cannot read {what} {}: {error}", path.display())))
}

fn step_kind_label(kind: &StepKind) -> String {
    match kind {
        StepKind::Sequential => "sequential".to_owned(),
        StepKind::Conditional { condition_port } => {
            format!("conditional (condition_port={})", condition_port.0)
        }
        StepKind::Parallel => "parallel".to_owned(),
        StepKind::Join { parallel } => format!("join (parallel={})", parallel.0),
        StepKind::HumanGate => "human_gate".to_owned(),
        StepKind::Loop { max_iterations } => format!("loop (max_iterations={max_iterations})"),
        StepKind::ModelCall { requested_model } => {
            format!("model_call (requested_model={requested_model})")
        }
        StepKind::Terminal => "terminal".to_owned(),
        StepKind::Declared(kind) => format!("declared ({})", declared_kind_label(*kind)),
    }
}

fn declared_kind_label(kind: DeclaredStepKind) -> &'static str {
    match kind {
        DeclaredStepKind::AgentCall => "agent_call",
        DeclaredStepKind::ToolCall => "tool_call",
        DeclaredStepKind::Job => "job",
        DeclaredStepKind::SemanticChange => "semantic_change",
        DeclaredStepKind::TestBuild => "test_build",
        DeclaredStepKind::PublicationRequest => "publication_request",
    }
}

/// `workflow inspect <workflow.json>`: structural decode only, no validation
/// performed -- a document that `validate` would reject can still be
/// inspected here, the same relationship `audit inspect` has to
/// `audit verify`.
pub(crate) fn run_inspect(path: &Path) -> Result<String, Diagnostic> {
    let bytes = read_bounded(path, "workflow graph document")?;
    let graph = graph_wire::parse_graph(&bytes)?;
    let mut out = format!(
        "workflow inspect: {}\nentry: {}\nsteps: {}\n",
        path.display(),
        graph.entry.0,
        graph.steps.len()
    );
    for step in &graph.steps {
        out.push_str(&format!(
            "  {} : {} (in_ports={}, out_ports={})\n",
            step.id.0,
            step_kind_label(&step.kind),
            step.in_ports.len(),
            step.out_ports.len()
        ));
    }
    out.push_str(&format!("edges: {}\n", graph.edges.len()));
    for edge in &graph.edges {
        out.push_str(&format!(
            "  {} : {}.{} -> {}.{}\n",
            edge.id.0, edge.from.0, edge.from_port.0, edge.to.0, edge.to_port.0
        ));
    }
    out.push_str("status: INSPECTED (structural decode only; nothing was validated or run)\n");
    Ok(out)
}

/// `workflow validate <workflow.json>`: decodes, then runs
/// `WorkflowGraph::validate`. Fails closed (a nonzero exit) on the first
/// structural rule the owning module's own validator rejects, exactly as
/// `audit verify` fails closed on the first rule `audit_capsule` rejects.
pub(crate) fn run_validate(path: &Path) -> Result<String, Diagnostic> {
    let bytes = read_bounded(path, "workflow graph document")?;
    let graph = graph_wire::parse_graph(&bytes)?;
    graph.validate().map_err(|error| {
        check_failed(format!("{} does not validate: {error:?}", path.display()))
    })?;
    Ok(format!(
        "workflow validate: {}\nsteps: {}\nedges: {}\nstatus: VALID\n",
        path.display(),
        graph.steps.len(),
        graph.edges.len()
    ))
}

/// `workflow checkpoint <checkpoint.json>`: decodes a checkpoint wire
/// document and reports its recorded state. Never resumes or migrates
/// anything -- `Checkpoint::resume`/`Checkpoint::migrate` need a live
/// expected revision and ledger this front has no business inventing from a
/// bare file path.
pub(crate) fn run_checkpoint(path: &Path) -> Result<String, Diagnostic> {
    let bytes = read_bounded(path, "checkpoint document")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| document_error(format!("{} is not valid UTF-8", path.display())))?;
    let checkpoint = Checkpoint::decode(text).map_err(|error| {
        document_error(format!(
            "{} is not a valid checkpoint document: {error:?}",
            path.display()
        ))
    })?;
    let mut out = format!(
        "workflow checkpoint: {}\nrevision: {}\nstep: {}\nsequence: {}\n",
        path.display(),
        checkpoint.revision().0,
        checkpoint.step().0,
        checkpoint.sequence()
    );
    let ledger = checkpoint.ledger_snapshot();
    out.push_str(&format!("compensation ledger entries: {}\n", ledger.len()));
    for (step, run) in ledger {
        out.push_str(&format!("  step {step} run {run}\n"));
    }
    out.push_str(
        "status: DECODED (representation only; carries no signature and no live authority)\n",
    );
    Ok(out)
}

/// `workflow dispatch <policy.json> <request.json>`: the one decide-and-record
/// verb this front exposes. See the module docs for why the full engine is
/// not exposed and why this one narrow slice is safe to be.
pub(crate) fn run_dispatch(policy_path: &Path, request_path: &Path) -> Result<String, Diagnostic> {
    let policy_bytes = read_bounded(policy_path, "dispatch policy document")?;
    let policy = declared_dispatch::parse_policy(&policy_bytes)?;
    let request_bytes = read_bounded(request_path, "dispatch request document")?;
    let request = declared_dispatch::parse_request(&request_bytes)?;
    let target = declared_dispatch::decide(&policy, &request).map_err(|error| match error {
        DispatchError::NotInPolicy => check_failed(format!(
            "target `{}` is not a member of the declared policy",
            request.target
        )),
    })?;
    Ok(format!(
        "workflow dispatch: {} against {}\nadmitted target: {target}\n\
         status: ADMITTED (decide-and-record only; nothing was invoked, spawned, or published)\n",
        request_path.display(),
        policy_path.display(),
    ))
}

/// Runs one already-parsed [`WorkflowCommand`], returning its deterministic
/// report text.
pub(crate) fn run(command: &WorkflowCommand) -> Result<String, Diagnostic> {
    match command {
        WorkflowCommand::Inspect(path) => run_inspect(path),
        WorkflowCommand::Validate(path) => run_validate(path),
        WorkflowCommand::Checkpoint(path) => run_checkpoint(path),
        WorkflowCommand::Dispatch(policy, request) => run_dispatch(policy, request),
    }
}

#[cfg(test)]
#[path = "typed_workflow/tests.rs"]
mod tests;
