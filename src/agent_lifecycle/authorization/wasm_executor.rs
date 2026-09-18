//! `WasmStageExecutor`: the Core Wasm leg of the sealed [`super::StageExecutor`]
//! seam (#143), and an honest account of what it can and cannot do today.
//!
//! ## What this executor reuses, and what it refuses
//!
//! Per #143's hand-off, this executor must reuse the existing Wasm build and
//! the existing Node/V8 owned-data host-call arena -- the same
//! `project::derive_public_api_descriptor` +
//! `project::prepare_owned_data_npm_build` pipeline
//! `tests/agent_runtime_v1/stage_backend_parity.rs` already drives -- and
//! must not reimplement that arena for a second engine.
//!
//! That pipeline's own admission rule
//! (`src/project/public_api.rs::parameter_type`) accepts exactly four
//! parameter shapes: `i64`/`bool` by value, and `borrow Str`/`borrow SliceU8`.
//! It admits no record, no variant, and no owned-`Bytes` PARAMETER at all --
//! only `Bytes`/record/certain-nominal RESULTS. Every bound Agent stage
//! signature (`stages.rs::bind_with_step_result`) takes at least one
//! `own`/`borrow` record parameter (`Task`/`State`/`Outcome`) and, for
//! `authorize`/`reduce`, cannot be re-expressed without one. So no call this
//! crate's `authorization::dispatch` ever makes for a bound Agent stage can
//! be admitted by the existing descriptor as it stands today.
//!
//! Reaching a real argument-bearing stage call over this arena would require
//! injecting one additional, purely mechanical driver function into the
//! *compiled* program ahead of descriptor derivation (to reconstruct the
//! record/variant values inside the same translation unit the arena already
//! trusts) -- a bounded but real new piece of resolver-adjacent
//! infrastructure (it must go through the ordinary HIR resolver so cleanup
//! and loan planning stay correct), not a a call-site change within this
//! file. That is out of this file's safe scope. Calling the *existing* raw
//! Wasm export directly with hand-encoded linear-memory arguments was
//! considered and rejected: doing so without the arena's own bookkeeping is
//! exactly the "re-implement the arena" the hand-off says not to do.
//!
//! ## The concrete design for closing this (not yet implemented here)
//!
//! Audited against the current tree (#143). Named precisely so the next
//! change does not have to re-derive it:
//!
//! 1. **Synthesize driver source, do not hand-build HIR.** For one call,
//!    render a small `.spx` function as text: params restricted by
//!    construction to the four shapes [`admitted_parameter`]/
//!    [`admitted_result`] already check (`i64`/`bool` by value, `borrow
//!    Str`/`borrow SliceU8`); its body reconstructs the stage's real
//!    `Task`/`State`/`Outcome` argument as an ordinary record literal from
//!    those scalars, calls the target stage by its existing `@id`, and
//!    encodes the `Decision`/`Step` result back down to an admissible
//!    scalar -- the same encode shape `tests/agent_runtime_v1/
//!    stage_backend_parity.rs`'s hand-written wrapper cases already use for
//!    Decision/Step (#142/#143 audit history). Appending source text and
//!    re-parsing is deliberately preferred over building `ast::Function` by
//!    hand: the parser and resolver then validate every literal field
//!    against the real `Task`/`State`/`Outcome` declaration, instead of this
//!    file re-implementing that checking.
//! 2. **Get a genuine plan, the only way one exists today.** The plan
//!    builders are `loan_plan::build_plan(program: &ResolvedProgram,
//!    function: &ResolvedFunction) -> Result<LoanPlan, Diagnostic>`
//!    (`src/loan_plan.rs:112-120`) and `cleanup_plan::build::build_plan`
//!    (`src/cleanup_plan/build.rs:478-483`), but both consume an
//!    already-resolved `ResolvedFunction` -- they are not an entry point on
//!    their own. The only thing that produces one, by calling exactly those
//!    two builders internally through `resolve_function`/
//!    `resolve_function_in_scope` (`src/hir/resolve_program.rs:585-592`,
//!    `825-952`), is the whole-program pass `pub fn hir::resolve(program:
//!    &ast::Program) -> Result<ResolvedProgram, Vec<Diagnostic>>`
//!    (`src/hir.rs:433-441`), or its incremental sibling
//!    `pub(crate) fn hir::resolve_with_function_reuse` (`src/hir.rs:
//!    449-482`), which still requires the complete current `&ast::Program`
//!    and only skips replanning functions whose full AST is byte-identical
//!    to a prior resolution. **There is no resolver entry point today that
//!    adds or replans one function against an already-resolved
//!    `ResolvedProgram` without the complete source `ast::Program` that
//!    produced it** -- confirmed from `Resolver<'a> { program: &'a Program,
//!    .. }` (`src/hir.rs:563-568`), which borrows the whole AST program for
//!    the life of one resolution. So the driver must be spliced into real
//!    `.spx` source text and the *whole module* re-resolved through
//!    `hir::resolve`, not attached to the `ResolvedProgram` this executor
//!    already holds.
//! 3. **The source text this needs does not reach this file.** The only
//!    place in the reachable call graph holding the original `.spx` text is
//!    `CompiledAgentLifecycle.source: String` (`src/agent_lifecycle.rs:
//!    346-355`); parsing it back to `ast::Program` uses `pub fn
//!    crate::parse(source: &str, path: impl AsRef<Path>) -> Result<Program,
//!    Diagnostic>` (`src/lib.rs:240`), and the driver function is then one
//!    more push onto `ast::Program.functions: Vec<Function>`
//!    (`src/ast.rs:187-201`) before calling `hir::resolve` on the extended
//!    program. But `StageExecutor::execute`'s signature
//!    (`src/agent_lifecycle/authorization.rs:341-351`) receives only
//!    `program: &hir::ResolvedProgram` -- never the source text or a parsed
//!    `ast::Program` -- so nothing this file can change reaches it. Adding a
//!    parameter to that trait means editing `authorization.rs` itself (its
//!    `StageExecutor` trait, `dispatch`/`dispatch_on`, and
//!    `run_authorize_stage`) and every call site that currently calls
//!    `dispatch`/`dispatch_on`: `agent_lifecycle.rs::
//!    CompiledAgentLifecycle::evaluate` (`agent_lifecycle.rs:787`, already a
//!    documented residual bypass per `authorization.rs:262-267`),
//!    `durable.rs`, `iterative/driver.rs`, `iterative/driver/live.rs`, and
//!    `rich_stage.rs`. None of those files are `src/agent_lifecycle/
//!    authorization/**` or `tests.rs`, so this is real scope beyond a
//!    single-file change, not a fact this file's own contents could hide.
//! 4. **The re-derived program must still name the same declarations.**
//!    Re-parsing and re-resolving the whole module from text is expected to
//!    reproduce identical `DeclarationId`s for every function/record/variant
//!    already in `program` (they come from explicit `@id`s, and identity is
//!    persistent by the crate's own invariant), so the driver's call target
//!    and the caller's already-validated `prepared.function_id()` should
//!    still agree; that equivalence is asserted, not assumed, by comparing
//!    the re-resolved program's matching function against the one this
//!    executor was handed, before ever deriving a descriptor from it.
//! 5. **No admission-rule change.** The driver's own parameters/result are
//!    scalar/borrow shapes by construction, so `project::public_api::
//!    parameter_type`/`result_type` (`src/project/public_api.rs:675-688`,
//!    `690-717`) admit it unmodified; the record/variant argument and result
//!    never cross that boundary, only the driver's own scalar wrapper does.
//!
//! This executor therefore does the honest thing: it checks whether the
//! requested call's parameters and result are inside the existing
//! descriptor's admitted vocabulary, and if so, drives it for real through
//! that exact pipeline and Node; if not (the case for every real Agent
//! stage call today), it fails closed with a diagnostic naming the
//! unsupported shape rather than silently returning a wrong value or
//! panicking. It never bypasses the sealed seam and never widens it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::diagnostic::Diagnostic;
use crate::hir::{self, OwnershipMode, ResolvedType};
use crate::interpreter::retained_call::{
    PreparedRetainedCall, RetainedCallEvaluation, RetainedCallOutcome, RetainedValue,
};
use crate::project;

use crate::agent_lifecycle::stages::invariant;

use super::{sealed, ExecutionAuthority, StageExecutor};

pub(in crate::agent_lifecycle) struct WasmStageExecutor;

impl sealed::Sealed for WasmStageExecutor {}

impl StageExecutor for WasmStageExecutor {
    fn execute(
        &self,
        _authority: ExecutionAuthority,
        program: &hir::ResolvedProgram,
        prepared: &PreparedRetainedCall,
        arguments: &[RetainedValue],
        max_steps: usize,
    ) -> Result<RetainedCallEvaluation, Vec<Diagnostic>> {
        run(program, prepared, arguments, max_steps).map_err(|error| vec![error])
    }
}

fn admitted_parameter(ty: &ResolvedType, ownership: OwnershipMode) -> bool {
    matches!(
        (ty, ownership),
        (ResolvedType::I64, OwnershipMode::Value) | (ResolvedType::Bool, OwnershipMode::Value)
    )
}

fn admitted_result(ty: &ResolvedType) -> bool {
    matches!(ty, ResolvedType::I64 | ResolvedType::Bool)
}

static NEXT_PROBE: AtomicU64 = AtomicU64::new(0);

fn probe_root() -> PathBuf {
    let ordinal = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "semaprax-wasm-stage-executor-{}-{ordinal}",
        std::process::id()
    ))
}

fn run(
    program: &hir::ResolvedProgram,
    prepared: &PreparedRetainedCall,
    arguments: &[RetainedValue],
    max_steps: usize,
) -> Result<RetainedCallEvaluation, Diagnostic> {
    if !(1..=1_000_000).contains(&max_steps) {
        return Err(invariant("wasm_executor.max_steps"));
    }
    let entry = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == prepared.function_id())
        .ok_or_else(|| invariant("wasm_executor.entry.absent"))?;
    if entry.params.len() != arguments.len() || arguments.len() != prepared.parameter_count() {
        return Err(invariant("wasm_executor.argument.arity"));
    }
    if !entry
        .params
        .iter()
        .all(|parameter| admitted_parameter(&parameter.ty, parameter.ownership))
        || !admitted_result(&entry.return_type)
    {
        // The real, structural gap: see this module's doc comment. Every
        // bound Agent stage call hits this branch today.
        return Err(invariant("wasm_executor.unadmitted_stage_shape"));
    }

    let mut call_args = Vec::with_capacity(arguments.len());
    for (parameter, argument) in entry.params.iter().zip(arguments) {
        let literal = match (&parameter.ty, argument) {
            (ResolvedType::I64, RetainedValue::I64(value)) => value.to_string(),
            (ResolvedType::Bool, RetainedValue::Bool(value)) => value.to_string(),
            _ => return Err(invariant("wasm_executor.argument.shape")),
        };
        call_args.push(literal);
    }

    const FACT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let subject = project::PublicApiSubject {
        project_schema: project::PUBLIC_OWNED_DATA_PROJECT_SCHEMA,
        project_revision: FACT,
        workspace_revision: FACT,
        project_graph_digest: FACT,
    };
    let selected = vec![entry.id.as_str().to_owned()];
    let descriptor = project::derive_public_api_descriptor(program, &selected, subject)
        .map_err(|_| invariant("wasm_executor.descriptor"))?;
    let build = project::prepare_owned_data_npm_build(
        program,
        &descriptor,
        "agent-lifecycle-native-stage-executor",
        "0.1.0",
        40 * 1024 * 1024,
    )
    .map_err(|_| invariant("wasm_executor.npm_build"))?;
    let envelope: serde_json::Value =
        serde_json::from_str(build.envelope()).map_err(|_| invariant("wasm_executor.envelope"))?;

    let root = probe_root();
    std::fs::create_dir(&root).map_err(|_| invariant("wasm_executor.probe_directory"))?;
    let outcome = drive_node(&envelope, &entry.id, &call_args, &root);
    let _ = std::fs::remove_dir_all(&root);
    let stdout = outcome?;

    let value: i64 = stdout
        .trim()
        .parse()
        .map_err(|_| invariant("wasm_executor.decode"))?;
    let outcome = match entry.return_type {
        ResolvedType::I64 => RetainedCallOutcome::Returned(RetainedValue::I64(value)),
        ResolvedType::Bool => RetainedCallOutcome::Returned(RetainedValue::Bool(value != 0)),
        _ => return Err(invariant("wasm_executor.decode.result_shape")),
    };
    Ok(RetainedCallEvaluation {
        function_id: entry.id.clone(),
        outcome,
        cleanup_events: Vec::new(),
        steps_used: 0,
        max_steps,
        failure: None,
    })
}

fn drive_node(
    envelope: &serde_json::Value,
    entry_id: &hir::DeclarationId,
    call_args: &[String],
    root: &Path,
) -> Result<String, Diagnostic> {
    let directory = root.join("owned-data");
    std::fs::create_dir(&directory).map_err(|_| invariant("wasm_executor.artifact_directory"))?;
    for row in envelope["artifacts"]
        .as_array()
        .ok_or_else(|| invariant("wasm_executor.envelope.artifacts"))?
    {
        let hex = row["hex"]
            .as_str()
            .ok_or_else(|| invariant("wasm_executor.envelope.hex"))?;
        let path = row["path"]
            .as_str()
            .ok_or_else(|| invariant("wasm_executor.envelope.path"))?;
        if hex.len() % 2 != 0 {
            return Err(invariant("wasm_executor.envelope.hex"));
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let mut index = 0;
        while index < hex.len() {
            bytes.push(
                u8::from_str_radix(&hex[index..index + 2], 16)
                    .map_err(|_| invariant("wasm_executor.envelope.hex"))?,
            );
            index += 2;
        }
        std::fs::write(directory.join(path), bytes)
            .map_err(|_| invariant("wasm_executor.artifact_write"))?;
    }
    let call = format!(
        "api.functions['{}']({})",
        entry_id.as_str(),
        call_args.join(", ")
    );
    std::fs::write(
        directory.join("observe.mjs"),
        format!(
            r#"import fs from 'node:fs';
import instantiate from './semaprax.bindings.js';
const wasm = new Uint8Array(fs.readFileSync(new URL('./app.wasm', import.meta.url)));
const api = await instantiate(wasm);
process.stdout.write(String({call}));
"#
        ),
    )
    .map_err(|_| invariant("wasm_executor.driver_write"))?;
    let output = Command::new("node")
        .arg("observe.mjs")
        .current_dir(&directory)
        .output()
        .map_err(|_| invariant("wasm_executor.tool.node"))?;
    if !output.status.success() {
        return Err(invariant("wasm_executor.run"));
    }
    String::from_utf8(output.stdout).map_err(|_| invariant("wasm_executor.output_utf8"))
}
