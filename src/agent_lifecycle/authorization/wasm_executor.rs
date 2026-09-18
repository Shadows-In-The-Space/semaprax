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
//! file. That is out of this file's safe scope; see the handoff report for
//! specifics. Calling the *existing* raw Wasm export directly with
//! hand-encoded linear-memory arguments was considered and rejected: doing
//! so without the arena's own bookkeeping is exactly the "re-implement the
//! arena" the hand-off says not to do.
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
