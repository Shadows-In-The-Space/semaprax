//! `WasmStageExecutor`: the Core Wasm leg of the sealed [`super::StageExecutor`]
//! seam (#143, #182), and an exact account of what it executes and what it
//! still refuses.
//!
//! ## What this executor reuses
//!
//! Per #143's hand-off, this executor reuses the existing Wasm build and the
//! existing Node/V8 owned-data host-call arena -- the same
//! `project::derive_public_api_descriptor` +
//! `project::prepare_owned_data_npm_build` pipeline
//! `tests/agent_runtime_v1/stage_backend_parity.rs` already drives -- and does
//! not reimplement that arena for a second engine.
//!
//! ## The gap this file used to fail closed on, and how it is now crossed
//!
//! That pipeline's own admission rule
//! (`src/project/public_api.rs::parameter_type`) accepts exactly four
//! parameter shapes: `i64`/`bool` by value, and `borrow Str`/`borrow SliceU8`.
//! It admits no record, no variant, and no owned-`Bytes` PARAMETER at all.
//! Every bound Agent stage signature (`stages.rs::bind_with_step_result`)
//! takes at least one `own`/`borrow` record parameter (`Task`/`State`/
//! `Outcome`), so no bound stage call can be handed to that arena directly.
//!
//! The way across, recorded as a design by `994c6e25` and implemented here,
//! is NOT to widen that admission rule -- widening it to force a record
//! through would be exactly the "do not bypass verification in a backend"
//! prohibition. It is to inject an ordinary, fully checked SPX *driver*
//! function whose own parameters and result are inside the existing admitted
//! vocabulary by construction, and let the record/variant value live entirely
//! inside the Wasm module, never crossing the arena boundary:
//!
//! 1. **Synthesize driver source, do not hand-build HIR.** For one stage
//!    call this renders the call's arguments as ordinary `.spx` literals
//!    (`State { objective: bytes_copy(array_as_slice(seed)), budget: 10, ..
//!    }`) inside a zero-parameter function, calls the stage by its real
//!    source name, and projects the result down to one admitted leaf --
//!    exactly the shape the hand-written `case.*` wrappers in
//!    `tests/agent_runtime_v1/stage_backend_parity.rs` already use and that
//!    all four engines already agree on. Appending source text and
//!    re-parsing is deliberately preferred over building `ast::Function` by
//!    hand: the parser, verifier and resolver then validate every literal
//!    field against the real declaration instead of this file
//!    re-implementing that checking.
//! 2. **Get a genuine plan, the only way one exists today.**
//!    `loan_plan::build_plan` and `cleanup_plan::build::build_plan` both
//!    consume an already-resolved `ResolvedFunction`, and the only thing
//!    that produces one is the whole-program pass `hir::resolve`, which
//!    needs the complete source `ast::Program`. So the driver is spliced
//!    into real `.spx` text and the whole module is re-checked and
//!    re-resolved through `crate::check` + `hir::resolve` + `hir::validate`,
//!    the same three calls `compile_agent_lifecycle` itself makes. The
//!    driver therefore has a real `CleanupPlan`/`LoanPlan`, not a
//!    hand-forged one.
//! 3. **The source text reaches this file explicitly.** [`WasmStageExecutor`]
//!    holds the module source it was constructed with, supplied by the
//!    caller through `super::StageBackend::Wasm { source }`. Nothing is read
//!    from the filesystem and no ambient authority is acquired.
//! 4. **The re-derived program must still be the same program.** Driver text
//!    is appended after the existing source, so every existing declaration's
//!    byte offsets, spans and `@id` identities are unchanged. That is
//!    asserted rather than assumed: the re-resolved entry function is
//!    compared for exact equality against the `ResolvedFunction` this
//!    executor was handed, and a mismatch fails closed before any artifact
//!    is built.
//! 5. **No admission-rule change.** Each driver takes either no parameters
//!    or one `i64` by value, and returns `i64` or owned `Bytes` --
//!    `project::public_api::parameter_type` and `result_type` already admit
//!    all of those unmodified. The record/variant argument and result never
//!    cross that boundary.
//!
//! ## What is still refused
//!
//! This executor's closed result vocabulary is the same one
//! `native_executor.rs` uses: a record or variant whose leaves are all
//! `Bytes` or `i64`. A bare scalar result still takes the direct path (no
//! driver needed); anything else -- a nested record leaf, a `Str`/`Float`
//! leaf, a generic instantiation, a variant case with no fields, an empty
//! `Bytes` argument, or `i64::MIN` -- fails closed with an `SPX-G570`
//! diagnostic naming the unsupported shape rather than guessing.
//!
//! ## What this is not
//!
//! Running a stage body in a real Core Wasm module under a real engine is
//! not the same as running the Agent *lifecycle* on Wasm. Budgets,
//! cancellation, the effect/model request protocol and per-turn grant
//! material all still live in the interpreter-side driver and are untouched
//! here; `steps_used` is reported as `0` because Wasm does not count
//! interpreter steps, exactly as `native_executor.rs` already does. The
//! evidence this backend supports is local and re-runnable: it requires a
//! `node` on PATH and claims nothing about hosted, browser, or production
//! support.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::diagnostic::Diagnostic;
use crate::hir::{
    self, DeclarationId, OwnershipMode, ResolvedFieldDeclaration, ResolvedFunction, ResolvedType,
    ResolvedTypeDeclarationKind,
};
use crate::interpreter::retained_call::{
    PreparedRetainedCall, RetainedCallEvaluation, RetainedCallOutcome, RetainedField,
    RetainedRecord, RetainedValue, RetainedVariant,
};
use crate::project;

use crate::agent_lifecycle::stages::invariant;

use super::{sealed, ExecutionAuthority, StageExecutor};

/// The Core Wasm stage executor, carrying the exact module source text it is
/// allowed to re-resolve. It reads no file and opens no network; the source
/// is data the caller hands it.
pub(in crate::agent_lifecycle) struct WasmStageExecutor<'a> {
    pub(super) source: &'a str,
}

impl sealed::Sealed for WasmStageExecutor<'_> {}

impl StageExecutor for WasmStageExecutor<'_> {
    fn execute(
        &self,
        _authority: ExecutionAuthority,
        program: &hir::ResolvedProgram,
        prepared: &PreparedRetainedCall,
        arguments: &[RetainedValue],
        max_steps: usize,
    ) -> Result<RetainedCallEvaluation, Vec<Diagnostic>> {
        run(self.source, program, prepared, arguments, max_steps).map_err(|error| vec![error])
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
    source: &str,
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
    if entry
        .params
        .iter()
        .all(|parameter| admitted_parameter(&parameter.ty, parameter.ownership))
        && admitted_result(&entry.return_type)
    {
        return run_direct(program, entry, arguments, max_steps);
    }
    run_through_injected_driver(source, program, entry, arguments, max_steps)
}

// ---------------------------------------------------------------------------
// The direct path: a call the existing descriptor already admits unchanged.
// ---------------------------------------------------------------------------

fn run_direct(
    program: &hir::ResolvedProgram,
    entry: &ResolvedFunction,
    arguments: &[RetainedValue],
    max_steps: usize,
) -> Result<RetainedCallEvaluation, Diagnostic> {
    let mut call_args = Vec::with_capacity(arguments.len());
    for (parameter, argument) in entry.params.iter().zip(arguments) {
        let literal = match (&parameter.ty, argument) {
            // The generated bindings' own argument snapshot requires a
            // genuine JS `bigint` for an `i64` parameter, never a `Number` --
            // an un-suffixed literal like `10` is rejected with "argument 0
            // must be signed i64 bigint" before the call is even attempted.
            // Unlike the injected-driver path's SPX literal (which has no
            // negative-integer-literal syntax and must synthesize `0 - N`),
            // this is a JS expression: `-9223372036854775808n` is a plain
            // valid BigInt literal, so `i64::MIN` needs no special case here.
            (ResolvedType::I64, RetainedValue::I64(value)) => format!("{value}n"),
            (ResolvedType::Bool, RetainedValue::Bool(value)) => value.to_string(),
            _ => return Err(invariant("wasm_executor.argument.shape")),
        };
        call_args.push(literal);
    }
    // The decode below always parses plain decimal text as `i64`. A raw
    // `i64` result is a `bigint`, which THROWS if concatenated with the
    // trailing `'\n'` string (`out.map(value => value + '\n')` in
    // `drive_node`) rather than coercing like a `Number` or `boolean` would;
    // a raw `bool` result prints as `"true"`/`"false"`, which the same `i64`
    // parse cannot read either. Both are normalized to decimal text here
    // instead of guessing a decode per return type below.
    let call = match entry.return_type {
        ResolvedType::I64 => format!(
            "String(api.functions['{}']({}))",
            entry.id.as_str(),
            call_args.join(", ")
        ),
        ResolvedType::Bool => format!(
            "(api.functions['{}']({}) ? 1 : 0)",
            entry.id.as_str(),
            call_args.join(", ")
        ),
        _ => return Err(invariant("wasm_executor.decode.result_shape")),
    };
    let stdout = build_and_drive(program, &[entry.id.as_str().to_owned()], &[call])?;
    let value: i64 = stdout
        .trim()
        .parse()
        .map_err(|_| invariant("wasm_executor.decode"))?;
    let outcome = match entry.return_type {
        ResolvedType::I64 => RetainedCallOutcome::Returned(RetainedValue::I64(value)),
        ResolvedType::Bool => RetainedCallOutcome::Returned(RetainedValue::Bool(value != 0)),
        _ => return Err(invariant("wasm_executor.decode.result_shape")),
    };
    Ok(evaluation(entry, outcome, max_steps))
}

fn evaluation(
    entry: &ResolvedFunction,
    outcome: RetainedCallOutcome,
    max_steps: usize,
) -> RetainedCallEvaluation {
    RetainedCallEvaluation {
        function_id: entry.id.clone(),
        outcome,
        cleanup_events: Vec::new(),
        // Core Wasm does not count interpreter steps; `native_executor.rs`
        // reports the same `0` for the same reason. Step counts are not
        // claimed comparable across engines.
        steps_used: 0,
        max_steps,
        failure: None,
    }
}

// ---------------------------------------------------------------------------
// The injected-driver path: the record/variant value never leaves the module.
// ---------------------------------------------------------------------------

/// One admitted projection leaf: what a single driver function returns.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Leaf {
    Scalar,
    Bytes,
}

impl Leaf {
    fn of(ty: &ResolvedType) -> Option<Self> {
        match ty {
            ResolvedType::I64 => Some(Self::Scalar),
            ResolvedType::Bytes => Some(Self::Bytes),
            _ => None,
        }
    }
}

/// How one driver hands its leaf back across the arena boundary.
///
/// `IndexedBytes` exists because of a real, cited language rule, not an
/// executor shortcut: a `Bytes` payload carried by a variant CASE cannot
/// leave a `match own` arm at all. `SPX-T216` ("owned variant match arms
/// must return a Copy i64 or bool value") and `SPX-T258` ("aggregate-valued
/// match arms are outside the executable match profile") both refuse it. So
/// a variant case's `Bytes` leaf is read one byte at a time through an
/// ordinary `i64`-returning call inside the arm -- exactly the idiom
/// `std/bytes/src/bytes.spx::get_or` already uses -- with `-1` for "past the
/// end", a value no byte can take. A record's `Bytes` field has no such
/// restriction and is returned whole.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Projection {
    Scalar,
    OwnedBytes,
    IndexedBytes,
}

impl Projection {
    fn signature(self, name: &str) -> String {
        match self {
            Self::Scalar => format!("fn {name}() -> i64"),
            Self::OwnedBytes => format!("fn {name}() -> Bytes"),
            Self::IndexedBytes => format!("fn {name}(spx_index: i64) -> i64"),
        }
    }
}

/// The bound on one indexed byte stream. Exceeding it throws in the host
/// script, which fails the whole dispatch; it never truncates a payload.
const BYTE_STREAM_CAP: usize = 65_536;

/// The helper functions an `IndexedBytes` projection calls from inside a
/// `match own` arm. They are ordinary checked SPX -- `u8`-to-`i64` and
/// `i64`-to-`usize` widening written as the repository's own `std/bytes`
/// package writes them, because the language admits no cast for either.
const BYTE_HELPERS: &str = r#"
@id("wasm.stage.helper.byte-to-i64")
fn spx_wasm_stage_helper_byte_to_i64(byte: u8) -> i64
{
    let mut value = 0;
    let mut probe = 0u8;
    while probe != byte {
        value = value + 1;
        probe = probe + 1u8;
        probe != byte
    }
    value
}

@id("wasm.stage.helper.index")
fn spx_wasm_stage_helper_index(value: i64) -> usize
{
    let mut remaining = value;
    let mut count = 0usize;
    while remaining > 0 {
        remaining = remaining - 1;
        count = count + 1usize;
        remaining > 0
    }
    count
}

@id("wasm.stage.helper.byte-at")
fn spx_wasm_stage_helper_byte_at(payload: own Bytes, index: i64) -> i64
{
    let view = bytes_as_slice(payload);
    match byte_get(view, spx_wasm_stage_helper_index(index)) { Option::Some { value: byte } => spx_wasm_stage_helper_byte_to_i64(byte), Option::None {} => -1, }
}
"#;

struct FieldLeaf {
    field: DeclarationId,
    name: String,
    leaf: Leaf,
}

fn field_leaves(fields: &[ResolvedFieldDeclaration]) -> Result<Vec<FieldLeaf>, Diagnostic> {
    if fields.is_empty() {
        return Err(invariant("wasm_executor.result.empty_fields"));
    }
    fields
        .iter()
        .map(|field| {
            Leaf::of(&field.ty)
                .map(|leaf| FieldLeaf {
                    field: field.id.clone(),
                    name: field.name.clone(),
                    leaf,
                })
                .ok_or_else(|| invariant("wasm_executor.result.leaf"))
        })
        .collect()
}

struct CasePlan {
    case: DeclarationId,
    name: String,
    fields: Vec<FieldLeaf>,
}

enum ResultPlan {
    Record {
        record: DeclarationId,
        fields: Vec<FieldLeaf>,
    },
    Variant {
        variant: DeclarationId,
        name: String,
        cases: Vec<CasePlan>,
    },
}

fn nominal_declaration<'a>(
    program: &'a hir::ResolvedProgram,
    ty: &ResolvedType,
) -> Result<&'a hir::ResolvedTypeDeclaration, Diagnostic> {
    let ResolvedType::Nominal {
        declaration,
        arguments,
    } = ty
    else {
        return Err(invariant("wasm_executor.result.shape"));
    };
    if !arguments.is_empty() {
        return Err(invariant("wasm_executor.result.generic"));
    }
    program
        .types
        .iter()
        .find(|item| item.id == *declaration)
        .ok_or_else(|| invariant("wasm_executor.result.declaration"))
}

impl ResultPlan {
    fn derive(program: &hir::ResolvedProgram, ty: &ResolvedType) -> Result<Self, Diagnostic> {
        let declaration = nominal_declaration(program, ty)?;
        match &declaration.kind {
            ResolvedTypeDeclarationKind::Record { fields } => Ok(Self::Record {
                record: declaration.id.clone(),
                fields: field_leaves(fields)?,
            }),
            ResolvedTypeDeclarationKind::Variant { cases } => {
                if cases.is_empty() {
                    return Err(invariant("wasm_executor.result.empty_variant"));
                }
                let mut planned = Vec::with_capacity(cases.len());
                for case in cases {
                    planned.push(CasePlan {
                        case: case.id.clone(),
                        name: case.name.clone(),
                        fields: field_leaves(&case.fields)?,
                    });
                }
                Ok(Self::Variant {
                    variant: declaration.id.clone(),
                    name: declaration.name.clone(),
                    cases: planned,
                })
            }
            _ => Err(invariant("wasm_executor.result.kind")),
        }
    }
}

/// One synthesized driver function: one leaf of the stage's real result.
struct Driver {
    id: String,
    name: String,
    projection: Projection,
    tail: String,
}

/// Renders every `match own` arm of one variant projection, binding each
/// case's fields to fresh names so no arm can shadow another.
fn variant_arms(
    variant_name: &str,
    cases: &[CasePlan],
    arm: impl Fn(usize, &CasePlan) -> String,
) -> String {
    let mut rendered = String::new();
    for (index, case) in cases.iter().enumerate() {
        let bindings = case
            .fields
            .iter()
            .enumerate()
            .map(|(position, field)| format!("{}: spx_f{position}", field.name))
            .collect::<Vec<_>>()
            .join(", ");
        rendered.push_str(&format!(
            "        {variant_name}::{} {{ {bindings} }} => {},\n",
            case.name,
            arm(index, case)
        ));
    }
    rendered
}

fn drivers_for(plan: &ResultPlan) -> Vec<Driver> {
    let mut drivers = Vec::new();
    match plan {
        ResultPlan::Record { fields, .. } => {
            for field in fields {
                drivers.push(Driver {
                    id: format!("wasm.stage.driver.{}", drivers.len()),
                    name: format!("spx_wasm_stage_driver_{}", drivers.len()),
                    projection: match field.leaf {
                        Leaf::Scalar => Projection::Scalar,
                        Leaf::Bytes => Projection::OwnedBytes,
                    },
                    tail: format!("    spx_call.{}\n", field.name),
                });
            }
        }
        ResultPlan::Variant { name, cases, .. } => {
            // Driver 0 is the discriminant: which case the stage actually
            // took. Every later driver reads one field of one case, so the
            // reconstructed variant carries the real case and the real
            // payload, not a guess.
            let tag = variant_arms(name, cases, |index, _| index.to_string());
            drivers.push(Driver {
                id: "wasm.stage.driver.0".to_owned(),
                name: "spx_wasm_stage_driver_0".to_owned(),
                projection: Projection::Scalar,
                tail: format!("    match own spx_call {{\n{tag}    }}\n"),
            });
            for (case_index, case) in cases.iter().enumerate() {
                for (position, field) in case.fields.iter().enumerate() {
                    let ordinal = drivers.len();
                    let arms = variant_arms(name, cases, |index, _| {
                        match (index == case_index, field.leaf) {
                            (true, Leaf::Scalar) => format!("spx_f{position}"),
                            (true, Leaf::Bytes) => {
                                format!("spx_wasm_stage_helper_byte_at(spx_f{position}, spx_index)")
                            }
                            // A non-selected arm never contributes to the
                            // decoded value: driver 0 already fixed which case
                            // the stage took. `-1` is the same "past the end"
                            // sentinel the indexed read uses, so a
                            // non-selected byte stream is empty rather than
                            // wrong.
                            (false, Leaf::Scalar) => "0".to_owned(),
                            (false, Leaf::Bytes) => "-1".to_owned(),
                        }
                    });
                    drivers.push(Driver {
                        id: format!("wasm.stage.driver.{ordinal}"),
                        name: format!("spx_wasm_stage_driver_{ordinal}"),
                        projection: match field.leaf {
                            Leaf::Scalar => Projection::Scalar,
                            Leaf::Bytes => Projection::IndexedBytes,
                        },
                        tail: format!("    match own spx_call {{\n{arms}    }}\n"),
                    });
                }
            }
        }
    }
    drivers
}

/// Renders one `RetainedValue` as an `.spx` expression, pushing any
/// supporting `let` bindings onto `prelude`.
///
/// The declared parameter type is checked against the runtime shape here, so
/// a malformed argument is refused before any source is synthesized rather
/// than becoming a parse error later.
fn render_value(
    program: &hir::ResolvedProgram,
    ty: &ResolvedType,
    value: &RetainedValue,
    prelude: &mut String,
    next: &mut usize,
) -> Result<String, Diagnostic> {
    match (ty, value) {
        (ResolvedType::Bool, RetainedValue::Bool(item)) => Ok(item.to_string()),
        (ResolvedType::I64, RetainedValue::I64(item)) => {
            if *item >= 0 {
                Ok(item.to_string())
            } else if *item == i64::MIN {
                Err(invariant("wasm_executor.argument.i64_min"))
            } else {
                let name = format!("spx_lit{next}");
                *next += 1;
                prelude.push_str(&format!("    let {name} = 0 - {};\n", -*item));
                Ok(name)
            }
        }
        (ResolvedType::Usize, RetainedValue::Usize(item)) => Ok(format!("{item}usize")),
        (ResolvedType::U8, RetainedValue::U8(item)) => Ok(format!("{item}u8")),
        (ResolvedType::I32, RetainedValue::I32(item)) if *item >= 0 => Ok(format!("{item}i32")),
        (ResolvedType::Bytes, RetainedValue::Bytes(item)) => {
            if item.is_empty() {
                // An empty array literal has no admitted spelling here; refuse
                // rather than synthesize a value the stage never received.
                return Err(invariant("wasm_executor.argument.empty_bytes"));
            }
            let name = format!("spx_lit{next}");
            *next += 1;
            let elements = item
                .iter()
                .map(|byte| format!("{byte}u8"))
                .collect::<Vec<_>>()
                .join(", ");
            prelude.push_str(&format!("    let {name} = [{elements}];\n"));
            Ok(format!("bytes_copy(array_as_slice({name}))"))
        }
        (ResolvedType::Nominal { .. }, RetainedValue::Record(record)) => {
            let declaration = nominal_declaration(program, ty)?;
            if declaration.id != record.record {
                return Err(invariant("wasm_executor.argument.shape"));
            }
            let ResolvedTypeDeclarationKind::Record { fields } = &declaration.kind else {
                return Err(invariant("wasm_executor.argument.shape"));
            };
            let rendered = render_fields(program, fields, &record.fields, prelude, next)?;
            Ok(format!("{} {{ {rendered} }}", declaration.name))
        }
        (ResolvedType::Nominal { .. }, RetainedValue::Variant(variant)) => {
            let declaration = nominal_declaration(program, ty)?;
            if declaration.id != variant.variant {
                return Err(invariant("wasm_executor.argument.shape"));
            }
            let ResolvedTypeDeclarationKind::Variant { cases } = &declaration.kind else {
                return Err(invariant("wasm_executor.argument.shape"));
            };
            let case = cases
                .iter()
                .find(|item| item.id == variant.case)
                .ok_or_else(|| invariant("wasm_executor.argument.case"))?;
            let rendered = render_fields(program, &case.fields, &variant.fields, prelude, next)?;
            Ok(format!(
                "{}::{} {{ {rendered} }}",
                declaration.name, case.name
            ))
        }
        _ => Err(invariant("wasm_executor.argument.shape")),
    }
}

/// Renders a carrier's fields in DECLARED order, regardless of the order the
/// caller supplied them in, and refuses a missing or duplicated field.
fn render_fields(
    program: &hir::ResolvedProgram,
    declared: &[ResolvedFieldDeclaration],
    supplied: &[RetainedField],
    prelude: &mut String,
    next: &mut usize,
) -> Result<String, Diagnostic> {
    if declared.len() != supplied.len() {
        return Err(invariant("wasm_executor.argument.field_count"));
    }
    let mut rendered = Vec::with_capacity(declared.len());
    for field in declared {
        let mut matching = supplied.iter().filter(|item| item.field == field.id);
        let item = matching
            .next()
            .ok_or_else(|| invariant("wasm_executor.argument.field_absent"))?;
        if matching.next().is_some() {
            return Err(invariant("wasm_executor.argument.field_duplicate"));
        }
        let expression = render_value(program, &field.ty, &item.value, prelude, next)?;
        rendered.push(format!("{}: {expression}", field.name));
    }
    Ok(rendered.join(", "))
}

fn run_through_injected_driver(
    source: &str,
    program: &hir::ResolvedProgram,
    entry: &ResolvedFunction,
    arguments: &[RetainedValue],
    max_steps: usize,
) -> Result<RetainedCallEvaluation, Diagnostic> {
    let plan = ResultPlan::derive(program, &entry.return_type)?;

    let mut prelude = String::new();
    let mut next = 0usize;
    let mut call_args = Vec::with_capacity(arguments.len());
    for (index, (parameter, argument)) in entry.params.iter().zip(arguments).enumerate() {
        let expression = render_value(program, &parameter.ty, argument, &mut prelude, &mut next)?;
        // Every argument is bound to a local before the call, so a borrowed
        // aggregate parameter receives a place rather than a temporary --
        // the same shape the hand-written parity wrappers use.
        prelude.push_str(&format!("    let spx_arg{index} = {expression};\n"));
        call_args.push(format!("spx_arg{index}"));
    }
    let call = format!("{}({})", entry.name, call_args.join(", "));

    let drivers = drivers_for(&plan);
    let mut injected = String::from("\n");
    if drivers
        .iter()
        .any(|driver| driver.projection == Projection::IndexedBytes)
    {
        injected.push_str(BYTE_HELPERS);
    }
    for driver in &drivers {
        injected.push_str(&format!(
            "\n@id(\"{}\")\n{}\n{{\n",
            driver.id,
            driver.projection.signature(&driver.name)
        ));
        injected.push_str(&prelude);
        injected.push_str(&format!("    let spx_call = {call};\n"));
        injected.push_str(&driver.tail);
        injected.push_str("}\n");
    }

    let extended = format!("{source}{injected}");
    let parsed = crate::check(
        &extended,
        Path::new("agent-lifecycle-wasm-stage-driver.spx"),
    )
    .map_err(|_| invariant("wasm_executor.driver.check"))?;
    let resolved = hir::resolve(&parsed).map_err(|_| invariant("wasm_executor.driver.resolve"))?;
    hir::validate(&resolved).map_err(|_| invariant("wasm_executor.driver.validate"))?;

    // The re-resolved module must still BE the module this executor was
    // handed: driver text is appended, so every earlier declaration keeps its
    // byte offsets, spans and persistent `@id`. Asserted, never assumed.
    let reresolved_entry = resolved
        .functions
        .iter()
        .find(|function| function.id == entry.id)
        .ok_or_else(|| invariant("wasm_executor.driver.entry_absent"))?;
    if reresolved_entry != entry {
        return Err(invariant("wasm_executor.driver.entry_diverged"));
    }

    let selected = drivers
        .iter()
        .map(|driver| driver.id.clone())
        .collect::<Vec<_>>();
    let calls = drivers
        .iter()
        .map(|driver| match driver.projection {
            Projection::Scalar => format!("String(api.functions['{}']())", driver.id),
            Projection::OwnedBytes => format!(
                "Array.from(api.functions['{}'](), b => b.toString(16).padStart(2, '0')).join('')",
                driver.id
            ),
            // Reads the variant case's byte payload one byte at a time until
            // the module reports `-1` (past the end). The cap is a
            // fail-closed bound, not a silent truncation: exceeding it throws
            // and the whole dispatch is refused.
            Projection::IndexedBytes => format!(
                "(() => {{ let hex = ''; for (let i = 0; ; i += 1) {{ \
                 if (i > {BYTE_STREAM_CAP}) throw new Error('indexed byte stream cap'); \
                 const byte = api.functions['{}'](BigInt(i)); \
                 if (byte < 0n) break; \
                 hex += Number(byte).toString(16).padStart(2, '0'); }} return hex; }})()",
                driver.id
            ),
        })
        .collect::<Vec<_>>();
    let stdout = build_and_drive(&resolved, &selected, &calls)?;

    let lines = stdout.lines().collect::<Vec<_>>();
    if lines.len() != drivers.len() {
        return Err(invariant("wasm_executor.decode.arity"));
    }
    let mut leaves = Vec::with_capacity(drivers.len());
    for (driver, line) in drivers.iter().zip(&lines) {
        leaves.push(match driver.projection {
            Projection::Scalar => RetainedValue::I64(
                line.trim()
                    .parse()
                    .map_err(|_| invariant("wasm_executor.decode.scalar"))?,
            ),
            Projection::OwnedBytes | Projection::IndexedBytes => {
                RetainedValue::Bytes(decode_hex(line.trim())?)
            }
        });
    }

    let outcome = match plan {
        ResultPlan::Record { record, fields } => {
            RetainedCallOutcome::Returned(RetainedValue::Record(RetainedRecord {
                record,
                fields: fields
                    .into_iter()
                    .zip(leaves)
                    .map(|(field, value)| RetainedField {
                        field: field.field,
                        value,
                    })
                    .collect(),
            }))
        }
        ResultPlan::Variant { variant, cases, .. } => {
            let RetainedValue::I64(tag) = leaves[0] else {
                return Err(invariant("wasm_executor.decode.tag"));
            };
            let index = usize::try_from(tag).map_err(|_| invariant("wasm_executor.decode.tag"))?;
            let case = cases
                .get(index)
                .ok_or_else(|| invariant("wasm_executor.decode.tag"))?;
            // Driver 0 is the tag; the remaining drivers are laid out case by
            // case in declaration order, so the selected case's own leaves
            // start after every earlier case's.
            let start = 1 + cases
                .iter()
                .take(index)
                .map(|item| item.fields.len())
                .sum::<usize>();
            let mut fields = Vec::with_capacity(case.fields.len());
            for (position, field) in case.fields.iter().enumerate() {
                fields.push(RetainedField {
                    field: field.field.clone(),
                    value: leaves
                        .get(start + position)
                        .ok_or_else(|| invariant("wasm_executor.decode.arity"))?
                        .clone(),
                });
            }
            RetainedCallOutcome::Returned(RetainedValue::Variant(RetainedVariant {
                variant,
                case: case.case.clone(),
                fields,
            }))
        }
    };
    Ok(evaluation(entry, outcome, max_steps))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, Diagnostic> {
    if hex.len() % 2 != 0 {
        return Err(invariant("wasm_executor.decode.bytes"));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut index = 0;
    while index < hex.len() {
        bytes.push(
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| invariant("wasm_executor.decode.bytes"))?,
        );
        index += 2;
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// The shared build-and-run path: one owned-data package, one Node process.
// ---------------------------------------------------------------------------

fn build_and_drive(
    program: &hir::ResolvedProgram,
    selected: &[String],
    calls: &[String],
) -> Result<String, Diagnostic> {
    const FACT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let subject = project::PublicApiSubject {
        project_schema: project::PUBLIC_OWNED_DATA_PROJECT_SCHEMA,
        project_revision: FACT,
        workspace_revision: FACT,
        project_graph_digest: FACT,
    };
    let descriptor = project::derive_public_api_descriptor(program, selected, subject)
        .map_err(|_| invariant("wasm_executor.descriptor"))?;
    let build = project::prepare_owned_data_npm_build(
        program,
        &descriptor,
        "agent-lifecycle-wasm-stage-executor",
        "0.1.0",
        40 * 1024 * 1024,
    )
    .map_err(|_| invariant("wasm_executor.npm_build"))?;
    let envelope: serde_json::Value =
        serde_json::from_str(build.envelope()).map_err(|_| invariant("wasm_executor.envelope"))?;

    let root = probe_root();
    std::fs::create_dir(&root).map_err(|_| invariant("wasm_executor.probe_directory"))?;
    let outcome = drive_node(&envelope, calls, &root);
    let _ = std::fs::remove_dir_all(&root);
    outcome
}

fn drive_node(
    envelope: &serde_json::Value,
    calls: &[String],
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
        std::fs::write(directory.join(path), decode_hex(hex)?)
            .map_err(|_| invariant("wasm_executor.artifact_write"))?;
    }
    let emissions = calls
        .iter()
        .map(|call| format!("out.push({call});"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        directory.join("observe.mjs"),
        format!(
            r#"import fs from 'node:fs';
import instantiate from './semaprax.bindings.js';
const wasm = new Uint8Array(fs.readFileSync(new URL('./app.wasm', import.meta.url)));
const api = await instantiate(wasm);
const out = [];
{emissions}
process.stdout.write(out.map(value => value + '\n').join(''));
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
