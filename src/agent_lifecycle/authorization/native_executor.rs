//! `NativeStageExecutor`: the native C11 leg of the sealed [`super::StageExecutor`]
//! seam (#142).
//!
//! This executor never invents a second code-generation path. It compiles the
//! *entire* module through [`crate::codegen::emit_hir_c`] -- the exact,
//! already-proven-equivalent general native backend
//! `tests/agent_runtime_v1/stage_backend_parity.rs` exercises -- and then
//! appends one small, hand-written `main` that calls the bound stage's own
//! `spx_decl_<hex>` symbol directly, exactly the calling convention that
//! parity test's `native_probe` already establishes. It performs no codegen
//! of its own: every semantic byte of the stage body comes from
//! `emit_hir_c`.
//!
//! ## Scope, stated precisely
//!
//! The only values this executor can marshal across the C boundary are the
//! closed vocabulary [`super::super::stages`] already restricts Agent stage
//! signatures to: `i64`/`bool`/`u8`/`usize` scalars, one level of
//! `own`/`borrow` record arguments built only from `Bytes`/`i64`/`bool` leaves
//! (`Task`/`State`/`Observation`/`Outcome`), and record or two-/four-case
//! variant results whose leaves are `Bytes`, `i64`, `bool`, or `u8`, plus record
//! results that may additionally carry `usize` (`Decision`/`Report`/`Step`).
//! Record
//! and variant field/case C member names are recomputed here from each
//! field's persistent [`DeclarationId`] using the exact hex-encoding
//! `src/codegen/native_emit/symbols.rs` uses (`spx_record_<hex>`,
//! `spx_field_<hex>`, ...); field *order* and byte-leaf placement are never
//! guessed -- both come straight from
//! [`crate::aggregate_layout::AggregateLayout`] /
//! [`crate::variant_layout::VariantLayout`], the same `pub(crate)` layout
//! authority the native backend itself consumes, so this module can never
//! silently disagree with codegen about which field lives where.
//!
//! A call outside this vocabulary (a nested record, a resource, a fifth
//! variant case, a contract failure reported through the native status
//! arena, ...) is refused with a diagnostic rather than guessed at. In
//! particular, this executor does not yet decode a native contract-failure
//! status into [`RetainedCallOutcome::LanguageFailure`]; it reports a
//! diagnostic instead. Every Agent stage body exercised by the bound
//! `stages.rs` vocabulary today is a plain deterministic function with no
//! declared effect, and the fixture this module's own tests share with
//! `stage_backend_parity.rs` carries no `requires`/`ensures` -- so this gap
//! is a scoped, honestly-reported one, not a silently-passing one.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::aggregate_layout::{AggregateLayout, AggregateTarget};
use crate::diagnostic::Diagnostic;
use crate::hir::{self, DeclarationId, OwnershipMode, ResolvedType};
use crate::interpreter::retained_call::{
    PreparedRetainedCall, RetainedCallEvaluation, RetainedCallOutcome, RetainedField,
    RetainedRecord, RetainedValue, RetainedVariant,
};
use crate::variant_layout::{VariantLayout, VariantTarget};

use crate::agent_lifecycle::stages::invariant;

use super::{sealed, ExecutionAuthority, StageExecutor};

/// The native C11 executor, parameterized by the `clang` optimization flag
/// its one compile step uses.
///
/// [`super::StageBackend::Native`] always selects [`Self::o0`] -- production
/// dispatch behavior is unchanged by this field's addition. A second
/// dispatch route, [`super::StageBackend::NativeAtOptimization`], exists
/// solely so `tests.rs`'s cross-engine parity evidence can additionally
/// compile and run the exact same stage body at `-O2`: an optimizer is
/// exactly where backend divergence hides, and `-O0` alone never exercises
/// it. Both construct this same, single `StageExecutor` implementation --
/// the optimization level is data on an existing seam, not a fourth sealed
/// executor.
pub(in crate::agent_lifecycle) struct NativeStageExecutor {
    pub(in crate::agent_lifecycle) optimization: &'static str,
}

impl NativeStageExecutor {
    pub(in crate::agent_lifecycle) const fn o0() -> Self {
        Self {
            optimization: "-O0",
        }
    }
}

impl sealed::Sealed for NativeStageExecutor {}

impl StageExecutor for NativeStageExecutor {
    fn execute(
        &self,
        _authority: ExecutionAuthority,
        program: &hir::ResolvedProgram,
        prepared: &PreparedRetainedCall,
        arguments: &[RetainedValue],
        max_steps: usize,
        cancellation: Option<&crate::agent_runtime::AgentCancellation>,
    ) -> Result<RetainedCallEvaluation, Vec<Diagnostic>> {
        if cancellation.is_some_and(crate::agent_runtime::AgentCancellation::is_cancelled) {
            return Err(vec![super::super::stages::invariant(
                "stage_executor.cancelled",
            )]);
        }
        run(program, prepared, arguments, max_steps, self.optimization).map_err(|error| vec![error])
    }
}

fn hex_symbol(prefix: &str, id: &DeclarationId) -> String {
    let mut symbol = String::from(prefix);
    for byte in id.as_str().bytes() {
        symbol.push_str(&format!("{byte:02x}"));
    }
    symbol
}

fn function_symbol(id: &DeclarationId) -> String {
    hex_symbol("spx_decl_", id)
}

fn record_symbol(id: &DeclarationId) -> String {
    hex_symbol("spx_record_", id)
}

fn variant_symbol(id: &DeclarationId) -> String {
    hex_symbol("spx_variant_", id)
}

fn case_symbol(id: &DeclarationId) -> String {
    hex_symbol("spx_case_", id)
}

fn field_symbol(id: &DeclarationId) -> String {
    hex_symbol("spx_field_", id)
}

/// The hex payload alone (no prefix), used both to print a field/case
/// identity from C and to decode it back on the Rust side without needing a
/// second, independent naming scheme.
fn hex_payload(id: &DeclarationId) -> String {
    let mut out = String::new();
    for byte in id.as_str().bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex_payload(hex: &str) -> Result<DeclarationId, Diagnostic> {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(invariant("native_executor.decode.hex"));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars = hex.as_bytes();
    let mut index = 0;
    while index < chars.len() {
        let byte = u8::from_str_radix(&hex[index..index + 2], 16)
            .map_err(|_| invariant("native_executor.decode.hex"))?;
        bytes.push(byte);
        index += 2;
    }
    let text = String::from_utf8(bytes).map_err(|_| invariant("native_executor.decode.hex"))?;
    Ok(DeclarationId::new(text))
}

fn c_i64(value: i64) -> String {
    if value == i64::MIN {
        // `INT64_C(-9223372036854775808)` asks the C preprocessor to form a
        // positive magnitude it cannot represent. Keep the same portable
        // spelling the main native backend uses for the signed minimum.
        "(-INT64_C(9223372036854775807) - INT64_C(1))".to_owned()
    } else {
        format!("INT64_C({value})")
    }
}

struct Emitter {
    body: String,
    byte_ordinal: usize,
    arg_ordinal: usize,
}

impl Emitter {
    fn new() -> Self {
        Self {
            body: String::new(),
            byte_ordinal: 0,
            arg_ordinal: 0,
        }
    }

    fn bytes_expr(&mut self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "spx_bytes_copy((spx_slice_u8_v1){ .ptr = NULL, .len = UINT64_C(0) })"
                .to_owned();
        }
        self.byte_ordinal += 1;
        let name = format!("spx_native_exec_bytes_{}", self.byte_ordinal);
        let literal = bytes
            .iter()
            .map(|byte| format!("UINT8_C(0x{byte:02x})"))
            .collect::<Vec<_>>()
            .join(", ");
        self.body.push_str(&format!(
            "    static const uint8_t {name}[] = {{ {literal} }};\n"
        ));
        format!(
            "spx_bytes_copy((spx_slice_u8_v1){{ .ptr = {name}, .len = UINT64_C({}) }})",
            bytes.len()
        )
    }

    /// Declares one local `struct spx_record_<hex> <var> = { ... };` from a
    /// [`RetainedRecord`], using the record's own [`AggregateLayout`] for
    /// field order and C member names -- never a re-derived guess.
    fn record_local(
        &mut self,
        layout: &AggregateLayout,
        record: &RetainedRecord,
        var: &str,
    ) -> Result<(), Diagnostic> {
        let mut inits = Vec::with_capacity(layout.fields.len());
        for field in &layout.fields {
            let value = record
                .fields
                .iter()
                .find(|item| item.field == field.field)
                .ok_or_else(|| invariant("native_executor.record.missing_field"))?;
            let expr = match (&field.ty, &value.value) {
                (ResolvedType::Bytes, RetainedValue::Bytes(bytes)) => self.bytes_expr(bytes),
                (ResolvedType::I64, RetainedValue::I64(scalar)) => c_i64(*scalar),
                (ResolvedType::Bool, RetainedValue::Bool(flag)) => {
                    (if *flag { "true" } else { "false" }).to_owned()
                }
                _ => return Err(invariant("native_executor.record.field_shape")),
            };
            inits.push(format!("        .{} = {expr},", field_symbol(&field.field)));
        }
        self.body.push_str(&format!(
            "    struct {} {var} = {{\n{}\n    }};\n",
            record_symbol(&layout.record),
            inits.join("\n")
        ));
        Ok(())
    }
}

/// One prepared argument: its C expression (or the name of the local it was
/// declared into) plus any borrowed-byte-path pointer parameters the
/// generated C ABI additionally requires for a borrowed aggregate.
struct PreparedArgument {
    primary: String,
    extra_borrow_pointers: Vec<String>,
}

fn prepare_argument(
    emitter: &mut Emitter,
    program: &hir::ResolvedProgram,
    ownership: OwnershipMode,
    ty: &ResolvedType,
    value: &RetainedValue,
) -> Result<PreparedArgument, Diagnostic> {
    match (ty, value) {
        (ResolvedType::I64, RetainedValue::I64(scalar)) => Ok(PreparedArgument {
            primary: c_i64(*scalar),
            extra_borrow_pointers: Vec::new(),
        }),
        (ResolvedType::Bool, RetainedValue::Bool(flag)) => Ok(PreparedArgument {
            primary: if *flag {
                "true".to_owned()
            } else {
                "false".to_owned()
            },
            extra_borrow_pointers: Vec::new(),
        }),
        (ResolvedType::U8, RetainedValue::U8(byte)) => Ok(PreparedArgument {
            primary: format!("UINT8_C({byte})"),
            extra_borrow_pointers: Vec::new(),
        }),
        (ResolvedType::Usize, RetainedValue::Usize(count)) => Ok(PreparedArgument {
            primary: format!("UINT64_C({count})"),
            extra_borrow_pointers: Vec::new(),
        }),
        // An `own Bytes` parameter crosses the generated C ABI by value.
        // `bytes_expr` creates the one C owner which the callee's checked
        // cleanup plan consumes; it is deliberately not a borrowed slice or
        // a pointer to a caller-owned temporary.
        (ResolvedType::Bytes, RetainedValue::Bytes(bytes)) => Ok(PreparedArgument {
            primary: emitter.bytes_expr(bytes),
            extra_borrow_pointers: Vec::new(),
        }),
        (ResolvedType::Nominal { .. }, RetainedValue::Record(record)) => {
            if record.record != *nominal_declaration(ty)? {
                return Err(invariant("native_executor.argument.record_identity"));
            }
            let layout = AggregateLayout::for_type(program, AggregateTarget::Native64, ty)
                .map_err(|_| invariant("native_executor.argument.layout"))?;
            emitter.arg_ordinal += 1;
            let var = format!("spx_native_exec_arg_{}", emitter.arg_ordinal);
            emitter.record_local(&layout, record, &var)?;
            let mut extra = Vec::new();
            if ownership == OwnershipMode::Borrow {
                for field in &layout.fields {
                    if field.ty == ResolvedType::Bytes {
                        extra.push(format!("&{var}.{}", field_symbol(&field.field)));
                    }
                }
            }
            Ok(PreparedArgument {
                primary: format!("&{var}"),
                extra_borrow_pointers: extra,
            })
        }
        _ => Err(invariant("native_executor.argument.shape")),
    }
}

fn nominal_declaration(ty: &ResolvedType) -> Result<&DeclarationId, Diagnostic> {
    match ty {
        ResolvedType::Nominal { declaration, .. } => Ok(declaration),
        _ => Err(invariant("native_executor.argument.not_nominal")),
    }
}

/// Emits the decode/print statements for one record-typed result, reusing
/// the record's own layout for field order and member names.
fn emit_record_print(
    body: &mut String,
    layout: &AggregateLayout,
    expr: &str,
) -> Result<(), Diagnostic> {
    body.push_str("    printf(\"RECORD\");\n");
    for field in &layout.fields {
        let hex = hex_payload(&field.field);
        match field.ty {
            ResolvedType::Bytes => {
                body.push_str(&format!(
                    "    printf(\" {hex}=B:\"); for (uint64_t spx_i = UINT64_C(0); spx_i < ({expr}).{member}.len; ++spx_i) printf(\"%02x\", (unsigned)((({expr}).{member}.ptr)[spx_i]));\n",
                    member = field_symbol(&field.field)
                ));
            }
            ResolvedType::I64 => {
                body.push_str(&format!(
                    "    printf(\" {hex}=I:%lld\", (long long)({expr}).{member});\n",
                    member = field_symbol(&field.field)
                ));
            }
            ResolvedType::Bool => {
                body.push_str(&format!(
                    "    printf(\" {hex}=T:%u\", (unsigned)(({expr}).{member} ? 1 : 0));\n",
                    member = field_symbol(&field.field)
                ));
            }
            ResolvedType::Usize => {
                body.push_str(&format!(
                    "    printf(\" {hex}=U:%llu\", (unsigned long long)({expr}).{member});\n",
                    member = field_symbol(&field.field)
                ));
            }
            ResolvedType::U8 => {
                body.push_str(&format!(
                    "    printf(\" {hex}=Q:%u\", (unsigned)({expr}).{member});\n",
                    member = field_symbol(&field.field)
                ));
            }
            _ => return Err(invariant("native_executor.result.leaf")),
        }
    }
    body.push_str("    printf(\"\\n\");\n");
    Ok(())
}

fn emit_variant_print(
    body: &mut String,
    layout: &VariantLayout,
    expr: &str,
) -> Result<(), Diagnostic> {
    body.push_str(&format!("    switch (({expr}).spx_tag) {{\n"));
    for case in &layout.cases {
        body.push_str(&format!("    case UINT32_C({}): {{\n", case.tag));
        body.push_str(&format!(
            "        printf(\"VARIANT {}\");\n",
            hex_payload(&case.case)
        ));
        for field in &case.fields {
            let hex = hex_payload(&field.field);
            let member = format!(
                "({expr}).spx_payload.{}.{}",
                case_symbol(&case.case),
                field_symbol(&field.field)
            );
            match field.ty {
                ResolvedType::Bytes => {
                    body.push_str(&format!(
                        "        printf(\" {hex}=B:\"); for (uint64_t spx_i = UINT64_C(0); spx_i < ({member}).len; ++spx_i) printf(\"%02x\", (unsigned)((({member}).ptr)[spx_i]));\n"
                    ));
                }
                ResolvedType::I64 => {
                    body.push_str(&format!(
                        "        printf(\" {hex}=I:%lld\", (long long)({member}));\n"
                    ));
                }
                ResolvedType::Bool => {
                    body.push_str(&format!(
                        "        printf(\" {hex}=T:%u\", (unsigned)({member} ? 1 : 0));\n"
                    ));
                }
                ResolvedType::U8 => {
                    body.push_str(&format!(
                        "        printf(\" {hex}=Q:%u\", (unsigned)({member}));\n"
                    ));
                }
                _ => return Err(invariant("native_executor.result.leaf")),
            }
        }
        body.push_str("        printf(\"\\n\");\n        break;\n    }\n");
    }
    body.push_str("    default: printf(\"INVALID_TAG\\n\"); break;\n    }\n");
    Ok(())
}

fn c_value_type_name(
    program: &hir::ResolvedProgram,
    ty: &ResolvedType,
) -> Result<String, Diagnostic> {
    match ty {
        ResolvedType::Nominal { declaration, .. } => {
            if AggregateLayout::for_type(program, AggregateTarget::Native64, ty).is_ok() {
                return Ok(format!("struct {}", record_symbol(declaration)));
            }
            if VariantLayout::for_type(program, VariantTarget::Native64, ty).is_ok() {
                return Ok(format!("struct {}", variant_symbol(declaration)));
            }
            Err(invariant("native_executor.result.shape"))
        }
        _ => Err(invariant("native_executor.result.shape")),
    }
}

static NEXT_PROBE: AtomicU64 = AtomicU64::new(0);

fn probe_root() -> PathBuf {
    let ordinal = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "semaprax-native-stage-executor-{}-{ordinal}",
        std::process::id()
    ))
}

fn run(
    program: &hir::ResolvedProgram,
    prepared: &PreparedRetainedCall,
    arguments: &[RetainedValue],
    max_steps: usize,
    optimization: &str,
) -> Result<RetainedCallEvaluation, Diagnostic> {
    if !(1..=1_000_000).contains(&max_steps) {
        return Err(invariant("native_executor.max_steps"));
    }
    let entry = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == prepared.function_id())
        .ok_or_else(|| invariant("native_executor.entry.absent"))?;
    if entry.params.len() != arguments.len() || arguments.len() != prepared.parameter_count() {
        return Err(invariant("native_executor.argument.arity"));
    }

    let mut emitter = Emitter::new();
    let mut call_args = Vec::new();
    for (parameter, argument) in entry.params.iter().zip(arguments) {
        let prepared_argument = prepare_argument(
            &mut emitter,
            program,
            parameter.ownership,
            &parameter.ty,
            argument,
        )?;
        // Each borrowed aggregate's extra `spx_bytes_v1*` byte-path
        // parameters are interleaved immediately after that same argument,
        // exactly as `codegen::native_emit::emit_function` emits them --
        // never batched at the end of the parameter list.
        call_args.push(prepared_argument.primary);
        call_args.extend(prepared_argument.extra_borrow_pointers);
    }

    let result_type = c_value_type_name(program, &entry.return_type)?;
    let symbol = function_symbol(&entry.id);

    let mut body = String::new();
    body.push_str("    struct spx_status_entry spx_status_entries[UINT32_C(32)];\n");
    body.push_str("    struct spx_context spx_ctx = {0};\n");
    body.push_str("    if (!spx_context_init(&spx_ctx, UINT64_C(1), spx_status_entries, UINT32_C(32), NULL, NULL, NULL)) { return 90; }\n");
    body.push_str(&emitter.body);
    body.push_str(&format!(
        "    {result_type} spx_native_exec_result;\n    spx_status_token spx_native_exec_token = {symbol}(&spx_ctx"
    ));
    for argument in &call_args {
        body.push_str(&format!(", {argument}"));
    }
    body.push_str(", &spx_native_exec_result);\n");
    body.push_str(
        "    if (spx_native_exec_token != SPX_STATUS_SUCCESS) { printf(\"STATUS_FAILURE\\n\"); return 0; }\n",
    );

    if let Ok(layout) =
        AggregateLayout::for_type(program, AggregateTarget::Native64, &entry.return_type)
    {
        emit_record_print(&mut body, &layout, "spx_native_exec_result")?;
    } else if let Ok(layout) =
        VariantLayout::for_type(program, VariantTarget::Native64, &entry.return_type)
    {
        emit_variant_print(&mut body, &layout, "spx_native_exec_result")?;
    } else {
        return Err(invariant("native_executor.result.shape"));
    }
    body.push_str("    return 0;\n");

    let generated =
        crate::codegen::emit_hir_c(program).map_err(|_| invariant("native_executor.codegen"))?;

    let root = probe_root();
    std::fs::create_dir(&root).map_err(|_| invariant("native_executor.probe_directory"))?;
    let outcome = compile_and_run(&generated, &body, &root, optimization);
    let _ = std::fs::remove_dir_all(&root);
    let stdout = outcome?;
    let result_declaration = nominal_declaration(&entry.return_type)?.clone();

    decode(entry.id.clone(), &result_declaration, &stdout, max_steps)
}

fn compile_and_run(
    generated: &str,
    driver_body: &str,
    root: &Path,
    optimization: &str,
) -> Result<String, Diagnostic> {
    let source_path = root.join("native_executor.c");
    let executable_path = root.join(format!("native_executor{}", std::env::consts::EXE_SUFFIX));
    let source = format!("{generated}\nint main(void) {{\n{driver_body}\n}}\n");
    std::fs::write(&source_path, source).map_err(|_| invariant("native_executor.write_source"))?;
    let compiled = Command::new("clang")
        .args([
            "-std=c11",
            optimization,
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-tautological-compare",
            "-DSPX_NO_ENTRY_WRAPPER",
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .map_err(|_| invariant("native_executor.tool.clang"))?;
    if !compiled.status.success() {
        return Err(invariant("native_executor.compile"));
    }
    let output: Output = Command::new(&executable_path)
        .output()
        .map_err(|_| invariant("native_executor.tool.run"))?;
    if !output.status.success() {
        return Err(invariant("native_executor.run"));
    }
    String::from_utf8(output.stdout).map_err(|_| invariant("native_executor.output_utf8"))
}

fn decode(
    function_id: DeclarationId,
    result_declaration: &DeclarationId,
    stdout: &str,
    max_steps: usize,
) -> Result<RetainedCallEvaluation, Diagnostic> {
    let line = stdout
        .lines()
        .next()
        .ok_or_else(|| invariant("native_executor.decode.empty"))?;
    if line == "STATUS_FAILURE" {
        // A native contract/status failure is detected, not silently
        // ignored, but this executor does not yet reconstruct the exact
        // interpreter-shaped `NormalizedStatus` from the native status
        // arena. Reported honestly as a diagnostic rather than a guessed
        // `LanguageFailure`.
        return Err(invariant("native_executor.decode.status_failure"));
    }
    let outcome = if let Some(rest) = line.strip_prefix("RECORD") {
        RetainedCallOutcome::Returned(RetainedValue::Record(decode_record(
            result_declaration,
            rest,
        )?))
    } else if let Some(rest) = line.strip_prefix("VARIANT ") {
        RetainedCallOutcome::Returned(RetainedValue::Variant(decode_variant(
            result_declaration,
            rest,
        )?))
    } else {
        return Err(invariant("native_executor.decode.shape"));
    };
    Ok(RetainedCallEvaluation {
        function_id,
        outcome,
        cleanup_events: Vec::new(),
        steps_used: 0,
        max_steps,
        failure: None,
    })
}

fn decode_field(token: &str) -> Result<RetainedField, Diagnostic> {
    let (hex, value) = token
        .split_once('=')
        .ok_or_else(|| invariant("native_executor.decode.field"))?;
    let field = decode_hex_payload(hex)?;
    let value = if let Some(bytes_hex) = value.strip_prefix("B:") {
        RetainedValue::Bytes(decode_bytes_hex(bytes_hex)?)
    } else if let Some(scalar) = value.strip_prefix("I:") {
        RetainedValue::I64(
            scalar
                .parse()
                .map_err(|_| invariant("native_executor.decode.i64"))?,
        )
    } else if let Some(flag) = value.strip_prefix("T:") {
        RetainedValue::Bool(match flag {
            "0" => false,
            "1" => true,
            _ => return Err(invariant("native_executor.decode.bool")),
        })
    } else if let Some(count) = value.strip_prefix("U:") {
        RetainedValue::Usize(
            count
                .parse()
                .map_err(|_| invariant("native_executor.decode.usize"))?,
        )
    } else if let Some(byte) = value.strip_prefix("Q:") {
        RetainedValue::U8(
            byte.parse()
                .map_err(|_| invariant("native_executor.decode.u8"))?,
        )
    } else {
        return Err(invariant("native_executor.decode.field_value"));
    };
    Ok(RetainedField { field, value })
}

fn decode_bytes_hex(hex: &str) -> Result<Vec<u8>, Diagnostic> {
    if hex.len() % 2 != 0 {
        return Err(invariant("native_executor.decode.bytes"));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut index = 0;
    while index < hex.len() {
        bytes.push(
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| invariant("native_executor.decode.bytes"))?,
        );
        index += 2;
    }
    Ok(bytes)
}

fn decode_record(
    record_declaration: &DeclarationId,
    rest: &str,
) -> Result<RetainedRecord, Diagnostic> {
    let mut fields = Vec::new();
    for token in rest.split_whitespace() {
        fields.push(decode_field(token)?);
    }
    Ok(RetainedRecord {
        record: record_declaration.clone(),
        fields,
    })
}

fn decode_variant(
    variant_declaration: &DeclarationId,
    rest: &str,
) -> Result<RetainedVariant, Diagnostic> {
    let mut parts = rest.split_whitespace();
    let case_hex = parts
        .next()
        .ok_or_else(|| invariant("native_executor.decode.case"))?;
    let case = decode_hex_payload(case_hex)?;
    let mut fields = Vec::new();
    for token in parts {
        fields.push(decode_field(token)?);
    }
    Ok(RetainedVariant {
        variant: variant_declaration.clone(),
        case,
        fields,
    })
}
