//! Extends the Kernel-0 differential test to native C11 and Core Wasm.
//!
//! `super`'s own test drives only the compiler's interpreter backend against
//! the from-scratch reference interpreter, over the same corpus this module
//! reuses unchanged (`super::hand_written_cases`, `super::generated_cases`).
//! `docs/SEMANTIC-KERNEL-V1.md` and `docs/COMPLETION-MATRIX.md` both name the
//! gap this closes in the same words: "it exercises the interpreter backend
//! only -- native and Wasm are unexercised."
//!
//! Per this repository's central invariant ("A safe source program has
//! equivalent checked behavior on every backend that claims to implement the
//! admitted feature", `AGENTS.md`), a faithfulness corpus that never runs a
//! second backend cannot witness a cross-backend divergence at all. This
//! module runs each corpus program's entry, at every sample argument tuple
//! `super`'s corpus already carries, through:
//! - Native C11 at `-O0` and `-O2` (`crate::codegen::emit_hir_c`, compiled
//!   with the local `clang` and driven by a small generated `main` that
//!   calls the entry's raw `spx_decl_<hex(id)>` symbol directly -- the same
//!   naming convention `tests/scalar_status_backend_equivalence.rs` and
//!   `tests/wasm/scalar_exports_v1.rs` independently rely on).
//! - Core Wasm (`crate::wasm::build_web_with_scalar_exports`, the Public
//!   Scalar Export Profile v1 already proven Node-executable by
//!   `tests/wasm/scalar_exports_v1.rs`), through the generated
//!   `semaprax.bindings.js` and a small Node script.
//!
//! and compares each outcome against the from-scratch reference
//! interpreter's outcome for the same sample -- not against the compiler's
//! interpreter a second time, since `super`'s own test already establishes
//! that agreement.
//!
//! **What this proves, and what it does not.** Agreement here is evidence
//! over this one finite, seeded-and-adversarial 100-program corpus that the native and Wasm
//! backends compute the same values and the same arithmetic fault
//! (`semaprax.arithmetic.v1` domain and code, byte-for-byte) as the
//! reference interpreter, for every program the admission predicate accepts.
//! It is not a proof for any program outside the corpus, and it says nothing
//! about programs `reifies_into_kernel_zero` rejects. A disagreement found
//! here is a real cross-backend divergence, not a test bug to paper over --
//! see `super`'s own header doc for the same instruction, which applies here
//! unchanged.
//!
//! Slow-tool gating: this test needs a local `clang` and `node` on `PATH`.
//! Following `tests/scalar_status_backend_equivalence.rs`'s own convention,
//! it skips quietly when either is missing and fails loudly instead when
//! `SEMAPRAX_REQUIRE_KERNEL_ZERO_CROSS_BACKEND` is set, so a developer
//! machine without these tools never blocks on this test but CI can still
//! demand it run for real. Native compilation happens once per corpus
//! program per optimization level (every sample runs inside that one
//! binary), and the Wasm module is built once per corpus program too --
//! not once per sample -- to keep the 100-program corpus's wall-clock cost
//! bounded; see `run_case` below.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hir::{self, ResolvedType};
use crate::{codegen, wasm};

use super::super::eval::eval_program;
use super::super::reify::BoundTranslation;
use super::super::value::Value;
use super::{
    fault_from_status, generated_cases, hand_written_cases, reference_outcome, Case, Outcome,
};

const REQUIRE_ENV: &str = "SEMAPRAX_REQUIRE_KERNEL_ZERO_CROSS_BACKEND";

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn required() -> bool {
    std::env::var_os(REQUIRE_ENV).is_some()
}

fn temp_dir() -> PathBuf {
    let ordinal = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "semaprax-kernel-zero-cross-backend-{}-{ordinal}",
        std::process::id()
    ))
}

fn cleanup_dir(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

/// `spx_decl_<hex(id)>`: the deterministic raw C symbol
/// `src/codegen/native_emit/mod.rs::c_function_symbol` assigns every
/// resolved function, independently confirmed against the built compiler by
/// `tests/scalar_status_backend_equivalence.rs` and
/// `tests/wasm/scalar_exports_v1.rs`. Recomputed here rather than imported
/// because the emitter's own helper is a private implementation detail one
/// codegen module deep; the naming convention is the stable, external part.
fn c_symbol(id: &str) -> String {
    let mut symbol = String::from("spx_decl_");
    for byte in id.bytes() {
        write!(symbol, "{byte:02x}").expect("writing to a string cannot fail");
    }
    symbol
}

/// A sample argument rendered as a C11 literal. `i64::MIN` needs the
/// standard `-(MAX) - 1` split because `9223372036854775808` alone has no
/// positive `int64_t` representation for `INT64_C` to suffix.
fn c_arg_literal(value: &Value) -> String {
    match value {
        Value::Int(n) if *n == i64::MIN => "(-INT64_C(9223372036854775807) - 1)".to_owned(),
        Value::Int(n) if *n < 0 => format!("(-INT64_C({}))", n.unsigned_abs()),
        Value::Int(n) => format!("INT64_C({n})"),
        Value::Bool(b) => b.to_string(),
    }
}

/// A sample argument rendered as a JavaScript literal. `i64` samples become
/// `BigInt` literals (the `n` suffix), which -- unlike `INT64_C` -- accepts
/// the full `i64` range as plain decimal text with no split needed.
fn wasm_arg_literal(value: &Value) -> String {
    match value {
        Value::Int(n) => format!("{n}n"),
        Value::Bool(b) => b.to_string(),
    }
}

fn call_argument_suffix(literals: &[String]) -> String {
    if literals.is_empty() {
        String::new()
    } else {
        format!(", {}", literals.join(", "))
    }
}

/// One driver `main` that calls `symbol` once per sample in `samples`,
/// printing `"<index> VALUE <text>"` on success or `"<index> FAULT <domain>
/// <code>"` on a checked-arithmetic failure. Compiled with
/// `-DSPX_NO_ENTRY_WRAPPER` so it replaces, rather than collides with, the
/// entry wrapper `crate::codegen::emit_hir_c` always emits for the corpus
/// module's own decoy `app.main`.
fn native_driver(symbol: &str, is_bool_result: bool, samples: &[Vec<Value>]) -> String {
    let mut body = String::from("int main(void) {\n");
    let result_ty = if is_bool_result { "bool" } else { "int64_t" };
    for (index, args) in samples.iter().enumerate() {
        let literals: Vec<String> = args.iter().map(c_arg_literal).collect();
        let call_args = call_argument_suffix(&literals);
        let print_success = if is_bool_result {
            format!("printf(\"{index} VALUE %s\\n\", spx_result ? \"true\" : \"false\");")
        } else {
            format!("printf(\"{index} VALUE %lld\\n\", (long long)spx_result);")
        };
        write!(
            body,
            "    {{\n\
             \x20       struct spx_status_entry spx_status_entries[UINT32_C(1)];\n\
             \x20       struct spx_context spx_ctx = {{0}};\n\
             \x20       if (!spx_context_init(&spx_ctx, UINT64_C({budget}), spx_status_entries, UINT32_C(1), NULL, NULL, NULL)) {{\n\
             \x20           fputs(\"kernel-zero cross-backend: context init failed\\n\", stderr);\n\
             \x20           return 90;\n\
             \x20       }}\n\
             \x20       {result_ty} spx_result;\n\
             \x20       spx_status_token spx_status = {symbol}(&spx_ctx{call_args}, &spx_result);\n\
             \x20       if (spx_status != SPX_STATUS_SUCCESS) {{\n\
             \x20           const struct spx_normalized_status *spx_resolved = spx_status_resolve(&spx_ctx, spx_status);\n\
             \x20           if (spx_resolved == NULL) {{\n\
             \x20               fputs(\"kernel-zero cross-backend: unresolved status token\\n\", stderr);\n\
             \x20               return 91;\n\
             \x20           }}\n\
             \x20           printf(\"{index} FAULT %s %u\\n\", spx_resolved->domain_id, (unsigned int)spx_resolved->code);\n\
             \x20       }} else {{\n\
             \x20           {print_success}\n\
             \x20       }}\n\
             \x20   }}\n",
            budget = index + 1,
        )
        .expect("writing to a string cannot fail");
    }
    body.push_str("    return 0;\n}\n");
    body
}

/// Parses one native driver run's stdout: exactly one `"<index> VALUE ..."`
/// or `"<index> FAULT <domain> <code>"` line per sample, in order.
fn parse_backend_lines(stdout: &str, sample_count: usize, is_bool_result: bool) -> Vec<Outcome> {
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        sample_count,
        "kernel-0 cross-backend: expected {sample_count} output line(s), got {}: {stdout:?}",
        lines.len()
    );
    lines
        .into_iter()
        .enumerate()
        .map(|(expected_index, line)| {
            let mut parts = line.split_whitespace();
            let index: usize = parts
                .next()
                .and_then(|text| text.parse().ok())
                .unwrap_or_else(|| panic!("kernel-0 cross-backend: malformed line {line:?}"));
            assert_eq!(
                index, expected_index,
                "kernel-0 cross-backend: out-of-order line {line:?}"
            );
            match parts.next() {
                Some("VALUE") => {
                    let text = parts.next().unwrap_or_else(|| {
                        panic!("kernel-0 cross-backend: VALUE line missing a value {line:?}")
                    });
                    if is_bool_result {
                        Outcome::Value(Value::Bool(text == "true"))
                    } else {
                        Outcome::Value(Value::Int(text.parse().unwrap_or_else(|error| {
                            panic!("kernel-0 cross-backend: {text:?} did not parse as i64: {error}")
                        })))
                    }
                }
                Some("FAULT") => {
                    let domain = parts.next().unwrap_or_else(|| {
                        panic!("kernel-0 cross-backend: FAULT line missing a domain {line:?}")
                    });
                    let code: u64 = parts
                        .next()
                        .and_then(|text| text.parse().ok())
                        .unwrap_or_else(|| {
                            panic!("kernel-0 cross-backend: FAULT line missing a code {line:?}")
                        });
                    let fault = fault_from_status(domain, code).unwrap_or_else(|| {
                        panic!(
                            "kernel-0 cross-backend: native backend failed with status \
                             domain_id={domain:?} code={code}, outside Kernel-0's eight \
                             arithmetic fault codes\nline: {line:?}"
                        )
                    });
                    Outcome::Fault(fault)
                }
                other => {
                    panic!("kernel-0 cross-backend: unexpected line shape {other:?}: {line:?}")
                }
            }
        })
        .collect()
}

/// Compiles the corpus module plus its driver once at `optimization` and
/// runs the resulting binary once, returning one [`Outcome`] per sample.
fn run_native(
    resolved: &hir::ResolvedProgram,
    symbol: &str,
    is_bool_result: bool,
    samples: &[Vec<Value>],
    root: &Path,
    optimization: &str,
) -> Vec<Outcome> {
    let generated = codegen::emit_hir_c(resolved).unwrap_or_else(|error| {
        panic!("kernel-0 cross-backend: native C emission failed: {error:?}")
    });
    let source_path = root.join(format!("native-{optimization}.c"));
    let executable_path = root.join(format!(
        "native-{optimization}{}",
        std::env::consts::EXE_SUFFIX
    ));
    std::fs::write(
        &source_path,
        format!(
            "{generated}\n{}",
            native_driver(symbol, is_bool_result, samples)
        ),
    )
    .expect("writing the generated native source must succeed");
    let compiled = Command::new("clang")
        .args([
            "-std=c11",
            optimization,
            "-Wall",
            "-Wextra",
            "-Werror",
            // The generated corpus's random expression trees legitimately
            // compare a variable against itself sometimes (e.g. `x <= x`) --
            // a real, admitted Kernel-0 program, not a style problem, and
            // this differential test cares about computed values, not
            // clang's opinion of the emitted C's style.
            "-Wno-tautological-compare",
            "-DSPX_NO_ENTRY_WRAPPER",
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("clang must be invocable");
    assert!(
        compiled.status.success(),
        "kernel-0 cross-backend: native {optimization} compilation failed:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run = Command::new(&executable_path)
        .output()
        .expect("compiled native binary must be runnable");
    assert!(
        run.status.success(),
        "kernel-0 cross-backend: native {optimization} binary exited with {:?}:\nstdout: {}\nstderr: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    parse_backend_lines(
        &String::from_utf8_lossy(&run.stdout),
        samples.len(),
        is_bool_result,
    )
}

/// Builds the Public Scalar Export Profile v1 package once, exporting only
/// `entry_id`, then drives every sample through one Node script, returning
/// one [`Outcome`] per sample.
fn run_wasm(
    program: &crate::ast::Program,
    entry_id: &str,
    is_bool_result: bool,
    samples: &[Vec<Value>],
    root: &Path,
) -> Vec<Outcome> {
    let package = root.join("web");
    wasm::build_web_with_scalar_exports(program, &package, &[entry_id.to_owned()])
        .unwrap_or_else(|error| {
            panic!("kernel-0 cross-backend: scalar export package build failed for {entry_id}: {error:?}")
        });
    let id_literal = format!("{entry_id:?}");
    let mut script = String::from(
        "import { readFile } from \"node:fs/promises\";\n\
         import { pathToFileURL } from \"node:url\";\n\
         import { resolve } from \"node:path\";\n\
         const packageDirectory = resolve(process.argv[2]);\n\
         const bindings = await import(pathToFileURL(resolve(packageDirectory, \"semaprax.bindings.js\")));\n\
         const runtime = await bindings.instantiateBytes(await readFile(resolve(packageDirectory, \"app.wasm\")));\n\
         function emit(index, outcome) {\n\
         \x20 if (outcome.ok) {\n\
         \x20   const value = typeof outcome.value === \"bigint\" ? outcome.value.toString() : outcome.value;\n\
         \x20   process.stdout.write(`${index} VALUE ${value}\\n`);\n\
         \x20 } else {\n\
         \x20   process.stdout.write(`${index} FAULT ${outcome.status.domain_id} ${outcome.status.code}\\n`);\n\
         \x20 }\n\
         }\n",
    );
    for (index, args) in samples.iter().enumerate() {
        let literals: Vec<String> = args.iter().map(wasm_arg_literal).collect();
        let call_args = call_argument_suffix(&literals);
        writeln!(
            script,
            "emit({index}, runtime.call({id_literal}{call_args}));"
        )
        .expect("writing to a string cannot fail");
    }
    let script_path = root.join("observe.mjs");
    std::fs::write(&script_path, script).expect("writing the observer script must succeed");
    let run = Command::new("node")
        .arg(&script_path)
        .arg(&package)
        .output()
        .expect("node must be invocable");
    assert!(
        run.status.success(),
        "kernel-0 cross-backend: Node observer failed for {entry_id}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    parse_backend_lines(
        &String::from_utf8_lossy(&run.stdout),
        samples.len(),
        is_bool_result,
    )
}

/// Runs one corpus case's every sample through native `-O0`, native `-O2`,
/// and Core Wasm, comparing each against the from-scratch reference
/// interpreter (already proven to agree with the compiler's interpreter by
/// `super`'s own test). Appends a description of every disagreement found to
/// `failures`, mirroring `super::run_case`'s never-panic-mid-corpus shape.
fn run_case(case: &Case, failures: &mut Vec<String>, total: &mut usize) {
    let program =
        crate::parse(&case.source, "kernel-zero-cross-backend.spx").unwrap_or_else(|error| {
            panic!(
                "corpus program must parse: {error:?}\nsource:\n{}",
                case.source
            )
        });
    let resolved = hir::resolve(&program).unwrap_or_else(|errors| {
        panic!(
            "corpus program must resolve: {errors:?}\nsource:\n{}",
            case.source
        )
    });
    let entry_decl = resolved
        .functions
        .iter()
        .find(|function| function.id.as_str() == case.entry_id)
        .unwrap_or_else(|| {
            panic!(
                "no resolved function named {}\nsource:\n{}",
                case.entry_id, case.source
            )
        })
        .id
        .clone();
    let entry_function = resolved
        .functions
        .iter()
        .find(|function| function.id == entry_decl)
        .expect("just located this function above");
    let is_bool_result = matches!(entry_function.return_type, ResolvedType::Bool);

    let binding = BoundTranslation::derive(&case.source, &entry_decl).unwrap_or_else(|error| {
        panic!(
            "corpus entry {} must reify into Kernel-0: {error:?}\nsource:\n{}",
            case.entry_id, case.source
        )
    });
    let kernel_program = binding
        .replay(&case.source, &entry_decl)
        .expect("exact-source translation must replay before target comparison");
    let entry_fn = kernel_program
        .function(&entry_decl)
        .expect("translate_program always includes the entry it was given");

    let samples: &[Vec<Value>] = if case.samples.is_empty() {
        &[Vec::new()]
    } else {
        &case.samples
    };
    let references: Vec<Outcome> = samples
        .iter()
        .map(|args| reference_outcome(eval_program(kernel_program, entry_fn, args)))
        .collect();

    let root = temp_dir();
    std::fs::create_dir_all(&root).expect("creating the scratch directory must succeed");

    let symbol = c_symbol(&case.entry_id);
    for optimization in ["-O0", "-O2"] {
        let native = run_native(
            &resolved,
            &symbol,
            is_bool_result,
            samples,
            &root,
            optimization,
        );
        for (index, (reference, observed)) in references.iter().zip(native.iter()).enumerate() {
            *total += 1;
            if reference != observed {
                failures.push(format!(
                    "entry {} args {:?} (native {optimization}):\n  reference interpreter -> {reference:?}\n  \
                     native backend         -> {observed:?}\n  source:\n{}",
                    case.entry_id, samples[index], case.source
                ));
            }
        }
    }

    let wasm_outcomes = run_wasm(&program, &case.entry_id, is_bool_result, samples, &root);
    for (index, (reference, observed)) in references.iter().zip(wasm_outcomes.iter()).enumerate() {
        *total += 1;
        if reference != observed {
            failures.push(format!(
                "entry {} args {:?} (Core Wasm):\n  reference interpreter -> {reference:?}\n  \
                 Wasm backend           -> {observed:?}\n  source:\n{}",
                case.entry_id, samples[index], case.source
            ));
        }
    }

    cleanup_dir(&root);
}

#[test]
fn native_c11_and_core_wasm_agree_with_the_kernel_zero_reference_interpreter_over_the_corpus() {
    let missing: Vec<&str> = ["clang", "node"]
        .into_iter()
        .filter(|tool| !tool_available(tool))
        .collect();
    if !missing.is_empty() {
        assert!(
            !required(),
            "{REQUIRE_ENV} requires {} on PATH; missing {}",
            "clang and node",
            missing.join(", ")
        );
        eprintln!(
            "kernel-0 cross-backend differential test skipped: missing {} (set {REQUIRE_ENV}=1 to require it)",
            missing.join(", ")
        );
        return;
    }

    let mut failures = Vec::new();
    let mut total = 0usize;

    let hand_written = hand_written_cases();
    for case in &hand_written {
        run_case(case, &mut failures, &mut total);
    }
    let generated = generated_cases();
    for case in &generated {
        run_case(case, &mut failures, &mut total);
    }

    if !failures.is_empty() {
        panic!(
            "kernel-0 cross-backend differential test found {} disagreement(s) out of {total} \
             comparisons across native C11 (-O0/-O2) and Core Wasm ({} hand-written + {} \
             generated program(s), seed {:#x}):\n\n{}",
            failures.len(),
            hand_written.len(),
            generated.len(),
            super::super::corpus::CORPUS_SEED,
            failures.join("\n---\n")
        );
    }
    println!(
        "kernel-0 cross-backend differential test: {total} comparisons across native C11 \
         (-O0/-O2) and Core Wasm, {} hand-written and {} generated program(s) (seed {:#x}), \
         0 disagreements",
        hand_written.len(),
        generated.len(),
        super::super::corpus::CORPUS_SEED
    );
}
