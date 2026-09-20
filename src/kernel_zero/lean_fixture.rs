//! Concrete Rust-to-Lean lowering witnesses for Kernel-0.
//!
//! `Kernel0.lean` proves that its own `NamedTerm` lowering preserves types,
//! but that theorem deliberately does not assert anything about Rust HIR or
//! `reify::Term`.  This test is the narrow executable seam between the two:
//! it derives real terms from the deterministic source corpus, independently
//! lowers those terms to de Bruijn indices in Rust, then asks Lean to reduce
//! its `lowerNamed` over the corresponding opaque identities.  Every emitted
//! equality is proved by `rfl`; a disagreement in constructor mapping, scope
//! extension, function-table ordering, or argument order therefore fails at
//! Lean's actual executable lowering rather than in a text snapshot.
//!
//! The witness is finite corpus evidence, not a proof that either the parser
//! or the Rust translator is correct for all admitted programs.  In
//! particular, HIR typing remains an unproved translation assumption. The
//! fixture also constructs a concrete Lean `Program` and checks the strict
//! weighted-call certificate derived from these real terms in Rust.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::ast::{BinaryOp, UnaryOp};
use crate::hir::{DeclarationId, ValueId};

use super::corpus::generated_corpus;
use super::reify::BoundTranslation;
use super::term::{KernelProgram, KernelType, Term};
use super::weights;

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

fn lean_lake() -> Option<PathBuf> {
    let candidate = std::env::var_os("SEMAPRAX_KERNEL0_LAKE").unwrap_or_else(|| "lake".into());
    let candidate = PathBuf::from(candidate);
    if candidate.components().count() > 1 {
        return candidate.is_file().then_some(candidate);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(&candidate))
            .find(|path| path.is_file())
    })
}

fn proof_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("proofs/kernel0-lean")
}

fn function_labels(program: &KernelProgram) -> BTreeMap<DeclarationId, usize> {
    program
        .functions
        .iter()
        .enumerate()
        // These labels deliberately do not coincide with table indices.  Lean
        // must resolve the opaque identity through the supplied table; a test
        // that used 0, 1, 2 for both would miss a confused identity/index map.
        .map(|(index, function)| (function.id.clone(), 1_003 + index * 17))
        .collect()
}

fn function_positions(program: &KernelProgram) -> BTreeMap<DeclarationId, usize> {
    program
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.id.clone(), index))
        .collect()
}

fn collect_values(term: &Term, values: &mut BTreeSet<ValueId>) {
    match term {
        Term::Int(_) | Term::Bool(_) => {}
        Term::Var(id) => {
            values.insert(id.clone());
        }
        Term::Unary(_, value) => collect_values(value, values),
        Term::Binary(_, left, right) => {
            collect_values(left, values);
            collect_values(right, values);
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_values(condition, values);
            collect_values(then_branch, values);
            collect_values(else_branch, values);
        }
        Term::Let { bound, value, body } => {
            values.insert(bound.clone());
            collect_values(value, values);
            collect_values(body, values);
        }
        Term::Call { args, .. } => {
            for argument in args {
                collect_values(argument, values);
            }
        }
    }
}

fn value_ids(program: &KernelProgram) -> BTreeMap<ValueId, usize> {
    let mut values = BTreeSet::new();
    for function in &program.functions {
        for (id, _) in &function.params {
            values.insert(id.clone());
        }
        collect_values(&function.body, &mut values);
    }
    values
        .into_iter()
        .enumerate()
        // Likewise, ValueIds are opaque identities, not de Bruijn slots.
        .map(|(index, value)| (value, 10_007 + index * 19))
        .collect()
}

fn list<T>(values: impl IntoIterator<Item = T>, render: impl FnMut(T) -> String) -> String {
    let rendered = values
        .into_iter()
        .map(render)
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{rendered}]")
}

fn integer(value: i64) -> String {
    if value < 0 {
        format!("({value})")
    } else {
        value.to_string()
    }
}

fn arith(operator: BinaryOp) -> &'static str {
    match operator {
        BinaryOp::Add => ".add",
        BinaryOp::Sub => ".sub",
        BinaryOp::Mul => ".mul",
        BinaryOp::Div => ".div",
        BinaryOp::Rem => ".mod",
        other => panic!("Kernel-0 arithmetic renderer received {other:?}"),
    }
}

fn comparison(operator: BinaryOp) -> &'static str {
    match operator {
        BinaryOp::Eq => ".eq",
        BinaryOp::Ne => ".ne",
        BinaryOp::Lt => ".lt",
        BinaryOp::Le => ".le",
        BinaryOp::Gt => ".gt",
        BinaryOp::Ge => ".ge",
        other => panic!("Kernel-0 comparison renderer received {other:?}"),
    }
}

fn named_term(
    term: &Term,
    functions: &BTreeMap<DeclarationId, usize>,
    values: &BTreeMap<ValueId, usize>,
) -> String {
    match term {
        Term::Int(value) => format!(".intLit {}", integer(*value)),
        Term::Bool(value) => format!(".boolLit {value}"),
        Term::Var(id) => format!(".var {}", values[id]),
        Term::Unary(UnaryOp::Neg, value) => {
            format!(".neg ({})", named_term(value, functions, values))
        }
        Term::Unary(UnaryOp::Not, value) => {
            format!(".not ({})", named_term(value, functions, values))
        }
        Term::Binary(BinaryOp::And, left, right) => format!(
            ".and ({}) ({})",
            named_term(left, functions, values),
            named_term(right, functions, values)
        ),
        Term::Binary(BinaryOp::Or, left, right) => format!(
            ".or ({}) ({})",
            named_term(left, functions, values),
            named_term(right, functions, values)
        ),
        Term::Binary(
            operator @ (BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Rem),
            left,
            right,
        ) => format!(
            ".arith {} ({}) ({})",
            arith(*operator),
            named_term(left, functions, values),
            named_term(right, functions, values)
        ),
        Term::Binary(
            operator @ (BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::Lt
            | BinaryOp::Le
            | BinaryOp::Gt
            | BinaryOp::Ge),
            left,
            right,
        ) => format!(
            ".cmp {} ({}) ({})",
            comparison(*operator),
            named_term(left, functions, values),
            named_term(right, functions, values)
        ),
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => format!(
            ".ite ({}) ({}) ({})",
            named_term(condition, functions, values),
            named_term(then_branch, functions, values),
            named_term(else_branch, functions, values)
        ),
        Term::Let { bound, value, body } => format!(
            ".letIn {} ({}) ({})",
            values[bound],
            named_term(value, functions, values),
            named_term(body, functions, values)
        ),
        Term::Call { callee, args } => format!(
            ".call {} {}",
            functions[callee],
            list(args.iter(), |argument| named_term(
                argument, functions, values
            ))
        ),
    }
}

fn lowered_term(
    term: &Term,
    function_positions: &BTreeMap<DeclarationId, usize>,
    locals: &mut Vec<ValueId>,
) -> String {
    match term {
        Term::Int(value) => format!(".intLit {}", integer(*value)),
        Term::Bool(value) => format!(".boolLit {value}"),
        Term::Var(id) => format!(
            ".var {}",
            locals
                .iter()
                .position(|local| local == id)
                .unwrap_or_else(|| panic!("reified variable {} is not in scope", id.as_str()))
        ),
        Term::Unary(UnaryOp::Neg, value) => {
            format!(".neg ({})", lowered_term(value, function_positions, locals))
        }
        Term::Unary(UnaryOp::Not, value) => {
            format!(".not ({})", lowered_term(value, function_positions, locals))
        }
        Term::Binary(BinaryOp::And, left, right) => format!(
            ".and ({}) ({})",
            lowered_term(left, function_positions, locals),
            lowered_term(right, function_positions, locals)
        ),
        Term::Binary(BinaryOp::Or, left, right) => format!(
            ".or ({}) ({})",
            lowered_term(left, function_positions, locals),
            lowered_term(right, function_positions, locals)
        ),
        Term::Binary(
            operator @ (BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Rem),
            left,
            right,
        ) => format!(
            ".arith {} ({}) ({})",
            arith(*operator),
            lowered_term(left, function_positions, locals),
            lowered_term(right, function_positions, locals)
        ),
        Term::Binary(
            operator @ (BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::Lt
            | BinaryOp::Le
            | BinaryOp::Gt
            | BinaryOp::Ge),
            left,
            right,
        ) => format!(
            ".cmp {} ({}) ({})",
            comparison(*operator),
            lowered_term(left, function_positions, locals),
            lowered_term(right, function_positions, locals)
        ),
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => format!(
            ".ite ({}) ({}) ({})",
            lowered_term(condition, function_positions, locals),
            lowered_term(then_branch, function_positions, locals),
            lowered_term(else_branch, function_positions, locals)
        ),
        Term::Let { bound, value, body } => {
            let value = lowered_term(value, function_positions, locals);
            locals.insert(0, bound.clone());
            let body = lowered_term(body, function_positions, locals);
            locals.remove(0);
            format!(".letIn ({value}) ({body})")
        }
        Term::Call { callee, args } => format!(
            ".call {} {}",
            function_positions[callee],
            list(args.iter(), |argument| lowered_term(
                argument,
                function_positions,
                locals
            ))
        ),
    }
}

fn render_witnesses(program: &KernelProgram, label: &str, output: &mut String) -> usize {
    let function_labels = function_labels(program);
    let function_positions = function_positions(program);
    let values = value_ids(program);
    let function_scope = list(program.functions.iter(), |function| {
        function_labels[&function.id].to_string()
    });
    let weights = weights::derive(program).expect("reified corpus must have finite u64 weights");
    weights::verify(program, &weights).expect("derived weights must replay on the exact terms");
    // Labels are generated locally, never copied from source identifiers.
    let suffix = label.replace('-', "_");
    let program_name = format!("program_{suffix}");
    let weight_name = format!("weight_{suffix}");
    let bodies = program
        .functions
        .iter()
        .map(|function| {
            let mut locals = function.params.iter().map(|(id, _)| id.clone()).collect();
            lowered_term(&function.body, &function_positions, &mut locals)
        })
        .collect::<Vec<_>>();
    let lean_type = |ty| match ty {
        KernelType::I64 => ".int",
        KernelType::Bool => ".bool",
    };
    let definitions = list(program.functions.iter().zip(&bodies), |(function, body)| {
        let parameters = list(function.params.iter(), |(_, ty)| lean_type(*ty).to_owned());
        format!(
            "⟨{parameters}, {}, ({body})⟩",
            lean_type(function.return_type)
        )
    });
    output.push_str(&format!(
        "\ndef {program_name} : Program := {definitions}\n"
    ));
    output.push_str(&format!("def {weight_name} : Nat → Nat\n"));
    for (index, function) in program.functions.iter().enumerate() {
        output.push_str(&format!("  | {index} => {}\n", weights[&function.id]));
    }
    output.push_str("  | _ => 0\n");
    let mut count = 0;
    for (function_index, function) in program.functions.iter().enumerate() {
        let parameters = function
            .params
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let named_parameters = list(parameters.iter(), |id| values[id].to_string());
        let named = named_term(&function.body, &function_labels, &values);
        let lowered = &bodies[function_index];
        output.push_str(&format!(
            "\n-- exact reification witness {label}, function {function_index}\nexample :\n  lowerNamed {function_scope} {named_parameters} ({named}) = some ({lowered}) := by\n  rfl\n"
        ));
        count += 1;
    }
    // Exhaust the actual finite function table. Each leaf is checked by Lean's
    // reduction of weightedPotential, rather than trusting a Rust boolean or
    // an unbound certificate for a separate hand-authored example program.
    output.push_str(&format!(
        "\ntheorem certificate_{suffix} : WeightedCallCertificate {program_name} {weight_name} := by\n  intro f fd hf\n"
    ));
    for index in 0..program.functions.len() {
        let indent = " ".repeat(2 + index * 4);
        output.push_str(&format!(
            "{indent}cases f with\n{indent}| zero =>\n{indent}    simp [{program_name}] at hf\n{indent}    subst fd\n{indent}    decide\n{indent}| succ f =>\n"
        ));
    }
    let indent = " ".repeat(2 + program.functions.len() * 4);
    output.push_str(&format!("{indent}simp [{program_name}] at hf\n"));
    count
}

fn fixture_source() -> String {
    let mut output =
        String::from("import Kernel0\n\nopen Kernel0\n\nnamespace SemapraxKernel0Witness\n");
    let mut count = 0;
    for (program_index, generated) in generated_corpus().into_iter().enumerate() {
        let entry = DeclarationId::new(generated.entry_id);
        let translation = BoundTranslation::derive(&generated.source, &entry)
            .expect("deterministic corpus source must reify before rendering its Lean witness");
        let program = translation
            .replay(&generated.source, &entry)
            .expect("fresh exact source replay must retain the reified term");
        count += render_witnesses(program, &format!("generated-{program_index}"), &mut output);
    }
    output.push_str("\nend SemapraxKernel0Witness\n");
    output.push_str(&format!("\n-- witnesses: {count}\n"));
    output
}

#[test]
fn real_reified_weight_witnesses_are_deterministic_and_nonvacuous() {
    let source = fixture_source();
    assert_eq!(source, fixture_source());
    assert!(source.contains("def program_generated_0 : Program := ["));
    assert!(source.contains("theorem certificate_generated_0 : WeightedCallCertificate"));
    let programs = generated_corpus().len();
    assert!(programs > 0);
    assert_eq!(
        source.matches(" : WeightedCallCertificate ").count(),
        programs
    );
}

#[test]
fn real_reified_corpus_lowers_identically_in_lean() {
    let Some(lake) = lean_lake() else {
        eprintln!(
            "Kernel-0 Rust-to-Lean lowering witness skipped: `lake` is not on PATH; \
             set SEMAPRAX_KERNEL0_LAKE to an explicit Lean lake executable to require it"
        );
        return;
    };
    let directory = proof_directory();
    assert!(directory.join("lakefile.toml").is_file());
    let fixture = directory.join(format!(
        ".semaprax-rust-lowering-witness-{}-{}.lean",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&fixture, fixture_source()).expect("write deterministic Rust-to-Lean witness");
    let result = Command::new(lake)
        .args(["env", "lean"])
        .arg(&fixture)
        .current_dir(&directory)
        .output();
    fs::remove_file(&fixture).ok();
    let result = result.expect("run Lean against the generated Kernel-0 witness");
    assert!(
        result.status.success(),
        "Lean rejected a concrete Rust-to-Lean lowering witness:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
