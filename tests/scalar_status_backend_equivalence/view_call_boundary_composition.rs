//! Issue #103: borrowed byte-view call boundaries across backend lanes.
//!
//! The sibling view corpus exercises whole and ranged views only within the
//! creating function.  This corpus adds the missing source boundary: an
//! authenticated `borrow Slice<u8>` is passed directly or forwarded through a
//! second synchronous call.  It enumerates whole/ranged origin × direct/
//! forwarded call × conditional/loop context (eight cells) and compares the
//! scalar result through interpreter, native C11 `-O0`/`-O2`, and plain
//! Core-Wasm's single `semaprax_main` entry.
//!
//! The accepted profile deliberately ends at scalar returns.  A borrowed
//! `Slice<u8>` cannot escape its invocation, so the companion fixture pins
//! `SPX-T264` instead of counting a rejected view-return as execution support.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use semaprax::interpreter::{self, InterpreterOptions};
use semaprax::{codegen, parse, verify};

const SOURCE: &str = r#"
module test.view_call_boundary_composition;

@id("vcb.inspect")
fn inspect(view_value: borrow Slice<u8>) -> i64 {
    if byte_len(view_value) == 4usize {
        let first = match byte_get(view_value, 0usize) { Option::Some { value } => if value == 10u8 { 1 } else { 0 }, Option::None {} => 0, };
        let last = match byte_get(view_value, 3usize) { Option::Some { value } => if value == 40u8 { 4 } else { 0 }, Option::None {} => 0, };
        first * 10 + last
    } else {
        if byte_len(view_value) == 2usize {
            let first = match byte_get(view_value, 0usize) { Option::Some { value } => if value == 20u8 { 2 } else { 0 }, Option::None {} => 0, };
            let last = match byte_get(view_value, 1usize) { Option::Some { value } => if value == 30u8 { 3 } else { 0 }, Option::None {} => 0, };
            first * 10 + last
        } else { 0 }
    }
}

@id("vcb.forward")
fn forward(value: borrow Slice<u8>) -> i64 { inspect(value) }

@id("vcb.whole_direct_if")
fn whole_direct_if() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    if inspect(view) == 14 { inspect(view) } else { -1 }
}

@id("vcb.sub_direct_if")
fn sub_direct_if() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    let sub = byte_range(view, 1usize, 3usize);
    if inspect(sub) == 23 { inspect(sub) } else { -1 }
}

@id("vcb.whole_forward_if")
fn whole_forward_if() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    if forward(view) == 14 { forward(view) } else { -1 }
}

@id("vcb.sub_forward_if")
fn sub_forward_if() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    let sub = byte_range(view, 1usize, 3usize);
    if forward(sub) == 23 { forward(sub) } else { -1 }
}

@id("vcb.whole_direct_loop")
fn whole_direct_loop() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    let mut index = 0usize;
    let mut total = 0;
    while index < 2usize { total = total + inspect(view); index = index + 1usize; 0 }
    total
}

@id("vcb.sub_direct_loop")
fn sub_direct_loop() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    let sub = byte_range(view, 1usize, 3usize);
    let mut index = 0usize;
    let mut total = 0;
    while index < 2usize { total = total + inspect(sub); index = index + 1usize; 0 }
    total
}

@id("vcb.whole_forward_loop")
fn whole_forward_loop() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    let mut index = 0usize;
    let mut total = 0;
    while index < 2usize { total = total + forward(view); index = index + 1usize; 0 }
    total
}

@id("vcb.sub_forward_loop")
fn sub_forward_loop() -> i64 {
    let data = [10u8, 20u8, 30u8, 40u8];
    let view = array_as_slice(data);
    let sub = byte_range(view, 1usize, 3usize);
    let mut index = 0usize;
    let mut total = 0;
    while index < 2usize { total = total + forward(sub); index = index + 1usize; 0 }
    total
}

@id("app.main")
fn main() -> i64 {
    whole_direct_if() + sub_direct_if() * 100 + whole_forward_if() * 10000 + sub_forward_if() * 1000000 + whole_direct_loop() * 100000000 + sub_direct_loop() * 10000000000 + whole_forward_loop() * 1000000000000 + sub_forward_loop() * 100000000000000
}
"#;

const CASES: [(&str, i64); 8] = [
    ("vcb.whole_direct_if", 14),
    ("vcb.sub_direct_if", 23),
    ("vcb.whole_forward_if", 14),
    ("vcb.sub_forward_if", 23),
    ("vcb.whole_direct_loop", 28),
    ("vcb.sub_direct_loop", 46),
    ("vcb.whole_forward_loop", 28),
    ("vcb.sub_forward_loop", 46),
];

const VIEW_RETURN_SOURCE: &str = r#"
module test.view_call_boundary_return_refusal;
@id("vcb.return_view")
fn return_view(value: borrow Slice<u8>) -> Slice<u8> { value }
@id("app.main")
fn main() -> i64 { 0 }
"#;

fn temporary_root() -> PathBuf {
    super::temporary_root().join("view-call-boundary")
}

fn native_probe(cases: &[(&str, i64)]) -> String {
    let declarations = cases
        .iter()
        .map(|(id, _)| {
            format!(
                "extern spx_status_token {}(struct spx_context *, int64_t *);\n",
                super::c_symbol(id)
            )
        })
        .collect::<String>();
    let calls = cases
        .iter()
        .map(|(id, _)| {
            format!(
                "if (emit({id:?}, {}) != 0) return 1;\n",
                super::c_symbol(id)
            )
        })
        .collect::<String>();
    format!(
        r#"{declarations}
typedef spx_status_token (*case_fn)(struct spx_context *, int64_t *);
static int emit(const char *id, case_fn call) {{
    struct spx_status_entry records[UINT32_C(2)];
    struct spx_context context = {{0}};
    if (!spx_context_init(&context, UINT64_C(911), records, UINT32_C(2), NULL, NULL, NULL)) return 10;
    int64_t value = -INT64_C(1);
    if (call(&context, &value) != SPX_STATUS_SUCCESS || context.status_arena.length != 0) return 11;
    printf("{{\"id\":\"%s\",\"value\":%lld}}\n", id, (long long)value);
    return 0;
}}
int main(void) {{
{calls}    return 0;
}}
"#
    )
}

fn run_native(generated: &str, root: &Path, optimization: &str) -> Vec<(String, i64)> {
    let source = root.join(format!("native-{optimization}.c"));
    let executable = root.join(format!(
        "native-{optimization}{}",
        std::env::consts::EXE_SUFFIX
    ));
    fs::write(&source, format!("{generated}\n{}", native_probe(&CASES))).unwrap();
    let output = Command::new("clang")
        .args([
            "-std=c11",
            optimization,
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DSPX_NO_ENTRY_WRAPPER",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native {optimization} compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&executable).output().unwrap();
    assert!(
        output.status.success(),
        "native {optimization} execution failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "native {optimization} emitted unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_observations(&output.stdout, "native")
}

fn parse_observations(bytes: &[u8], label: &str) -> Vec<(String, i64)> {
    let text = String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|error| panic!("{label} emitted non-UTF-8: {error}"));
    text.lines()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{label} emitted malformed JSON {line:?}: {error}"));
            (
                value["id"].as_str().unwrap().to_owned(),
                value["value"].as_i64().unwrap(),
            )
        })
        .collect()
}

fn run_core_wasm(program: &semaprax::ast::Program, root: &Path) -> i64 {
    super::view_ownership_composition::run_core_wasm_aggregate(program, root)
}

fn run_interpreter(path: &Path) -> Vec<(String, i64)> {
    CASES
        .iter()
        .map(|(id, _)| {
            let result = interpreter::interpret(path, id, &[], &InterpreterOptions::default())
                .unwrap_or_else(|diagnostics| panic!("interpreter rejected {id}: {diagnostics:?}"));
            assert!(
                result.returned,
                "interpreter did not return for {id}: {}",
                result.envelope
            );
            let value: serde_json::Value = serde_json::from_str(&result.envelope).unwrap();
            (
                (*id).to_owned(),
                value["payload"]["outcome"]["value"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        })
        .collect()
}

/// Every pinned case value is below 100, so base-100 slots cannot carry into
/// a neighbor. The eight highest-weighted slots remain below `i64::MAX`.
fn expected_aggregate() -> i64 {
    CASES
        .iter()
        .enumerate()
        .map(|(index, (_, value))| value * 100i64.pow(index as u32))
        .sum()
}

fn decode(aggregate: i64) -> Vec<i64> {
    (0..CASES.len())
        .map(|index| (aggregate / 100i64.pow(index as u32)) % 100)
        .collect()
}

fn assert_case(
    case_id: &str,
    expected: i64,
    interpreter: i64,
    native_o0: i64,
    native_o2: i64,
    wasm: i64,
) {
    assert_eq!(interpreter, expected, "{case_id}: interpreter value");
    assert_eq!(native_o0, expected, "{case_id}: native O0 value");
    assert_eq!(native_o2, expected, "{case_id}: native O2 value");
    assert_eq!(wasm, expected, "{case_id}: Core-Wasm value");
    assert_eq!(
        native_o0, native_o2,
        "{case_id}: native optimization disagreement"
    );
    assert_eq!(
        interpreter, wasm,
        "{case_id}: interpreter/Core-Wasm disagreement"
    );
}

#[test]
fn borrowed_view_call_matrix_agrees_across_interpreter_native_and_core_wasm() {
    if !super::require_tools_or_skip() {
        return;
    }
    let program = parse(SOURCE, Path::new("view-call-boundary.spx")).unwrap();
    let diagnostics = verify::verify(&program);
    assert!(
        diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.severity.is_error()),
        "fixture verification failed: {diagnostics:?}"
    );
    let root = temporary_root();
    fs::create_dir_all(&root).unwrap();
    let native = codegen::emit_c(&program).unwrap();
    let native_o0 = run_native(&native, &root, "-O0");
    let native_o2 = run_native(&native, &root, "-O2");
    let wasm_aggregate = run_core_wasm(&program, &root);
    assert_eq!(
        wasm_aggregate,
        expected_aggregate(),
        "Core-Wasm aggregate differs before per-case decoding"
    );
    let wasm = decode(wasm_aggregate);
    let source = root.join("fixture.spx");
    fs::write(&source, SOURCE).unwrap();
    let interpreter = run_interpreter(&source);
    assert_eq!(native_o0.len(), CASES.len());
    assert_eq!(native_o2.len(), CASES.len());
    assert_eq!(wasm.len(), CASES.len());
    assert_eq!(interpreter.len(), CASES.len());
    for (index, (case_id, expected)) in CASES.iter().enumerate() {
        assert_eq!(native_o0[index].0, *case_id);
        assert_eq!(native_o2[index].0, *case_id);
        assert_eq!(interpreter[index].0, *case_id);
        assert_case(
            case_id,
            *expected,
            interpreter[index].1,
            native_o0[index].1,
            native_o2[index].1,
            wasm[index],
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn borrowed_view_return_is_rejected_with_stable_diagnostic() {
    let program = parse(VIEW_RETURN_SOURCE, Path::new("view-return-refusal.spx")).unwrap();
    let diagnostics = verify::verify(&program);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "SPX-T264"),
        "borrowed Slice return must remain refused as SPX-T264: {diagnostics:?}"
    );
}

#[test]
#[should_panic(expected = "Core-Wasm value")]
fn borrowed_view_call_comparator_rejects_a_changed_backend_value() {
    let expected = CASES[0].1;
    assert_case(
        CASES[0].0,
        expected,
        expected,
        expected,
        expected,
        expected + 1,
    );
}
