//! Direct owned-string variant evidence across every executable backend.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::{codegen, format, graph, hir, interpreter, parse, verify, wasm};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

const SOURCE: &str = r#"
module test.owned_string_variant;

@id("text.choice")
variant Choice {
    @id("text.choice.empty") Empty,
    @id("text.choice.text") Text {
        @id("text.choice.text.value") value: string,
        @id("text.choice.text.marker") marker: i64,
    },
}

@id("text.make")
fn make() -> Choice { Choice::Text { value: "hello", marker: 3 } }

@id("text.borrow")
fn borrow_value(value: borrow Choice) -> i64 {
    match borrow value {
        Choice::Empty {} => 0,
        Choice::Text { value: text, marker } => string_len(text) + marker,
    }
}

@id("text.consume")
fn consume(value: own Choice) -> i64 {
    match own value {
        Choice::Empty {} => 0,
        Choice::Text { value: text, marker } => string_len(text) + marker,
    }
}

@id("text.keep")
fn keep(value: string) -> string { value }

@id("text.scoped")
fn scoped() -> i64 {
    match 1 {
        1 if string_contains(keep("guard"), "g") =>
            string_len(keep("x")) - {
                let joined = string_concat(string_from_char('λ'), string_from_i64(7));
                if string_len_chars(joined) == 2 && string_len(joined) == 3
                    && joined == "λ7" && joined != "bad" {
                    let nested = keep("x");
                    string_len(nested)
                } else { 0 }
            },
        _ => 99,
    }
}

@id("app.main")
fn main() -> i64 {
    let value = make();
    let empty = Choice::Empty {};
    borrow_value(value) + consume(value) + consume(empty) + scoped()
}
"#;

fn command_available(command: &str) -> bool {
    Command::new(command).arg("--version").output().is_ok()
}

fn checked() -> semaprax::ast::Program {
    let program = parse(SOURCE, Path::new("owned-string-variant.spx")).unwrap();
    let diagnostics = verify::verify(&program);
    assert!(
        diagnostics.is_empty(),
        "unexpected source diagnostics: {diagnostics:?}"
    );
    program
}

fn source_file(source: &str, label: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "semaprax-owned-string-variant-{label}-{}-{id}.spx",
        std::process::id()
    ));
    fs::write(&path, source).unwrap();
    path
}

#[test]
fn direct_string_variant_round_trips_graphs_and_interprets_repeatedly() {
    let program = checked();
    let canonical = format::canonical(&program);
    let reparsed = parse(&canonical, Path::new("owned-string-variant-roundtrip.spx")).unwrap();
    assert_eq!(format::canonical(&reparsed), canonical);
    let graph = graph::to_json(&program).unwrap();
    assert!(graph.contains("core.string.drop"));
    hir::validate(&hir::resolve(&program).unwrap()).unwrap();

    let path = source_file(&canonical, "interpreter");
    for _ in 0..3 {
        let result = interpreter::interpret(
            &path,
            "app.main",
            &[],
            &interpreter::InterpreterOptions::default(),
        )
        .unwrap();
        assert!(result.returned);
        assert!(result.envelope.contains("\"value\":\"16\""));
        interpreter::verify_envelope_against_source(&result.envelope, &path).unwrap();
    }
    fs::remove_file(path).unwrap();
}

#[test]
fn direct_string_variant_native_o0_o2_and_node_wasm_settle_each_invocation() {
    if !command_available("clang") || !command_available("node") {
        return;
    }
    let program = checked();
    let generated = codegen::emit_c(&program).unwrap();
    assert_eq!(generated, codegen::emit_c(&program).unwrap());
    assert!(generated.contains("spx_string_drop"));

    let main = "spx_decl_6170702e6d61696e";
    let probe = format!(
        "{}\n{}\n{}\n#undef malloc\n#undef free\nint main(void) {{\n    REQUIRE(fixture_binary_stdout());\n    struct spx_status_entry entries[8];\n    struct spx_context context = {{0}};\n    REQUIRE(spx_context_init(&context, 31, entries, 8, NULL, NULL, NULL));\n    for (unsigned repeat = 0; repeat < 3; ++repeat) {{\n        int64_t result = INT64_MIN;\n        REQUIRE({main}(&context, &result) == SPX_STATUS_SUCCESS && result == INT64_C(16));\n        REQUIRE(fixture_live == 0 && fixture_allocations == fixture_frees);\n    }}\n    return 0;\n}}\n",
        include_str!("../support/native_fixture_stdio.c"),
        include_str!("../native_owned_utf8_settlement_v1/allocations.c"),
        generated,
    );
    for optimization in ["-O0", "-O2"] {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let source = std::env::temp_dir().join(format!(
            "semaprax-owned-string-variant-{optimization}-{}-{id}.c",
            std::process::id()
        ));
        let executable = std::env::temp_dir().join(format!(
            "semaprax-owned-string-variant-{optimization}-{}-{id}{}",
            std::process::id(),
            std::env::consts::EXE_SUFFIX
        ));
        fs::write(&source, &probe).unwrap();
        let built = Command::new("clang")
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
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let ran = Command::new(&executable).output().unwrap();
        let _ = fs::remove_file(&source);
        let _ = fs::remove_file(&executable);
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "semaprax-owned-string-variant-wasm-{}-{id}",
        std::process::id()
    ));
    wasm::build_web(&program, &root).unwrap();
    let output = Command::new("node")
        .args([
            "--input-type=module",
            "--eval",
            r#"
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const directory = process.argv[1];
const { instantiateBytes } = await import(pathToFileURL(join(directory, "semaprax.js")));
const { instance } = await instantiateBytes(await readFile(join(directory, "app.wasm")), {
    maxOwnedByteEntries: 16,
});
// One leaked allocation per invocation exhausts this unchanged small arena.
for (let repeat = 0; repeat < 32; repeat++) {
    const result = instance.exports.semaprax_main();
    if (result !== 16n) throw new Error(`expected 16, received ${result}`);
}
console.log("16");
"#,
        ])
        .arg(&root)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"16\n");
}

#[test]
fn string_variant_profile_keeps_generic_nested_and_bytes_mixes_closed() {
    for source in [
        SOURCE.replace("variant Choice", "variant Choice<T>"),
        SOURCE
            .replace(
                "@id(\"text.choice.text.value\") value: string",
                "@id(\"text.choice.text.value\") value: Inner",
            )
            .replace(
                "@id(\"text.choice\")\nvariant Choice {",
                "@id(\"inner\")\nrecord Inner { @id(\"inner.value\") value: string, }\n\n@id(\"text.choice\")\nvariant Choice {",
            ),
        SOURCE.replace(
            "marker: i64",
            "marker: i64, @id(\"text.choice.text.bytes\") bytes: Bytes",
        ),
    ] {
        let program = parse(&source, Path::new("owned-string-variant-rejected.spx")).unwrap();
        let errors = verify::verify(&program);
        assert!(
            errors
                .iter()
                .any(|error| error.code == "SPX-T215" || error.code == "SPX-T268"),
            "{errors:?}"
        );
    }
}
