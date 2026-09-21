//! Executes the actual catalog-normalizer source's named application tests.
//! The frozen oracle and its cases remain independent of this backend gate.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use semaprax::{codegen, format, parse, project};

const SOURCE_FILES: &[&str] = &[
    "app.spx",
    "batch.spx",
    "enrichment.spx",
    "limits.spx",
    "record.spx",
    "tests.spx",
];

struct ScratchRoot(PathBuf);

impl ScratchRoot {
    fn new() -> Self {
        #[cfg(windows)]
        let base = std::env::temp_dir();
        #[cfg(not(windows))]
        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!(
            "semaprax-catalog-normalizer-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/catalog-normalizer-project")
}

fn application_options() -> project::ProjectExecutionOptions {
    project::ProjectExecutionOptions::new(64 * 1024, 1_000_000)
        .expect("catalog-normalizer's documented bounded interpreter envelope")
}

fn copy_fixture(root: &Path, destination: &Path) {
    std::fs::create_dir_all(destination.join("src")).unwrap();
    std::fs::copy(
        root.join("semaprax.toml"),
        destination.join("semaprax.toml"),
    )
    .unwrap();
    for source in SOURCE_FILES {
        std::fs::copy(
            root.join("src").join(source),
            destination.join("src").join(source),
        )
        .unwrap();
    }
}

fn assert_batch_mutant_rejected(
    root: &Path,
    scratch: &Path,
    name: &str,
    expected: &str,
    replacement: &str,
) {
    let mutant = scratch.join(name);
    copy_fixture(root, &mutant);
    let batch_path = mutant.join("src/batch.spx");
    let batch = std::fs::read_to_string(&batch_path).unwrap();
    let broken = batch.replace(expected, replacement);
    assert_ne!(
        broken, batch,
        "{name} negative-control mutation must be applied"
    );
    std::fs::write(&batch_path, broken).unwrap();
    project::with_authenticated_project(&mutant.join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let result = snapshot.execute_test(&application_options())?;
        assert_ne!(
            result.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "{name} mutant unexpectedly passed the application suite"
        );
        Ok(())
    })
    .unwrap();
}

fn run_oracle_with(input: &[u8], enriched: bool) -> Vec<u8> {
    let oracle_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/catalog_normalizer");
    let mut command = Command::new("python3");
    command.arg("oracle.py");
    if enriched {
        command
            .arg("--enrich")
            .arg("--fixture")
            .arg("fixtures/enrichment.json");
    }
    let mut child = command
        .current_dir(oracle_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the independent catalog-normalizer oracle");
    child
        .stdin
        .take()
        .expect("piped oracle stdin")
        .write_all(input)
        .expect("write oracle input");
    let output = child.wait_with_output().expect("wait for oracle");
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn run_oracle_bytes(input: &[u8]) -> Vec<u8> {
    run_oracle_with(input, false)
}

fn run_oracle(input: &[u8]) -> serde_json::Value {
    serde_json::from_slice(&run_oracle_bytes(input)).expect("oracle emits one JSON response")
}

#[test]
fn decoded_id_bounds_and_escaped_duplicates_match_the_independent_oracle() {
    let id64 = "x".repeat(64);
    let accepted = format!("{{\"id\":\"{id64}\",\"label\":\"l\",\"quantity\":1}}\n");
    assert_eq!(run_oracle(accepted.as_bytes())["status"], "ok");

    let id65 = "x".repeat(65);
    let oversized = format!("{{\"id\":\"{id65}\",\"label\":\"l\",\"quantity\":1}}\n");
    let oversized_response = run_oracle(oversized.as_bytes());
    assert_eq!(oversized_response["status"], "error");
    assert_eq!(oversized_response["category"], "oversized_input");

    let escaped_duplicate = b"{\"id\":\"dup\",\"label\":\"one\",\"quantity\":1}\n{\"id\":\"d\\u0075p\",\"label\":\"two\",\"quantity\":2}\n";
    let duplicate_response = run_oracle(escaped_duplicate);
    assert_eq!(duplicate_response["status"], "error");
    assert_eq!(duplicate_response["category"], "duplicate_id");
    assert_eq!(duplicate_response["record_index"], 1);
}

// These literals are also exercised by the candidate's named `test_record_parser`
// and `test_duplicate_batch` cases. Running the independent oracle here keeps
// their frozen category/position contract honest without pretending the current
// scalar parser helper already publishes a complete CNORM-042 response envelope.
#[test]
fn record_parser_categories_and_positions_match_the_independent_oracle() {
    for (input, category, record_index, byte_offset) in [
        (b"{\"id\":\"a\",\"label\":\"x\"}\n".as_slice(), "schema", 0, 0),
        (
            b"{\"id\":\"a\",\"label\":\"x\",\"quantity\":\"1\"}\n".as_slice(),
            "schema",
            0,
            33,
        ),
        (
            b"{\"\\u0069d\":\"a\",\"label\":\"x\",\"quantity\":1}\n".as_slice(),
            "schema",
            0,
            1,
        ),
        (b"{\"id\":\"a\n".as_slice(), "malformed_json", 0, 8),
        (
            b"{\"id\":\"a\",\"label\":\"\",\"quantity\":0}\n{\"id\":\"\\u0061\",\"label\":\"\",\"quantity\":0}\n"
                .as_slice(),
            "duplicate_id",
            1,
            6,
        ),
    ] {
        let output = run_oracle(input);
        assert_eq!(output["status"], "error", "input={input:?}");
        assert_eq!(output["category"], category, "input={input:?}");
        assert_eq!(output["record_index"], record_index, "input={input:?}");
        assert_eq!(output["byte_offset"], byte_offset, "input={input:?}");
    }
}

// Exact canonical lines retained in the Semaprax source's `test_canonical_responses`.
// This proves that its expected bytes are independently derived by the frozen oracle,
// while the three-backend project test below proves that the candidate reaches them.
#[test]
fn canonical_response_literals_match_the_independent_oracle() {
    assert_eq!(
        run_oracle_bytes(b"{\"id\":\"a\",\"label\":\" x \",\"quantity\":1}\n"),
        b"{\"status\":\"ok\",\"count\":1,\"total_quantity\":1,\"records\":[{\"id\":\"a\",\"label\":\"x\",\"quantity\":1}]}\n"
    );
    assert_eq!(
        run_oracle_bytes(
            b"{\"id\":\"a\",\"label\":\"\",\"quantity\":0}\n{\"id\":\"\\u0061\",\"label\":\"\",\"quantity\":0}\n"
        ),
        b"{\"status\":\"error\",\"category\":\"duplicate_id\",\"record_index\":1,\"byte_offset\":6}\n"
    );
}

#[test]
fn enriched_response_literals_match_the_independent_oracle() {
    assert_eq!(
        run_oracle_with(b"{\"id\":\"widget-1\",\"label\":\" l \",\"quantity\":1}\n", true),
        b"{\"status\":\"ok\",\"count\":1,\"total_quantity\":1,\"records\":[{\"id\":\"widget-1\",\"label\":\"l\",\"quantity\":1,\"category\":7}]}\n"
    );
    assert_eq!(
        run_oracle_with(b"{\"id\":\"blocked-vendor\",\"label\":\"l\",\"quantity\":1}\n", true),
        b"{\"status\":\"error\",\"category\":\"provider_denied\",\"record_index\":0,\"byte_offset\":6}\n"
    );
}

#[test]
fn batch_boundaries_and_string_normalization_agree_across_backends() {
    let root = fixture();
    for source in SOURCE_FILES {
        let path = root.join("src").join(source);
        let bytes = std::fs::read_to_string(&path).unwrap();
        let (program, comments) = semaprax::parse_with_comments(&bytes, &path).unwrap();
        assert_eq!(
            format::comments::canonical_with_comments(&program, &comments),
            bytes
        );
    }
    let tests_path = root.join("src/tests.spx");
    let tests_source = std::fs::read_to_string(&tests_path).unwrap();
    let tests = parse(&tests_source, &tests_path).unwrap();
    let named_cases = tests
        .functions
        .iter()
        .filter(|function| function.name.starts_with("test_"))
        .count();
    assert_eq!(
        named_cases, 14,
        "catalog-normalizer application case inventory drifted"
    );
    // This is deliberately one test: each backend lane runs serially against
    // one authenticated snapshot, so the capacity-sensitive graph is never
    // built concurrently merely because libtest has multiple worker threads.
    let scratch = ScratchRoot::new();
    project::with_authenticated_project(&root.join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        {
            let result = snapshot.execute_test(&application_options())?;
            assert_eq!(
                result.outcome(),
                &project::ProjectExecutionOutcome::Returned(0),
                "catalog-normalizer application tests failed on the interpreter"
            );
        }

        {
            let c = codegen::emit_hir_c(snapshot.test_program()).map_err(|e| vec![e])?;
            for optimization in ["-O0", "-O2"] {
                let c_path = scratch.path().join(format!("tests-{optimization}.c"));
                let executable = scratch.path().join(format!("tests-{optimization}"));
                std::fs::write(&c_path, &c).unwrap();
                let build = Command::new("clang")
                    .args(["-std=c11", optimization, "-Wall", "-Wextra", "-Werror"])
                    .arg(&c_path)
                    .arg("-o")
                    .arg(&executable)
                    .output()
                    .unwrap();
                assert!(
                    build.status.success(),
                    "{}",
                    String::from_utf8_lossy(&build.stderr)
                );
                let run = Command::new(&executable).output().unwrap();
                assert!(
                    run.status.success(),
                    "{}",
                    String::from_utf8_lossy(&run.stderr)
                );
                assert_eq!(run.stdout, b"0\n");
            }
        }

        {
            let wasm_path = scratch.path().join("tests.wasm");
            let wasm = snapshot.test_wasm_module()?;
            std::fs::write(&wasm_path, &wasm).unwrap();
            drop(wasm);
            let script = scratch.path().join("tests.mjs");
            let mut host = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/useful_data/environment_provider_fixture.mjs"),
            )
            .unwrap();
            host.push('\n');
            host.push_str(
                &std::fs::read_to_string(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/useful_data/catalog_normalizer_application.mjs"),
                )
                .unwrap(),
            );
            std::fs::write(&script, host).unwrap();
            let node = Command::new("node")
                .arg(&script)
                .arg(&wasm_path)
                .output()
                .unwrap();
            assert!(
                node.status.success(),
                "{}",
                String::from_utf8_lossy(&node.stderr)
            );
        }
        Ok(())
    })
    .unwrap();

    // A candidate that counts the terminal LF as a record must fail the
    // frozen CNORM-001 case; success above cannot come from an inert harness.
    assert_batch_mutant_rejected(
        &root,
        scratch.path(),
        "terminal-lf-mutant",
        "if only_line { 0usize } else { count }",
        "count",
    );

    // CNORM-005 is not covered by the terminal-LF control. Deliberately
    // accepting every line must make the raw malformed-sequence case fail.
    assert_batch_mutant_rejected(
        &root,
        scratch.path(),
        "utf8-mutant",
        "line_utf8_end(body, record) == end - start",
        "true",
    );

    // CNORM-015's boundary is likewise independent of record splitting: a
    // checked-total predicate that never reports overflow must be caught.
    assert_batch_mutant_rejected(
        &root,
        scratch.path(),
        "total-mutant",
        "total > 9223372036854775807 - quantity",
        "false",
    );
}
