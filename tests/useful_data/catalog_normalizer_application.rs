//! Executes the actual catalog-normalizer source's named application tests.
//! The frozen oracle and its cases remain independent of this backend gate.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use semaprax::{codegen, format, parse, project};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/catalog-normalizer-project")
}

fn run_oracle(input: &[u8]) -> serde_json::Value {
    let oracle_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/catalog_normalizer");
    let mut child = Command::new("python3")
        .arg("oracle.py")
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
    serde_json::from_slice(&output.stdout).expect("oracle emits one JSON response")
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

#[test]
fn batch_boundaries_and_string_normalization_agree_across_backends() {
    let root = fixture();
    for source in [
        "src/app.spx",
        "src/batch.spx",
        "src/limits.spx",
        "src/tests.spx",
    ] {
        let path = root.join(source);
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
        named_cases, 8,
        "catalog-normalizer application case inventory drifted"
    );
    #[cfg(windows)]
    let scratch = std::env::temp_dir().join(format!(
        "semaprax-catalog-normalizer-batch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    #[cfg(not(windows))]
    let scratch = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "semaprax-catalog-normalizer-batch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    project::with_authenticated_project(&root.join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let result = snapshot.execute_test(&project::ProjectExecutionOptions::default())?;
        assert_eq!(
            result.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "catalog-normalizer application tests failed on the interpreter"
        );

        let c = codegen::emit_hir_c(snapshot.test_program()).map_err(|e| vec![e])?;
        for optimization in ["-O0", "-O2"] {
            let c_path = scratch.join(format!("tests-{optimization}.c"));
            let executable = scratch.join(format!("tests-{optimization}"));
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

        let wasm_path = scratch.join("tests.wasm");
        std::fs::write(&wasm_path, snapshot.test_wasm_module()?).unwrap();
        let script = scratch.join("tests.mjs");
        let host = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/useful_data/environment_provider_fixture.mjs"),
        )
        .unwrap();
        let probe = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/useful_data/catalog_normalizer_application.mjs"),
        )
        .unwrap();
        std::fs::write(&script, format!("{host}\n{probe}")).unwrap();
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
        Ok(())
    })
    .unwrap();

    // A candidate that counts the terminal LF as a record must fail the
    // frozen CNORM-001 case; success above cannot come from an inert harness.
    let mutant = scratch.join("mutant");
    std::fs::create_dir_all(mutant.join("src")).unwrap();
    std::fs::copy(root.join("semaprax.toml"), mutant.join("semaprax.toml")).unwrap();
    for source in ["app.spx", "batch.spx", "limits.spx", "tests.spx"] {
        std::fs::copy(
            root.join("src").join(source),
            mutant.join("src").join(source),
        )
        .unwrap();
    }
    let batch_path = mutant.join("src/batch.spx");
    let batch = std::fs::read_to_string(&batch_path).unwrap();
    let broken = batch.replace("if only_line { 0usize } else { count }", "count");
    assert_ne!(broken, batch, "negative-control mutation must be applied");
    std::fs::write(&batch_path, broken).unwrap();
    project::with_authenticated_project(&mutant.join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let result = snapshot.execute_test(&project::ProjectExecutionOptions::default())?;
        assert_ne!(
            result.outcome(),
            &project::ProjectExecutionOutcome::Returned(0)
        );
        Ok(())
    })
    .unwrap();
    let _ = std::fs::remove_dir_all(scratch);
}
