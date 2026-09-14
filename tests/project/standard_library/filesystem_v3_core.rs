//! Small raw-operation fixtures isolate ABI behavior from the std.fs composition.
#![allow(unused_imports, dead_code)]
use super::{filesystem_v3::C_PROVIDER, project, temporary};
use semaprax::filesystem_provider::{CheckedAtomicWriteFault, FixtureFileProvider};
use semaprax::interpreter::CommandEvaluationOutcome;

#[cfg(unix)]
#[test]
fn filesystem_v3_raw_outcomes_and_nested_refusal_execute_on_three_backends() {
    for (number, scenario, path, expected, fault) in [
        (0, "published", "99u8", 0, None),
        (
            1,
            "not-published",
            "100u8,47u8,97u8",
            1,
            Some(CheckedAtomicWriteFault::BeforeCommit),
        ),
        (
            2,
            "uncertain",
            "99u8",
            2,
            Some(CheckedAtomicWriteFault::CommitOutcomeUnknown),
        ),
        (4, "invalid-path", "97u8,47u8,46u8,46u8,47u8,98u8", 1, None),
    ] {
        let directory = temporary(&format!("fs-v3-core-{number}"));
        let manifest = directory.join("semaprax.toml");
        let source = format!(
            r#"module checked.core;
permit {{ fs.write }}
@id("checked.main") fn main()->i64 {{0}}
@id("checked.run") fn run()->bool uses {{ fs.write }} {{
 let path=[{path}]; let data=[65u8];
 let outcome=if true {{ if true {{ file_write_atomic_checked(array_as_slice(path),{}usize,array_as_slice(data),1usize) }} else {{0usize}} }} else {{0usize}};
 outcome=={expected}usize
}}
"#,
            path.split(',').count()
        );
        std::fs::write(
            directory.join("app.spx"),
            semaprax::format::canonical(&semaprax::parse(&source, "app.spx").unwrap()),
        )
        .unwrap();
        std::fs::write(
            directory.join("tests.spx"),
            semaprax::format::canonical(
                &semaprax::parse(
                    "module checked.tests;\n@id(\"checked.tests.main\") fn main()->i64 {0}\n",
                    "tests.spx",
                )
                .unwrap(),
            ),
        )
        .unwrap();
        std::fs::write(
            &manifest,
            r#"schema = "semaprax.manifest.v1"

[package]
name = "checked-core"
version = "0.1.0"
profile = "filesystem-io.v3"

[modules]
entry = "checked.core"
sources = ["app.spx", "tests.spx"]
tests = ["checked.tests"]

[exports]
web = []

[command]
function = "checked.run"

[capabilities]
required = ["fs.read", "fs.write"]
"#,
        )
        .unwrap();
        let mut provider = FixtureFileProvider::new([(b"c".to_vec(), vec![66])], true).unwrap();
        provider.set_checked_atomic_fault(fault);
        project::with_authenticated_project(&manifest, |snapshot| {
            let run = snapshot.execute_filesystem_command(&mut provider, 100_000)?;
            assert!(
                matches!(run.outcome, CommandEvaluationOutcome::ReturnedBool(true)),
                "{scenario}: {run:?}"
            );
            assert_eq!(
                provider.files().get(b"c".as_slice()),
                Some(&vec![if number == 0 || number == 2 { 65 } else { 66 }])
            );
            assert_eq!(provider.settlements(), 1);
            let revision = snapshot.retain_revision();
            let c = format!(
                "{}\n#define SCENARIO {number}\n{C_PROVIDER}",
                revision.filesystem_c_source()?
            );
            for optimization in ["-O0", "-O2"] {
                super::compile_and_run_c(&c, &directory, optimization, "");
            }
            let wasm = directory.join("core.wasm");
            let facade = directory.join("core.mjs");
            std::fs::write(&wasm, revision.filesystem_wasm_module()?).unwrap();
            std::fs::write(&facade, include_str!("filesystem_v3_facade.mjs")).unwrap();
            let symbol = format!(
                "spx_data_{}",
                "checked.run"
                    .bytes()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let output = std::process::Command::new("node")
                .arg(&facade)
                .arg(&wasm)
                .arg(symbol)
                .arg(scenario)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{scenario}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"ok\n");
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
