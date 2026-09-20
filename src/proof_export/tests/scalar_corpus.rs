//! A second all-admitted structural/replay corpus member for the Lean export.
//!
//! The pinned Lean transcript remains the sole live-kernel evidence. This
//! module broadens deterministic translation, certificate, ProgramRoot and
//! Assurance Manifest coverage without relabeling the fixture kernel as a
//! real proof result.

use std::cell::Cell;
use std::path::PathBuf;

use super::{
    assurance_method_attachment, bind_certificate_to_program_root, certificate_for_declaration,
    export_module, verify_certificate, verify_certificate_against_source,
    verify_certificate_with_kernel_against_program_root, AcceptingKernel, CountingKernel,
};
use crate::assurance_manifest::{self, project::ProjectAssuranceOptions, ObligationKind};
use crate::project::with_authenticated_project;

/// A second complete admitted module. It exercises the remaining fixed-width
/// scalar modes and unary negation/subtraction paths.
const SCALAR_CORPUS: &str = "module app.scalar;\n\
@id(\"app.scalar.negated\")\n\
fn negated(value: i32) -> i32\n\
    requires value >= 1i32\n\
    ensures result < 0i32\n\
{ let negative = -value; negative }\n\
\n\
@id(\"app.scalar.increment\")\n\
fn increment(value: u8) -> u8\n\
    requires value <= 254u8\n\
    ensures result > value\n\
{ let next = value + 1u8; next }\n\
\n\
@id(\"app.scalar.decrement\")\n\
fn decrement(value: usize) -> usize\n\
    requires value >= 1usize\n\
    ensures result < value\n\
{ let previous = value - 1usize; previous }\n\
\n\
@id(\"app.scalar.main\")\n\
fn main() -> i64 ensures result == 0 { 0 }\n";

fn scalar_corpus_module() -> super::super::ModuleExport {
    let parsed = super::program(SCALAR_CORPUS);
    let revision = crate::graph::revision(&parsed);
    export_module(&parsed, &revision)
}

/// A Project-shaped second corpus member. It deliberately has no synthetic
/// test import: the entry source contains its own admitted main, and the
/// proof target is independently selected by stable id below.
fn scalar_project_fixture(label: &str, name: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "semaprax-proof-export-scalar-project-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).unwrap();
    let source_path = root.join("src/scalar.spx");
    let canonical = crate::format::canonical(
        &crate::parse(SCALAR_CORPUS, &source_path).expect("scalar corpus parses"),
    );
    std::fs::write(&source_path, canonical).unwrap();
    let test_path = root.join("src/tests.spx");
    let test_source = crate::format::canonical(
        &crate::parse(
            "module app.tests;\nuse function @id(\"app.scalar.increment\") from app.scalar as increment;\n@id(\"app.tests.main\")\nfn main() -> i64 { if increment(0u8) == 1u8 { 0 } else { 1 } }\n",
            &test_path,
        )
        .expect("scalar corpus test source parses"),
    );
    std::fs::write(test_path, test_source).unwrap();
    let manifest = root.join("semaprax.toml");
    std::fs::write(
        &manifest,
        format!(
            "schema = \"semaprax.project.v8\"\nname = \"{name}\"\nversion = \"1.0.0\"\nprofile = \"owned-data-api.v1\"\nentry = \"app.scalar\"\nsources = [\"src/scalar.spx\", \"src/tests.spx\"]\nweb_exports = []\ntests = [\"app.tests\"]\n"
        ),
    )
    .unwrap();
    (manifest, source_path)
}

#[test]
fn scalar_corpus_module_is_wholly_admitted_and_byte_deterministic() {
    let first = scalar_corpus_module();
    let second = scalar_corpus_module();
    assert_eq!(first.lean_source, second.lean_source);
    assert!(first.unsupported.is_empty(), "{:#?}", first.unsupported);
    assert_eq!(
        first
            .exported
            .iter()
            .map(|item| item.declaration_id.as_str())
            .collect::<Vec<_>>(),
        [
            "app.scalar.negated",
            "app.scalar.increment",
            "app.scalar.decrement",
            "app.scalar.main",
        ]
    );
    assert_eq!(
        first
            .obligations()
            .iter()
            .filter(|obligation| obligation.kind == "checked_arithmetic_range")
            .count(),
        3,
        "one checked range theorem for negation, addition and subtraction"
    );
    assert_eq!(
        first
            .obligations()
            .iter()
            .filter(|obligation| obligation.kind == "postcondition")
            .count(),
        4,
        "one selected postcondition theorem per admitted declaration"
    );
}

#[test]
fn scalar_corpus_certificate_replays_against_its_exact_source_and_artifact() {
    let path = super::write_temp_exact(SCALAR_CORPUS, "scalar-corpus-certificate");
    let certificate = certificate_for_declaration(&path, "app.scalar.increment");
    let checked = verify_certificate(&certificate).expect("structural scalar certificate replay");
    assert_eq!(checked.declaration_id, "app.scalar.increment");
    assert!(certificate.contains("\"module\":\"app.scalar\""));
    verify_certificate_against_source(&certificate, &path)
        .expect("scalar certificate must rederive its exact Lean and Wasm bindings");
    std::fs::remove_file(&path).ok();
}

#[test]
fn scalar_corpus_proof_replays_through_program_root_and_promotes_only_its_postcondition() {
    let (manifest, source_path) = scalar_project_fixture("program-root", "proof-scalar-a");
    let certificate = certificate_for_declaration(&source_path, "app.scalar.increment");
    let envelope = with_authenticated_project(&manifest, |snapshot| {
        let revision = snapshot.retain_revision();
        let binding = bind_certificate_to_program_root(&certificate, &revision, "src/scalar.spx")
            .map_err(|error| vec![error])?;
        let attachment =
            assurance_method_attachment(&certificate, &binding, &revision, &AcceptingKernel)
                .map_err(|error| vec![error])?;
        assurance_manifest::project::generate_from_snapshot_with_verified_proofs(
            snapshot,
            &ProjectAssuranceOptions::default(),
            &[attachment],
        )
    })
    .expect("second scalar corpus member binds one exact Project postcondition");
    let value: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let theorem_proved = value["payload"]["obligations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|obligation| obligation["classification"] == "theorem_proved")
        .collect::<Vec<_>>();
    assert_eq!(theorem_proved.len(), 1);
    assert_eq!(theorem_proved[0]["declaration_id"], "app.scalar.increment");
    assert_eq!(
        theorem_proved[0]["kind"],
        ObligationKind::Postcondition.token()
    );
    std::fs::remove_dir_all(manifest.parent().unwrap()).ok();
}

#[test]
fn hostile_program_root_and_source_field_mutations_never_dispatch_the_kernel() {
    let (manifest, source_path) = scalar_project_fixture("binding-mutations", "proof-scalar-b");
    let certificate = certificate_for_declaration(&source_path, "app.scalar.increment");
    with_authenticated_project(&manifest, |snapshot| {
        let revision = snapshot.retain_revision();
        let binding = bind_certificate_to_program_root(&certificate, &revision, "src/scalar.spx")
            .map_err(|error| vec![error])?;
        let mutations = [
            (
                "program_root",
                "program_root",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "program_root",
                "sha256",
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            ),
            ("source", "path", "src/substituted.spx"),
            (
                "source",
                "revision",
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            ),
            (
                "source",
                "sha256",
                "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            ),
        ];
        for (row, field, replacement) in mutations {
            let mut value: serde_json::Value = serde_json::from_str(&binding).unwrap();
            value["payload"][row][field] = serde_json::Value::String(replacement.to_owned());
            let hostile = serde_json::to_string(&value).unwrap();
            let kernel = CountingKernel {
                calls: Cell::new(0),
            };
            let error = verify_certificate_with_kernel_against_program_root(
                &certificate,
                &hostile,
                &revision,
                &kernel,
            )
            .expect_err(
                "a bound ProgramRoot/source field must be authenticated before kernel dispatch",
            );
            assert_eq!(error.code, "SPX-Z111", "mutated {row}.{field}");
            assert_eq!(kernel.calls.get(), 0, "mutated {row}.{field}");
        }
        Ok(())
    })
    .expect("hostile binding bytes do not affect Project admission");
    std::fs::remove_dir_all(manifest.parent().unwrap()).ok();
}
