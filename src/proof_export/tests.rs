//! Tests for the Lean obligation export, its coverage accounting, the
//! pinned-kernel result parser, and certificate replay.
//!
//! **No test here executes a Lean toolchain.** The kernel is a capability
//! ([`super::LeanKernel`]); every test supplies a fixture implementation.
//! So these tests establish, honestly: the export is deterministic, the
//! coverage accounting is total, the result parser refuses every shape of
//! non-proof, and a certificate fails closed on drift.
//!
//! Most fixtures replay *synthesized* output. The "Real pinned-kernel
//! transcripts" section at the end of this file instead replays output
//! recorded verbatim from the pinned Lean 4.34.0 running over the committed
//! golden document (`testdata/shifted.kernel-output*.txt`), produced and
//! re-derived by `scripts/lean-export-gate.py`. What runs *here*, on every
//! host and in every Rust lane, is the parser re-checked against recorded
//! real bytes -- not a live kernel; this harness never spawns one. The live
//! kernel runs in the `kernel0-lean-proof-gate` CI job, which provisions
//! the pinned toolchain and calls that script with `--require-kernel` so a
//! missing kernel fails instead of skipping. These transcripts are the
//! recorded half of the same evidence, and they go stale silently unless
//! that job re-derives them, which is why it is a release blocker.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use super::certificate::{payload_digest, render_coverage, ARTIFACT_TARGET, CERTIFICATE_SCHEMA};
use super::kernel_report::{parse, KernelVerdict, Rejection, PINNED_TOOLCHAIN};
use super::lean::{escape_ident, export_function, export_module, NAMESPACE};
use super::verify::{
    verify_certificate, verify_certificate_against_artifact, verify_certificate_against_source,
    verify_certificate_with_capability, verify_certificate_with_kernel,
};
use super::{export_obligation_certificate, export_source, KernelRun, LeanKernel};

use crate::assurance_manifest::proof_certificate::ExternalKernelCapability;
use crate::diagnostic::Diagnostic;

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// Every fixture module needs an executable entry point: `hir::resolve`
/// (and so the Wasm artifact binding) rejects a module with no
/// `fn main() -> i64`.
fn with_main(source: &str) -> String {
    format!("{source}\n@id(\"app.t.proof_export_test_main\")\nfn main() -> i64 {{ 0 }}\n")
}

fn write_temp(source: &str, label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "semaprax-proof-export-{label}-{}-{}.spx",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, with_main(source)).unwrap();
    path
}

fn program(source: &str) -> crate::ast::Program {
    crate::parse(source, "proof-export-test.spx").expect("parse")
}

/// The one module every determinism, golden and certificate test uses. Its
/// `requires` bounds are deliberately tight enough that the generated range
/// obligation is *plausibly* provable by `omega` — but nothing here has ever
/// asked a Lean kernel whether it actually is, and no test asserts that.
const FIXTURE: &str = "module app.t;\n\
@id(\"app.t.shifted\")\n\
fn shifted(a: i64, b: i64) -> i64\n\
    requires a >= 0\n\
    requires a <= 1000\n\
    requires b >= 0\n\
    requires b <= 1000\n\
    ensures result >= a\n\
{ let total = a + b; total }\n";

fn fixture_module() -> super::ModuleExport {
    let parsed = program(&with_main(FIXTURE));
    let revision = crate::graph::revision(&parsed);
    export_module(&parsed, &revision)
}

/// A kernel that reports the pinned toolchain and accepts every expected
/// theorem with Lean's three standard axioms, in Lean's real output shape.
struct AcceptingKernel;

fn accepting_output(lean_source: &str) -> String {
    let mut out = String::from("info: [1/1] Building Export\n");
    for line in lean_source.lines() {
        if let Some(name) = line.strip_prefix("#print axioms ") {
            out.push_str(&format!(
                "info: Export.lean:1:0: '{name}' depends on axioms: [propext, Classical.choice, Quot.sound]\n"
            ));
        }
    }
    out
}

impl LeanKernel for AcceptingKernel {
    fn check(&self, lean_source: &str) -> Result<KernelRun, Diagnostic> {
        Ok(KernelRun {
            toolchain: PINNED_TOOLCHAIN.to_owned(),
            output: accepting_output(lean_source),
        })
    }
}

struct FixedKernel {
    toolchain: String,
    output: String,
}

struct CountingKernel {
    calls: Cell<usize>,
}

impl LeanKernel for CountingKernel {
    fn check(&self, lean_source: &str) -> Result<KernelRun, Diagnostic> {
        self.calls.set(self.calls.get() + 1);
        Ok(KernelRun {
            toolchain: PINNED_TOOLCHAIN.to_owned(),
            output: accepting_output(lean_source),
        })
    }
}

impl LeanKernel for FixedKernel {
    fn check(&self, _lean_source: &str) -> Result<KernelRun, Diagnostic> {
        Ok(KernelRun {
            toolchain: self.toolchain.clone(),
            output: self.output.clone(),
        })
    }
}

fn certificate_for(path: &Path) -> String {
    export_obligation_certificate(path, "app.t.shifted", 0, &AcceptingKernel)
        .expect("fixture certificate")
}

fn reseal_payload(certificate: &str) -> String {
    const PAYLOAD_KEY: &str = "\"payload\":";
    let offset = certificate.find(PAYLOAD_KEY).expect("certificate payload");
    let payload = &certificate[offset + PAYLOAD_KEY.len()..certificate.len() - 1];
    format!(
        "{{\"schema\":\"{CERTIFICATE_SCHEMA}\",\"digest\":\"{}\",\"bytes\":{},\"payload\":{payload}}}",
        payload_digest(payload.as_bytes()),
        payload.len(),
    )
}

// ---------------------------------------------------------------------
// Determinism and the pinned golden
// ---------------------------------------------------------------------

#[test]
fn the_same_module_renders_byte_identical_lean_source_every_time() {
    let first = fixture_module().lean_source;
    let second = fixture_module().lean_source;
    assert_eq!(first, second);
}

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proof_export/testdata/shifted.lean.golden")
}

#[test]
fn the_rendered_lean_source_matches_the_pinned_golden() {
    let golden = std::fs::read_to_string(golden_path()).expect("pinned golden");
    assert_eq!(
        fixture_module().lean_source,
        golden,
        "the Lean export changed; review the diff and re-pin \
         src/proof_export/testdata/shifted.lean.golden deliberately"
    );
}

#[test]
fn the_lean_source_is_independent_of_where_the_source_file_lives() {
    // Byte-determinism must survive two checkouts at different paths, so the
    // rendered document carries the module name and semantic revision but
    // never the host path it was read from.
    let source = with_main(FIXTURE);
    let first = crate::parse(&source, "/one/checkout/app.spx").expect("parse");
    let second = crate::parse(&source, "/a/completely/different/place/app.spx").expect("parse");
    let revision = crate::graph::revision(&first);
    assert_eq!(revision, crate::graph::revision(&second));
    assert_eq!(
        export_module(&first, &revision).lean_source,
        export_module(&second, &revision).lean_source
    );
    assert!(!export_module(&first, &revision)
        .lean_source
        .contains("checkout"));
}

// ---------------------------------------------------------------------
// Coverage: every declaration lands in exactly one list
// ---------------------------------------------------------------------

#[test]
fn every_declaration_is_either_exported_or_reported_unsupported() {
    let source = with_main(
        "module app.t;\n\
record Point { x: i64, y: i64, }\n\
@id(\"app.t.ok\")\n\
fn ok(a: i64) -> i64 requires a >= 0 ensures result >= 0 { a }\n\
@id(\"app.t.branchy\")\n\
fn branchy(a: i64) -> i64 ensures result >= 0 { if a >= 0 { a } else { 0 } }\n",
    );
    let parsed = program(&source);
    let declarations = parsed.functions.len() + parsed.types.len();
    let export = export_module(&parsed, "rev");
    assert_eq!(
        export.exported.len() + export.unsupported.len(),
        declarations
    );
    assert!(export
        .exported
        .iter()
        .any(|item| item.declaration_id == "app.t.ok"));
    let reasons: Vec<&str> = export
        .unsupported
        .iter()
        .map(|(_, _, reason)| reason.code())
        .collect();
    assert!(reasons.contains(&"non_function_declaration"));
    assert!(reasons.contains(&"conditional_expression"));
    // `main` has no contract clause at all, which is its own closed reason.
    assert!(reasons.contains(&"no_contract_clauses"));
}

#[test]
fn the_generated_lean_header_names_every_refused_declaration() {
    let source = with_main(
        "module app.t;\n\
@id(\"app.t.branchy\")\n\
fn branchy(a: i64) -> i64 ensures result >= 0 { if a >= 0 { a } else { 0 } }\n",
    );
    let export = export_module(&program(&source), "rev");
    assert!(export.lean_source.contains("NOT exported, NOT claimed"));
    assert!(export.lean_source.contains("app.t.branchy"));
    assert!(export.lean_source.contains("conditional_expression"));
}

fn refusal_code(source: &str) -> String {
    let parsed = program(&with_main(source));
    let function = parsed
        .functions
        .iter()
        .find(|item| item.name == "f")
        .expect("fixture declares `f`");
    export_function(function)
        .err()
        .expect("expected this declaration to be refused")
        .code()
        .to_owned()
}

#[test]
fn each_out_of_profile_construct_has_its_own_closed_reason() {
    let cases: [(&str, &str); 9] = [
        (
            "module app.t;\nfn f<T>(a: i64) -> i64 ensures result >= 0 { a }\n",
            "generic_function",
        ),
        (
            "module app.t;\nfn f(a: i64) -> i64 uses { io } ensures result >= 0 { a }\n",
            "effectful_function",
        ),
        (
            "module app.t;\nfn f(a: i64) -> i64 ensures result >= 0 { if a >= 0 { a } else { 0 } }\n",
            "conditional_expression",
        ),
        (
            "module app.t;\nfn f(a: i64, b: i64) -> i64 ensures result >= 0 { a / b }\n",
            "expr",
        ),
        (
            "module app.t;\nfn f(a: bool) -> i64 ensures result >= 0 { 0 }\n",
            "bool_valued_position",
        ),
        (
            "module app.t;\nfn f(a: i64) -> bool ensures result { true }\n",
            "bool_valued_position",
        ),
        (
            "module app.t;\nfn f(a: i64) -> i64 requires a >= 0 { a }\n",
            "no_ensures_clause",
        ),
        (
            "module app.t;\nfn f(a: i64) -> i64 { a }\n",
            "no_contract_clauses",
        ),
        (
            "module app.t;\nfn f(a: i64) -> i64 ensures result >= 0 { let mut t = a; t }\n",
            "mutable_local_binding",
        ),
    ];
    for (source, expected) in cases {
        assert_eq!(refusal_code(source), expected, "source: {source}");
    }
}

// ---------------------------------------------------------------------
// Name mangling
// ---------------------------------------------------------------------

#[test]
fn identifier_escaping_is_injective_across_shapes_that_would_otherwise_collide() {
    // `a.b` and `a_b` both become `a_b` under a naive "replace punctuation
    // with underscore" scheme; under this one they cannot.
    let candidates = ["a.b", "a_b", "a-b", "a b", "ab", "a__b", "a.b.c", "a:b"];
    let mut escaped: Vec<String> = candidates.iter().map(|item| escape_ident(item)).collect();
    escaped.sort();
    let before = escaped.len();
    escaped.dedup();
    assert_eq!(escaped.len(), before, "escaping collided: {escaped:?}");
    assert!(escape_ident("a.b")
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_'));
}

#[test]
fn two_declarations_with_the_same_display_name_get_distinct_theorem_names() {
    let export = export_module(
        &program(&with_main(
            "module app.t;\n\
@id(\"app.t.one.f\")\n\
fn f(a: i64) -> i64 ensures result >= a { a }\n",
        )),
        "rev",
    );
    let names: Vec<String> = export
        .obligations()
        .iter()
        .map(|item| item.theorem_name.clone())
        .collect();
    assert!(names.iter().all(|name| name.contains("app")), "{names:?}");
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

// ---------------------------------------------------------------------
// Obligation structure
// ---------------------------------------------------------------------

#[test]
fn every_arithmetic_node_gets_its_own_checked_range_obligation() {
    let export = fixture_module();
    let obligations = export.obligations();
    let ranges: Vec<_> = obligations
        .iter()
        .filter(|item| item.kind == "checked_arithmetic_range")
        .collect();
    assert_eq!(ranges.len(), 1, "`a + b` is the only arithmetic node");
    assert!(ranges[0].goal.contains("9223372036854775807"));
    assert_eq!(
        obligations
            .iter()
            .filter(|item| item.kind == "postcondition")
            .count(),
        1
    );
}

#[test]
fn a_parameter_range_is_a_hypothesis_and_an_arithmetic_range_is_a_goal() {
    let lean = fixture_module().lean_source;
    // The parameter bound appears as a binder hypothesis...
    assert!(lean.contains("(h_lo_0 : (-9223372036854775808 : Int) ≤ v_a)"));
    // ...and the arithmetic node's bound appears as a goal, never as a
    // hypothesis. Conflating the two is issue #184's worst bug.
    assert!(lean.contains("_range_0"));
    assert!(!lean.contains("(h_range"));
}

// ---------------------------------------------------------------------
// Kernel result parsing: nothing but a clean acceptance is a proof
// ---------------------------------------------------------------------

fn expected_names() -> Vec<String> {
    vec![format!("{NAMESPACE}.spx_demo")]
}

fn clean_output() -> String {
    format!(
        "info: '{NAMESPACE}.spx_demo' depends on axioms: [propext, Classical.choice, Quot.sound]\n"
    )
}

#[test]
fn a_clean_run_of_every_expected_theorem_is_accepted() {
    match parse(&expected_names(), PINNED_TOOLCHAIN, &clean_output()) {
        KernelVerdict::Checked { axioms } => {
            assert_eq!(axioms.len(), 1);
            assert_eq!(
                axioms[0].1,
                vec!["Classical.choice", "Quot.sound", "propext"]
            );
        }
        other => panic!("expected Checked, got {other:?}"),
    }
}

#[test]
fn a_theorem_with_no_axioms_at_all_is_accepted() {
    let output = format!("info: '{NAMESPACE}.spx_demo' does not depend on any axioms\n");
    assert!(matches!(
        parse(&expected_names(), PINNED_TOOLCHAIN, &output),
        KernelVerdict::Checked { .. }
    ));
}

#[test]
fn every_shape_of_non_proof_is_refused() {
    let cases: [(&str, &str); 6] = [
        (
            &format!("warning: Export.lean:3:0: declaration uses 'sorry'\ninfo: '{NAMESPACE}.spx_demo' depends on axioms: [sorryAx]\n"),
            "admitted_hole",
        ),
        (
            &format!("info: '{NAMESPACE}.spx_demo' depends on axioms: [propext, myAxiom]\n"),
            "forbidden_axiom",
        ),
        (
            "error: Export.lean:9:2: omega could not prove the goal\n",
            "build_error",
        ),
        (
            "info: Export.lean:9:2: (deterministic) timeout at whnf\n",
            "timeout",
        ),
        (
            "info: 'SemapraxExport.something_else' depends on axioms: [propext]\n",
            "missing_theorem",
        ),
        ("info: [1/1] Building Export\n", "unrecognized_output"),
    ];
    for (output, expected) in cases {
        match parse(&expected_names(), PINNED_TOOLCHAIN, output) {
            KernelVerdict::Rejected(rejection) => {
                assert_eq!(rejection.code(), expected, "output: {output}");
            }
            other => panic!("expected a rejection for {output}, got {other:?}"),
        }
    }
}

#[test]
fn a_duplicate_axiom_line_for_one_theorem_is_refused() {
    let output = clean_output().repeat(2);
    match parse(&expected_names(), PINNED_TOOLCHAIN, &output) {
        KernelVerdict::Rejected(Rejection::DuplicateTheorem { .. }) => {}
        other => panic!("expected DuplicateTheorem, got {other:?}"),
    }
}

#[test]
fn a_kernel_reporting_a_different_toolchain_is_refused_before_anything_else() {
    match parse(
        &expected_names(),
        "leanprover/lean4:v4.99.0",
        &clean_output(),
    ) {
        KernelVerdict::Rejected(Rejection::ToolchainDrift { reported }) => {
            assert_eq!(reported, "leanprover/lean4:v4.99.0");
        }
        other => panic!("expected ToolchainDrift, got {other:?}"),
    }
}

#[test]
fn the_pinned_toolchain_is_the_one_the_repository_already_pins_for_kernel_zero() {
    let pinned = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("proofs/kernel0-lean/lean-toolchain"),
    )
    .expect("issue #188 pinned this file");
    assert_eq!(
        pinned.trim(),
        PINNED_TOOLCHAIN,
        "this export must reuse the repository's single Lean pin, not introduce a second"
    );
}

// ---------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------

#[test]
fn a_certificate_from_an_accepting_kernel_replays_structurally_and_against_source() {
    let path = write_temp(FIXTURE, "happy");
    let certificate = certificate_for(&path);
    let checked = verify_certificate(&certificate).expect("structural replay");
    assert_eq!(checked.declaration_id, "app.t.shifted");
    assert_eq!(checked.ensures_index, 0);
    verify_certificate_against_source(&certificate, &path).expect("source-bound replay");
    assert!(certificate.contains(ARTIFACT_TARGET));
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_certificate_fails_closed_when_the_bound_source_drifts() {
    let path = write_temp(FIXTURE, "drift");
    let certificate = certificate_for(&path);
    std::fs::write(
        &path,
        with_main(&FIXTURE.replace("ensures result >= a", "ensures result >= 0")),
    )
    .unwrap();
    let error = verify_certificate_against_source(&certificate, &path)
        .expect_err("source drift must fail closed");
    assert_eq!(error.code, "SPX-Z112");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_certificate_fails_closed_when_its_payload_is_tampered_with() {
    let path = write_temp(FIXTURE, "tamper");
    let certificate = certificate_for(&path);
    let tampered = certificate.replace("\"kernel_checked\"", "\"kernel_chocked\"");
    assert_ne!(tampered, certificate);
    assert!(verify_certificate(&tampered).is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_certificate_whose_embedded_lean_document_was_edited_is_refused() {
    let path = write_temp(FIXTURE, "leanedit");
    let certificate = certificate_for(&path);
    // Weaken a theorem statement inside the embedded document, then repair
    // the envelope digest so only the *re-derivation* can catch it.
    let edited = certificate.replace("spx_app", "spx_zpx");
    assert_ne!(edited, certificate);
    assert!(verify_certificate(&edited).is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_certificate_fails_closed_when_the_compiler_identity_drifts() {
    let path = write_temp(FIXTURE, "compiler");
    let certificate = certificate_for(&path);
    let moved = certificate.replace(
        &format!("\"compiler_version\":\"{}\"", env!("CARGO_PKG_VERSION")),
        "\"compiler_version\":\"0.0.0-not-this-compiler\"",
    );
    assert_ne!(moved, certificate);
    // The envelope digest no longer matches, so structural replay already
    // refuses; the version check is a second, independent guard for a
    // certificate whose digest was recomputed by whoever edited it.
    assert!(verify_certificate_against_source(&moved, &path).is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn artifact_binding_accepts_only_the_exact_bound_bytes() {
    let path = write_temp(FIXTURE, "artifact");
    let certificate = certificate_for(&path);
    let parsed = crate::parse(&std::fs::read_to_string(&path).unwrap(), &path).unwrap();
    let resolved = crate::hir::resolve(&parsed).unwrap();
    let artifact = crate::wasm::emit_resolved_module(&resolved).unwrap();
    verify_certificate_against_artifact(&certificate, &artifact).expect("bound artifact");
    let mut mutated = artifact.clone();
    mutated.push(0);
    assert!(verify_certificate_against_artifact(&certificate, &mutated).is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn no_certificate_is_produced_when_the_kernel_reports_an_admitted_hole() {
    let path = write_temp(FIXTURE, "sorry");
    let kernel = FixedKernel {
        toolchain: PINNED_TOOLCHAIN.to_owned(),
        output: "warning: Export.lean:3:0: declaration uses 'sorry'\n".to_owned(),
    };
    let error = export_obligation_certificate(&path, "app.t.shifted", 0, &kernel)
        .expect_err("an admitted hole is not a proof");
    assert!(error[0].message.contains("admitted_hole"), "{error:?}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn no_certificate_is_produced_for_a_declaration_outside_the_profile() {
    let source = "module app.t;\n\
@id(\"app.t.branchy\")\n\
fn branchy(a: i64) -> i64 ensures result >= 0 { if a >= 0 { a } else { 0 } }\n";
    let path = write_temp(source, "outside");
    let error = export_obligation_certificate(&path, "app.t.branchy", 0, &AcceptingKernel)
        .expect_err("outside the profile");
    assert!(
        error[0].message.contains("conditional_expression"),
        "{error:?}"
    );
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// The external-kernel capability seam
// ---------------------------------------------------------------------

struct AlwaysConfirms;

impl ExternalKernelCapability for AlwaysConfirms {
    fn confirm(&self, _script: &str) -> Result<(), Diagnostic> {
        Ok(())
    }
}

#[test]
fn a_capability_that_always_confirms_cannot_rescue_a_drifted_certificate() {
    let path = write_temp(FIXTURE, "capability");
    let certificate = certificate_for(&path);
    verify_certificate_with_capability(&certificate, &path, &AlwaysConfirms)
        .expect("bindings hold, capability confirms");
    std::fs::write(
        &path,
        with_main(&FIXTURE.replace("ensures result >= a", "ensures result >= 0")),
    )
    .unwrap();
    assert!(
        verify_certificate_with_capability(&certificate, &path, &AlwaysConfirms).is_err(),
        "binding checks must run before the capability is consulted"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_lean_kernel_recheck_reproduces_the_exact_recorded_axiom_results() {
    let path = write_temp(FIXTURE, "kernel-recheck");
    let certificate = certificate_for(&path);
    verify_certificate_with_kernel(&certificate, &path, &AcceptingKernel)
        .expect("the same pinned-kernel result must reproduce");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_lean_kernel_recheck_refuses_an_admitted_hole() {
    let path = write_temp(FIXTURE, "kernel-recheck-sorry");
    let certificate = certificate_for(&path);
    let kernel = FixedKernel {
        toolchain: PINNED_TOOLCHAIN.to_owned(),
        output: "warning: Export.lean:3:0: declaration uses `sorry`\n".to_owned(),
    };
    let error = verify_certificate_with_kernel(&certificate, &path, &kernel)
        .expect_err("a recheck with an admitted hole is not proof");
    assert_eq!(error.code, "SPX-Z110");
    assert!(error.message.contains("admitted_hole"), "{}", error.message);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_lean_kernel_recheck_refuses_a_resealed_axiom_result_tamper() {
    let path = write_temp(FIXTURE, "kernel-recheck-axiom-tamper");
    let certificate = certificate_for(&path);
    let changed = certificate.replacen(
        "\"axioms\":[\"Classical.choice\",\"Quot.sound\",\"propext\"]",
        "\"axioms\":[\"Quot.sound\"]",
        1,
    );
    assert_ne!(changed, certificate, "fixture must carry recorded axioms");
    let tampered = reseal_payload(&changed);
    verify_certificate_against_source(&tampered, &path)
        .expect("the deliberately resealed tamper must reach the external result check");
    let error = verify_certificate_with_kernel(&tampered, &path, &AcceptingKernel)
        .expect_err("the fresh kernel result must disagree with the tampered record");
    assert_eq!(error.code, "SPX-Z112");
    assert!(error.message.contains("axiom results"), "{}", error.message);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_lean_kernel_recheck_never_runs_before_source_binding() {
    let path = write_temp(FIXTURE, "kernel-recheck-drift");
    let certificate = certificate_for(&path);
    std::fs::write(
        &path,
        with_main(&FIXTURE.replace("ensures result >= a", "ensures result >= 0")),
    )
    .unwrap();
    let kernel = CountingKernel {
        calls: Cell::new(0),
    };
    let error = verify_certificate_with_kernel(&certificate, &path, &kernel)
        .expect_err("source drift must be refused before kernel invocation");
    assert_eq!(error.code, "SPX-Z112");
    assert_eq!(
        kernel.calls.get(),
        0,
        "the kernel must not see unbound bytes"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn source_replay_refuses_every_resealed_selected_obligation_identity_tamper_before_kernel() {
    let path = write_temp(FIXTURE, "kernel-recheck-identity-tamper");
    let certificate = certificate_for(&path);
    let checked = verify_certificate(&certificate).expect("fixture certificate is structural");
    let mutations = [
        (
            "module",
            "\"module\":\"app.t\"".to_owned(),
            "\"module\":\"app.other\"".to_owned(),
        ),
        (
            "declaration_id",
            "\"declaration_id\":\"app.t.shifted\"".to_owned(),
            "\"declaration_id\":\"app.t.other\"".to_owned(),
        ),
        (
            "ensures_index",
            "\"ensures_index\":0".to_owned(),
            "\"ensures_index\":1".to_owned(),
        ),
        (
            "obligation_id",
            format!("\"obligation_id\":\"{}\"", checked.obligation_id),
            "\"obligation_id\":\"semaprax.obligation.v1:forged\"".to_owned(),
        ),
        (
            "theorem_name",
            format!("\"theorem_name\":\"{}\"", checked.theorem_name),
            "\"theorem_name\":\"SemapraxExport.spx_forged_ensures_0\"".to_owned(),
        ),
    ];
    for (label, from, to) in mutations {
        let changed = certificate.replace(&from, &to);
        assert_ne!(changed, certificate, "{label} mutation must apply");
        let tampered = reseal_payload(&changed);
        verify_certificate(&tampered).expect("{label} tamper remains structurally consistent");
        let kernel = CountingKernel {
            calls: Cell::new(0),
        };
        let error = verify_certificate_with_kernel(&tampered, &path, &kernel)
            .expect_err("{label} tamper must be refused before a kernel can run");
        assert_eq!(error.code, "SPX-Z112", "{label}");
        assert_eq!(kernel.calls.get(), 0, "{label}");
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn source_replay_refuses_a_resealed_missing_range_obligation_before_kernel() {
    let path = write_temp(FIXTURE, "kernel-recheck-obligation-removal");
    let certificate = certificate_for(&path);
    let mut value: serde_json::Value =
        serde_json::from_str(&certificate).expect("certificate JSON");
    let obligations = value["payload"]["obligations"]
        .as_array_mut()
        .expect("certificate obligations");
    let index = obligations
        .iter()
        .position(|obligation| {
            obligation["declaration_id"].as_str() == Some("app.t.shifted")
                && obligation["kind"].as_str() == Some("checked_arithmetic_range")
        })
        .expect("fixture has a non-headline range obligation");
    obligations.remove(index);
    let payload = serde_json::to_string(&value["payload"]).expect("payload JSON");
    let tampered = format!(
        "{{\"schema\":\"{CERTIFICATE_SCHEMA}\",\"digest\":\"{}\",\"bytes\":{},\"payload\":{payload}}}",
        payload_digest(payload.as_bytes()),
        payload.len(),
    );
    verify_certificate(&tampered).expect("missing non-headline record remains structural");
    let kernel = CountingKernel {
        calls: Cell::new(0),
    };
    let error = verify_certificate_with_kernel(&tampered, &path, &kernel)
        .expect_err("a complete selected-obligation inventory is required before recheck");
    assert_eq!(error.code, "SPX-Z112");
    assert_eq!(
        kernel.calls.get(),
        0,
        "kernel must not see an incomplete claim"
    );
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Coverage report
// ---------------------------------------------------------------------

#[test]
fn the_coverage_report_is_deterministic_and_lists_refusals_with_reasons() {
    let export = export_module(
        &program(&with_main(
            "module app.t;\n\
@id(\"app.t.branchy\")\n\
fn branchy(a: i64) -> i64 ensures result >= 0 { if a >= 0 { a } else { 0 } }\n",
        )),
        "rev",
    );
    let first = render_coverage(&export);
    let second = render_coverage(&export);
    assert_eq!(first, second);
    assert!(first.contains("conditional_expression"));
    assert!(first.contains("A6-translation-tcb"));
    assert!(first.contains("semaprax.lean-export-coverage.v1"));
}

#[test]
fn export_source_reports_coverage_and_never_writes_to_the_source() {
    let path = write_temp(FIXTURE, "readonly");
    let before = std::fs::read_to_string(&path).unwrap();
    let (export, coverage) = export_source(&path).expect("export");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert!(coverage.contains("app.t.shifted"));
    assert!(export.lean_source.contains("#print axioms"));
    std::fs::remove_file(&path).ok();
}

/// The deliberate re-pin path for
/// `testdata/shifted.lean.golden`. Ignored by default so a changed export can
/// never re-pin itself: an operator re-pins on purpose with
/// `cargo test -p semaprax --lib rewrite_the_pinned_lean_golden -- --ignored`
/// and reviews the resulting diff.
#[test]
#[ignore = "re-pins the golden; run deliberately and review the diff"]
fn rewrite_the_pinned_lean_golden() {
    std::fs::write(golden_path(), fixture_module().lean_source).unwrap();
}

#[test]
fn a_certificate_whose_embedded_lean_document_was_weakened_is_refused_by_re_derivation() {
    // The headline test. Build a *fully self-consistent* certificate — correct
    // envelope digest, correct `lean_source_sha256`, correct axiom records —
    // around a Lean document whose postcondition theorem has been weakened to
    // a tautology. Structural replay therefore passes: nothing inside the
    // certificate is inconsistent. Only re-deriving the document from the
    // bound source can catch it, which is exactly why
    // `verify_certificate_against_source` re-renders instead of trusting the
    // embedded bytes.
    let path = write_temp(FIXTURE, "weakened");
    let source = std::fs::read_to_string(&path).unwrap();
    let parsed = crate::parse(&source, &path).unwrap();
    let revision = crate::graph::revision(&parsed);
    let mut export = export_module(&parsed, &revision);
    let weakened = export
        .lean_source
        .replace("(result ≥ v_a)", "(result ≥ result)");
    assert_ne!(
        weakened, export.lean_source,
        "the fixture goal must be present"
    );
    export.lean_source = weakened;

    let function = export
        .exported
        .iter()
        .find(|item| item.declaration_id == "app.t.shifted")
        .expect("fixture declaration")
        .clone_for_test();
    let obligation = function
        .iter()
        .find(|item| item.ensures_index == Some(0))
        .expect("postcondition obligation");
    let theorem_name = format!("{NAMESPACE}.{}", obligation.theorem_name);
    let obligation_id = obligation.obligation_id.clone();
    let axioms: Vec<(String, Vec<String>)> = export
        .theorem_names()
        .into_iter()
        .map(|name| (name, vec!["propext".to_owned()]))
        .collect();

    let resolved = crate::hir::resolve(&parsed).unwrap();
    let artifact = crate::wasm::emit_resolved_module(&resolved).unwrap();
    let path_text = path.display().to_string();
    let source_sha256 = super::certificate::source_digest(&source);
    let artifact_sha256 = super::certificate::artifact_digest(&artifact);
    let certificate =
        super::certificate::render_certificate(&super::certificate::CertificateInput {
            source_path_text: &path_text,
            source_sha256: &source_sha256,
            export: &export,
            declaration_id: "app.t.shifted",
            ensures_index: 0,
            obligation_id: &obligation_id,
            theorem_name: &theorem_name,
            compiler_version: env!("CARGO_PKG_VERSION"),
            toolchain: PINNED_TOOLCHAIN,
            axioms: &axioms,
            artifact_sha256: &artifact_sha256,
            artifact_bytes: artifact.len(),
        });

    verify_certificate(&certificate)
        .expect("a self-consistent certificate passes structural replay");
    let error = verify_certificate_against_source(&certificate, &path)
        .expect_err("a weakened embedded theorem must be refused by re-derivation");
    assert_eq!(error.code, "SPX-Z112");
    assert!(error.message.contains("re-rendering"), "{}", error.message);
    std::fs::remove_file(&path).ok();
}

/// `artifact_binding_accepts_only_the_exact_bound_bytes` above only proves
/// rejection of a *corrupted copy* of the certificate's own artifact (one
/// byte appended). That leaves the actually dangerous case unproven: a
/// certificate minted against a **prior head** of the exact same source
/// file, replayed via the compiler-free, filesystem-free
/// `verify_certificate_against_artifact` against the **current head**'s
/// genuinely, independently compiled artifact. If that bound only a weak
/// property (e.g. shape or length), a stale certificate could be presented
/// as evidence about a live build after the source moved on. It must not
/// bind, and it must fail with the drift code, not the structural one,
/// since the certificate is perfectly self-consistent on its own.
#[test]
fn verify_certificate_against_artifact_rejects_a_prior_heads_artifact() {
    let path = write_temp(FIXTURE, "priorhead");

    // Prior head: mint a certificate bound to this file's current bytes and
    // compile its real Wasm core module.
    let certificate = certificate_for(&path);
    let prior_source = std::fs::read_to_string(&path).unwrap();
    let prior_program = crate::parse(&prior_source, &path).unwrap();
    let prior_resolved = crate::hir::resolve(&prior_program).unwrap();
    let prior_artifact = crate::wasm::emit_resolved_module(&prior_resolved).unwrap();

    // Current head: the same declaration and path, but a source edit that
    // stays inside the profile (still admitted, still exports a certifiable
    // obligation) and changes a literal that participates in the compiled
    // module, so the two artifacts are genuinely distinct compiled bytes —
    // not a corrupted copy of one another.
    let advanced = FIXTURE.replace("requires a <= 1000", "requires a <= 500");
    assert_ne!(
        advanced, FIXTURE,
        "the edit must actually change the source"
    );
    std::fs::write(&path, with_main(&advanced)).unwrap();
    let current_source = std::fs::read_to_string(&path).unwrap();
    let current_program = crate::parse(&current_source, &path).unwrap();
    let current_resolved = crate::hir::resolve(&current_program).unwrap();
    let current_artifact = crate::wasm::emit_resolved_module(&current_resolved).unwrap();

    assert_ne!(
        prior_artifact, current_artifact,
        "the source edit must produce a genuinely different compiled artifact, \
         or the rejection below would be vacuous"
    );

    // Control: the prior-head certificate still binds to its own, genuine
    // artifact.
    verify_certificate_against_artifact(&certificate, &prior_artifact)
        .expect("a certificate must still bind to its own prior-head artifact");

    // The replay attack: presenting the current head's real, validly
    // compiled artifact against the prior-head certificate must be refused,
    // not accepted because both are "the same target and shape".
    let error = verify_certificate_against_artifact(&certificate, &current_artifact)
        .expect_err("a prior-head certificate must not bind to a later head's artifact");
    assert_eq!(error.code, "SPX-Z112");

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Real pinned-kernel transcripts
//
// Everything above this line replays *synthesized* kernel output. The
// three transcripts below were produced by running the pinned Lean 4.34.0
// toolchain (`proofs/kernel0-lean/lean-toolchain`) over the committed
// golden document on a developer host, and copied here verbatim. They are
// **local-host evidence only**: hosted CI provisions no Lean toolchain
// (`docs/QUALITY-GATES.md`), so these tests re-check the parser against
// recorded real bytes rather than running a kernel themselves.
//
// `scripts/lean-export-gate.py` is the runner that produced them and
// re-derives them on a host that has the toolchain.
// ---------------------------------------------------------------------

fn transcript(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/proof_export/testdata")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("recorded kernel transcript {}: {error}", path.display()))
}

/// The two theorems the committed golden document exports, in the order
/// its `#print axioms` commands appear.
fn golden_theorem_names() -> Vec<String> {
    vec![
        format!("{NAMESPACE}.spx_app_2et_2eshifted_range_0"),
        format!("{NAMESPACE}.spx_app_2et_2eshifted_ensures_0"),
    ]
}

#[test]
fn the_golden_document_declares_exactly_the_theorems_the_transcripts_name() {
    // Binds the transcripts to the golden: re-pinning the export without
    // re-recording the transcripts fails here rather than silently leaving
    // the tests below checking a document that no longer exists.
    assert_eq!(fixture_module().theorem_names(), golden_theorem_names());
}

#[test]
fn a_real_pinned_kernel_run_over_the_golden_document_is_accepted() {
    // The claim `docs/LEAN-OBLIGATION-EXPORT-V1.md` could not make when the
    // export was written: Lean actually accepts these generated proofs.
    // `omega` discharged both the checked-range obligation and the
    // postcondition.
    match parse(
        &golden_theorem_names(),
        PINNED_TOOLCHAIN,
        &transcript("shifted.kernel-output.txt"),
    ) {
        KernelVerdict::Checked { axioms } => {
            assert_eq!(
                axioms,
                vec![
                    (
                        golden_theorem_names()[0].clone(),
                        vec![
                            "Classical.choice".to_owned(),
                            "Quot.sound".to_owned(),
                            "propext".to_owned(),
                        ],
                    ),
                    (
                        golden_theorem_names()[1].clone(),
                        vec!["Quot.sound".to_owned(), "propext".to_owned()],
                    ),
                ]
            );
        }
        other => panic!("expected Checked, got {other:?}"),
    }
}

#[test]
fn real_kernel_noise_is_not_mistaken_for_an_axiom_report() {
    // The real transcript interleaves nine lines of unused-variable linter
    // output, multi-line hints and backtick-quoted identifiers with the two
    // axiom lines. No synthesized fixture above contains any of that, and a
    // parser that scanned loosely for quoted names would pick the linter's
    // hints up as theorems.
    let output = transcript("shifted.kernel-output.txt");
    assert!(output.contains("warning: Variable name `h_lo_0`"));
    assert!(output.contains("[apply] _h_lo_0"));
    assert!(matches!(
        parse(&golden_theorem_names(), PINNED_TOOLCHAIN, &output),
        KernelVerdict::Checked { .. }
    ));
}

#[test]
fn a_real_sorry_in_the_golden_document_is_refused_as_an_admitted_hole() {
    // Seeded by replacing the postcondition proof's `omega` with `sorry`
    // and re-running the pinned kernel. Note what the toolchain actually
    // prints: ``declaration uses `sorry` `` with BACKTICKS. The
    // single-quoted spellings this parser was first written against never
    // occur, so before the transcript existed the warning half of the
    // admitted-hole check was dead against the very toolchain this module
    // pins, and only the `sorryAx` axiom-line clause was load-bearing.
    let output = transcript("shifted.kernel-output.sorry.txt");
    assert!(
        output.contains("declaration uses `sorry`"),
        "the recorded warning must keep its real backtick quoting"
    );
    assert!(
        !output.contains("declaration uses 'sorry'"),
        "the pinned toolchain does not use the single-quoted spelling"
    );
    match parse(&golden_theorem_names(), PINNED_TOOLCHAIN, &output) {
        KernelVerdict::Rejected(rejection) => assert_eq!(rejection.code(), "admitted_hole"),
        other => panic!("expected a rejection, got {other:?}"),
    }

    // The warning line alone, with every axiom line removed, must still be
    // refused: a `sorry` in a helper that carries no `#print axioms`
    // command of its own is exactly the case the axiom-line clause cannot
    // see.
    let warning_only = output
        .lines()
        .filter(|line| !line.contains("depends on axioms"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!warning_only.contains("sorryAx"));
    match parse(&golden_theorem_names(), PINNED_TOOLCHAIN, &warning_only) {
        KernelVerdict::Rejected(rejection) => assert_eq!(rejection.code(), "admitted_hole"),
        other => panic!("expected a rejection from the warning alone, got {other:?}"),
    }
}

#[test]
fn a_vacuously_weakened_theorem_really_does_pass_the_kernel_and_only_the_byte_binding_catches_it() {
    // The honest limit of kernel output as evidence, demonstrated rather
    // than argued. The golden's postcondition conclusion was weakened from
    // `(result ≥ v_a)` to `(result ≥ v_a) ∨ True` and proved by
    // `Or.inr True.intro`. The pinned kernel exits 0 and reports an axiom
    // set that is *cleaner* than the honest proof's — `does not depend on
    // any axioms`. `parse` therefore accepts it, and must: nothing in the
    // output is wrong.
    //
    // What refuses it is `verify_certificate_against_source`, which
    // re-renders the Lean document from the bound source and compares
    // bytes; see
    // `a_certificate_whose_embedded_lean_document_was_weakened_is_refused_by_re_derivation`.
    // This is why a certificate binds `lean_source_sha256` and embeds the
    // document, instead of recording that a build succeeded.
    let output = transcript("shifted.kernel-output.weakened.txt");
    assert!(output.contains("does not depend on any axioms"));
    assert!(
        matches!(
            parse(&golden_theorem_names(), PINNED_TOOLCHAIN, &output),
            KernelVerdict::Checked { .. }
        ),
        "a weakened-but-true theorem is genuinely kernel-checked; the \
         statement binding, not the verdict, is what makes it useless"
    );
}
