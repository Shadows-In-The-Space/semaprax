//! Validation of [`super::project_admitted_subject`]'s output against a real
//! WebAssembly Component Model toolchain.
//!
//! Issue #176 asks for a projection a standard Component Model toolchain
//! accepts. Every other test in this tree checks the projection against this
//! repository's *own* bounded parser, which is exactly as wrong as the
//! renderer whenever both share a misreading of the WIT grammar. These tests
//! close that gap by handing the emitted bytes to `wasm-tools` and letting it
//! judge.
//!
//! They are `#[ignore]`d and read an explicitly provisioned path, following
//! the convention `assurance_manifest::smt_discharge::tests` already uses for
//! a provisioned `z3`: a bare `cargo test` must never appear to have
//! validated WIT against a toolchain it never ran. Run them with:
//!
//! ```sh
//! SEMAPRAX_WIT_WASM_TOOLS=/opt/homebrew/bin/wasm-tools \
//!   cargo test --locked -p semaprax --lib \
//!   public_generic_abi::wit_projection::toolchain_tests -- --ignored
//! ```
//!
//! A missing or unset `SEMAPRAX_WIT_WASM_TOOLS` is a **panic**, never a
//! silent skip: an ignored test that quietly returns `Ok` when the tool is
//! absent is a false pass, and reporting "validated" on that basis would be a
//! nonclaim violation.
//!
//! ## What these tests do not claim
//!
//! `wasm-tools component wit` parses and resolves WIT text. Passing it proves
//! the emitted *types* are a well-formed Component Model world. It does not
//! build, link, instantiate, or execute a component; no compiled `.wasm`
//! implements the public-generic provider ABI (issue #229), and public
//! generic ownership remains unsupported and unpublished pending PG-9.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use super::tests::{resolved, BASE};
use super::{parse_wit_projection, project_admitted_subject, MALFORMED_WIT};
use crate::public_generic_abi::classifier::classify;

/// The provisioned `wasm-tools` binary. Absent provisioning is a hard
/// failure, so a run of these tests can never report success without having
/// executed the toolchain.
fn wasm_tools() -> PathBuf {
    let raw = env::var("SEMAPRAX_WIT_WASM_TOOLS").expect(
        "these tests are #[ignore]d and must only be run with SEMAPRAX_WIT_WASM_TOOLS set to an \
         absolute path to a provisioned wasm-tools binary",
    );
    let path = PathBuf::from(&raw);
    assert!(
        path.is_absolute() && path.is_file(),
        "SEMAPRAX_WIT_WASM_TOOLS must be an absolute path to an existing wasm-tools binary, got \
         `{raw}`"
    );
    path
}

/// Write `wit` into a fresh directory under the system temporary directory
/// and run `wasm-tools component wit` over it. Returns the exit status and
/// the combined output. The directory is removed before returning.
fn validate(wit: &str, label: &str) -> (bool, String) {
    let tool = wasm_tools();
    let dir = env::temp_dir().join(format!(
        "semaprax-wit-{label}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::create_dir_all(&dir).expect("temporary directory");
    let file = dir.join("projection.wit");
    fs::write(&file, wit).expect("write projected WIT");
    let output = Command::new(&tool)
        .arg("component")
        .arg("wit")
        .arg(&file)
        .output()
        .unwrap_or_else(|error| panic!("could not run `{}`: {error}", tool.display()));
    let _ = fs::remove_dir_all(&dir);
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

/// Every scalar this projection admits, plus the owned `Bytes` leaf, in one
/// record. `usize` is deliberately absent: the grammar admits it but this
/// projection refuses it (`SPX-PGWIT101`), so a fixture containing it would
/// never reach the toolchain at all. The point of this fixture is to put
/// every WIT primitive the mapping table emits in front of `wasm-tools`.
const EVERY_PROJECTED_PRIMITIVE: &str = r#"
module test.public_generic_wit_toolchain;

@id("wit_toolchain.scalars")
record Scalars {
    @id("wit_toolchain.scalars.a")
    a: i64,
    @id("wit_toolchain.scalars.b")
    b: i32,
    @id("wit_toolchain.scalars.c")
    c: u8,
    @id("wit_toolchain.scalars.e")
    e: char,
    @id("wit_toolchain.scalars.f")
    f: f32,
    @id("wit_toolchain.scalars.g")
    g: f64,
    @id("wit_toolchain.scalars.h")
    h: bool,
    @id("wit_toolchain.scalars.leaf")
    leaf: Bytes,
}

@id("wit_toolchain.take")
fn take(value: own Scalars) -> Scalars { value }

@id("wit_toolchain.main")
fn main() -> i64 { 0 }
"#;

fn projection_wit_of(source: &str, export: &str) -> String {
    let program = resolved(source);
    let admitted = classify(&program, export).unwrap();
    project_admitted_subject(&admitted).unwrap().wit
}

fn projection_wit(export: &str) -> String {
    projection_wit_of(BASE, export)
}

#[test]
#[ignore = "requires explicitly provisioned SEMAPRAX_WIT_WASM_TOOLS (wasm-tools)"]
fn the_projected_world_is_accepted_by_a_real_component_model_toolchain() {
    // A nested-record world with a shared `resource`, and a flat world
    // exercising every WIT primitive the mapping table emits.
    let cases = [
        (BASE, "wit_projection.take"),
        (EVERY_PROJECTED_PRIMITIVE, "wit_toolchain.take"),
    ];
    for (source, export) in cases {
        let wit = projection_wit_of(source, export);
        let (ok, output) = validate(&wit, "valid");
        assert!(
            ok,
            "wasm-tools rejected the projection of `{export}`:\n{output}\n--- emitted ---\n{wit}"
        );
    }
    // Guard against a vacuous pass: the primitive fixture really does emit
    // every primitive row of the mapping table.
    let wit = projection_wit_of(EVERY_PROJECTED_PRIMITIVE, "wit_toolchain.take");
    for primitive in ["s64", "s32", "u8", "char", "f32", "f64", "bool"] {
        assert!(
            wit.contains(&format!(": {primitive},")),
            "the primitive fixture must emit `{primitive}`:\n{wit}"
        );
    }
}

/// The negative control that makes the test above mean something. If
/// `wasm-tools component wit` accepted anything at all — a wrong subcommand,
/// a stubbed binary, a tool that only checks the file exists — the positive
/// test would pass while proving nothing. Deliberately broken WIT must be
/// rejected by the same command.
#[test]
#[ignore = "requires explicitly provisioned SEMAPRAX_WIT_WASM_TOOLS (wasm-tools)"]
fn deliberately_broken_wit_is_rejected_by_the_same_toolchain_command() {
    let wit = projection_wit("wit_projection.take");

    // A field whose type names a record that was never declared: structurally
    // plausible text that only a resolver catches.
    let dangling = wit.replace("own<spx-owned-bytes>", "spx-never-declared");
    assert_ne!(dangling, wit, "the mutation must really change the text");
    let (ok, output) = validate(&dangling, "dangling");
    assert!(
        !ok,
        "wasm-tools accepted WIT naming an undeclared type; the positive \
         validation above would therefore prove nothing:\n{output}"
    );

    // An unbalanced brace: a pure syntax break.
    let truncated = wit.replace("}\n\nworld ", "\n\nworld ");
    assert_ne!(truncated, wit);
    let (ok, output) = validate(&truncated, "truncated");
    assert!(!ok, "wasm-tools accepted unbalanced WIT:\n{output}");
}

/// The interop boundary this projection has, recorded as an executable fact
/// rather than a comment.
///
/// `wasm-tools` re-renders WIT in its own canonical form: `own<T>` is printed
/// bare (in WIT a resource-typed field is owned by default, so this is a
/// notation difference, not a semantic one) and blank lines are inserted
/// between declarations. That re-rendered text is still valid WIT, and this
/// profile's decoder still refuses it with `SPX-PGWIT105`, because
/// [`parse_wit_projection`] is a strict canonical-form determinism check —
/// "these bytes are exactly what SEMAPRAX emits" — and not a general WIT
/// parser.
///
/// The consequence is real and belongs in a test: any workflow that round
/// trips this WIT through standard tooling and feeds the result back is
/// refused. This asserts both halves — the toolchain accepts its own
/// re-rendering, and this profile's decoder does not — so neither half can
/// change silently.
#[test]
#[ignore = "requires explicitly provisioned SEMAPRAX_WIT_WASM_TOOLS (wasm-tools)"]
fn toolchain_canonical_text_stays_valid_wit_and_is_still_refused_by_this_profile() {
    let wit = projection_wit("wit_projection.take");
    // The projection decodes as its own canonical form before anything else,
    // so a later refusal is attributable to the re-rendering and not to a
    // broken fixture.
    parse_wit_projection(&wit).expect("the projection is its own canonical form");

    let tool = wasm_tools();
    let dir = env::temp_dir().join(format!("semaprax-wit-canon-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temporary directory");
    let file = dir.join("projection.wit");
    fs::write(&file, &wit).expect("write projected WIT");
    let output = Command::new(&tool)
        .arg("component")
        .arg("wit")
        .arg(&file)
        .output()
        .unwrap_or_else(|error| panic!("could not run `{}`: {error}", tool.display()));
    let _ = fs::remove_dir_all(&dir);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let canonical = String::from_utf8(output.stdout).expect("wasm-tools emits UTF-8");

    assert_ne!(
        canonical, wit,
        "this test documents a re-rendering difference; if wasm-tools now \
         round trips byte-exactly, delete this test rather than relaxing it"
    );
    let (ok, _) = validate(&canonical, "canonical");
    assert!(ok, "the toolchain must accept its own canonical rendering");

    let refusal = parse_wit_projection(&canonical)
        .expect_err("a re-rendered variant is not this profile's canonical form");
    assert_eq!(refusal.code, MALFORMED_WIT);
}
