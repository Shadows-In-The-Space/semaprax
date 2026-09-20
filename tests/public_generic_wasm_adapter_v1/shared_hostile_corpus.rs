//! Issue #160: the shared malformed-input/wrong-binding corpus, executed by
//! the generated TypeScript/Wasm calling consumer (#157) against the SAME
//! canonical descriptor baseline the native shared-corpus harness
//! (`tests/public_generic_native_adapter_v1/shared_hostile_corpus.rs`) feeds
//! to the Rust/C11/C++17 consumers, and cross-checked against the identical
//! manifest (`tests/support/public_generic_hostile_corpus.rs`).
//!
//! The native and Wasm harnesses are separate test binaries with disjoint
//! toolchain preconditions (clang/cargo vs. node/tsc) and cannot compare
//! outcomes inside one process. Real agreement is still enforced
//! transitively: this test's outcomes and the native trio's outcomes are
//! each asserted against the SAME `EXPECTED` table in the SAME on-disk
//! manifest file, so a route that diverges from the other three fails a
//! hard assertion in its own harness, not merely a hand-written local
//! approximation nobody else is compared against.
//!
//! Known gap, stated once here rather than papered over (see #229 and this
//! directory's own `typescript_calling_consumer.rs`): no compiled `.wasm`
//! artifact implements the Core Wasm provider ABI yet. This test runs the
//! SAME hand-assembled, clearly test-only `reference_wasm_module` the sibling
//! harness uses -- one real endpoint export over real `WebAssembly.Memory`,
//! never a second provider implementation -- so the TypeScript route here
//! cannot honestly be said to exercise a real provider ABI, only the
//! generated consumer's own codec/lifecycle logic against it. Its "provider"
//! zero-allocation counters are therefore the generated `wasm-provider.ts`'s
//! OWN host-side bookkeeping (`Provider.diagnostics.liveAllocations`),
//! standing in for a missing real provider's counters, not an independent
//! compiled provider's counters the way the native trio's
//! `spx_pg_consumer_test_live_allocations` genuinely is.
//!
//! For the same reason the descriptor-mutation cases are the one family
//! that is byte-for-byte identical with the native trio (the descriptor is
//! provider-family-agnostic); the binding-mutation case necessarily mutates
//! THIS route's own `WasmProviderBindingV1`-encoded bytes (a native binding
//! and a Wasm binding are different types with different content), applying
//! the identical mutation RECIPE (flip the last byte) to each route's own
//! valid binding rather than literally shared bytes.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::public_generic_abi::carrier::{CarrierBindingV1, TargetProfile};
use semaprax::public_generic_abi::wasm::binding::WasmProviderBindingV1;
use semaprax::public_generic_abi::wasm::provider::FIXTURE_ENDPOINT_EXPORT_NAME;
use semaprax::public_generic_consumer::rust_calling::{OwnedByteField, RecordShape};
use semaprax::public_generic_consumer::typescript_calling::generate_typescript_calling_consumer;

use super::reference_wasm_module;

#[path = "../support/public_generic_hostile_corpus.rs"]
mod public_generic_hostile_corpus;
use public_generic_hostile_corpus::{
    assert_matches_expected, baseline_descriptor_bytes, malformed_result_carrier_cases,
    malformed_trusted_descriptor_cases, malformed_trusted_descriptor_mutation_cases,
    parse_shared_corpus_lines, structured_descriptor_cases, MAX_BYTES_PER_LEAF,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn module_artifact_digest(wasm_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const DOMAIN: &[u8] = b"semaprax.public-generic-typescript-wasm-consumer.v1.module-artifact\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update((wasm_bytes.len() as u64).to_le_bytes());
    hasher.update(wasm_bytes);
    format!(
        "sha256:{:x}",
        semaprax::digest_hex::LowerHex(hasher.finalize())
    )
}

fn fixture_binding(wasm_bytes: &[u8]) -> WasmProviderBindingV1 {
    WasmProviderBindingV1::new(
        CarrierBindingV1::new(
            "sha256:6262626262626262626262626262626262626262626262626262626262626262",
            TargetProfile::CoreWasm,
            "runtime:core-wasm-fixture-issue-160-shared-corpus",
        ),
        module_artifact_digest(wasm_bytes),
        FIXTURE_ENDPOINT_EXPORT_NAME,
        "semaprax-0.4.1",
    )
}

/// Issue #173's `binding_wrong_target_profile` case: a fully well-formed
/// [`WasmProviderBindingV1`] whose wrapped [`CarrierBindingV1`] names
/// `TargetProfile::NativeC11` instead of the real `CoreWasm` this route
/// actually is -- everything else matches [`fixture_binding`] exactly, so
/// only the target-profile confusion is under test. Mirrors the native
/// harness's own `cross_target_binding` (see its doc comment for why real
/// dual-toolchain interop is not attempted here).
fn cross_target_binding(wasm_bytes: &[u8]) -> WasmProviderBindingV1 {
    WasmProviderBindingV1::new(
        CarrierBindingV1::new(
            "sha256:6262626262626262626262626262626262626262626262626262626262626262",
            TargetProfile::NativeC11,
            "runtime:core-wasm-fixture-issue-160-shared-corpus",
        ),
        module_artifact_digest(wasm_bytes),
        FIXTURE_ENDPOINT_EXPORT_NAME,
        "semaprax-0.4.1",
    )
}

/// Issue #173's `binding_valid_for_different_artifact` case: a fully
/// well-formed [`WasmProviderBindingV1`] -- same descriptor identity digest,
/// same `TargetProfile::CoreWasm`, same runtime identity -- but a DIFFERENT
/// `provider_artifact_digest` and `exported_endpoint_export_name`, as if
/// minted for a genuinely different deployed Wasm module rather than
/// corrupted.
fn cross_artifact_binding() -> WasmProviderBindingV1 {
    WasmProviderBindingV1::new(
        CarrierBindingV1::new(
            "sha256:6262626262626262626262626262626262626262626262626262626262626262",
            TargetProfile::CoreWasm,
            "runtime:core-wasm-fixture-issue-160-shared-corpus",
        ),
        "sha256:8888888888888888888888888888888888888888888888888888888888888888".to_owned(),
        format!("{FIXTURE_ENDPOINT_EXPORT_NAME}_different_artifact"),
        "semaprax-0.4.1",
    )
}

/// Render `bytes` as a JavaScript numeric-literal array, e.g. `[1,2,3]`, for
/// splicing a fixed byte value into generated TypeScript test source
/// (`new Uint8Array(<literal>)`).
fn js_byte_array_literal(bytes: &[u8]) -> String {
    let mut out = String::from("[");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(out, "{byte}").unwrap();
    }
    out.push(']');
    out
}

fn shapes() -> (RecordShape, RecordShape) {
    let input = RecordShape::new(vec![OwnedByteField::new(
        "consumers.shared_hostile_corpus.leaf",
    )]);
    let output = input.clone();
    (input, output)
}

struct Workspace(PathBuf);

impl Workspace {
    fn new(label: &str) -> Self {
        let root = env::temp_dir().join(format!(
            "spx-pg-wasm-shared-hostile-corpus-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

/// Persistent executable negatives for exactly the #173 branches requested
/// for mutation proof. Each source edit happens only in a fresh temporary
/// generated package. A successful instantiation is the discriminating
/// signal: the original byte-exact pairing cannot reject because these bytes
/// are also the generated consumer's trusted descriptor.
#[test]
fn each_requested_descriptor_envelope_mutation_is_detected_by_typescript_consumer() {
    if !node_available() {
        eprintln!("skipping: node is not available on PATH");
        return;
    }
    let Some(tsc) = locate_tsc() else {
        eprintln!("skipping: no repository-pinned (5.8.3) tsc is available on this host");
        return;
    };
    let wasm_bytes = reference_wasm_module::build();
    let (input, output) = shapes();
    let binding = fixture_binding(&wasm_bytes);
    let cases = malformed_trusted_descriptor_mutation_cases();
    assert_eq!(
        cases.len(),
        6,
        "the requested mutation-control set is closed"
    );
    for (name, bytes, _, _) in cases {
        let consumer = generate_typescript_calling_consumer(&bytes, &binding, &input, &output)
            .expect(
                "generation stores configured descriptor bytes without granting them authority",
            );
        let workspace = Workspace::new(&format!("mutant-{name}"));
        let root = workspace.path("generated-typescript-consumer");
        write_generated_package(&root, consumer.files());
        let descriptor_path = root.join("src/descriptor.ts");
        let mut descriptor = fs::read_to_string(&descriptor_path).unwrap();
        weaken_typescript_descriptor_branch(&mut descriptor, name);
        fs::write(&descriptor_path, descriptor).unwrap();
        let build = run(
            Command::new(&tsc)
                .current_dir(&root)
                .args(["-p", "tsconfig.json"]),
            "tsc -p tsconfig.json for descriptor-envelope mutant",
        );
        assert!(
            build.status.success(),
            "{name}: TypeScript descriptor-envelope mutant did not type-check:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let wasm_path = workspace.path("reference.wasm");
        fs::write(&wasm_path, &wasm_bytes).unwrap();
        fs::write(
            root.join("test/mutated-descriptor.mjs"),
            r#"
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Provider } from "../dist/wasm-provider.js";
import { TRUSTED_DESCRIPTOR_BYTES } from "../dist/descriptor.js";
const wasmBytes = readFileSync(process.argv[2]);
const original = WebAssembly.instantiate;
let instantiations = 0;
WebAssembly.instantiate = async (...args) => {
  instantiations++;
  return original(...args);
};
try {
  const provider = await Provider.open(wasmBytes, { descriptorBytes: TRUSTED_DESCRIPTOR_BYTES });
  assert.equal(instantiations, 1, "the weakened descriptor check must reach instantiation");
  provider.close();
} finally {
  WebAssembly.instantiate = original;
}

console.log("MUTATED_DESCRIPTOR_ENVELOPE_REACHED_PROVIDER");
"#,
        )
        .unwrap();
        let output = run(
            Command::new("node")
                .current_dir(&root)
                .arg("test/mutated-descriptor.mjs")
                .arg(&wasm_path),
            "node test/mutated-descriptor.mjs",
        );
        assert!(
            output.status.success(),
            "{name}: descriptor-envelope mutation was not detected:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("MUTATED_DESCRIPTOR_ENVELOPE_REACHED_PROVIDER"),
            "{name}"
        );
    }
}

/// The shared u64::MAX result-carrier case must reach TypeScript's exact
/// incoming-result width branch. This temporary mutant changes only that
/// branch's closed class; the observed capacity error proves the corpus does
/// not pass merely because a later framing check also refuses the bytes.
#[test]
fn result_carrier_capacity_reason_mutation_is_detected_by_typescript_consumer() {
    if !node_available() {
        eprintln!("skipping: node is not available on PATH");
        return;
    }
    let Some(tsc) = locate_tsc() else {
        eprintln!("skipping: no repository-pinned (5.8.3) tsc is available on this host");
        return;
    };
    let wasm_bytes = reference_wasm_module::build();
    let (input, output) = shapes();
    let binding = fixture_binding(&wasm_bytes);
    let consumer = generate_typescript_calling_consumer(
        baseline_descriptor_bytes(),
        &binding,
        &input,
        &output,
    )
    .expect("a well-formed shape must generate");
    let workspace = Workspace::new("result-carrier-capacity-mutant");
    let root = workspace.path("generated-typescript-consumer");
    write_generated_package(&root, consumer.files());
    let carrier_path = root.join("src/carrier.ts");
    let mut carrier = fs::read_to_string(&carrier_path).unwrap();
    replace_once(
        &mut carrier,
        "if (length > BigInt(MAX_BYTES_PER_LEAF)) throw resultRejected(\"leaf-bytes\");",
        "if (length > BigInt(MAX_BYTES_PER_LEAF)) throw capacityExceeded(\"leaf-bytes\");",
        "result-carrier u64::MAX width",
    );
    fs::write(&carrier_path, carrier).unwrap();
    let build = run(
        Command::new(&tsc)
            .current_dir(&root)
            .args(["-p", "tsconfig.json"]),
        "tsc -p tsconfig.json for result-carrier mutant",
    );
    assert!(
        build.status.success(),
        "TypeScript result-carrier mutant did not type-check:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let bytes = malformed_result_carrier_cases()
        .into_iter()
        .find(|(name, _)| *name == "result_carrier_u64_max_leaf_length")
        .map(|(_, bytes)| bytes)
        .expect("the closed corpus contains the u64::MAX width case");
    fs::write(
        root.join("test/mutated-result-carrier.mjs"),
        format!(
            r#"
import assert from "node:assert/strict";
import {{ decodeOutput }} from "../dist/carrier.js";
import {{ SemapraxPublicGenericException }} from "../dist/errors.js";
const candidate = new Uint8Array({});
assert.throws(
  () => decodeOutput(candidate),
  error => error instanceof SemapraxPublicGenericException &&
    error.detail.kind === "capacity-exceeded",
);
console.log("MUTATED_RESULT_CARRIER_CAPACITY_BRANCH_REACHED");
"#,
            js_byte_array_literal(&bytes)
        ),
    )
    .unwrap();
    let output = run(
        Command::new("node")
            .current_dir(&root)
            .arg("test/mutated-result-carrier.mjs"),
        "node mutated-result-carrier.mjs",
    );
    assert!(
        output.status.success(),
        "result-carrier mutation was not detected:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("MUTATED_RESULT_CARRIER_CAPACITY_BRANCH_REACHED"));
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Mirrors `typescript_calling_consumer.rs::locate_tsc` exactly (kept
/// independent rather than shared: that file is a sibling harness module
/// this one must not otherwise depend on).
fn locate_tsc() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = {
        let mut list = Vec::new();
        if let Some(explicit) = env::var_os("SPX_PG_TSC") {
            list.push(PathBuf::from(explicit));
        }
        list.push(PathBuf::from("tsc"));
        if let Some(home) = env::var_os("HOME") {
            let home = PathBuf::from(home);
            list.push(home.join("Library/pnpm/tsc"));
            list.push(home.join(".local/share/pnpm/tsc"));
        }
        list
    };
    for candidate in candidates {
        let output = Command::new(&candidate).arg("--version").output();
        if let Ok(output) = output {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                if version.contains("5.8.3") {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn write_generated_package(root: &Path, files: &[(String, String)]) {
    for (relative, contents) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
    }
}

fn replace_once(source: &mut String, old: &str, new: &str, label: &str) {
    assert_eq!(
        source.matches(old).count(),
        1,
        "{label}: generated-source mutation anchor drifted: {old:?}"
    );
    *source = source.replacen(old, new, 1);
}

/// Temporarily weaken exactly one generated TypeScript Descriptor-v1 branch.
/// The mutations preserve type-checking and avoid reading beyond the hostile
/// input; their required observable effect is that `Provider::open` reaches
/// `WebAssembly.instantiate` below.
fn weaken_typescript_descriptor_branch(source: &mut String, case: &str) {
    match case {
        "truncated_final_frame" => replace_once(
            source,
            "if (length > bytes.length - offset) return false;",
            "if (length > bytes.length - offset) return true;",
            case,
        ),
        "unknown_descriptor_schema" => replace_once(
            source,
            "\"semaprax.public-generic-descriptor.v1\",",
            "undefined,",
            case,
        ),
        "stale_boundary_profile_version" => replace_once(
            source,
            "\"semaprax.public-generic-boundary-profile.v1\",",
            "undefined,",
            case,
        ),
        "stale_type_grammar_version" => replace_once(
            source,
            "\"semaprax.public-generic-type-grammar.v1\",",
            "undefined,",
            case,
        ),
        "invalid_utf8_export_id" => replace_once(
            source,
            "catch {\n      return false;\n    }",
            "catch {\n      text = \"\";\n    }",
            case,
        ),
        "trailing_bytes_after_final_frame" => replace_once(
            source,
            "return offset === bytes.length;",
            "return true;",
            case,
        ),
        other => panic!("{other}: not an admitted #173 mutation control"),
    }
}

fn run(command: &mut Command, label: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("run {label}: {error}"))
}

/// Spliced into the generated `test/round-trip.mjs`'s `run()` function,
/// immediately before its fixed `if (failed > 0) {` tail, so every shared
/// case still counts toward that file's own `test()`/pass-fail bookkeeping
/// while ALSO printing one `SHARED_CORPUS <case_id> <STATUS>` line this
/// harness parses back out.
const TS_APPENDIX: &str = r#"
  await test("shared corpus: success_baseline", async () => {
    const provider = await Provider.open(wasmBytes);
    const input = sampleInput();
    const expected = sampleInput();
    let status = "OTHER";
    try {
      const output = provider.transform(input);
      assertReversed(output, expected);
      status = "ACCEPTED";
    } catch (error) {
      status = "TRANSFORM_REJECTED";
    }
    provider.close();
    console.log(`SHARED_CORPUS success_baseline ${status}`);
  });

  await test("shared corpus: descriptor_first_byte_flipped", async () => {
    const mutated = Uint8Array.from(TRUSTED_DESCRIPTOR_BYTES);
    mutated[0] ^= 0xff;
    let status = "OTHER";
    try {
      const provider = await Provider.open(wasmBytes, { descriptorBytes: mutated });
      provider.close();
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException) {
        if (error.detail.kind === "descriptor-rejected") status = "DESCRIPTOR_REJECTED";
        else if (error.detail.kind === "provider-mismatch") status = "PROVIDER_MISMATCH";
      }
    }
    console.log(`SHARED_CORPUS descriptor_first_byte_flipped ${status}`);
  });

  await test("shared corpus: binding_last_byte_flipped", async () => {
    const mutated = Uint8Array.from(TRUSTED_BINDING_BYTES);
    mutated[mutated.length - 1] ^= 0xff;
    let status = "OTHER";
    try {
      const provider = await Provider.open(wasmBytes, { bindingBytes: mutated });
      provider.close();
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException) {
        if (error.detail.kind === "descriptor-rejected") status = "DESCRIPTOR_REJECTED";
        else if (error.detail.kind === "provider-mismatch") status = "PROVIDER_MISMATCH";
      }
    }
    console.log(`SHARED_CORPUS binding_last_byte_flipped ${status}`);
  });

  await test("shared corpus: descriptor_names_different_document", async () => {
    const suffix = new TextEncoder().encode("-a-different-but-well-formed-descriptor");
    const different = new Uint8Array(TRUSTED_DESCRIPTOR_BYTES.length + suffix.length);
    different.set(TRUSTED_DESCRIPTOR_BYTES);
    different.set(suffix, TRUSTED_DESCRIPTOR_BYTES.length);
    let status = "OTHER";
    try {
      const provider = await Provider.open(wasmBytes, { descriptorBytes: different });
      provider.close();
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException) {
        if (error.detail.kind === "descriptor-rejected") status = "DESCRIPTOR_REJECTED";
        else if (error.detail.kind === "provider-mismatch") status = "PROVIDER_MISMATCH";
      }
    }
    console.log(`SHARED_CORPUS descriptor_names_different_document ${status}`);
  });

  await test("shared corpus: exactly_per_leaf_bound_accepted", async () => {
    const provider = await Provider.open(wasmBytes);
    const atBound = inputWithFirstField(new Uint8Array(65536).fill(0x5a));
    let status = "OTHER";
    try {
      provider.transform(atBound);
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException && error.detail.kind === "capacity-exceeded") {
        status = "CAPACITY_EXCEEDED";
      }
    }
    assert.equal(Provider.diagnostics.liveAllocations(provider), 0);
    provider.close();
    console.log(`SHARED_CORPUS exactly_per_leaf_bound_accepted ${status}`);
  });

  await test("shared corpus: one_byte_over_per_leaf_bound_rejected", async () => {
    const provider = await Provider.open(wasmBytes);
    const overBound = inputWithFirstField(new Uint8Array(65537).fill(0x5a));
    let status = "OTHER";
    try {
      provider.transform(overBound);
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException && error.detail.kind === "capacity-exceeded") {
        status = "CAPACITY_EXCEEDED";
      }
    }
    assert.equal(Provider.diagnostics.liveAllocations(provider), 0);
    provider.close();
    console.log(`SHARED_CORPUS one_byte_over_per_leaf_bound_rejected ${status}`);
  });

  await test("shared corpus: binding_wrong_target_profile", async () => {
    // A fully well-formed alternate binding naming the OTHER route's target
    // profile, not a corrupted byte string.
    const crossTargetBinding = new Uint8Array(__CROSS_TARGET_BINDING_BYTES__);
    let status = "OTHER";
    try {
      const provider = await Provider.open(wasmBytes, { bindingBytes: crossTargetBinding });
      provider.close();
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException) {
        if (error.detail.kind === "descriptor-rejected") status = "DESCRIPTOR_REJECTED";
        else if (error.detail.kind === "provider-mismatch") status = "PROVIDER_MISMATCH";
      }
    }
    console.log(`SHARED_CORPUS binding_wrong_target_profile ${status}`);
  });

  await test("shared corpus: binding_valid_for_different_artifact", async () => {
    // A fully well-formed alternate binding naming a different provider
    // artifact digest and export name, not a corrupted byte string.
    const crossArtifactBinding = new Uint8Array(__CROSS_ARTIFACT_BINDING_BYTES__);
    let status = "OTHER";
    try {
      const provider = await Provider.open(wasmBytes, { bindingBytes: crossArtifactBinding });
      provider.close();
      status = "ACCEPTED";
    } catch (error) {
      if (error instanceof SemapraxPublicGenericException) {
        if (error.detail.kind === "descriptor-rejected") status = "DESCRIPTOR_REJECTED";
        else if (error.detail.kind === "provider-mismatch") status = "PROVIDER_MISMATCH";
      }
    }
    console.log(`SHARED_CORPUS binding_valid_for_different_artifact ${status}`);
  });

__STRUCTURED_DESCRIPTOR_CASES__
__MALFORMED_RESULT_CARRIER_CASES__
"#;

fn ts_structured_cases() -> String {
    let mut result = String::new();
    for (name, bytes, _, _) in structured_descriptor_cases() {
        write!(
            &mut result,
            r#"
  await test("shared corpus: {name}", async () => {{
    const candidate = new Uint8Array({});
    let status = "OTHER";
    try {{
      const provider = await Provider.open(wasmBytes, {{ descriptorBytes: candidate }});
      provider.close();
      status = "ACCEPTED";
    }} catch (error) {{
      if (error instanceof SemapraxPublicGenericException &&
          error.detail.kind === "descriptor-rejected") status = "DESCRIPTOR_REJECTED";
    }}
    console.log(`SHARED_CORPUS {name} ${{status}}`);
  }});
"#,
            js_byte_array_literal(&bytes)
        )
        .unwrap();
    }
    result
}

fn ts_malformed_result_carrier_cases() -> String {
    let mut result = String::new();
    for (name, bytes) in malformed_result_carrier_cases() {
        write!(
            &mut result,
            r#"
  await test("shared corpus: {name}", async () => {{
    const candidate = new Uint8Array({});
    let status = "OTHER";
    try {{
      Provider.diagnostics.validateResultCarrier(candidate);
      status = "ACCEPTED";
    }} catch (error) {{
      if (error instanceof SemapraxPublicGenericException &&
          error.detail.kind === "result-rejected") status = "RESULT_REJECTED";
    }}
    console.log(`SHARED_CORPUS {name} ${{status}}`);
  }});
"#,
            js_byte_array_literal(&bytes)
        )
        .unwrap();
    }
    result
}

#[test]
fn shared_hostile_corpus_agrees_with_the_native_manifest() {
    // The TS-side per-leaf-bound cases below restate this literal (65536 /
    // 65537), exactly like the generated consumer's own TypeScript source
    // restates it rather than depending on the `semaprax` crate; this
    // harness CAN depend on `semaprax`, so it asserts the restated bound has
    // not drifted from the real constant, exactly like the native shared
    // corpus harness does.
    assert_eq!(
        MAX_BYTES_PER_LEAF,
        semaprax::public_generic_abi::boundary_profile::MAX_BYTES_PER_LEAF,
    );
    assert_eq!(MAX_BYTES_PER_LEAF, 65536);

    if !node_available() {
        eprintln!("skipping: node is not available on PATH");
        return;
    }
    let Some(tsc) = locate_tsc() else {
        eprintln!("skipping: no repository-pinned (5.8.3) tsc is available on this host");
        return;
    };

    let wasm_bytes = reference_wasm_module::build();
    let (input, output) = shapes();
    let binding = fixture_binding(&wasm_bytes);
    let consumer = generate_typescript_calling_consumer(
        baseline_descriptor_bytes(),
        &binding,
        &input,
        &output,
    )
    .expect("a well-formed shape must generate");

    let workspace = Workspace::new("execute");
    eprintln!(
        "shared hostile corpus TypeScript workspace: {}",
        workspace.0.display()
    );
    let package_root = workspace.path("generated-typescript-consumer");
    write_generated_package(&package_root, consumer.files());

    // Issue #173: the byte literals for `binding_wrong_target_profile` and
    // `binding_valid_for_different_artifact` are computed once here (this
    // harness CAN depend on `semaprax`) and spliced into the generated
    // TypeScript test source as a fixed literal.
    let cross_target_binding_bytes = cross_target_binding(&wasm_bytes).encode();
    let cross_artifact_binding_bytes = cross_artifact_binding().encode();
    let ts_appendix = TS_APPENDIX
        .replace(
            "__CROSS_TARGET_BINDING_BYTES__",
            &js_byte_array_literal(&cross_target_binding_bytes),
        )
        .replace(
            "__CROSS_ARTIFACT_BINDING_BYTES__",
            &js_byte_array_literal(&cross_artifact_binding_bytes),
        )
        .replace("__STRUCTURED_DESCRIPTOR_CASES__", &ts_structured_cases())
        .replace(
            "__MALFORMED_RESULT_CARRIER_CASES__",
            &ts_malformed_result_carrier_cases(),
        );

    let round_trip_path = package_root.join("test/round-trip.mjs");
    let mut contents = fs::read_to_string(&round_trip_path).unwrap();
    let anchor = "  if (failed > 0) {";
    let position = contents.find(anchor).unwrap_or_else(|| {
        panic!("splice anchor {anchor:?} not found in generated round-trip.mjs")
    });
    contents.insert_str(position, &ts_appendix);
    fs::write(&round_trip_path, &contents).unwrap();

    let wasm_path = workspace.path("reference.wasm");
    fs::write(&wasm_path, &wasm_bytes).unwrap();

    let build_dist = run(
        Command::new(&tsc)
            .current_dir(&package_root)
            .args(["-p", "tsconfig.json"]),
        "tsc -p tsconfig.json",
    );
    assert!(
        build_dist.status.success(),
        "the generated package failed to type-check:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_dist.stdout),
        String::from_utf8_lossy(&build_dist.stderr)
    );

    let round_trip = run(
        Command::new("node")
            .current_dir(&package_root)
            .arg("test/round-trip.mjs")
            .arg(&wasm_path),
        "node test/round-trip.mjs",
    );
    let stdout = String::from_utf8_lossy(&round_trip.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&round_trip.stderr).into_owned();
    assert!(
        round_trip.status.success(),
        "the generated package's own shared-corpus run failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("FAIL -"),
        "no selected test may fail:\n{stdout}"
    );

    let outcomes = parse_shared_corpus_lines(&stdout);
    assert_matches_expected("typescript_calling_consumer", &outcomes);
}

#[test]
fn malformed_trusted_descriptor_is_rejected_before_wasm_instantiation() {
    if !node_available() {
        eprintln!("skipping: node is not available on PATH");
        return;
    }
    let Some(tsc) = locate_tsc() else {
        eprintln!("skipping: no repository-pinned (5.8.3) tsc is available on this host");
        return;
    };
    let wasm_bytes = reference_wasm_module::build();
    let (input, output) = shapes();
    let binding = fixture_binding(&wasm_bytes);
    let baseline = baseline_descriptor_bytes();
    let schema_length =
        usize::try_from(u64::from_le_bytes(baseline[..8].try_into().unwrap())).unwrap();
    let mut bom_schema = Vec::with_capacity(baseline.len() + 3);
    bom_schema.extend_from_slice(&u64::try_from(schema_length + 3).unwrap().to_le_bytes());
    bom_schema.extend_from_slice(&[0xef, 0xbb, 0xbf]);
    bom_schema.extend_from_slice(&baseline[8..]);
    assert!(semaprax::public_generic_abi::descriptor::decode(&bom_schema).is_err());

    // Issue #173: the closed malformed-trusted manifest, plus this route's
    // own BOM-prefixed schema case (a schema frame that is valid UTF-8 and
    // correctly framed but is not the frozen literal -- the case that caught
    // the generated TypeScript decoder stripping a BOM, and which no other
    // route reproduces, so it stays local rather than joining the shared
    // manifest). The manifest's own `unknown_descriptor_schema` is the
    // byte-identical successor of this test's former local
    // `"unknown-schema"` entry, taken from the shared corpus so the native
    // and TypeScript routes can no longer drift apart on it.
    let mut shapes_to_run: Vec<(String, Vec<u8>)> = malformed_trusted_descriptor_cases()
        .into_iter()
        .map(|(name, bytes, _, _)| (name.replace('_', "-"), bytes))
        .collect();
    assert_eq!(shapes_to_run.len(), 6, "the manifest is closed");
    shapes_to_run.push(("bom-prefixed-schema".to_owned(), bom_schema));
    for (name, malformed) in shapes_to_run {
        let name = name.as_str();
        let consumer = generate_typescript_calling_consumer(&malformed, &binding, &input, &output)
            .expect(
                "generation stores configured descriptor bytes without granting them authority",
            );
        let workspace = Workspace::new(name);
        let root = workspace.path("generated-typescript-consumer");
        write_generated_package(&root, consumer.files());
        let build = run(
            Command::new(&tsc)
                .current_dir(&root)
                .args(["-p", "tsconfig.json"]),
            "tsc -p tsconfig.json",
        );
        assert!(
            build.status.success(),
            "type-check failed:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let wasm_path = workspace.path("reference.wasm");
        fs::write(&wasm_path, &wasm_bytes).unwrap();
        fs::write(
            root.join("test/malformed-trusted.mjs"),
            r#"
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Provider } from "../dist/wasm-provider.js";
import { TRUSTED_DESCRIPTOR_BYTES } from "../dist/descriptor.js";
import { SemapraxPublicGenericException } from "../dist/errors.js";
const wasmBytes = readFileSync(process.argv[2]);
const original = WebAssembly.instantiate;
let instantiations = 0;
WebAssembly.instantiate = async (...args) => {
  instantiations++;
  throw new Error("provider instantiation reached before descriptor rejection");
};
try {
  await assert.rejects(
    () => Provider.open(wasmBytes, { descriptorBytes: TRUSTED_DESCRIPTOR_BYTES }),
    error => error instanceof SemapraxPublicGenericException &&
      error.detail.kind === "descriptor-rejected",
  );
  assert.equal(instantiations, 0);
} finally {
  WebAssembly.instantiate = original;
}
console.log("MALFORMED_TRUSTED_DESCRIPTOR_REJECTED");
"#,
        )
        .unwrap();
        let output = run(
            Command::new("node")
                .current_dir(&root)
                .arg("test/malformed-trusted.mjs")
                .arg(&wasm_path),
            "node test/malformed-trusted.mjs",
        );
        assert!(
        output.status.success(),
        "malformed trusted descriptor was not rejected before instantiation:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("MALFORMED_TRUSTED_DESCRIPTOR_REJECTED"),
            "{name}"
        );
    }
}
