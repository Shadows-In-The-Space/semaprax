use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

const SOURCE: &str = r#"module provider.artifact;

@id("provider.leaf-pair")
record LeafPair {
    @id("provider.leaf-pair.left")
    left: Bytes,
    @id("provider.leaf-pair.right")
    right: Bytes,
}

@id("provider.envelope")
record Envelope<T> {
    @id("provider.envelope.payload")
    payload: T,
}

@id("provider.transform")
fn transform(value: own Envelope<LeafPair>) -> Envelope<LeafPair> {
    Envelope<LeafPair> { payload: LeafPair { left: value.payload.right, right: value.payload.left } }
}

@id("provider.main")
fn main() -> i64 { 0 }
"#;

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn resolved_program() -> semaprax::hir::ResolvedProgram {
    let program = semaprax::check(SOURCE, Path::new("compiler-provider-artifact.spx")).unwrap();
    semaprax::hir::resolve(&program).unwrap()
}

pub(super) fn artifact() -> semaprax::wasm::PublicGenericWasmProviderArtifactV1 {
    let parsed = semaprax::parse(SOURCE, Path::new("compiler-provider-artifact.spx")).unwrap();
    let source_revision = semaprax::format::canonical(&parsed);
    let program = resolved_program();
    let endpoint = semaprax::public_generic_abi::compiler_endpoint::derive_admitted_public_generic_endpoint_v1(
        &program,
        &source_revision,
        "provider.transform",
    )
    .unwrap();
    semaprax::wasm::emit_public_generic_wasm_provider_v1(&program, &endpoint).unwrap()
}

fn frame(
    direction: semaprax::public_generic_abi::carrier::trace::Direction,
    payloads: &[&[u8]],
) -> Vec<u8> {
    use semaprax::public_generic_abi::carrier::frame::{
        CarrierFrameBinding, CarrierLeaf, LeafKind,
    };

    let parsed = semaprax::parse(SOURCE, Path::new("compiler-provider-artifact.spx")).unwrap();
    let source_revision = semaprax::format::canonical(&parsed);
    let program = resolved_program();
    let endpoint = semaprax::public_generic_abi::compiler_endpoint::derive_admitted_public_generic_endpoint_v1(
        &program,
        &source_revision,
        "provider.transform",
    )
    .unwrap();
    let binding = CarrierFrameBinding::from_verified_descriptor(endpoint.descriptor(), direction);
    assert_eq!(binding.leaf_paths().len(), payloads.len());
    binding
        .frame_with_leaves(
            binding
                .leaf_paths()
                .iter()
                .zip(payloads)
                .map(|(path, payload)| {
                    CarrierLeaf::new(path.clone(), LeafKind::Bytes, payload.to_vec())
                })
                .collect(),
        )
        .encode()
}

#[test]
fn compiler_provider_artifact_is_deterministic_closed_and_binding_normalized() {
    let first = artifact();
    let second = artifact();
    assert_eq!(first.wasm(), second.wasm());
    assert_eq!(first.binding_bytes(), second.binding_bytes());
    assert_eq!(
        first.artifact_digest(),
        first.binding().provider_artifact_digest()
    );
    assert_eq!(
        first.binding().exported_endpoint_export_name(),
        "spx_pg_v1_call"
    );
    first.verify().unwrap();
    wasmparser::Validator::new()
        .validate_all(first.wasm())
        .unwrap();

    let imports = wasmparser::Parser::new(0)
        .parse_all(first.wasm())
        .filter_map(Result::ok)
        .filter(|payload| matches!(payload, wasmparser::Payload::ImportSection(_)))
        .count();
    assert_eq!(imports, 0, "provider gains no ambient Wasm imports");
}

#[test]
fn node_loads_exact_closed_provider_inventory_without_fixture_or_host_imports() {
    if !node_available() {
        return;
    }
    let artifact = artifact();
    let root = std::env::temp_dir().join(format!(
        "semaprax-pg-compiler-provider-artifact-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("provider.wasm"), artifact.wasm()).unwrap();
    fs::write(root.join("descriptor.bin"), artifact.descriptor_bytes()).unwrap();
    fs::write(root.join("binding.bin"), artifact.binding_bytes()).unwrap();
    fs::write(
        root.join("input.bin"),
        frame(
            semaprax::public_generic_abi::carrier::trace::Direction::Input,
            &[b"left", b"right"],
        ),
    )
    .unwrap();
    fs::write(
        root.join("expected.bin"),
        frame(
            semaprax::public_generic_abi::carrier::trace::Direction::Result,
            &[b"right", b"left"],
        ),
    )
    .unwrap();
    fs::write(
        root.join("probe.mjs"),
        r#"import { readFileSync } from 'node:fs';
const module = await WebAssembly.compile(readFileSync('provider.wasm'));
if (WebAssembly.Module.imports(module).length !== 0) throw new Error('ambient import');
const expected = ['memory','spx_pg_v1_scratch_ptr','spx_pg_v1_scratch_reserve','spx_pg_v1_scratch_capacity','spx_pg_v1_open','spx_pg_v1_input_prepare','spx_pg_v1_call','spx_pg_v1_result_export','spx_pg_v1_value_release','spx_pg_v1_result_release','spx_pg_v1_provider_close'].sort();
const actual = WebAssembly.Module.exports(module).map(item => item.name).sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('inventory');
const instance = await WebAssembly.instantiate(module, {});
const lane = raw => ({ status: Number(raw & 0xffffffffn), value: Number((raw >> 32n) & 0xffffffffn) });
const descriptor = readFileSync('descriptor.bin');
const binding = readFileSync('binding.bin');
const input = readFileSync('input.bin');
const expectedBytes = readFileSync('expected.bin');
const reserved = lane(instance.exports.spx_pg_v1_scratch_reserve(16 * 1024 * 1024 + 2056));
if (reserved.status !== 0 || reserved.value !== 393216) throw new Error('reserve');
let memory = new Uint8Array(instance.exports.memory.buffer);
memory.set(descriptor, 393216);
memory.set(binding, 393216 + descriptor.length);
const opened = lane(instance.exports.spx_pg_v1_open(393216, descriptor.length, 393216 + descriptor.length, binding.length));
if (opened.status !== 0 || !opened.value) throw new Error('open');
memory.set(input, 393216);
const prepared = lane(instance.exports.spx_pg_v1_input_prepare(opened.value, 393216, input.length));
if (prepared.status !== 0 || !prepared.value) throw new Error('prepare:' + JSON.stringify(prepared));
const called = lane(instance.exports.spx_pg_v1_call(opened.value, prepared.value));
if (called.status !== 0 || !called.value) throw new Error('call:' + JSON.stringify(called));
const probe = lane(instance.exports.spx_pg_v1_result_export(called.value, 393216, 0));
if (probe.status !== 12 || probe.value !== expectedBytes.length) throw new Error('export probe:' + JSON.stringify(probe) + ':expected=' + expectedBytes.length);
const copied = lane(instance.exports.spx_pg_v1_result_export(called.value, 393216, probe.value));
memory = new Uint8Array(instance.exports.memory.buffer);
if (copied.status !== 0 || copied.value !== expectedBytes.length || !memory.slice(393216, 393216 + copied.value).every((byte, index) => byte === expectedBytes[index])) throw new Error('nonidentity result carrier');
if (instance.exports.spx_pg_v1_result_release(called.value) !== 0) throw new Error('result release');
if (instance.exports.spx_pg_v1_provider_close(opened.value) !== 0) throw new Error('provider close');
"#,
    )
    .unwrap();
    let output = Command::new("node")
        .arg("probe.mjs")
        .current_dir(&root)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
