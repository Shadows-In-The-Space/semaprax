//! Generated calling-consumer cell for the exact existing matrix subject.
//! The generated package owns framing, artifact admission and lifecycle calls.
use semaprax::{
    public_generic_abi::compiler_endpoint::AdmittedPublicGenericEndpointV1,
    public_generic_consumer::{
        rust_calling::{OwnedByteField, RecordShape},
        typescript_calling::generate_typescript_calling_consumer,
    },
    wasm::PublicGenericWasmProviderArtifactV1,
};
use std::{fs, path::Path, process::Command};

pub(super) fn observe(
    root: &Path,
    endpoint: &AdmittedPublicGenericEndpointV1,
    artifact: &PublicGenericWasmProviderArtifactV1,
    guard: bool,
) -> (u32, Vec<Vec<u8>>) {
    let version = Command::new("tsc")
        .arg("--version")
        .output()
        .expect("generated consumer requires tsc 5.8.3");
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        "Version 5.8.3"
    );
    let shape = |paths: &[String]| {
        RecordShape::new(paths.iter().cloned().map(OwnedByteField::new).collect())
    };
    let input = shape(&endpoint.descriptor().input_facts().owned_leaves);
    let output = shape(&endpoint.descriptor().result_facts().owned_leaves);
    assert_eq!(artifact.descriptor_bytes(), endpoint.descriptor_bytes());
    let consumer = generate_typescript_calling_consumer(
        artifact.descriptor_bytes(),
        artifact.binding(),
        &input,
        &output,
    )
    .unwrap();
    let package = root.join("typescript");
    for (name, contents) in consumer.files() {
        let path = package.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    // Only host field identifiers are spelled here. No carrier bytes or host
    // adapter are supplied: Provider.transform uses the generated codec/ABI.
    let names: Vec<_> = input
        .fields
        .iter()
        .map(|field| {
            format!(
                "field_{}",
                field
                    .identity
                    .bytes()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )
        })
        .collect();
    fs::write(
        package.join("test/subject.json"),
        serde_json::to_vec(&(guard, names, super::PAYLOADS)).unwrap(),
    )
    .unwrap();
    fs::write(
        package.join("test/same-subject.mjs"),
        include_str!("same_subject_typescript.mjs"),
    )
    .unwrap();
    let built = Command::new("tsc")
        .current_dir(&package)
        .args(["-p", "tsconfig.json"])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "generated tsc: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executed = Command::new("node")
        .current_dir(&package)
        .args(["test/same-subject.mjs", "../provider.wasm"])
        .output()
        .expect("generated consumer requires Node");
    assert!(
        executed.status.success(),
        "generated Node: {}",
        String::from_utf8_lossy(&executed.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&executed.stderr).trim());
    serde_json::from_slice(&executed.stdout).unwrap()
}
