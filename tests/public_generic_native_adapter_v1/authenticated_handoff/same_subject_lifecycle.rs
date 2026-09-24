//! Physical API lifecycle agreement, not injected-failure/heap parity.
//! Native frees owned allocations; Core-Wasm releases opaque slots in retained
//! linear memory. Failed-call transfer differs and is asserted per target.
use semaprax::public_generic_abi::{
    carrier::{
        frame::{parse_bounded, CarrierFrameBinding, CarrierLeaf, LeafKind},
        trace::Direction,
    },
    compiler_endpoint::derive_admitted_public_generic_endpoint_v1,
    native::{authenticated, template},
};
use std::{env, fs, path::Path, process::Command};

fn run(command: &mut Command) -> Vec<Vec<u8>> {
    let output = command
        .output()
        .expect("focused lifecycle gate requires clang and Node");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn checked_identity_native_and_core_wasm_refuse_absent_handles_and_retry_export() {
    let root = env::temp_dir().join(format!(
        "semaprax-lifecycle-parity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    eprintln!("physical lifecycle evidence: {}", root.display());
    for guard in [true, false] {
        let directory = root.join(guard.to_string());
        fs::create_dir(&directory).unwrap();
        let result = prepare(&directory, guard);
        compare(&directory, guard, &result);
    }
}

fn prepare(directory: &Path, guard: bool) -> CarrierFrameBinding {
    let source = super::SOURCE.replace(
        "requires true",
        if guard {
            "requires true"
        } else {
            "requires false"
        },
    );
    let parsed = semaprax::check(&source, Path::new("same-subject.spx")).unwrap();
    let revision = semaprax::format::canonical(&parsed);
    let program = semaprax::hir::resolve(&parsed).unwrap();
    let endpoint =
        derive_admitted_public_generic_endpoint_v1(&program, &revision, "auth.identity").unwrap();
    let native = authenticated::render_authenticated_identity_provider(
        &program,
        &revision,
        endpoint.descriptor(),
    )
    .unwrap();
    let wasm = semaprax::wasm::emit_public_generic_wasm_provider_v1(&program, &endpoint).unwrap();
    wasm.verify().unwrap();
    assert_eq!(native.descriptor_bytes(), wasm.descriptor_bytes());
    let input =
        CarrierFrameBinding::from_verified_descriptor(endpoint.descriptor(), Direction::Input);
    let result =
        CarrierFrameBinding::from_verified_descriptor(endpoint.descriptor(), Direction::Result);
    let frame = input
        .frame_with_leaves(
            input
                .leaf_paths()
                .iter()
                .zip(super::PAYLOADS)
                .map(|(path, payload)| CarrierLeaf::new(path, LeafKind::Bytes, payload.to_vec()))
                .collect(),
        )
        .encode();
    for (name, bytes) in [
        ("provider.wasm", wasm.wasm()),
        ("descriptor.bin", wasm.descriptor_bytes()),
        ("binding.bin", &wasm.binding_bytes()),
        ("input.bin", &frame),
    ] {
        fs::write(directory.join(name), bytes).unwrap();
    }
    fs::write(
        directory.join("probe.mjs"),
        include_str!("same_subject_lifecycle.mjs"),
    )
    .unwrap();
    let expected = if guard { "0" } else { "11" };
    let mut constants = String::new();
    for (name, bytes) in [
        ("descriptor", native.descriptor_bytes()),
        ("binding", &native.binding().encode()),
        (
            "cleanup",
            endpoint.descriptor().settlement().digest().as_bytes(),
        ),
        ("canonical", &frame),
    ] {
        constants.push_str(&super::array(name, bytes));
    }
    let provider = format!("{}\nstatic size_t endpoint_calls;\n#define SPX_PG_OBSERVE_ENDPOINT() (++endpoint_calls)\n{}\n#undef malloc\n#undef free\nsize_t auth_live(void) {{ return fixture_live; }}\nsize_t auth_calls(void) {{ return endpoint_calls; }}\n",
            include_str!("../allocations.c"), native.source());
    let driver = format!(
        "{}\n{}\n{constants}\n#define EXPECT_CALL_STATUS {expected}\n{}",
        template::HEADER_V1,
        authenticated::HEADER,
        include_str!("same_subject_lifecycle.c")
    );
    fs::write(directory.join("provider.c"), provider).unwrap();
    fs::write(directory.join("driver.c"), driver).unwrap();
    result
}

fn compare(directory: &Path, guard: bool, result: &CarrierFrameBinding) {
    let expected = if guard { "0" } else { "11" };
    let wasm_outputs = run(Command::new("node")
        .current_dir(directory)
        .args(["probe.mjs", expected]));
    assert_eq!(wasm_outputs.len(), 2);
    let wasm_leaves: Vec<Vec<Vec<u8>>> = wasm_outputs
        .iter()
        .map(|bytes| {
            if !guard {
                assert!(bytes.is_empty());
                return Vec::new();
            }
            let frame = parse_bounded(bytes).unwrap();
            result.validate_frame(&frame).unwrap();
            frame
                .leaves()
                .iter()
                .map(|leaf| leaf.payload().to_vec())
                .collect()
        })
        .collect();
    for opt in ["-O0", "-O2"] {
        let executable = directory.join(format!("probe{opt}{}", env::consts::EXE_SUFFIX));
        let output = Command::new("clang")
            .args(["-std=c11", opt, "-Wall", "-Wextra", "-Werror"])
            .arg(directory.join("provider.c"))
            .arg(directory.join("driver.c"))
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let native_outputs = run(&mut Command::new(executable));
        assert_eq!(native_outputs.len(), 2);
        let native_leaves: Vec<_> = native_outputs
            .iter()
            .map(|bytes| {
                if guard {
                    super::decode_native(bytes)
                } else {
                    assert!(bytes.is_empty());
                    Vec::new()
                }
            })
            .collect();
        assert_eq!(native_leaves, wasm_leaves);
        if guard {
            assert_eq!(
                native_leaves,
                vec![super::PAYLOADS.map(<[u8]>::to_vec).to_vec(); 2]
            );
        }
        eprintln!("requires={guard} native{opt}/Core-Wasm: two cycles, status{expected}, absent/stale refusals, target-local cleanup; success export12->0 retry byte-exact");
    }
}
