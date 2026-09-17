//! Private compiled C11-reference route, not a new Semaprax export profile.
//! This bridge checks actual Rust-rendered bytes before external compilation.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use semaprax::public_generic_abi::carrier::{CarrierBindingV1, TargetProfile};
use semaprax::public_generic_abi::native::binding::NativeProviderBindingV1;
use semaprax::public_generic_abi::native::template::render_reference_provider;

struct Workspace(PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires provisioned clang wasm32, wasm-ld and Node; Linux CI selects explicitly"]
fn actual_native_renderer_executes_in_core_wasm() {
    let directory = std::env::temp_dir().join(format!(
        "spx-compiled-reference-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("create private compiled-reference fixture");
    let workspace = Workspace(directory);
    let binding = NativeProviderBindingV1::new(
        CarrierBindingV1::new(
            "sha256:settlement-corpus-native-descriptor-identity",
            TargetProfile::NativeC11,
            "sha256:settlement-corpus-native-runtime-identity",
        ),
        "sha256:settlement-corpus-native-provider-artifact-fixture",
        "spx_pg_endpoint_reverse_bytes_v1",
        "semaprax-0.4.1",
    );
    let provider = workspace.0.join("provider.c");
    fs::write(
        &provider,
        render_reference_provider(
            include_bytes!("../fixtures/public-generic-settlement-v1/descriptor.txt"),
            &binding,
        ),
    )
    .expect("render the existing native reference provider");
    let output = Command::new(std::env::var_os("PYTHON").unwrap_or_else(|| "python3".into()))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("scripts/public_generic_compiled_wasm.py")
        .arg("--generated-provider")
        .arg(provider)
        .output()
        .expect("selected compiled-reference gate requires provisioned tools");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
