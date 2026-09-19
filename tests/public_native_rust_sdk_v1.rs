use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::hir;
use sha2::{Digest, Sha256};

#[path = "support/native_rust_cargo.rs"]
mod native_rust_cargo;

const CALCULATOR: &str = include_str!("../examples/calculator.spx");
const CALLBACK: &str = include_str!("../examples/calculator-rust/callback.spx");
const EXPECTED_42_LINE: &[u8] = b"42\n";
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "semaprax-public-native-rust-sdk-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.0) else {
            return;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_owned()
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn copied_consumer(source: &str, destination: &Path) {
    fs::create_dir_all(destination.join("src")).unwrap();
    for relative in ["Cargo.toml", "src/main.rs"] {
        fs::copy(
            root()
                .join("examples/calculator-rust")
                .join(source)
                .join(relative),
            destination.join(relative),
        )
        .unwrap();
    }
}

fn run(command: &mut Command, label: &str) -> std::process::Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("run {label}: {error}"));
    assert!(
        output.status.success(),
        "{label} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn calculator_node_command(fixture: &Path) -> Command {
    let mut command = Command::new("node");
    command.current_dir(fixture).arg("calculator.mjs");
    command
}

#[test]
fn node_entrypoint_is_relative_to_canonical_fixture_root() {
    use std::ffi::OsStr;
    use std::path::Component;

    let fixture = Fixture::create();
    let command = calculator_node_command(&fixture.0);
    assert_eq!(command.get_current_dir(), Some(fixture.0.as_path()));
    let args = command.get_args().collect::<Vec<_>>();
    assert_eq!(args, [OsStr::new("calculator.mjs")]);
    let entrypoint = Path::new(args[0]);
    assert!(entrypoint.is_relative());
    let mut components = entrypoint.components();
    assert!(matches!(
        components.next(),
        Some(Component::Normal(name)) if name == OsStr::new("calculator.mjs")
    ));
    assert_eq!(components.next(), None);
}

#[cfg(windows)]
#[test]
fn nested_cargo_rebinds_a_poisoned_command_to_the_validated_linker_path() {
    use std::ffi::OsStr;

    // This inspects the configured Command only; it does not execute Cargo or
    // claim held-linker or same-path-race evidence.
    let (Some(linker), Some(_vctools)) = (
        std::env::var_os("SEMAPRAX_LINKER"),
        std::env::var_os("SEMAPRAX_VCTOOLS"),
    ) else {
        return;
    };
    let mut command = native_rust_cargo::cargo_command();
    command
        .env("LINK", ".obj")
        .env("_LINK_", ".obj")
        .env(
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
            r"C:\foreign\link.exe",
        )
        .env("LIB", "preserved-lib")
        .env("INCLUDE", "preserved-include");
    native_rust_cargo::bind_nested_cargo_linker_path(&mut command);

    let configured = |name: &str| {
        command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(name))
            .map(|(_, value)| value)
    };
    assert_eq!(
        configured("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"),
        Some(Some(linker.as_os_str())),
    );
    assert_eq!(configured("LINK"), Some(None));
    assert_eq!(configured("_LINK_"), Some(None));
    assert_eq!(configured("LIB"), Some(Some(OsStr::new("preserved-lib"))));
    assert_eq!(
        configured("INCLUDE"),
        Some(Some(OsStr::new("preserved-include"))),
    );
    assert_eq!(configured("PATH"), None);
    assert_eq!(configured("RUSTFLAGS"), None);
}

fn recursive_files(directory: &Path) -> Vec<(String, Vec<u8>)> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.file_type().unwrap();
            if metadata.is_dir() {
                visit(root, &entry.path(), files);
            } else {
                assert!(metadata.is_file());
                files.push((
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    fs::read(entry.path()).unwrap(),
                ));
            }
        }
    }
    let mut files = Vec::new();
    visit(directory, directory, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut rendered = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut rendered, "{byte:02x}").unwrap();
    }
    rendered
}

fn inventory_difference_report(left: &[(String, Vec<u8>)], right: &[(String, Vec<u8>)]) -> String {
    let rows = left.len().max(right.len()).min(10);
    let mut differences = Vec::with_capacity(rows);
    for index in 0..rows {
        let left_row = left.get(index);
        let right_row = right.get(index);
        if left_row == right_row {
            continue;
        }
        let describe = |row: Option<&(String, Vec<u8>)>| match row {
            Some((path, bytes)) => format!(
                "path={path:?},bytes={},sha256={}",
                bytes.len(),
                sha256_hex(bytes)
            ),
            None => "missing".to_owned(),
        };
        let first_difference = match (left_row, right_row) {
            (Some((_, left_bytes)), Some((_, right_bytes))) => left_bytes
                .iter()
                .zip(right_bytes)
                .position(|(left, right)| left != right)
                .or_else(|| {
                    (left_bytes.len() != right_bytes.len())
                        .then_some(left_bytes.len().min(right_bytes.len()))
                }),
            _ => None,
        };
        differences.push(format!(
            "row={index},first_difference={first_difference:?},left=({}),right=({})",
            describe(left_row),
            describe(right_row),
        ));
    }
    format!(
        "left_files={},right_files={},differences=[{}]",
        left.len(),
        right.len(),
        differences.join("; ")
    )
}

fn sdk_method(stable_id: &str) -> String {
    let mut method = String::from("spx_");
    for character in stable_id.chars() {
        match character {
            'a'..='z' | '0'..='9' => method.push(character),
            '_' => method.push_str("_underscore_"),
            '.' => method.push_str("_dot_"),
            '-' => method.push_str("_hyphen_"),
            _ => panic!("inadmissible stable-ID character in test fixture"),
        }
    }
    method
}

#[test]
fn calculator_and_callback_are_checked_public_sdk_inputs() {
    let calculator = semaprax::check(CALCULATOR, "examples/calculator.spx").unwrap();
    let calculator_hir = hir::resolve(&calculator).unwrap();
    assert_eq!(calculator_hir.interfaces.len(), 0);
    assert_eq!(
        calculator_hir
            .functions
            .iter()
            .map(|function| function.id.as_str())
            .collect::<Vec<_>>(),
        [
            "calculator.add",
            "calculator.subtract",
            "calculator.multiply",
            "calculator.divide",
            "calculator.is-negative",
            "calculator.not",
            "app.main",
        ]
    );

    let callback = semaprax::check(CALLBACK, "examples/calculator-rust/callback.spx").unwrap();
    let callback_hir = hir::resolve(&callback).unwrap();
    assert_eq!(callback_hir.interfaces.len(), 1);
    assert_eq!(callback_hir.interfaces[0].imports.len(), 1);
    assert!(callback_hir.interfaces[0].imports[0].native_rust);
    assert_eq!(
        callback_hir.interfaces[0].imports[0].id.as_str(),
        "calculator.callback.adjust"
    );
    assert_eq!(
        callback_hir.functions[0].id.as_str(),
        "calculator.callback.apply"
    );
}

#[test]
fn public_method_spelling_is_injective_for_the_promoted_surface() {
    let cases = [
        ("calculator.add", "spx_calculator_dot_add"),
        (
            "calculator.is-negative",
            "spx_calculator_dot_is_hyphen_negative",
        ),
        ("calculator.not", "spx_calculator_dot_not"),
        (
            "calculator.callback.adjust",
            "spx_calculator_dot_callback_dot_adjust",
        ),
        (
            "calculator.callback.apply",
            "spx_calculator_dot_callback_dot_apply",
        ),
        ("a_b.c-d", "spx_a_underscore_b_dot_c_hyphen_d"),
    ];
    let mut observed = cases
        .iter()
        .map(|(stable_id, expected)| {
            let actual = sdk_method(stable_id);
            assert_eq!(&actual, expected);
            actual
        })
        .collect::<Vec<_>>();
    observed.sort();
    observed.dedup();
    assert_eq!(observed.len(), cases.len());
}

#[test]
fn display_rename_preserves_the_selected_rust_identity() {
    let renamed = CALCULATOR.replacen("fn add(", "fn sum(", 1).replacen(
        "    add(19, 23)",
        "    sum(19, 23)",
        1,
    );
    assert_ne!(renamed, CALCULATOR);
    let original = hir::resolve(&semaprax::check(CALCULATOR, "calculator.spx").unwrap()).unwrap();
    let renamed =
        hir::resolve(&semaprax::check(&renamed, "calculator-renamed.spx").unwrap()).unwrap();
    let original = original
        .functions
        .iter()
        .find(|function| function.id.as_str() == "calculator.add")
        .unwrap();
    let renamed = renamed
        .functions
        .iter()
        .find(|function| function.id.as_str() == "calculator.add")
        .unwrap();
    assert_eq!(original.id, renamed.id);
    assert_eq!(original.name, "add");
    assert_eq!(renamed.name, "sum");
    assert_eq!(sdk_method(original.id.as_str()), "spx_calculator_dot_add");
    assert_eq!(sdk_method(renamed.id.as_str()), "spx_calculator_dot_add");
}

#[test]
fn external_example_has_a_closed_two_phase_dependency_topology() {
    let setup = read("examples/calculator-rust/Cargo.toml");
    assert!(setup.contains("[workspace]"));
    assert!(setup.contains(
        "semaprax-native-rust-interop = { path = \"../../crates/semaprax-native-rust-interop-builder\" }"
    ));
    let driver = read("examples/calculator-rust/src/main.rs");
    for required in [
        "build_native_rust_sdk",
        "NativeRustSdkOptions",
        "calculator.add",
        "calculator.callback.apply",
        "calculator.callback.adjust",
    ] {
        assert!(
            driver.contains(required),
            "setup driver is missing `{required}`"
        );
    }
    for forbidden in [
        "Command::new",
        "unsafe",
        "std::fs::write",
        "http://",
        "https://",
    ] {
        assert!(
            !driver.contains(forbidden),
            "setup driver admitted `{forbidden}`"
        );
    }

    let consumer = read("examples/calculator-rust/consumer/Cargo.toml");
    assert!(consumer.contains("[workspace]"));
    assert!(
        consumer.contains("semaprax-generated-native-rust-sdk = { path = \"../generated-sdk\" }")
    );
    for forbidden in [
        "semaprax =",
        "semaprax-native-rust-interop",
        "build-dependencies",
    ] {
        assert!(
            !consumer.contains(forbidden),
            "public consumer retained compiler authority through `{forbidden}`"
        );
    }
    let consumer_source = read("examples/calculator-rust/consumer/src/main.rs");
    for required in [
        "semaprax_generated_native_rust_sdk",
        "NativeRustSdkImports for Host",
        "spx_calculator_dot_add",
        "spx_calculator_dot_is_hyphen_negative",
        "spx_calculator_dot_divide(1, 0)",
        "NativeRustSdkCallError::Semantic",
        "semaprax.native-rust-semantics.v1",
        "const OUTPUT: &[u8] = b\"42\\n\"",
        "write_all(OUTPUT)",
        "stdout.flush()",
    ] {
        assert!(
            consumer_source.contains(required),
            "calculator consumer is missing `{required}`"
        );
    }
    assert!(!consumer_source.contains("42\\r\\n"));
    assert!(!consumer_source.contains("#[cfg(windows)]"));
    assert!(!consumer_source.contains("unsafe"));

    let callback_consumer = read("examples/calculator-rust/callback-consumer/src/main.rs");
    for required in [
        "NativeRustSdkImportResult",
        "spx_calculator_dot_callback_dot_adjust",
        "NativeRustSdkImportResult::Success(value + 1)",
        "spx_calculator_dot_callback_dot_apply",
        "NativeRustSdkCallError::HostFailed",
        "NativeRustSdkCallError::HostPanicked",
        "NativeRustSdkCallError::AdapterRejected",
        "const OUTPUT: &[u8] = b\"42\\n\"",
        "write_all(OUTPUT)",
        "stdout.flush()",
    ] {
        assert!(
            callback_consumer.contains(required),
            "callback consumer is missing `{required}`"
        );
    }
    assert!(!callback_consumer.contains("42\\r\\n"));
    assert!(!callback_consumer.contains("#[cfg(windows)]"));
    assert!(!callback_consumer.contains("unsafe"));
}

#[test]
fn project_example_selects_manifest_exports_for_a_compiler_free_consumer() {
    let setup = read("examples/calculator-rust/src/main.rs");
    for required in [
        "build_project_native_rust_sdk",
        "bundle.project_revision()",
        "bundle.workspace_revision()",
        "bundle.subject_digest()",
    ] {
        assert!(
            setup.contains(required),
            "Project setup is missing `{required}`"
        );
    }
    let builder = read("crates/semaprax-native-rust-interop-builder/src/public_sdk/project.rs");
    assert!(builder.contains("with_authenticated_native_rust_sdk_subject"));

    let manifest = read("examples/calculator-project/semaprax.toml");
    for stable_id in [
        "calculator.add",
        "calculator.divide",
        "calculator.is-negative",
        "calculator.multiply",
        "calculator.not",
        "calculator.subtract",
    ] {
        assert!(manifest.contains(stable_id));
    }

    let consumer = read("examples/calculator-rust/project-consumer/Cargo.toml");
    assert!(consumer
        .contains("semaprax-generated-native-rust-sdk = { path = \"../generated-project-sdk\" }"));
    for forbidden in [
        "semaprax =",
        "semaprax-native-rust-interop",
        "build-dependencies",
    ] {
        assert!(
            !consumer.contains(forbidden),
            "Project consumer retained compiler authority through `{forbidden}`"
        );
    }

    let consumer_source = read("examples/calculator-rust/project-consumer/src/main.rs");
    for required in [
        "spx_calculator_dot_add",
        "spx_calculator_dot_divide",
        "spx_calculator_dot_is_hyphen_negative",
        "spx_calculator_dot_multiply",
        "spx_calculator_dot_not",
        "spx_calculator_dot_subtract",
        "const OUTPUT: &[u8] = b\"42\\n\"",
        "write_all(OUTPUT)",
        "stdout.flush()",
    ] {
        assert!(
            consumer_source.contains(required),
            "Project consumer is missing `{required}`"
        );
    }
    assert!(!consumer_source.contains("42\\r\\n"));
    assert!(!consumer_source.contains("#[cfg(windows)]"));
    assert!(!consumer_source.contains("unsafe"));
}

#[test]
fn public_builder_contract_names_the_fixed_package_and_inventory() {
    let facade = read("crates/semaprax-native-rust-interop-builder/src/lib.rs");
    let implementation = [
        "crates/semaprax-native-rust-interop-builder/src/implementation.rs",
        "crates/semaprax-native-rust-interop-builder/src/public_sdk/mod.rs",
        "crates/semaprax-native-rust-interop-builder/src/public_sdk/descriptor.rs",
        "crates/semaprax-native-rust-interop-builder/src/public_sdk/package.rs",
        "crates/semaprax-native-rust-interop-builder/src/public_sdk/authentication.rs",
        "crates/semaprax-native-rust-interop-builder/src/public_sdk/authority.rs",
        "crates/semaprax-native-rust-interop-builder/src/public_sdk/build.rs",
    ]
    .map(read)
    .join("\n");
    for required in [
        "pub struct NativeRustSdkOptions",
        "pub struct NativeRustSdkBundle",
        "pub fn build_native_rust_sdk",
    ] {
        assert!(
            facade.contains(required) || implementation.contains(required),
            "public builder is missing `{required}`"
        );
    }
    for required in [
        "semaprax-generated-native-rust-sdk",
        "Cargo.toml",
        "build.rs",
        "src/lib.rs",
        "src/semaprax_native_rust_interop.rs",
        "src/semaprax_native_rust_interop_ffi.rs",
        "native/descriptor.json",
        "native/semaprax.native-rust-interop.json",
        "semaprax.native-rust-sdk.json",
    ] {
        assert!(
            implementation.contains(required),
            "SDK inventory is missing `{required}`"
        );
    }
    assert!(
        implementation.contains("native/libsemaprax_native_rust_sdk.a")
            || implementation.contains("libsemaprax_native_rust_sdk.a")
    );
    assert!(
        implementation.contains("native/semaprax_native_rust_sdk.lib")
            || implementation.contains("semaprax_native_rust_sdk.lib")
    );
}

#[test]
fn public_sdk_authentication_module_has_no_mutation_or_publication_authority() {
    let authentication =
        read("crates/semaprax-native-rust-interop-builder/src/public_sdk/authentication.rs");
    for forbidden in [
        "create_directory_new_prepared",
        "write_file_new_prepared",
        "discard_owned_stage_prepared",
        "archive_tool_prepared",
        "publish_directory_new_prepared",
    ] {
        assert!(
            !authentication.contains(forbidden),
            "read-only SDK authentication admitted `{forbidden}`"
        );
    }
}

#[test]
fn hosted_external_consumers_are_deterministic_and_match_native_c_and_wasm() {
    if std::env::var_os("SEMAPRAX_REQUIRE_PUBLIC_NATIVE_RUST_SDK").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }

    let fixture = Fixture::create();
    let setup_manifest = root().join("examples/calculator-rust/Cargo.toml");
    let first = fixture.0.join("generated-sdk");
    let second = fixture.0.join("generated-sdk-second");
    for output in [&first, &second] {
        run(
            native_rust_cargo::cargo_command()
                .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
                .arg(&setup_manifest)
                .arg("--")
                .arg("calculator")
                .arg(output),
            "generate calculator SDK",
        );
    }
    let first_files = recursive_files(&first);
    let second_files = recursive_files(&second);
    assert_eq!(
        first_files,
        second_files,
        "generated SDK inventories differ: {}",
        inventory_difference_report(&first_files, &second_files),
    );
    assert_eq!(first_files.len(), 9);
    assert_eq!(
        first_files
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        if cfg!(windows) {
            vec![
                "Cargo.toml",
                "build.rs",
                "native/descriptor.json",
                "native/semaprax.native-rust-interop.json",
                "native/semaprax_native_rust_sdk.lib",
                "semaprax.native-rust-sdk.json",
                "src/lib.rs",
                "src/semaprax_native_rust_interop.rs",
                "src/semaprax_native_rust_interop_ffi.rs",
            ]
        } else {
            vec![
                "Cargo.toml",
                "build.rs",
                "native/descriptor.json",
                "native/libsemaprax_native_rust_sdk.a",
                "native/semaprax.native-rust-interop.json",
                "semaprax.native-rust-sdk.json",
                "src/lib.rs",
                "src/semaprax_native_rust_interop.rs",
                "src/semaprax_native_rust_interop_ffi.rs",
            ]
        }
    );

    let consumer = fixture.0.join("consumer");
    copied_consumer("consumer", &consumer);
    run(
        native_rust_cargo::cargo_command()
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(consumer.join("Cargo.toml")),
        "lock calculator consumer",
    );
    let rust = run(
        native_rust_cargo::cargo_command()
            .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
            .arg(consumer.join("Cargo.toml")),
        "run calculator consumer",
    );
    assert_eq!(rust.stdout, EXPECTED_42_LINE);

    let renamed_root = fixture.0.join("renamed");
    fs::create_dir(&renamed_root).unwrap();
    let renamed_sdk = renamed_root.join("generated-sdk");
    run(
        native_rust_cargo::cargo_command()
            .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
            .arg(&setup_manifest)
            .arg("--")
            .arg("calculator-renamed")
            .arg(&renamed_sdk),
        "generate display-renamed calculator SDK",
    );
    assert_eq!(
        fs::read(first.join("src/lib.rs")).unwrap(),
        fs::read(renamed_sdk.join("src/lib.rs")).unwrap(),
        "display-only source rename changed the stable-ID public facade",
    );
    let renamed_consumer = renamed_root.join("consumer");
    copied_consumer("consumer", &renamed_consumer);
    run(
        native_rust_cargo::cargo_command()
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(renamed_consumer.join("Cargo.toml")),
        "lock display-renamed calculator consumer",
    );
    let renamed_rust = run(
        native_rust_cargo::cargo_command()
            .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
            .arg(renamed_consumer.join("Cargo.toml")),
        "run display-renamed calculator consumer",
    );
    assert_eq!(renamed_rust.stdout, rust.stdout);

    let callback_sdk = fixture.0.join("callback-sdk");
    run(
        native_rust_cargo::cargo_command()
            .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
            .arg(&setup_manifest)
            .arg("--")
            .arg("callback")
            .arg(&callback_sdk),
        "generate callback SDK",
    );
    let callback_consumer = fixture.0.join("callback-consumer");
    copied_consumer("callback-consumer", &callback_consumer);
    run(
        native_rust_cargo::cargo_command()
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(callback_consumer.join("Cargo.toml")),
        "lock callback consumer",
    );
    let callback = run(
        native_rust_cargo::cargo_command()
            .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
            .arg(callback_consumer.join("Cargo.toml")),
        "run callback consumer",
    );
    assert_eq!(callback.stdout, EXPECTED_42_LINE);

    let program = semaprax::check(CALCULATOR, "examples/calculator.spx").unwrap();
    let c_path = fixture.0.join("calculator.c");
    let executable = fixture.0.join(if cfg!(windows) {
        "calculator.exe"
    } else {
        "calculator"
    });
    fs::write(&c_path, semaprax::codegen::emit_c(&program).unwrap()).unwrap();
    let compiler = std::env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    run(
        Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&c_path)
            .arg("-o")
            .arg(&executable),
        "compile calculator C backend",
    );
    let native = run(&mut Command::new(executable), "run calculator C backend");
    assert_eq!(native.stdout, rust.stdout);

    run(
        Command::new("node").arg("--version"),
        "locate required Node",
    );
    fs::write(
        fixture.0.join("calculator.wasm"),
        semaprax::wasm::emit_module(&program).unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.0.join("calculator.mjs"),
        r#"import {readFile} from "node:fs/promises";
const bytes=await readFile(new URL("calculator.wasm",import.meta.url));
const checked=(operation)=>(a,b)=>{const value=operation(a,b);if(value<-(1n<<63n)||value>(1n<<63n)-1n)throw new RangeError();return value;};
const imports={env:{spx_add:checked((a,b)=>a+b),spx_sub:checked((a,b)=>a-b),spx_mul:checked((a,b)=>a*b),spx_div:(a,b)=>a/b,spx_rem:(a,b)=>a%b,spx_neg:(a)=>-a,spx_contract_fail:()=>{throw new Error();}}};
const linked=await WebAssembly.instantiate(bytes,imports);
const value=linked.instance.exports.semaprax_main().toString();
process.stdout.write(value+"\n");
"#,
    )
    .unwrap();
    let node_source = fs::read_to_string(fixture.0.join("calculator.mjs")).unwrap();
    assert!(!node_source.contains("console.log"));
    assert!(!node_source.contains("process.platform"));
    assert!(!node_source.contains("\\r\\n"));
    let wasm = run(
        &mut calculator_node_command(&fixture.0),
        "run calculator Wasm backend",
    );
    assert_eq!(wasm.stdout, rust.stdout);
}

/// Issue #145 step 3 asks for "independent clean external Rust/npm consumers
/// of packaged artifacts. Use the package tarball/archive route, not a path
/// dependency into the checkout; provision any registry inputs explicitly
/// and preserve lockfiles." The sibling test above depends on the raw
/// generated directory tree directly, which is a path dependency into
/// generated output, but never exercises Cargo's own packaging rules (file
/// inclusion, `Cargo.toml` normalization/rewrite for publication). This test
/// runs `cargo package` to produce the exact `.crate` tarball a registry
/// would hold, extracts it (nothing is fetched from any registry; the
/// tarball is produced and consumed entirely from this machine's own
/// output), and builds+runs an external consumer against that EXTRACTED
/// archive content with its own preserved `Cargo.lock` -- never a path back
/// into this checkout or the pre-packaging tree.
///
/// It also locks in step 4's checksum/source-association gate: a SHA-256 of
/// the packaged tarball is an integrity value tying the archive to exact
/// source bytes, never a signature or a trust/publisher attestation (see
/// docs/RELEASE-PROCESS.md). Two independent generate-and-package runs from
/// identical `.spx` source must reproduce the identical digest (positive
/// control), and packaging a materially different program must not collide
/// onto that digest (negative control).
#[test]
fn packaged_tarball_consumer_round_trips_with_preserved_lockfile_and_source_tied_checksum() {
    if std::env::var_os("SEMAPRAX_REQUIRE_PUBLIC_NATIVE_RUST_SDK").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }

    const PACKAGE_CRATE_FILE: &str = "semaprax-generated-native-rust-sdk-0.1.0.crate";
    const PACKAGE_CRATE_DIR: &str = "semaprax-generated-native-rust-sdk-0.1.0";

    fn package_calculator_tarball(setup_manifest: &Path, workdir: &Path, mode: &str) -> Vec<u8> {
        let generated = workdir.join("generated-sdk");
        run(
            native_rust_cargo::cargo_command()
                .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
                .arg(setup_manifest)
                .arg("--")
                .arg(mode)
                .arg(&generated),
            "generate calculator SDK for packaging",
        );
        let package_target_dir = workdir.join("package-target");
        run(
            native_rust_cargo::cargo_command()
                .args(["package", "--offline", "--no-verify", "--manifest-path"])
                .arg(generated.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&package_target_dir),
            "package generated calculator SDK",
        );
        let crate_file = package_target_dir.join("package").join(PACKAGE_CRATE_FILE);
        fs::read(&crate_file).unwrap_or_else(|error| {
            panic!("read packaged tarball {}: {error}", crate_file.display())
        })
    }

    let fixture = Fixture::create();
    let setup_manifest = root().join("examples/calculator-rust/Cargo.toml");

    let first_dir = fixture.0.join("first");
    fs::create_dir(&first_dir).unwrap();
    let first_bytes = package_calculator_tarball(&setup_manifest, &first_dir, "calculator");

    let second_dir = fixture.0.join("second");
    fs::create_dir(&second_dir).unwrap();
    let second_bytes = package_calculator_tarball(&setup_manifest, &second_dir, "calculator");
    assert_eq!(
        sha256_hex(&first_bytes),
        sha256_hex(&second_bytes),
        "packaged tarball checksum must tie to exact source content, not build-time entropy",
    );

    let callback_dir = fixture.0.join("callback");
    fs::create_dir(&callback_dir).unwrap();
    let callback_bytes = package_calculator_tarball(&setup_manifest, &callback_dir, "callback");
    assert_ne!(
        sha256_hex(&first_bytes),
        sha256_hex(&callback_bytes),
        "packaged tarballs for different programs must not share a checksum",
    );

    // Extract the actual shipped tarball bytes (what a real registry install
    // would place on disk) and re-check the private-crate/local-path
    // leakage property (#145's required negative case) against the
    // packaging-normalized `Cargo.toml`, which Cargo rewrites independently
    // of the pre-packaging render already covered by
    // `public_sdk::tests::generated_cargo_package_never_embeds_a_local_checkout_path_or_a_private_crate_name`.
    let extracted_root = fixture.0.join("extracted");
    fs::create_dir(&extracted_root).unwrap();
    run(
        Command::new("tar")
            .arg("xzf")
            .arg(
                first_dir
                    .join("package-target/package")
                    .join(PACKAGE_CRATE_FILE),
            )
            .arg("-C")
            .arg(&extracted_root),
        "extract packaged tarball",
    );
    let extracted_crate_dir = extracted_root.join(PACKAGE_CRATE_DIR);
    let packaged_cargo_toml = fs::read_to_string(extracted_crate_dir.join("Cargo.toml")).unwrap();
    let this_checkout = env!("CARGO_MANIFEST_DIR");
    assert!(!packaged_cargo_toml.contains(this_checkout));
    for private_crate in [
        "semaprax-native-rust-interop-builder",
        "semaprax-native-rust-interop",
        "semaprax-native-rust-owned-data-package",
        "semaprax-native-rust-interop-platform",
        "semaprax-toolchain",
    ] {
        assert!(
            !packaged_cargo_toml.contains(private_crate),
            "packaged tarball manifest names the private crate `{private_crate}`"
        );
    }
    for separator in ["/Users/", "/home/", r"C:\Users\"] {
        assert!(
            !packaged_cargo_toml.contains(separator),
            "packaged tarball manifest embeds an absolute host path ({separator})"
        );
    }

    // Independent clean external consumer, via the tarball/archive route:
    // a path dependency onto the EXTRACTED packaged content (what a
    // registry-installed dependency looks like on disk), never onto this
    // checkout or the pre-packaging generated tree. No registry is
    // provisioned or contacted; the consumer gets its own preserved
    // `Cargo.lock`.
    let consumer = fixture.0.join("packaged-consumer");
    fs::create_dir_all(consumer.join("src")).unwrap();
    fs::copy(
        root().join("examples/calculator-rust/consumer/src/main.rs"),
        consumer.join("src/main.rs"),
    )
    .unwrap();
    fs::write(
        consumer.join("Cargo.toml"),
        format!(
            "[package]\nname = \"semaprax-calculator-rust-packaged-consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\nrust-version = \"1.85\"\npublish = false\n\n[workspace]\n\n[dependencies]\nsemaprax-generated-native-rust-sdk = {{ path = {extracted_crate_dir:?} }}\n\n[lints.rust]\nunsafe_code = \"forbid\"\n",
        ),
    )
    .unwrap();
    run(
        native_rust_cargo::cargo_command()
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(consumer.join("Cargo.toml")),
        "lock packaged-tarball calculator consumer",
    );
    assert!(
        consumer.join("Cargo.lock").is_file(),
        "tarball-route consumer must preserve a generated lockfile"
    );
    let packaged_run = run(
        native_rust_cargo::cargo_command()
            .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
            .arg(consumer.join("Cargo.toml")),
        "run packaged-tarball calculator consumer",
    );
    assert_eq!(packaged_run.stdout, EXPECTED_42_LINE);
}
