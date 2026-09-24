//! Generated standalone Rust package, with no workspace dependency or adapter.
use semaprax::{
    public_generic_abi::{
        carrier::{
            frame::{parse_bounded, CarrierFrameBinding, CarrierLeaf, LeafKind},
            trace::Direction,
        },
        descriptor::verify::VerifiedPublicGenericDescriptor,
        native::authenticated::AuthenticatedNativeIdentityArtifact,
    },
    public_generic_consumer::rust_calling::{
        generate_authenticated_identity_calling_consumer_v1, generate_rust_calling_consumer,
        CallingConsumer, OwnedByteField, RecordShape,
    },
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) fn observe(
    root: &Path,
    descriptor: &VerifiedPublicGenericDescriptor,
    artifact: &AuthenticatedNativeIdentityArtifact,
    provider: &str,
    guard: bool,
) {
    let generated =
        generate_authenticated_identity_calling_consumer_v1(descriptor, artifact).unwrap();
    assert_eq!(
        generated,
        generate_authenticated_identity_calling_consumer_v1(descriptor, artifact).unwrap()
    );
    if !guard {
        refuse_other_descriptor(artifact);
    }
    let shape = |paths: &[String]| {
        RecordShape::new(paths.iter().cloned().map(OwnedByteField::new).collect())
    };
    let input = shape(&descriptor.input_facts().owned_leaves);
    let output = shape(&descriptor.result_facts().owned_leaves);
    let legacy = generate_rust_calling_consumer(
        descriptor.accepted_bytes(),
        artifact.binding(),
        &input,
        &output,
    )
    .unwrap();
    let (canonical, malformed) = malformed_template(descriptor);
    let target = env::var_os("CARGO_TARGET_DIR")
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/agent-private"),
            PathBuf::from,
        )
        .join("generated-rust")
        .join(root.parent().unwrap().file_name().unwrap());
    for (label, consumer, mode) in [
        ("authenticated", &generated, 1),
        ("malformed", &generated, 2),
        ("old-flat", &legacy, 0),
    ] {
        let directory = root.join(format!("rust-{label}"));
        write_consumer(&directory, consumer);
        if mode == 2 {
            let path = directory.join("src/authenticated.rs");
            let source = fs::read_to_string(&path).unwrap();
            assert_eq!(source.matches(&canonical).count(), 1);
            // Only direction metadata changes. The actual generated encoder
            // hashes the changed frame normally, ruling out checksum luck.
            fs::write(path, source.replace(&canonical, &malformed)).unwrap();
        }
        fs::write(
            directory.join("provider.c"),
            format!(
                "{provider}\nsize_t auth_allocations(void) {{ return fixture_allocations; }}\n"
            ),
        )
        .unwrap();
        write_driver(&directory, &input, &output, mode, guard);
        let locked = cargo(&directory, &target)
            .args(["generate-lockfile", "--offline"])
            .output()
            .unwrap();
        assert!(
            locked.status.success(),
            "offline consumer lock: {}",
            String::from_utf8_lossy(&locked.stderr)
        );
        for opt in ["-O0", "-O2"] {
            let library = compile_provider(&directory, opt);
            let run = cargo(&directory, &target)
                .env("SPX_PG_PROVIDER_LIB_DIR", library)
                .env("SPX_PG_PROVIDER_LIB_NAME", "spx_pg_reference_provider")
                .args([
                    "run",
                    "--locked",
                    "--offline",
                    "--quiet",
                    "--bin",
                    "same_subject",
                ])
                .output()
                .unwrap();
            assert!(
                run.status.success(),
                "Rust {label} {opt}: {}",
                String::from_utf8_lossy(&run.stderr)
            );
            assert_eq!(run.stdout, b"rust-authenticated-caller-settled\n");
            eprintln!("generated Rust requires={guard} {label} {opt}: offline package executed twice; exact result/error and provider allocation/dispatch/settlement asserted");
        }
    }
}

fn refuse_other_descriptor(artifact: &AuthenticatedNativeIdentityArtifact) {
    let parsed = semaprax::check(super::super::SOURCE, Path::new("same-subject.spx")).unwrap();
    let revision = semaprax::format::canonical(&parsed);
    let program = semaprax::hir::resolve(&parsed).unwrap();
    let other = semaprax::public_generic_abi::compiler_endpoint::derive_admitted_public_generic_endpoint_v1(&program, &revision, "auth.identity").unwrap();
    assert_eq!(
        generate_authenticated_identity_calling_consumer_v1(other.descriptor(), artifact)
            .unwrap_err()
            .code,
        "SPX-PG803"
    );
}

fn malformed_template(descriptor: &VerifiedPublicGenericDescriptor) -> (String, String) {
    let plan = CarrierFrameBinding::from_verified_descriptor(descriptor, Direction::Input);
    let empty = plan
        .frame_with_leaves(
            plan.leaf_paths()
                .iter()
                .map(|path| CarrierLeaf::new(path, LeafKind::Bytes, Vec::new()))
                .collect(),
        )
        .encode();
    let mut malformed = empty.clone();
    let schema_len = usize::try_from(u64::from_le_bytes(empty[..8].try_into().unwrap())).unwrap();
    malformed[8 + schema_len + 8] = b'x';
    super::super::remint(&mut malformed);
    assert_eq!(parse_bounded(&malformed).unwrap_err().code, "SPX-PG801");
    (
        format!("const EMPTY: &[u8] = &{empty:?};"),
        format!("const EMPTY: &[u8] = &{malformed:?};"),
    )
}

pub(super) fn write_consumer(root: &Path, consumer: &CallingConsumer) {
    for (name, contents) in consumer.files() {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

fn write_driver(root: &Path, input: &RecordShape, output: &RecordShape, mode: u8, guard: bool) {
    let library = if mode == 0 {
        "spx_pg_rust_calling_consumer"
    } else {
        "spx_pg_private_authenticated_rust_v1"
    };
    let field = |path: &str| {
        format!(
            "field_{}",
            path.bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    let mut driver = include_str!("same_subject_rust_driver.rs.txt").to_owned();
    for (token, value) in [
        ("@LIBRARY@", library.to_owned()),
        ("@MODE@", mode.to_string()),
        ("@GUARD@", guard.to_string()),
        ("@INPUT0@", field(&input.fields[0].identity)),
        ("@INPUT1@", field(&input.fields[1].identity)),
        ("@OUTPUT0@", field(&output.fields[0].identity)),
        ("@OUTPUT1@", field(&output.fields[1].identity)),
    ] {
        driver = driver.replace(token, &value);
    }
    fs::create_dir_all(root.join("src/bin")).unwrap();
    fs::write(root.join("src/bin/same_subject.rs"), driver).unwrap();
}

pub(super) fn cargo(root: &Path, target: &Path) -> Command {
    let mut command = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTFLAGS", "-C debuginfo=0 -D warnings")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    command
}

pub(super) fn compile_provider(root: &Path, opt: &str) -> PathBuf {
    let directory = root.join(format!("provider{opt}"));
    fs::create_dir(&directory).unwrap();
    let object = directory.join("provider.o");
    let compile = Command::new(env::var_os("CLANG").unwrap_or_else(|| "clang".into()))
        .args(["-std=c11", opt, "-Wall", "-Wextra", "-Werror", "-c"])
        .arg(root.join("provider.c"))
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let archive = Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
        .arg("rcs")
        .arg(directory.join("libspx_pg_reference_provider.a"))
        .arg(object)
        .output()
        .unwrap();
    assert!(
        archive.status.success(),
        "{}",
        String::from_utf8_lossy(&archive.stderr)
    );
    directory
}
