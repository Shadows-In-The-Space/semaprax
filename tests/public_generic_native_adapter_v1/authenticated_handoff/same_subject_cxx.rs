//! C++ owns only move/RAII wrapping; actual admission is the generated C client.
use semaprax::{
    public_generic_abi::{
        carrier::{
            frame::{parse_bounded, CarrierFrameBinding, CarrierLeaf, LeafKind},
            trace::Direction,
        },
        descriptor::verify::VerifiedPublicGenericDescriptor,
        native::authenticated::AuthenticatedNativeIdentityArtifact,
    },
    public_generic_consumer::{
        c_calling,
        cxx_calling::{
            generate_authenticated_identity_calling_consumer_v1, generate_cxx_calling_consumer,
            CallingConsumer, WRAPPER_HEADER_FILE_NAME,
        },
        rust_calling::{OwnedByteField, RecordShape},
    },
};
use std::{env, fs, path::Path, process::Command};

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
    let c = c_calling::generate_authenticated_identity_calling_consumer_v1(descriptor, artifact)
        .unwrap();
    assert_eq!(
        &generated.files()[..c.files().len()],
        c.files(),
        "C artifacts must be byte-identical, not a copied codec"
    );
    if !guard {
        refuse_other_descriptor(artifact);
    }
    let shape = |paths: &[String]| {
        RecordShape::new(paths.iter().cloned().map(OwnedByteField::new).collect())
    };
    let input = shape(&descriptor.input_facts().owned_leaves);
    let output = shape(&descriptor.result_facts().owned_leaves);
    let legacy = generate_cxx_calling_consumer(
        descriptor.accepted_bytes(),
        artifact.binding(),
        &input,
        &output,
    )
    .unwrap();
    let wrapper = |consumer: &CallingConsumer| {
        consumer
            .files()
            .iter()
            .find(|(name, _)| name == WRAPPER_HEADER_FILE_NAME)
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(
        wrapper(&generated),
        wrapper(&legacy),
        "ownership wrapper remains byte-identical"
    );
    let (canonical, wrong_path) = wrong_path_template(descriptor);
    for (label, consumer, mode) in [
        ("authenticated", &generated, 1),
        ("wrong-path", &generated, 2),
        ("old-flat", &legacy, 0),
    ] {
        let directory = root.join(format!("cxx-{label}"));
        write_consumer(&directory, consumer);
        if mode == 2 {
            let path = directory.join(c_calling::CONSUMER_SOURCE_FILE_NAME);
            let source = fs::read_to_string(&path).unwrap();
            assert_eq!(source.matches(&canonical).count(), 1);
            // The real C encoder remints its digest over substituted metadata.
            fs::write(path, source.replace(&canonical, &wrong_path)).unwrap();
        }
        fs::write(
            directory.join("provider.c"),
            format!(
                "{provider}\nsize_t auth_allocations(void) {{ return fixture_allocations; }}\n"
            ),
        )
        .unwrap();
        write_driver(&directory, &input, &output, mode, guard, 14);
        for opt in ["-O0", "-O2"] {
            compile_and_run(&directory, opt);
            eprintln!("generated C++17 requires={guard} {label} {opt}: two transforms, typed/raw status, zero prephysical refusal, move/RAII/close assertions passed");
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

fn wrong_path_template(descriptor: &VerifiedPublicGenericDescriptor) -> (String, String) {
    let plan = CarrierFrameBinding::from_verified_descriptor(descriptor, Direction::Input);
    let empty = |wrong: bool| {
        plan.frame_with_leaves(
            plan.leaf_paths()
                .iter()
                .enumerate()
                .map(|(index, path)| {
                    CarrierLeaf::new(
                        if wrong && index == 0 {
                            "@9:auth.Left"
                        } else {
                            path
                        },
                        LeafKind::Bytes,
                        Vec::new(),
                    )
                })
                .collect(),
        )
        .encode()
    };
    let canonical = empty(false);
    let wrong = empty(true);
    assert_eq!(
        plan.validate_frame(&parse_bounded(&wrong).unwrap())
            .unwrap_err()
            .code,
        "SPX-PG803"
    );
    let array = |bytes: &[u8]| {
        format!(
            "static const uint8_t spx_pg_ccc_auth_empty[] = {{{}}};",
            bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    (array(&canonical), array(&wrong))
}

fn write_consumer(root: &Path, consumer: &CallingConsumer) {
    for (name, contents) in consumer.files() {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

pub(super) fn write_driver(
    root: &Path,
    input: &RecordShape,
    output: &RecordShape,
    mode: u8,
    guard: bool,
    refusal: u8,
) {
    let field = |path: &str| {
        format!(
            "field_{}",
            path.bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    let mut driver = include_str!("same_subject_cxx.cpp").to_owned();
    for (token, value) in [
        ("@MODE@", mode.to_string()),
        ("@GUARD@", guard.to_string()),
        ("@REFUSAL@", refusal.to_string()),
        ("@INPUT0@", field(&input.fields[0].identity)),
        ("@INPUT1@", field(&input.fields[1].identity)),
        ("@OUTPUT0@", field(&output.fields[0].identity)),
        ("@OUTPUT1@", field(&output.fields[1].identity)),
    ] {
        driver = driver.replace(token, &value);
    }
    fs::write(root.join("driver.cpp"), driver).unwrap();
}

fn compile_and_run(root: &Path, opt: &str) {
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let mut objects = Vec::new();
    for source in ["provider.c", c_calling::CONSUMER_SOURCE_FILE_NAME] {
        let object = root.join(format!("{source}{opt}.o"));
        let compile = Command::new(&clang)
            .args(["-std=c11", opt, "-Wall", "-Wextra", "-Werror", "-c"])
            .arg(root.join(source))
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        objects.push(object);
    }
    let executable = root.join(format!("probe{opt}{}", env::consts::EXE_SUFFIX));
    let link = Command::new(env::var_os("CLANGXX").unwrap_or_else(|| "clang++".into()))
        .args(["-std=c++17", opt, "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root)
        .arg(root.join("driver.cpp"))
        .args(objects)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run = Command::new(executable).output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.stdout, b"cxx-authenticated-caller-settled");
}
