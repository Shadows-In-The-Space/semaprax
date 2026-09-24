//! Actual generated caller; the driver only supplies/observes host values.
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
        c_calling::{
            generate_authenticated_identity_calling_consumer_v1, generate_c_calling_consumer,
            CallingConsumer, CONSUMER_SOURCE_FILE_NAME,
        },
        rust_calling::{OwnedByteField, RecordShape},
    },
};
use std::{fs, path::Path, process::Command};

pub(super) fn observe(
    root: &Path,
    descriptor: &VerifiedPublicGenericDescriptor,
    artifact: &AuthenticatedNativeIdentityArtifact,
    provider: &str,
    frame: &[u8],
    guard: bool,
) {
    if !guard {
        let parsed = semaprax::check(super::super::SOURCE, Path::new("same-subject.spx")).unwrap();
        let revision = semaprax::format::canonical(&parsed);
        let program = semaprax::hir::resolve(&parsed).unwrap();
        let different = semaprax::public_generic_abi::compiler_endpoint::derive_admitted_public_generic_endpoint_v1(
            &program, &revision, "auth.identity").unwrap();
        assert_eq!(
            generate_authenticated_identity_calling_consumer_v1(different.descriptor(), artifact)
                .unwrap_err()
                .code,
            "SPX-PG803"
        );
    }
    let generated =
        generate_authenticated_identity_calling_consumer_v1(descriptor, artifact).unwrap();
    assert_eq!(
        generated,
        generate_authenticated_identity_calling_consumer_v1(descriptor, artifact).unwrap()
    );
    let input = RecordShape::new(
        descriptor
            .input_facts()
            .owned_leaves
            .iter()
            .cloned()
            .map(OwnedByteField::new)
            .collect(),
    );
    let output = RecordShape::new(
        descriptor
            .result_facts()
            .owned_leaves
            .iter()
            .cloned()
            .map(OwnedByteField::new)
            .collect(),
    );
    let legacy = generate_c_calling_consumer(
        descriptor.accepted_bytes(),
        artifact.binding(),
        &input,
        &output,
    )
    .unwrap();
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
    let wrong_path = empty(true);
    assert_eq!(canonical.len(), wrong_path.len());
    assert_eq!(
        plan.validate_frame(&parse_bounded(&wrong_path).unwrap())
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
    for (label, consumer, mode) in [
        ("authenticated", &generated, 1),
        ("wrong-path", &generated, 2),
        ("old-flat", &legacy, 0),
    ] {
        let directory = root.join(format!("c-{label}"));
        fs::create_dir(&directory).unwrap();
        write_consumer(&directory, consumer);
        if mode == 2 {
            let path = directory.join(CONSUMER_SOURCE_FILE_NAME);
            let source = fs::read_to_string(&path).unwrap();
            assert_eq!(source.matches(&array(&canonical)).count(), 1);
            // Mutate only generated path metadata. The real encoder must remint
            // the digest, so refusal proves semantic binding, not checksum luck.
            fs::write(
                path,
                source.replace(&array(&canonical), &array(&wrong_path)),
            )
            .unwrap();
        }
        fs::write(
            directory.join("provider.c"),
            format!(
                "{provider}\nsize_t auth_allocations(void) {{ return fixture_allocations; }}\n"
            ),
        )
        .unwrap();
        let field = |path: &str| {
            format!(
                "field_{}",
                path.bytes().map(|b| format!("{b:02x}")).collect::<String>()
            )
        };
        let driver = format!("#define MODE {mode}\n#define EXPECT_CALL_STATUS {}\n#define INPUT0 {}\n#define INPUT1 {}\n#define OUTPUT0 {}\n#define OUTPUT1 {}\n{}",
            if guard { 0 } else { 11 }, field(&input.fields[0].identity), field(&input.fields[1].identity),
            field(&output.fields[0].identity), field(&output.fields[1].identity),
            include_str!("same_subject_c.c"));
        // The canonical frame declaration must precede the driver body.
        let driver = driver.replace(
            "/* CANONICAL_FRAME */",
            &super::super::array("expected_frame", frame),
        );
        fs::write(directory.join("driver.c"), driver).unwrap();
        compile_and_run(&directory, label, guard);
    }
}

fn compile_and_run(directory: &Path, label: &str, guard: bool) {
    for opt in ["-O0", "-O2"] {
        let executable = directory.join(format!("probe{opt}{}", std::env::consts::EXE_SUFFIX));
        let built = Command::new("clang")
            .args(["-std=c11", opt, "-Wall", "-Wextra", "-Werror"])
            .arg(directory.join("provider.c"))
            .arg(directory.join("driver.c"))
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("C caller requires clang");
        assert!(
            built.status.success(),
            "{label} {opt}: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let run = Command::new(executable).output().unwrap();
        assert!(
            run.status.success(),
            "{label} {opt}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        eprintln!("generated C11 requires={guard} {label} {opt}: exact result/status, dispatch and settlement assertions passed");
    }
}

fn write_consumer(root: &Path, consumer: &CallingConsumer) {
    for (name, contents) in consumer.files() {
        fs::write(root.join(name), contents).unwrap();
    }
}
