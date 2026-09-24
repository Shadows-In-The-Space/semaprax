//! Two generated callers of one checked native provider, NOT Core-Wasm parity.
//! The existing corpus hooks observe actual native provider allocations and
//! releases; host-side C allocations/Rust Vecs are outside this receipt.
use semaprax::{
    public_generic_abi::{
        compiler_endpoint::derive_admitted_public_generic_endpoint_v1,
        native::authenticated::render_authenticated_identity_provider,
    },
    public_generic_consumer::{c_calling, rust_calling},
};
use std::{env, fs, path::Path, process::Command};

fn fields(template: &str, input: &[String], output: &[String]) -> String {
    let mut result = template.to_owned();
    for (token, path) in [
        ("@INPUT0@", &input[0]),
        ("@INPUT1@", &input[1]),
        ("@OUTPUT0@", &output[0]),
        ("@OUTPUT1@", &output[1]),
    ] {
        let field = format!(
            "field_{}",
            path.bytes().map(|b| format!("{b:02x}")).collect::<String>()
        );
        result = result.replace(token, &field);
    }
    result
}

fn run(command: &mut Command, label: &str) -> Vec<u8> {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{label}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn checked_identity_c_and_rust_share_physical_export_cleanup_receipt() {
    let root = env::temp_dir().join(format!(
        "semaprax-physical-callers-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let c_root = root.join("c");
    let rust_root = root.join("rust");
    fs::create_dir_all(&c_root).unwrap();
    eprintln!("native physical caller evidence: {}", root.display());
    let parsed = semaprax::check(super::SOURCE, Path::new("same-subject.spx")).unwrap();
    let revision = semaprax::format::canonical(&parsed);
    let program = semaprax::hir::resolve(&parsed).unwrap();
    let endpoint =
        derive_admitted_public_generic_endpoint_v1(&program, &revision, "auth.identity").unwrap();
    let descriptor = endpoint.descriptor();
    let artifact = render_authenticated_identity_provider(&program, &revision, descriptor).unwrap();
    let c = c_calling::generate_authenticated_identity_calling_consumer_v1(descriptor, &artifact)
        .unwrap();
    let rust =
        rust_calling::generate_authenticated_identity_calling_consumer_v1(descriptor, &artifact)
            .unwrap();
    for (name, bytes) in c.files() {
        fs::write(c_root.join(name), bytes).unwrap();
    }
    super::rust::write_consumer(&rust_root, &rust);
    // Reuse the owning corpus's exact instrumentation, without altering the
    // artifact source, logical labels, codec, ABI, or selected checked call.
    let provider = format!(
        "{}\n{}\n{}\n#undef malloc\n#undef free\n{}",
        include_str!("../allocations.c"),
        include_str!("../settlement_corpus/observations.c"),
        artifact.source(),
        include_str!("same_subject_physical_provider.c")
    );
    for directory in [&c_root, &rust_root] {
        fs::write(directory.join("provider.c"), &provider).unwrap();
    }
    let driver = |template| {
        fields(
            template,
            &descriptor.input_facts().owned_leaves,
            &descriptor.result_facts().owned_leaves,
        )
    };
    fs::write(
        c_root.join("driver.c"),
        driver(include_str!("same_subject_physical_c.c")),
    )
    .unwrap();
    fs::create_dir_all(rust_root.join("src/bin")).unwrap();
    fs::write(
        rust_root.join("src/bin/same_subject.rs"),
        driver(include_str!("same_subject_physical_rust.rs.txt")),
    )
    .unwrap();
    let target = env::var_os("CARGO_TARGET_DIR")
        .map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("target/agent-private"),
            Into::into,
        )
        .join("generated-rust")
        .join(root.file_name().unwrap());
    run(
        super::rust::cargo(&rust_root, &target).args(["generate-lockfile", "--offline"]),
        "offline generated package lock",
    );
    let mut previous = None;
    for opt in ["-O0", "-O2"] {
        let executable = c_root.join(format!("probe{opt}{}", env::consts::EXE_SUFFIX));
        run(
            Command::new("clang")
                .args(["-std=c11", opt, "-Wall", "-Wextra", "-Werror"])
                .arg(c_root.join("provider.c"))
                .arg(c_root.join("driver.c"))
                .arg("-o")
                .arg(&executable),
            "C11 physical caller compile",
        );
        let c_receipt = run(&mut Command::new(executable), "C11 physical caller");
        let library = super::rust::compile_provider(&rust_root, opt);
        let rust_receipt = run(
            super::rust::cargo(&rust_root, &target)
                .env("SPX_PG_PROVIDER_LIB_DIR", library)
                .env("SPX_PG_PROVIDER_LIB_NAME", "spx_pg_reference_provider")
                .args([
                    "run",
                    "--locked",
                    "--offline",
                    "--quiet",
                    "--bin",
                    "same_subject",
                ]),
            "Rust physical caller",
        );
        assert_eq!(c_receipt, rust_receipt, "provider-local physical receipts");
        let text = std::str::from_utf8(&c_receipt).unwrap();
        assert_eq!(
            text.lines().count(),
            3,
            "nonzero success/failure/wrong-hook cases"
        );
        assert!(text.lines().nth(1).unwrap().starts_with("1 11 11 1 2 "));
        if let Some(previous) = previous.replace(c_receipt.clone()) {
            assert_eq!(previous, c_receipt, "O0/O2 physical receipts");
        }
        eprintln!("C11/Rust {opt}: success, export+cleanup failure, wrong-hook success; matching receipts:\n{text}");
    }
}
