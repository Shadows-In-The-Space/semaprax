//! A postcondition failure occurs after field movement, unlike requires-false.
use super::*;

fn replace_once(source: &str, from: &str, to: &str) -> String {
    assert_eq!(
        source.matches(from).count(),
        1,
        "exact observation boundary"
    );
    source.replacen(from, to, 1)
}

fn observe_c(root: &Path) {
    let path = root.join("driver.c");
    let driver = fs::read_to_string(&path).unwrap();
    let driver = replace_once(&driver,
        "    for (size_t iteration = 0; iteration < 2; ++iteration) {",
        "    const size_t live_baseline = auth_live();\n    for (size_t iteration = 0; iteration < 2; ++iteration) {");
    let driver = replace_once(&driver,
        "        assert(report.native_status == EXPECT_CALL_STATUS);",
        "        if (report.native_status != 11 || status != SPX_PG_CONSUMER_EXECUTION_FAILED) {\n            assert(auth_calls() == iteration + 1);\n            return 43; /* Exact postcondition-status omission oracle. */\n        }\n        assert(auth_live() == live_baseline);\n        assert(spx_pg_consumer_test_live_handles(consumer) == 0);\n        assert(report.native_status == EXPECT_CALL_STATUS);");
    // Existing assertions independently inspect the consumed/null input, absent
    // output, per-attempt endpoint count, generation, release and close-to-zero.
    fs::write(path, driver).unwrap();
}

fn observe_cxx(root: &Path, descriptor: &VerifiedPublicGenericDescriptor) {
    let path = root.join("driver.cpp");
    let driver = fs::read_to_string(&path).unwrap();
    let driver = replace_once(&driver,
        "            auto result = provider.transform(sample());",
        "            auto result = provider.transform(sample());\n            assert(auth_live() == live_baseline);");
    fs::write(path, format!("#include <cassert>\n{driver}")).unwrap();

    // The wrapper keeps its C input and handle private. Observe those actual
    // values just after its unchanged generated call, without substituting any
    // codec, status mapping, dispatch or settlement operation. On raw11, check
    // before the wrapper constructs its typed error or returns to the driver.
    let path = root.join(cxx_calling::WRAPPER_HEADER_FILE_NAME);
    let header = fs::read_to_string(&path).unwrap();
    let call = "    const auto status = ::spx_pg_consumer_transform_with_settlement(raw_, &c_input, &c_output, &report);";
    let mut observation = format!("{call}\n    if (report.native_status == 11) {{\n        assert(::spx_pg_consumer_test_live_handles(raw_) == 0);\n");
    for (record, paths) in [
        ("c_input", &descriptor.input_facts().owned_leaves),
        ("c_output", &descriptor.result_facts().owned_leaves),
    ] {
        for path in paths {
            let field = path
                .bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            observation.push_str(&format!(
                "        assert(!{record}.field_{field}.data && !{record}.field_{field}.len);\n"
            ));
        }
    }
    observation.push_str("    }");
    fs::write(path, replace_once(&header, call, &observation)).unwrap();
}

fn run_subject(
    root: &Path,
    descriptor: &VerifiedPublicGenericDescriptor,
    artifact: &AuthenticatedNativeMovesArtifact,
    swap: bool,
) {
    let physical = provider(artifact);
    for cxx in [false, true] {
        let directory = root.join(format!("postcondition-{swap}-{cxx}"));
        fs::create_dir(&directory).unwrap();
        let files = if cxx {
            cxx_calling::generate_authenticated_moves_calling_consumer_v1(descriptor, artifact)
                .unwrap()
                .files()
                .to_vec()
        } else {
            c_calling::generate_authenticated_moves_calling_consumer_v1(descriptor, artifact)
                .unwrap()
                .files()
                .to_vec()
        };
        for (name, bytes) in files {
            let path = directory.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fs::write(directory.join("provider.c"), &physical).unwrap();
        write_driver(&directory, descriptor, 1, false, swap, cxx);
        if cxx {
            observe_cxx(&directory, descriptor);
        } else {
            observe_c(&directory);
        }
        for opt in ["-O0", "-O2"] {
            super::super::caller_hostility::run(&directory, cxx, opt, 0);
            eprintln!("R07 postcondition branch={swap} cxx={cxx} {opt}: raw11/ExecutionFailed, two consumed inputs, no output, endpoint2, immediate live baseline, handles0, close0");
        }
        if swap && !cxx {
            let call = physical
                .lines()
                .find(|line| line.contains("(&context, &input, &result) != SPX_STATUS_SUCCESS"))
                .unwrap();
            fs::write(
                directory.join("provider.c"),
                replace_once(&physical, call, "    result = input;"),
            )
            .unwrap();
            super::super::caller_hostility::run(&directory, false, "-O0", 43);
            eprintln!("R07 postcondition identity-stub: exact status omission detected, exit43");
        }
    }
}

pub(super) fn run(root: &Path) {
    for swap in [true, false] {
        let source = SOURCE
            .replace(
                "{ value }",
                &BODY.replace("if true", if swap { "if true" } else { "if false" }),
            )
            .replace("requires true", "requires true\n    ensures false");
        let (program, revision) = checked(&source);
        let endpoint =
            derive_admitted_public_generic_endpoint_v1(&program, &revision, "auth.identity")
                .unwrap();
        let artifact =
            render_authenticated_moves_provider(&program, &revision, endpoint.descriptor())
                .unwrap();
        run_subject(root, endpoint.descriptor(), &artifact, swap);
    }
}
