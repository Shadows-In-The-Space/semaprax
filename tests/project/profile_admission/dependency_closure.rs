use semaprax::project::with_authenticated_project;

use super::{fixture, manifest, TESTS};

const V1: &str = "schema = \"semaprax.manifest.v1\"\n\n[package]\nname = \"dependency-closure\"\nversion = \"0.1.0\"\nprofile = \"useful-data.v1\"\n\n[modules]\nentry = \"compat.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\ntests = [\"profile.tests\"]\n\n[exports]\nweb = [\"compat.main\"]\n";

#[test]
fn useful_data_v1_authored_nominal_boundary_is_still_rejected() {
    let app = r#"
module compat.app;

@id("compat.reader")
record Reader { @id("compat.reader.data") data: Bytes, }

@id("compat.hidden")
fn hidden(value: own Reader) -> Reader { value }

@id("compat.main")
fn main() -> i64 { 0 }
"#;
    let fixture = fixture("authored-nominal", V1, app, TESTS);
    let error =
        with_authenticated_project(&manifest(&fixture.0), |snapshot| snapshot.check()).unwrap_err();
    assert_eq!(error[0].code, "SPX-G172", "{error:?}");
    assert_eq!(error[0].message, "workspace module `compat.app` contains declarations outside the selected project linker profile");
}

#[test]
fn useful_data_v1_rejects_a_reached_json_cursor_dependency_member() {
    let manifest_text =
        format!("{V1}\n[dependencies]\nstd.data.json.write = \"=0.1.0\"\nstd.io = \"=0.1.0\"\n");
    let app = r#"
module compat.app;
use function @id("std.io.reader.from-bytes") from std.io as reader_from_bytes;
use function @id("std.io.writer.from-bytes") from std.io as writer_from_bytes;
use function @id("std.data.json.write.quoted-into") from std.data.json.write as quoted_into;

@id("compat.main")
fn main() -> i64 {
    let source = [97u8];
    let destination = [0u8, 0u8, 0u8];
    let input = reader_from_bytes(bytes_copy(array_as_slice(source)));
    let output = writer_from_bytes(bytes_copy(array_as_slice(destination)));
    let rendered = quoted_into(input, output);
    0
}
"#;
    let fixture = fixture("reached-json-cursor", &manifest_text, app, TESTS);
    let error =
        with_authenticated_project(&manifest(&fixture.0), |snapshot| snapshot.check()).unwrap_err();
    assert_eq!(error[0].code, "SPX-G172", "{error:?}");
    assert_eq!(error[0].message, "function target must be monomorphic with admitted value parameters, or borrowed byte-slice parameters and a scalar return");
}

/// `V1` exports `compat.main`, which the Public Useful Data Export v1 gate
/// refuses once a project gets far enough to be checked end to end. The two
/// tests below need a project that reaches the linker, so they export a real
/// slice predicate instead.
const EXPORTING_V1: &str = "schema = \"semaprax.manifest.v1\"\n\n[package]\nname = \"dependency-closure\"\nversion = \"0.1.0\"\nprofile = \"useful-data.v1\"\n\n[modules]\nentry = \"compat.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\ntests = [\"profile.tests\"]\n\n[exports]\nweb = [\"compat.not_empty\"]\n\n[dependencies]\nstd.auth = \"=0.1.0\"\n";

/// The bundled `std.auth` source this suite composes against must still
/// declare the generic record, or the two tests below would prove nothing.
fn bundled_auth_declares_a_generic_record() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("std/auth/src/auth.spx"),
    )
    .unwrap();
    assert!(
        source.contains("record Secret<T>"),
        "std/auth/src/auth.spx no longer declares the generic record these tests compose"
    );
}

/// Control for the refusal below: a bundled package that declares a generic
/// record still composes into a `useful-data.v1` project, whose linker retains
/// no authored type declaration at all. The unreached record-using member is
/// dropped with the rest of the incompatible dependency inventory.
#[test]
fn useful_data_v1_composes_a_bundled_package_declaring_a_generic_record() {
    bundled_auth_declares_a_generic_record();
    let app = r#"
module compat.app;
use function @id("std.auth.password.policy_within_bounds") from std.auth as password_policy_within_bounds;

@id("compat.not_empty")
fn not_empty(value: borrow Slice<u8>) -> bool { byte_len(value) > 0usize }

@id("compat.main")
fn main() -> i64 { if password_policy_within_bounds(65536usize, 3usize, 4usize) { 0 } else { 1 } }
"#;
    let fixture = fixture("bundled-generic-record", EXPORTING_V1, app, TESTS);
    with_authenticated_project(&manifest(&fixture.0), |snapshot| snapshot.check()).unwrap();
}

/// Reaching the record-using member is refused by name at the linker boundary,
/// not left to surface later as an unknown type inside capacity analysis.
#[test]
fn useful_data_v1_refuses_a_reached_generic_record_dependency_member() {
    bundled_auth_declares_a_generic_record();
    let app = r#"
module compat.app;
use function @id("std.auth.secret.self_check") from std.auth as secret_self_check;

@id("compat.not_empty")
fn not_empty(value: borrow Slice<u8>) -> bool { byte_len(value) > 0usize }

@id("compat.main")
fn main() -> i64 { if secret_self_check() { 0 } else { 1 } }
"#;
    let fixture = fixture("reached-generic-record", EXPORTING_V1, app, TESTS);
    let error =
        with_authenticated_project(&manifest(&fixture.0), |snapshot| snapshot.check()).unwrap_err();
    assert_eq!(error[0].code, "SPX-H006", "{error:?}");
    assert_eq!(
        error[0].message,
        "workspace function `std.auth.secret.self_check` uses authored type `std.auth.secret`, which is outside the Useful Data linker profile"
    );
}
