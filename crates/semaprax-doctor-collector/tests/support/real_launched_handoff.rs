//! Opt-in real distributions through the actual production launcher and both
//! downstream processes. The trusted provisioner supplies the closed bundle,
//! immutable startup images/loader closure and independent expected details.
//! No observed version/report is used to manufacture its own passing oracle.
use super::{launch, launched_handoff, observe, report};
use semaprax_native_rust_interop_platform_sys::{
    create_doctor_offline_input, DoctorOfflineBundle, DoctorOfflineInput, DoctorOfflineTarget,
    DOCTOR_OFFLINE_INPUT_MAX_BYTES,
};
use std::fs::File;
use std::io::Read;

const BUNDLE_LIMIT: usize = DOCTOR_OFFLINE_INPUT_MAX_BYTES;
const DETAIL_LIMIT: usize = 8192;

fn expected_detail(variable: &str) -> String {
    let detail = std::env::var(variable).expect(variable);
    assert!(
        !detail.is_empty() && detail.len() <= DETAIL_LIMIT,
        "{variable} must contain 1..={DETAIL_LIMIT} UTF-8 bytes"
    );
    assert_eq!(
        detail.trim(),
        detail,
        "{variable} must already be normalized"
    );
    assert!(
        !detail.chars().any(char::is_control),
        "{variable} must contain no control characters"
    );
    detail
}

fn supplied_bundle() -> Vec<u8> {
    let path = launch::provisioned_path("SEMAPRAX_DOCTOR_REAL_BUNDLE");
    let file = File::open(path).unwrap();
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file());
    assert!(metadata.len() > 0 && metadata.len() <= BUNDLE_LIMIT as u64);
    let mut bytes = Vec::new();
    file.take(BUNDLE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, metadata.len());
    assert!(!bytes.is_empty() && bytes.len() <= BUNDLE_LIMIT);
    // Quiescence and real-distribution provenance are provisioner facts. This
    // bounded read neither authenticates provenance nor assembles loader files.
    bytes
}

#[test]
#[ignore = "requires real all-role bundle, independent expected details and fully provisioned current-head launcher/worker/collector"]
fn production_launcher_reports_all_roles_from_provisioned_real_distributions() {
    launched_handoff::context();
    let selector = std::env::var("SEMAPRAX_DOCTOR_REAL_SELECTOR").expect("provision real selector");
    assert!(!selector.is_empty() && selector.len() <= 64 && selector.is_ascii());
    let clang = expected_detail("SEMAPRAX_DOCTOR_EXPECTED_CLANG_DETAIL");
    let node = expected_detail("SEMAPRAX_DOCTOR_EXPECTED_NODE_DETAIL");
    let rust = expected_detail("SEMAPRAX_DOCTOR_EXPECTED_RUST_DETAIL");
    // Clang's supplied detail includes the exact absolute in-root path and
    // parenthesized first version line. Node/Rust supply their normalized first
    // lines. All must satisfy current production version policy; no downgrades.
    let tools = [
        ("clang", "ok", clang.as_str()),
        ("node", "ok", node.as_str()),
        ("rust", "ok", rust.as_str()),
    ];
    let bytes = supplied_bundle();
    let (bundle_file, snapshot) = create_doctor_offline_input(&bytes, bytes.len()).unwrap();
    assert_eq!(snapshot.bytes(), bytes);
    // This sole existing parser enforces the selector grammar, native host,
    // closed inventory and ELF contract. Encoding All requires all three roles.
    let bundle = DoctorOfflineBundle::parse(snapshot, &selector).unwrap();
    let request = bundle
        .encode_worker_request(DoctorOfflineTarget::All, [0x37; 32])
        .unwrap();
    drop(bundle);
    let (request_file, snapshot) = create_doctor_offline_input(&request, request.len()).unwrap();
    assert_eq!(snapshot.bytes(), request);
    drop(snapshot);
    // Fixed test nonce binds this invocation's bytes, not freshness/provenance.
    // Production-created executable files remain the actual transferred images.
    let worker = launched_handoff::prepared_executable(&launched_handoff::installed_image(
        "SEMAPRAX_DOCTOR_WORKER",
    ));
    let collector = launched_handoff::prepared_executable(&launched_handoff::installed_image(
        "SEMAPRAX_DOCTOR_COLLECTOR",
    ));
    require_all_roles(
        launched_handoff::run(&request_file, &bundle_file, &worker, &collector),
        &selector,
        "all",
        &tools,
        0,
    );
    // The launcher receives duplicates, not ownership of these originals.
    // Require exact retained transport bytes after the complete live handoff.
    assert_eq!(
        DoctorOfflineInput::acquire(&bundle_file, bytes.len())
            .unwrap()
            .bytes(),
        bytes
    );
    assert_eq!(
        DoctorOfflineInput::acquire(&request_file, request.len())
            .unwrap()
            .bytes(),
        request
    );
}

/// Keep the real-distribution assertion fail-closed while reporting every
/// role present in the canonical report. The outer collector cannot observe
/// the worker's wire termination trailer, so this layer reports role status
/// and the worker test supplies the finer exit/signal reason.
fn require_all_roles(
    observation: observe::Observation,
    selector: &str,
    target: &str,
    tools: &[(&str, &str, &str)],
    status: i32,
) {
    let mut failures = Vec::new();
    if observation.status.code() != Some(status) {
        failures.push(format!(
            "collector status {:?}; observed roles [{}]",
            observation.status,
            observed_role_statuses(&observation.stdout, tools)
        ));
    }
    if !observation.stderr.is_empty() {
        failures.push(format!(
            "collector stderr: {:?}",
            String::from_utf8_lossy(&observation.stderr)
        ));
    }
    let expected_debug = report::expected_for_selector(selector, target, tools, "debug");
    let expected_release = report::expected_for_selector(selector, target, tools, "release");
    if observation.stdout != expected_debug && observation.stdout != expected_release {
        failures.push(format!(
            "canonical report mismatch; observed roles [{}]; stdout {:?}",
            observed_role_statuses(&observation.stdout, tools),
            String::from_utf8_lossy(&observation.stdout)
        ));
    }
    if !failures.is_empty() {
        panic!(
            "real-distribution roles failed under the production launcher:\n{}",
            failures.join("\n")
        );
    }
}

/// Diagnostic-only status extraction. It intentionally has no authority over
/// the exact canonical-byte assertion above; malformed or missing rows are
/// rendered as `<missing>` and remain failures rather than being repaired.
fn observed_role_statuses(stdout: &[u8], tools: &[(&str, &str, &str)]) -> String {
    let text = String::from_utf8_lossy(stdout);
    tools
        .iter()
        .map(|(id, _, _)| {
            let marker = format!("\"id\":\"{id}\",\"required\":true,\"status\":\"");
            let status = text
                .find(&marker)
                .and_then(|start| {
                    let after = &text[start + marker.len()..];
                    after.find('"').map(|end| &after[..end])
                })
                .unwrap_or("<missing>");
            format!("{id}={status}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn role_status_summary_keeps_all_real_distribution_failures() {
    let tools = [
        ("clang", "ok", "clang"),
        ("node", "ok", "node"),
        ("rust", "ok", "rust"),
    ];
    let report = br#"{"checks":[{"id":"clang","required":true,"status":"ok"},{"id":"node","required":true,"status":"failed"},{"id":"rust","required":true,"status":"failed"}]}"#;
    assert_eq!(
        observed_role_statuses(report, &tools),
        "clang=ok, node=failed, rust=failed"
    );
}
