use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use super::*;
use crate::package_registry::artifact_manifest::{
    self, ArtifactRow, PackageArtifactManifestInput, FEATURES, TARGET_PROFILE,
};

static FIXTURE_SERIAL: AtomicU64 = AtomicU64::new(0);

fn hash(seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

fn publication(version: &str, seed: &str) -> PublishedEntry {
    let report = crate::package_report_v2::generate(
        Path::new("examples/meaning.spx"),
        &crate::package_report_v2::PackageReportV2Options::default(),
    )
    .expect("report fixture");
    let subject_bytes = crate::package_lock_v3::create_subject(
        &crate::package_lock_v3::Coordinate {
            package: "examples.meaning".to_owned(),
            version: version.to_owned(),
        },
        &report,
        &[],
        &[],
    )
    .expect("Subject-v3 fixture");
    PublishedEntry {
        package: "examples.meaning".to_owned(),
        version: version.to_owned(),
        content_digest: crate::audit_capsule::sha256_digest(subject_bytes.as_bytes()),
        api_digest: hash(&format!("api:{seed}")),
        license: "Apache-2.0".to_owned(),
        provenance_digest: None,
        signature: RegistrySignature {
            algorithm: "ed25519".to_owned(),
            identity: "publisher.example".to_owned(),
            signature: format!("opaque:{seed}"),
        },
        status: PublicationStatus::Active,
        subject_bytes,
    }
}

fn bound_entry(version: &str, seed: &str) -> ManifestBoundEntry {
    let publication = publication(version, seed);
    let manifest = artifact_manifest::create_unverified_for_test(PackageArtifactManifestInput {
        package: publication.package.clone(),
        version: publication.version.clone(),
        capsule_digest: hash(&format!("capsule:{seed}")),
        content_digest: publication.content_digest.clone(),
        api_abi_digest: publication.api_digest.clone(),
        target_profile: TARGET_PROFILE.to_owned(),
        features: FEATURES.map(str::to_owned).to_vec(),
        effects: Vec::new(),
        capabilities: Vec::new(),
        artifacts: [
            ("core-wasm-module", "module.wasm"),
            ("build-evidence", "semaprax.package-build.evidence.json"),
            ("build-manifest", "semaprax.package-build.json"),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (role, path))| ArtifactRow {
            role: role.to_owned(),
            path: path.to_owned(),
            bytes: index + 1,
            sha256: hash(&format!("artifact:{seed}:{path}")),
            profile: TARGET_PROFILE.to_owned(),
        })
        .collect(),
    })
    .expect("manifest fixture");
    ManifestBoundEntry {
        publication,
        artifact_manifest_digest: manifest.digest().to_owned(),
        artifact_manifest_bytes: manifest.bytes().to_owned(),
    }
}

#[test]
fn document_and_snapshot_independently_replay() {
    let entry = bound_entry("1.0.0", "alpha");
    let snapshot = build_snapshot(std::slice::from_ref(&entry)).expect("snapshot v2");
    let decoded = parse_registry_document(snapshot.document()).expect("document replay");
    assert_eq!(decoded, vec![decoded_entry(&entry)]);
    assert_eq!(
        decode_snapshot(snapshot.envelope()).expect("snapshot decode"),
        snapshot
    );
    assert_eq!(
        verify_snapshot(snapshot.envelope(), &[entry]).expect("independent entry replay"),
        snapshot
    );
}

#[test]
fn argument_order_does_not_change_v2_bytes() {
    let one = bound_entry("1.0.0", "alpha");
    let two = bound_entry("2.0.0", "beta");
    let forward = build_snapshot(&[one.clone(), two.clone()]).expect("forward");
    let reverse = build_snapshot(&[two, one]).expect("reverse");
    assert_eq!(forward.document(), reverse.document());
    assert_eq!(forward.envelope(), reverse.envelope());
    assert_eq!(forward.digest(), reverse.digest());
}

#[test]
fn v1_schema_digest_domain_and_bytes_remain_unchanged_after_v2_use() {
    assert_eq!(
        super::super::SCHEMA,
        "semaprax.package-registry-snapshot.v1"
    );
    assert_eq!(
        super::super::wire::DOCUMENT_SCHEMA,
        "semaprax.package-registry-document.v1"
    );
    let publication = publication("1.0.0", "alpha");
    let before =
        super::super::build_snapshot(std::slice::from_ref(&publication)).expect("v1 before");
    let _ = build_snapshot(&[bound_entry("1.0.0", "alpha")]).expect("v2 activity");
    let after = super::super::build_snapshot(&[publication]).expect("v1 after");
    assert_eq!(before.envelope(), after.envelope());
    assert_eq!(before.digest(), after.digest());
    assert!(before
        .envelope()
        .starts_with("{\"schema\":\"semaprax.package-registry-snapshot.v1\""));
}

#[test]
fn document_unknown_missing_duplicate_and_reordered_fields_are_refused() {
    let document =
        render_registry_document(&[bound_entry("1.0.0", "alpha")]).expect("canonical document");
    let unknown = document.replacen("\"schema\":", "\"unknown\":0,\"schema\":", 1);
    let missing = document.replacen("\"license\":\"Apache-2.0\",", "", 1);
    let duplicate = document.replacen(
        "\"schema\":",
        &format!("\"schema\":{},\"schema\":", quote_json(DOCUMENT_SCHEMA)),
        1,
    );
    let reordered = document.replacen(
        "\"package\":\"examples.meaning\",\"version\":\"1.0.0\"",
        "\"version\":\"1.0.0\",\"package\":\"examples.meaning\"",
        1,
    );
    for hostile in [unknown, missing, duplicate, reordered] {
        assert_eq!(
            parse_registry_document(&hostile).unwrap_err().code,
            "SPX-PKR618"
        );
    }
}

#[test]
fn snapshot_noncanonical_trailing_depth_work_and_byte_hostiles_are_bounded() {
    let snapshot = build_snapshot(&[bound_entry("1.0.0", "alpha")]).expect("snapshot");
    for hostile in [
        format!(" {}", snapshot.envelope()),
        format!("{}\n", snapshot.envelope()),
        format!("{}null", snapshot.envelope()),
    ] {
        assert_eq!(decode_snapshot(&hostile).unwrap_err().code, "SPX-PKR618");
    }
    let deep = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    assert_eq!(decode_snapshot(&deep).unwrap_err().code, "SPX-PKR618");
    let work = format!(
        "[{}]",
        std::iter::repeat_n("0", 4_100)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(decode_snapshot(&work).unwrap_err().code, "SPX-PKR618");
    let oversized = "x".repeat(MAX_SNAPSHOT_BYTES + 1);
    assert_eq!(decode_snapshot(&oversized).unwrap_err().code, "SPX-PKR618");
}

#[test]
fn cross_profile_digest_coordinate_and_api_substitution_fail_closed() {
    let baseline = bound_entry("1.0.0", "alpha");

    let mut digest = baseline.clone();
    digest.artifact_manifest_digest = hash("substituted");
    assert_eq!(build_snapshot(&[digest]).unwrap_err().code, "SPX-PKR615");

    let mut coordinate = baseline.clone();
    coordinate.publication.version = "2.0.0".to_owned();
    assert_eq!(
        build_snapshot(&[coordinate]).unwrap_err().code,
        "SPX-PKR603"
    );

    let mut api = baseline.clone();
    api.publication.api_digest = hash("another api");
    assert_eq!(build_snapshot(&[api]).unwrap_err().code, "SPX-PKR619");

    let mut profile_input = artifact_manifest::decode(&baseline.artifact_manifest_bytes)
        .expect("manifest")
        .input()
        .clone();
    profile_input.target_profile = "wasi-preview2".to_owned();
    assert_eq!(
        artifact_manifest::create_unverified_for_test(profile_input)
            .unwrap_err()
            .code,
        "SPX-PKR616"
    );
}

#[test]
fn cross_entry_manifest_splice_is_refused() {
    let one = bound_entry("1.0.0", "alpha");
    let two = bound_entry("2.0.0", "beta");
    let mut spliced = one.clone();
    spliced.artifact_manifest_digest = two.artifact_manifest_digest;
    spliced.artifact_manifest_bytes = two.artifact_manifest_bytes;
    assert_eq!(build_snapshot(&[spliced]).unwrap_err().code, "SPX-PKR619");
}

#[test]
fn decoded_entries_are_a_distinct_non_admission_type() {
    let admitted = bound_entry("1.0.0", "alpha");
    let document = render_registry_document(std::slice::from_ref(&admitted)).expect("document");
    let decoded = parse_registry_document(&document).expect("decode");
    assert!(std::any::type_name_of_val(&decoded[0]).ends_with("DecodedManifestBoundEntry"));
    assert_ne!(
        std::any::type_name::<ManifestBoundEntry>(),
        std::any::type_name::<DecodedManifestBoundEntry>()
    );
}

#[test]
fn snapshot_digest_and_byte_count_substitution_are_refused() {
    let snapshot = build_snapshot(&[bound_entry("1.0.0", "alpha")]).expect("snapshot");
    let bad_digest = snapshot
        .envelope()
        .replacen(snapshot.digest(), &hash("wrong"), 1);
    assert_eq!(decode_snapshot(&bad_digest).unwrap_err().code, "SPX-PKR619");
    let bad_bytes = snapshot.envelope().replacen(
        &format!("\"bytes\":{}", snapshot.document().len()),
        &format!("\"bytes\":{}", snapshot.document().len() + 1),
        1,
    );
    assert_eq!(decode_snapshot(&bad_bytes).unwrap_err().code, "SPX-PKR619");
}

#[test]
fn v2_decoder_and_replay_sources_have_no_authority_surface() {
    let sources = [
        include_str!("../registry_v2.rs"),
        include_str!("../artifact_manifest.rs"),
    ]
    .join("\n");
    for forbidden in [
        "std::fs",
        "std::process",
        "std::net",
        "Command::new",
        "File::open",
        "TcpStream",
    ] {
        assert!(
            !sources.contains(forbidden),
            "forbidden authority: {forbidden}"
        );
    }
}

#[test]
fn real_verified_linked_build_is_admitted_and_populates_derived_api_digest() {
    let _ = real_admitted_fixture();
}

pub(in crate::package_registry) fn real_admitted_fixture() -> (
    ManifestBoundEntry,
    crate::package_build_v2::LinkedOfflinePackageBuild,
) {
    real_admitted_fixture_with_status(PublicationStatus::Active)
}

pub(in crate::package_registry) fn real_admitted_fixture_with_status(
    status: PublicationStatus,
) -> (
    ManifestBoundEntry,
    crate::package_build_v2::LinkedOfflinePackageBuild,
) {
    const ROOT: &str = "app.main";
    const PROVIDER: &str = "lib.math";
    let canonical = |source: &str| {
        crate::format::canonical(
            &crate::parse(source, Path::new("registry-v2-fixture.spx")).expect("parse fixture"),
        )
    };
    let root_source = canonical(
        "module app.main;\nuse function @id(\"lib.math.answer\") from lib.math as answer;\n\
         @id(\"app.main.run\")\nfn run() -> i64 { answer() + 1 }\n",
    );
    let root_interface =
        canonical("module app.main;\n@id(\"app.main.run\")\nfn main() -> i64 { 0 }\n");
    let provider_source =
        canonical("module lib.math;\n@id(\"lib.math.answer\")\nfn answer() -> i64 { 41 }\n");
    let provider_interface = provider_source.replace("fn answer()", "fn main()");
    let directory = std::env::temp_dir().join(format!(
        "semaprax-registry-v2-real-{}-{}",
        std::process::id(),
        FIXTURE_SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).expect("create report fixture directory");
    let report = |name: &str, source: &str| {
        let path = directory.join(name);
        std::fs::write(&path, source).expect("write report fixture");
        crate::package_report_v2::generate(
            &path,
            &crate::package_report_v2::PackageReportV2Options::default(),
        )
        .expect("generate report")
    };
    let root_report = report("root.spx", &root_interface);
    let provider_report = report("provider.spx", &provider_interface);
    let coordinate = |package: &str| crate::package_lock_v2::Coordinate {
        package: package.to_owned(),
        version: "1.0.0".to_owned(),
    };
    let provider_coordinate = coordinate(PROVIDER);
    let root_subject_v2 = crate::package_lock_v2::create_subject(
        &coordinate(ROOT),
        &root_report,
        std::slice::from_ref(&provider_coordinate),
        &[],
    )
    .expect("root Subject-v2");
    let provider_subject_v2 =
        crate::package_lock_v2::create_subject(&provider_coordinate, &provider_report, &[], &[])
            .expect("provider Subject-v2");
    let input = crate::package_resolver::ResolutionInput {
        requirements: vec![crate::package_resolver::Requirement {
            package: ROOT.to_owned(),
            range: "=1.0.0".to_owned(),
        }],
        subjects: vec![root_subject_v2, provider_subject_v2],
        target: "wasm32".to_owned(),
        allowed_capabilities: vec![],
    };
    let resolution_options = crate::package_resolver::ResolutionOptions::default();
    let resolution = crate::package_resolver::generate(&input, &resolution_options)
        .expect("resolution evidence");
    let sources = vec![
        crate::package_source_capsule::PackageSource {
            package: ROOT.to_owned(),
            report: root_report.clone(),
            source: root_source.clone(),
        },
        crate::package_source_capsule::PackageSource {
            package: PROVIDER.to_owned(),
            report: provider_report,
            source: provider_source,
        },
    ];
    let capsule_options = crate::package_source_capsule::SourceCapsuleOptions {
        root_package: ROOT.to_owned(),
        max_bytes: crate::package_source_capsule::MAX_OUTPUT_BYTES,
    };
    let capsule = crate::package_source_capsule::generate(
        &sources,
        &resolution,
        &input,
        &resolution_options,
        &capsule_options,
    )
    .expect("source capsule");
    let build_options = crate::package_build_v2::LinkedOfflinePackageBuildOptions {
        root_package: ROOT.to_owned(),
        exports: vec!["app.main.run".to_owned()],
        max_artifact_bytes: crate::package_build_v2::MAX_ARTIFACT_BYTES,
        max_evidence_bytes: crate::package_build_v2::MAX_EVIDENCE_BYTES,
    };
    let build = crate::package_build_v2::generate(
        &capsule,
        &sources,
        &resolution,
        &input,
        &resolution_options,
        &capsule_options,
        &build_options,
    )
    .expect("real Build-v2");
    let root_subject_v3 = crate::package_lock_v3::create_subject(
        &crate::package_lock_v3::Coordinate {
            package: ROOT.to_owned(),
            version: "1.0.0".to_owned(),
        },
        &root_report,
        &[crate::package_lock_v3::DependencyRequirement {
            package: PROVIDER.to_owned(),
            range: "=1.0.0".to_owned(),
        }],
        &[],
    )
    .expect("root Subject-v3");
    let publication = PublishedEntry {
        package: ROOT.to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: crate::audit_capsule::sha256_digest(root_subject_v3.as_bytes()),
        api_digest: String::new(),
        license: "Apache-2.0".to_owned(),
        provenance_digest: None,
        signature: RegistrySignature {
            algorithm: "ed25519".to_owned(),
            identity: "publisher.example".to_owned(),
            signature: "opaque".to_owned(),
        },
        status,
        subject_bytes: root_subject_v3,
    };
    let admitted = admit_linked_build(
        publication,
        &build,
        &capsule,
        &sources,
        &resolution,
        &input,
        &resolution_options,
        &capsule_options,
        &build_options,
    )
    .expect("admit exact verified Build-v2");
    assert!(admitted.publication().api_digest.starts_with("sha256:"));
    assert!(build_snapshot(std::slice::from_ref(&admitted)).is_ok());
    std::fs::remove_file(directory.join("root.spx")).expect("remove root fixture");
    std::fs::remove_file(directory.join("provider.spx")).expect("remove provider fixture");
    std::fs::remove_dir(directory).expect("remove fixture directory");
    (admitted, build)
}
