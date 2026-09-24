use super::*;
use crate::package_registry::{PublicationStatus, RegistrySignature};
use crate::{
    package_build as b1, package_build_v2 as b2, package_lock_v2 as l2, package_lock_v3 as l3,
    package_resolver as r1, package_resolver_v2 as r2, package_source_capsule as capsule,
};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    leaf: PublishedEntry,
    root: PublishedEntry,
    leaf_build: b1::OfflinePackageBuild,
    root_build: b2::LinkedOfflinePackageBuild,
    leaf_input: r1::ResolutionInput,
    root_input: r1::ResolutionInput,
    leaf_evidence: String,
    root_evidence: String,
    capsule: String,
    sources: Vec<capsule::PackageSource>,
    leaf_options: b1::OfflinePackageBuildOptions,
    root_options: b2::LinkedOfflinePackageBuildOptions,
    capsule_options: capsule::SourceCapsuleOptions,
}
fn publication(package: &str, subject: String) -> PublishedEntry {
    PublishedEntry {
        package: package.into(),
        version: "1.0.0".into(),
        content_digest: leaf::raw(subject.as_bytes()),
        api_digest: String::new(),
        license: "Apache-2.0".into(),
        provenance_digest: None,
        signature: RegistrySignature {
            algorithm: "ed25519".into(),
            identity: "fixture.publisher".into(),
            signature: "opaque".into(),
        },
        status: PublicationStatus::Active,
        subject_bytes: subject,
    }
}
impl Fixture {
    fn new() -> Self {
        Self::with_leaf_value(41)
    }
    fn with_leaf_value(value: i64) -> Self {
        let canonical = |text: &str| {
            crate::format::canonical(&crate::parse(text, Path::new("fixture.spx")).unwrap())
        };
        let leaf_source = canonical(&format!(
            "module lib.leaf;\n@id(\"lib.leaf.answer\")\nfn main() -> i64 {{ {value} }}\n"
        ));
        let root_source = canonical("module app.root;\nuse function @id(\"lib.leaf.answer\") from lib.leaf as answer;\n@id(\"app.root.run\")\nfn run() -> i64 { answer() + 1 }\n");
        let root_interface =
            canonical("module app.root;\n@id(\"app.root.run\")\nfn main() -> i64 { 0 }\n");
        let directory = std::env::temp_dir().join(format!(
            "semaprax-registry-leaf-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let report = |name: &str, source: &str| {
            let path = directory.join(name);
            std::fs::write(&path, source).unwrap();
            crate::package_report_v2::generate(&path, &Default::default()).unwrap()
        };
        let root_report = report("root.spx", &root_interface);
        let leaf_report = report("leaf.spx", &leaf_source);
        std::fs::remove_file(directory.join("root.spx")).unwrap();
        std::fs::remove_file(directory.join("leaf.spx")).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        let coord = |p: &str| l2::Coordinate {
            package: p.into(),
            version: "1.0.0".into(),
        };
        let leaf_v2 = l2::create_subject(&coord("lib.leaf"), &leaf_report, &[], &[]).unwrap();
        let root_v2 =
            l2::create_subject(&coord("app.root"), &root_report, &[coord("lib.leaf")], &[])
                .unwrap();
        let input = |p: &str, subjects: Vec<String>| r1::ResolutionInput {
            requirements: vec![r1::Requirement {
                package: p.into(),
                range: "=1.0.0".into(),
            }],
            subjects,
            target: "wasm32".into(),
            allowed_capabilities: vec![],
        };
        let leaf_input = input("lib.leaf", vec![leaf_v2.clone()]);
        let root_input = input("app.root", vec![root_v2, leaf_v2]);
        let leaf_evidence = r1::generate(&leaf_input, &Default::default()).unwrap();
        let root_evidence = r1::generate(&root_input, &Default::default()).unwrap();
        let leaf_options = b1::OfflinePackageBuildOptions {
            root_package: "lib.leaf".into(),
            exports: vec!["lib.leaf.answer".into()],
            max_artifact_bytes: b1::MAX_ARTIFACT_BYTES,
            max_evidence_bytes: b1::MAX_EVIDENCE_BYTES,
        };
        let leaf_build = b1::generate(
            &leaf_evidence,
            &leaf_input,
            &Default::default(),
            &leaf_options,
        )
        .unwrap();
        let sources = vec![
            capsule::PackageSource {
                package: "app.root".into(),
                report: root_report.clone(),
                source: root_source,
            },
            capsule::PackageSource {
                package: "lib.leaf".into(),
                report: leaf_report.clone(),
                source: leaf_source,
            },
        ];
        let capsule_options = capsule::SourceCapsuleOptions {
            root_package: "app.root".into(),
            max_bytes: capsule::MAX_OUTPUT_BYTES,
        };
        let capsule = capsule::generate(
            &sources,
            &root_evidence,
            &root_input,
            &Default::default(),
            &capsule_options,
        )
        .unwrap();
        let root_options = b2::LinkedOfflinePackageBuildOptions {
            root_package: "app.root".into(),
            exports: vec!["app.root.run".into()],
            max_artifact_bytes: b2::MAX_ARTIFACT_BYTES,
            max_evidence_bytes: b2::MAX_EVIDENCE_BYTES,
        };
        let root_build = b2::generate(
            &capsule,
            &sources,
            &root_evidence,
            &root_input,
            &Default::default(),
            &capsule_options,
            &root_options,
        )
        .unwrap();
        let coord3 = |p: &str| l3::Coordinate {
            package: p.into(),
            version: "1.0.0".into(),
        };
        let leaf = publication(
            "lib.leaf",
            l3::create_subject(&coord3("lib.leaf"), &leaf_report, &[], &[]).unwrap(),
        );
        let root = publication(
            "app.root",
            l3::create_subject(
                &coord3("app.root"),
                &root_report,
                &[l3::DependencyRequirement {
                    package: "lib.leaf".into(),
                    range: "=1.0.0".into(),
                }],
                &[],
            )
            .unwrap(),
        );
        Self {
            leaf,
            root,
            leaf_build,
            root_build,
            leaf_input,
            root_input,
            leaf_evidence,
            root_evidence,
            capsule,
            sources,
            leaf_options,
            root_options,
            capsule_options,
        }
    }
    fn leaf(&self) -> Result<DistributionEntry> {
        admit_leaf_build(
            self.leaf.clone(),
            &self.leaf_build,
            &self.leaf_evidence,
            &self.leaf_input,
            &Default::default(),
            &self.leaf_options,
        )
    }
    fn root(&self) -> Result<DistributionEntry> {
        admit_linked_build(
            self.root.clone(),
            &self.root_build,
            &self.capsule,
            &self.sources,
            &self.root_evidence,
            &self.root_input,
            &Default::default(),
            &self.capsule_options,
            &self.root_options,
        )
    }
    fn snapshot(&self) -> RegistrySnapshotV3 {
        build_snapshot(&[self.root().unwrap(), self.leaf().unwrap()]).unwrap()
    }
    fn subjects(&self) -> Vec<String> {
        vec![
            self.root.subject_bytes.clone(),
            self.leaf.subject_bytes.clone(),
        ]
    }
}
fn rejected<T>(result: Result<T>) {
    assert!(result.is_err());
}

#[test]
fn genuine_root_leaf_resolves_reproducibly_and_replays_exact_graph_and_bytes() {
    let fixture = Fixture::new();
    let snapshot = fixture.snapshot();
    let subjects = fixture.subjects();
    let input = r2::ResolutionInput {
        requirements: vec![r2::Requirement {
            package: "app.root".into(),
            range: "=1.0.0".into(),
        }],
        subjects: subjects.clone(),
        target: "wasm32".into(),
        allowed_capabilities: vec![],
    };
    let a = r2::generate(&input, &Default::default()).unwrap();
    let b = r2::generate(&input, &Default::default()).unwrap();
    assert_eq!(a, b);
    let resolved = r2::verify(&a, &input, &Default::default()).unwrap();
    verify_lock_selection(&snapshot, &resolved.lock, &subjects).unwrap();
    assert_eq!(
        resolved.lock,
        l3::generate(&subjects, &Default::default()).unwrap()
    );
    let reversed = build_snapshot(&[fixture.leaf().unwrap(), fixture.root().unwrap()]).unwrap();
    assert_eq!(snapshot.envelope(), reversed.envelope());
    verify_snapshot(snapshot.envelope(), reversed.entries()).unwrap();
    let inspected = inspect_snapshot(snapshot.envelope()).unwrap();
    assert_eq!(inspected.entries().len(), 2);
    assert_eq!(
        fixture.leaf().unwrap().manifest.build_facts[0].source,
        fixture.sources[1].source
    );
    let manifest = leaf::inspect_with_digest(
        &fixture.leaf().unwrap().manifest.bytes,
        &fixture.leaf().unwrap().manifest.digest,
    )
    .unwrap();
    assert_eq!(
        manifest.artifacts()[0].sha256,
        leaf::raw(&fixture.leaf_build.module_wasm)
    );
    // Existing v1 manifest decoder must not silently widen to the new profile.
    rejected(super::super::artifact_manifest::decode(manifest.bytes()));
}

#[test]
fn leaf_exact_build_evidence_source_report_and_coordinate_tampering_refuses() {
    let mut fixture = Fixture::new();
    fixture.leaf_build.module_wasm[0] ^= 1;
    rejected(fixture.leaf());
    let mut fixture = Fixture::new();
    fixture.leaf_build.evidence_json.push(' ');
    rejected(fixture.leaf());
    let mut fixture = Fixture::new();
    fixture.leaf.version = "2.0.0".into();
    rejected(fixture.leaf());
    let other = Fixture::with_leaf_value(99);
    let mut fixture = Fixture::new();
    fixture.leaf = other.leaf;
    rejected(fixture.leaf());
    let mut fixture = Fixture::new();
    fixture.leaf_evidence = other.leaf_evidence;
    rejected(fixture.leaf());
}

#[test]
fn leaf_inspection_rejects_api_digest_rebinding_profile_and_inventory_splices() {
    let mut fixture = Fixture::new();
    let entry = fixture.leaf().unwrap();
    fixture.leaf.api_digest = entry.publication.api_digest.clone();
    assert_eq!(
        fixture.leaf().unwrap().publication.api_digest,
        entry.publication.api_digest
    );
    fixture.leaf.api_digest = leaf::raw(b"wrong caller API");
    assert_eq!(fixture.leaf().unwrap_err().code, "SPX-PKR631");
    rejected(leaf::inspect(&entry.manifest.bytes.replace(
        leaf::PROFILE,
        "linked-effect-free-core-wasm-scalar.v2",
    )));
    let inspected = leaf::inspect(&entry.manifest.bytes).unwrap();
    let original = encode(&inspected.artifacts());
    let mut rows = inspected.artifacts().to_vec();
    rows.swap(0, 1);
    rejected(leaf::inspect(
        &entry.manifest.bytes.replace(&original, &encode(&rows)),
    ));
    rejected(leaf::inspect_with_digest(
        &entry.manifest.bytes,
        &leaf::raw(b"wrong"),
    ));
    // Wire inspection is not admission: exact caller-owned producer replay is required.
    let mut forged = entry.clone();
    forged.publication.api_digest = leaf::raw(b"forged");
    rejected(build_snapshot(&[forged]));
    let forged_wire = entry
        .manifest
        .bytes
        .replace(&entry.publication.api_digest, &leaf::raw(b"forged"));
    assert!(leaf::inspect(&forged_wire).is_ok()); // Canonical inspection cannot authenticate producer facts.
    rejected(leaf::inspect_with_digest(
        &forged_wire,
        &entry.manifest.digest,
    ));
}

#[test]
fn missing_leaf_yank_and_cross_built_leaf_are_rejected() {
    let fixture = Fixture::new();
    let subjects = fixture.subjects();
    let lock = l3::generate(&subjects, &Default::default()).unwrap();
    let root_only = build_snapshot(&[fixture.root().unwrap()]).unwrap();
    rejected(verify_lock_selection(&root_only, &lock, &subjects));
    let mut yanked = Fixture::new();
    yanked.leaf.status = PublicationStatus::Yanked {
        reason: "fixture".into(),
    };
    rejected(verify_lock_selection(&yanked.snapshot(), &lock, &subjects));
    let other = Fixture::with_leaf_value(99);
    let snapshot = build_snapshot(&[fixture.root().unwrap(), other.leaf().unwrap()]).unwrap();
    let selected = vec![
        fixture.root.subject_bytes.clone(),
        other.leaf.subject_bytes.clone(),
    ];
    let lock = l3::generate(&selected, &Default::default()).unwrap();
    rejected(verify_lock_selection(&snapshot, &lock, &selected));
}

#[test]
fn linked_root_cannot_erase_its_capsule_dependency_graph() {
    let mut fixture = Fixture::new();
    let subject = l3::verify_dependency_subject(&fixture.root.subject_bytes).unwrap();
    fixture.root.subject_bytes =
        l3::create_subject(&subject.coordinate, &subject.report, &[], &[]).unwrap();
    fixture.root.content_digest = leaf::raw(fixture.root.subject_bytes.as_bytes());
    assert_eq!(fixture.root().unwrap_err().code, "SPX-PKR631");
}

#[test]
fn v3_decoder_rejects_tamper_noncanonical_and_missing_manifest() {
    let fixture = Fixture::new();
    let snapshot = fixture.snapshot();
    rejected(inspect_snapshot(&(snapshot.envelope().to_owned() + "\n")));
    let mut envelope: Envelope = serde_json::from_str(snapshot.envelope()).unwrap();
    envelope.digest = leaf::raw(b"wrong");
    rejected(inspect_snapshot(&encode(&envelope)));
    let mut envelope: Envelope = serde_json::from_str(snapshot.envelope()).unwrap();
    let mut doc: Document = serde_json::from_str(&envelope.document).unwrap();
    doc.manifests.pop();
    envelope.document = encode(&doc);
    envelope.bytes = envelope.document.len();
    envelope.digest = domain(SNAPSHOT_SCHEMA, envelope.document.as_bytes());
    rejected(inspect_snapshot(&encode(&envelope)));
    rejected(verify_snapshot(
        snapshot.envelope(),
        &[fixture.root().unwrap()],
    ));
}
