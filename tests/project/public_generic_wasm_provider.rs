//! Phase-A admission for the compiler-owned public-generic Wasm provider.
//!
//! These tests deliberately stop before artifact emission. They prove that
//! the new profile owns one checked generic endpoint and its independently
//! replayed descriptor, while every executable/publication route stays
//! closed until the provider emitter exists.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::project::{
    render_project_lock, with_authenticated_project, ManifestLayout, ProjectManifest,
    ProjectProfile, PACKAGE_MANIFEST_SCHEMA, PROJECT_SCHEMA_V20,
};

static SERIAL: AtomicU64 = AtomicU64::new(0);

const MANIFEST: &str = "schema = \"semaprax.manifest.v1\"\n\n[package]\nname = \"public-generic-provider\"\nversion = \"1.0.0\"\nprofile = \"public-generic-wasm-provider.v1\"\n\n[modules]\nentry = \"provider.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\ntests = [\"provider.tests\"]\n\n[exports]\nweb = [\"provider.transform\"]\n";

const APP: &str = r#"module provider.app;

@id("provider.leaf")
record Leaf {
    @id("provider.leaf.head")
    head: Bytes,
    @id("provider.leaf.tail")
    tail: Bytes,
}

@id("provider.envelope")
record Envelope<T> {
    @id("provider.envelope.payload")
    payload: T,
    @id("provider.envelope.marker")
    marker: i64,
}

@id("provider.transform")
fn transform(value: own Envelope<Leaf>) -> Envelope<Leaf> { value }

@id("provider.app.main")
fn main() -> i64 { 0 }
"#;

const TESTS: &str = r#"module provider.tests;

@id("provider.tests.main")
fn main() -> i64 { 0 }
"#;

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str, manifest: &str, app: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "semaprax-public-generic-provider-{label}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("semaprax.toml"), manifest).unwrap();
        write_canonical(&root.join("src/app.spx"), app);
        write_canonical(&root.join("src/tests.spx"), TESTS);
        Self(root.canonicalize().unwrap())
    }

    fn manifest(&self) -> PathBuf {
        self.0.join("semaprax.toml")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_canonical(path: &Path, source: &str) {
    let parsed = semaprax::parse(source, path).unwrap();
    fs::write(path, semaprax::format::canonical(&parsed)).unwrap();
}

#[test]
fn package_manifest_selects_one_separate_v20_provider_contract() {
    let manifest = ProjectManifest::parse(MANIFEST).unwrap();
    assert_eq!(manifest.manifest_schema(), PACKAGE_MANIFEST_SCHEMA);
    assert_eq!(manifest.schema(), PROJECT_SCHEMA_V20);
    assert_eq!(manifest.layout(), ManifestLayout::Tables);
    assert_eq!(
        manifest.project_profile(),
        ProjectProfile::PublicGenericWasmProviderV1
    );
    assert_eq!(manifest.web_exports(), ["provider.transform"]);
    assert!(manifest.capabilities().is_empty());
    assert!(manifest.command().is_none());
    assert_eq!(manifest.to_canonical_toml(), MANIFEST);
}

#[test]
fn checked_generic_endpoint_is_retained_replayed_and_lock_bound() {
    let fixture = Fixture::new("admitted", MANIFEST, APP);
    with_authenticated_project(&fixture.manifest(), |snapshot| {
        snapshot.check()?;
        let endpoint = snapshot.public_generic_wasm_provider_endpoint_v1()?;
        let replayed = snapshot
            .retain_revision()
            .public_generic_wasm_provider_endpoint_v1()?;

        assert_eq!(endpoint.export_id(), "provider.transform");
        assert_eq!(endpoint.export_name(), "transform");
        assert_eq!(endpoint.descriptor_bytes(), replayed.descriptor_bytes());
        assert_eq!(
            endpoint.descriptor().descriptor_digest(),
            replayed.descriptor().descriptor_digest()
        );
        assert_eq!(endpoint.subject().input().owned_leaves.len(), 2);
        assert_eq!(endpoint.subject().settlement().obligations().len(), 2);
        assert_eq!(
            endpoint.subject().input().term,
            endpoint.subject().result().term
        );

        let lock: serde_json::Value =
            serde_json::from_str(&render_project_lock(snapshot)?).unwrap();
        assert_eq!(lock["payload"]["package"]["contract"], PROJECT_SCHEMA_V20);
        assert_eq!(
            lock["payload"]["package"]["profile"],
            "public-generic-wasm-provider.v1"
        );
        assert_eq!(
            lock["payload"]["interface"]["kind"],
            "public-generic-wasm-provider.v1"
        );
        assert_eq!(
            lock["payload"]["interface"]["digest"],
            endpoint.descriptor().descriptor_digest()
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn every_artifact_route_fails_closed_without_creating_output() {
    let fixture = Fixture::new("closed", MANIFEST, APP);
    with_authenticated_project(&fixture.manifest(), |snapshot| {
        let inline = snapshot.build_web_inline(16 * 1024 * 1024).unwrap_err();
        assert_eq!(inline[0].code, "SPX-W120");
        assert_eq!(
            inline[0].message,
            "public-generic-wasm-provider.v1 has no Core Wasm provider emitter yet"
        );
        let npm_inline = snapshot.build_npm_inline(16 * 1024 * 1024).unwrap_err();
        assert_eq!(npm_inline[0].code, "SPX-W120");
        assert_eq!(
            npm_inline[0].message,
            "public-generic-wasm-provider.v1 has no npm/package provider route yet"
        );

        for (name, errors) in [
            (
                "web",
                snapshot.build_web(&fixture.0.join("web")).unwrap_err(),
            ),
            (
                "npm",
                snapshot.build_npm(&fixture.0.join("npm")).unwrap_err(),
            ),
            (
                "native",
                snapshot
                    .build_native(&fixture.0.join("native"))
                    .unwrap_err(),
            ),
        ] {
            assert_eq!(errors.len(), 1, "{name}: {errors:#?}");
            assert!(
                errors[0]
                    .message
                    .contains("public-generic-wasm-provider.v1"),
                "{name}: {}",
                errors[0]
            );
            assert!(!fixture.0.join(name).exists(), "{name} mutated output");
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn wrong_export_count_and_non_generic_shape_are_rejected_before_revision() {
    let no_export = MANIFEST.replace("web = [\"provider.transform\"]", "web = []");
    let fixture = Fixture::new("no-export", &no_export, APP);
    let errors = with_authenticated_project(&fixture.manifest(), |_snapshot| Ok(())).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].code, "SPX-J100");

    let two_exports = MANIFEST.replace(
        "web = [\"provider.transform\"]",
        "web = [\"provider.transform\", \"provider.transform-again\"]",
    );
    let two_export_app = APP.replace(
        "@id(\"provider.app.main\")",
        "@id(\"provider.transform-again\")\nfn transform_again(value: own Envelope<Leaf>) -> Envelope<Leaf> { value }\n\n@id(\"provider.app.main\")",
    );
    let fixture = Fixture::new("two-exports", &two_exports, &two_export_app);
    let errors = with_authenticated_project(&fixture.manifest(), |_snapshot| Ok(())).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].code, "SPX-J105");

    let scalar_app = APP.replace(
        "fn transform(value: own Envelope<Leaf>) -> Envelope<Leaf> { value }",
        "fn transform(value: i64) -> i64 { value }",
    );
    let fixture = Fixture::new("scalar", MANIFEST, &scalar_app);
    let errors = with_authenticated_project(&fixture.manifest(), |_snapshot| Ok(())).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert_eq!(errors[0].code, "SPX-PG706");
}

#[test]
fn checked_program_drift_changes_the_bound_descriptor_identity() {
    let first = Fixture::new("drift-a", MANIFEST, APP);
    let changed = APP.replace("fn main() -> i64 { 0 }", "fn main() -> i64 { 1 }");
    let second = Fixture::new("drift-b", MANIFEST, &changed);
    let identity = |fixture: &Fixture| {
        with_authenticated_project(&fixture.manifest(), |snapshot| {
            let endpoint = snapshot.public_generic_wasm_provider_endpoint_v1()?;
            Ok((
                snapshot.project_revision().to_owned(),
                endpoint.descriptor().descriptor_digest(),
                endpoint.descriptor_bytes().to_vec(),
            ))
        })
        .unwrap()
    };
    let first = identity(&first);
    let second = identity(&second);
    assert_ne!(first.0, second.0);
    assert_ne!(first.1, second.1);
    assert_ne!(first.2, second.2);
}
