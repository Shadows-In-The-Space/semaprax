use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::project::with_authenticated_project;

static NEXT: AtomicU64 = AtomicU64::new(0);

const MANIFEST: &str = "schema = \"semaprax.manifest.v1\"\n\n[package]\nname = \"public-generic-component\"\nversion = \"1.0.0\"\nprofile = \"public-generic-wasm-provider.v1\"\n\n[modules]\nentry = \"provider.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\ntests = [\"provider.tests\"]\n\n[exports]\nweb = [\"provider.transform\"]\n";

const APP: &str = r#"module provider.app;

@id("provider.leaf-pair")
record LeafPair {
    @id("provider.leaf-pair.left")
    left: Bytes,
    @id("provider.leaf-pair.right")
    right: Bytes,
}

@id("provider.envelope")
record Envelope<T> {
    @id("provider.envelope.payload")
    payload: T,
}

@id("provider.transform")
fn transform(value: own Envelope<LeafPair>) -> Envelope<LeafPair> {
    Envelope<LeafPair> { payload: LeafPair { left: value.payload.right, right: value.payload.left } }
}

@id("provider.main")
fn main() -> i64 { 0 }
"#;

const TESTS: &str =
    "module provider.tests;\n\n@id(\"provider.tests.main\")\nfn main() -> i64 { 0 }\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "semaprax-public-generic-component-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("semaprax.toml"), MANIFEST).unwrap();
        write_canonical(&root.join("src/app.spx"), APP);
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
fn retained_component_replays_deterministically_and_rejects_tampered_identity() {
    let fixture = Fixture::new();
    with_authenticated_project(&fixture.manifest(), |snapshot| {
        let revision = snapshot.retain_revision();
        let first = revision.public_generic_wasm_component_artifact_v1()?;
        let second = revision.public_generic_wasm_component_artifact_v1()?;
        assert_eq!(first.bytes(), second.bytes());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.descriptor_digest(), second.descriptor_digest());
        assert_eq!(first.provider_digest(), second.provider_digest());

        let replayed = revision.replay_public_generic_wasm_component_v1(
            first.bytes(),
            first.digest(),
            first.descriptor_digest(),
            first.provider_digest(),
        )?;
        assert_eq!(replayed, first);

        let mut changed_component = first.bytes().to_vec();
        let final_byte = changed_component
            .last_mut()
            .expect("component artifact must be nonempty");
        *final_byte ^= 1;
        let component_error = revision
            .replay_public_generic_wasm_component_v1(
                &changed_component,
                first.digest(),
                first.descriptor_digest(),
                first.provider_digest(),
            )
            .unwrap_err();
        assert_eq!(component_error[0].code, "SPX-W121");

        let binding_metadata = format!("{}-changed", first.provider_digest());
        let binding_error = revision
            .replay_public_generic_wasm_component_v1(
                first.bytes(),
                first.digest(),
                first.descriptor_digest(),
                &binding_metadata,
            )
            .unwrap_err();
        assert_eq!(binding_error[0].code, "SPX-W121");
        Ok(())
    })
    .unwrap();
}

#[test]
fn retained_component_refuses_source_drift_before_runtime_and_accepts_new_revision() {
    let fixture = Fixture::new();
    let prior = with_authenticated_project(&fixture.manifest(), |snapshot| {
        snapshot.check()?;
        snapshot
            .retain_revision()
            .public_generic_wasm_component_artifact_v1()
    })
    .unwrap();

    let drifted = APP.replace(
        "Envelope<LeafPair> { payload: LeafPair { left: value.payload.right, right: value.payload.left } }",
        "value",
    );
    assert_ne!(
        drifted, APP,
        "the fixture mutation must change checked source"
    );
    write_canonical(&fixture.0.join("src/app.spx"), &drifted);
    with_authenticated_project(&fixture.manifest(), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();
        let error = revision
            .replay_public_generic_wasm_component_v1(
                prior.bytes(),
                prior.digest(),
                prior.descriptor_digest(),
                prior.provider_digest(),
            )
            .unwrap_err();
        assert_eq!(error[0].code, "SPX-W121");

        let current = revision.public_generic_wasm_component_artifact_v1()?;
        assert_ne!(current.bytes(), prior.bytes());
        assert_eq!(
            revision.replay_public_generic_wasm_component_v1(
                current.bytes(),
                current.digest(),
                current.descriptor_digest(),
                current.provider_digest(),
            )?,
            current
        );
        Ok(())
    })
    .unwrap();
}
