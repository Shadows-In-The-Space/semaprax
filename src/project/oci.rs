//! Glue between the compiler's Project v1 scalar Web build envelope and the
//! standalone, dependency-inverted `semaprax-oci-package` crate.
//!
//! This module owns no OCI rendering or publication logic itself -- that
//! authority lives entirely in `semaprax-oci-package`, which knows neither
//! HIR nor Project manifests. This module's only job is to independently
//! replay an already-produced [`ProjectWebBuild`] envelope, extract its
//! identity and `app.wasm` artifact, and hand them across that boundary
//! exactly as received. See `docs/OCI-DEPLOYABLE-ARTIFACT-V1.md`.

use std::path::Path;

use serde_json::Value;

use crate::diagnostic::Diagnostic;
use crate::wasm::ProjectWebBuild;

fn error(code: &'static str, message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(code, message.into())
}

/// Independently replay `build`, extract the Project v1 identity and the
/// `app.wasm` artifact bytes from its canonical envelope, and publish the
/// deterministic OCI Image Layout at `output`.
pub(super) fn build_and_publish(
    build: &ProjectWebBuild,
    output: &Path,
) -> Result<semaprax_oci_package::OciBundle, Diagnostic> {
    build.verify().map_err(|_| {
        error(
            "SPX-J143",
            "OCI packaging input failed independent Web build replay",
        )
    })?;
    let envelope: Value = serde_json::from_str(build.envelope())
        .map_err(|_| error("SPX-J143", "OCI packaging input envelope is not valid JSON"))?;
    let object = envelope
        .as_object()
        .ok_or_else(|| error("SPX-J143", "OCI packaging input envelope is not one JSON object"))?;

    let text = |key: &str| -> Result<String, Diagnostic> {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                error(
                    "SPX-J143",
                    format!("OCI packaging input envelope is missing `{key}`"),
                )
            })
    };
    let project_name = text("project")?;
    let project_revision = text("project_revision")?;
    let workspace_revision = text("workspace_revision")?;
    let project_graph_digest = text("project_graph_digest")?;
    let entry_module = text("entry_module")?;

    let artifacts = object
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| error("SPX-J143", "OCI packaging input envelope is missing `artifacts`"))?;
    let wasm_artifact = artifacts
        .first()
        .and_then(Value::as_object)
        .filter(|artifact| artifact.get("path").and_then(Value::as_str) == Some("app.wasm"))
        .ok_or_else(|| {
            error(
                "SPX-J143",
                "OCI packaging input envelope's first artifact is not `app.wasm`",
            )
        })?;
    let content_hex = wasm_artifact
        .get("content_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "SPX-J143",
                "OCI packaging input envelope's app.wasm artifact carries no content",
            )
        })?;
    let wasm_bytes = decode_lowercase_hex(content_hex).ok_or_else(|| {
        error(
            "SPX-J143",
            "OCI packaging input envelope's app.wasm content is not lowercase hex",
        )
    })?;
    let wasm_sha256 = wasm_artifact
        .get("sha256")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            error(
                "SPX-J143",
                "OCI packaging input envelope's app.wasm artifact carries no sha256",
            )
        })?;

    let plan = semaprax_oci_package::OciPlan {
        project_name,
        project_revision,
        workspace_revision,
        project_graph_digest,
        entry_module,
        wasm_bytes,
        wasm_sha256,
    };
    semaprax_oci_package::build_and_publish(plan, output)
        .map_err(|_| error("SPX-J144", "OCI artifact publication failed"))
}

fn decode_lowercase_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let raw = value.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    let mut index = 0;
    while index < raw.len() {
        let high = hex_nibble(raw[index])?;
        let low = hex_nibble(raw[index + 1])?;
        bytes.push((high << 4) | low);
        index += 2;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::project::with_authenticated_project;

    static SERIAL: AtomicU64 = AtomicU64::new(0);

    /// A minimal Project v1 scalar-profile fixture: one entry closure and
    /// one test closure, nothing else. `oci` packaging only admits this
    /// profile today.
    fn scalar_fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "semaprax-oci-glue-{name}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        let app_source =
            format!("module {name}.app;\n@id(\"app.main\") fn main() -> i64 {{ 0 }}\n");
        let tests_source =
            format!("module {name}.tests;\n@id(\"tests.main\") fn main() -> i64 {{ 0 }}\n");
        for (file, source) in [
            ("app.spx", app_source.as_str()),
            ("tests.spx", tests_source.as_str()),
        ] {
            let parsed = crate::parse(source, root.join("src").join(file)).unwrap();
            std::fs::write(
                root.join("src").join(file),
                crate::format::canonical(&parsed),
            )
            .unwrap();
        }
        std::fs::write(
            root.join("semaprax.toml"),
            format!(
                "schema = \"semaprax.project.v1\"\nname = \"{name}\"\nentry = \"{name}.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\nweb_exports = [\"app.main\"]\ntests = [\"{name}.tests\"]\n"
            ),
        )
        .unwrap();
        root
    }

    /// Would fail if the emitter dropped a required layout file, wrote fewer
    /// or more than one manifest entry into `index.json`, or if the
    /// `src/project/oci.rs` glue silently swallowed a real project's Wasm
    /// build instead of packaging it.
    #[test]
    fn scalar_project_publishes_a_structurally_valid_oci_layout() {
        let root = scalar_fixture("ocilayout");
        let output = root.join("oci-out");
        with_authenticated_project(&root.join("semaprax.toml"), |snapshot| {
            snapshot.build_oci(&output)
        })
        .unwrap();
        assert!(output.join("oci-layout").is_file());
        assert!(output.join("index.json").is_file());
        assert!(output.join("blobs").join("sha256").is_dir());
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["manifests"].as_array().unwrap().len(), 1);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Would fail if the `ScalarV1`-only gate in `ProjectSnapshot::build_oci`
    /// were removed or bypassed: a v8 owned-data-api.v1 project must be
    /// refused with `SPX-J142` before any Wasm build or filesystem write is
    /// attempted, not packaged as if it were scalar.
    #[test]
    fn non_scalar_project_is_refused_before_any_packaging() {
        let root = scalar_fixture("ocinonscalar");
        std::fs::write(
            root.join("semaprax.toml"),
            "schema = \"semaprax.project.v8\"\nname = \"ocinonscalar\"\nversion = \"1.0.0\"\nprofile = \"owned-data-api.v1\"\nentry = \"ocinonscalar.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\nweb_exports = [\"api.value\"]\ntests = [\"ocinonscalar.tests\"]\n",
        )
        .unwrap();
        let app_source = "module ocinonscalar.app;\n@id(\"api.value\") fn value(input: borrow Slice<u8>) -> Bytes { bytes_copy(input) }\n@id(\"app.main\") fn main() -> i64 { 0 }\n";
        let parsed = crate::parse(app_source, root.join("src/app.spx")).unwrap();
        std::fs::write(
            root.join("src/app.spx"),
            crate::format::canonical(&parsed),
        )
        .unwrap();
        let output = root.join("oci-out");
        let errors = with_authenticated_project(&root.join("semaprax.toml"), |snapshot| {
            snapshot.build_oci(&output)
        })
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "SPX-J142");
        assert!(!output.exists());
        std::fs::remove_dir_all(&root).ok();
    }
}
