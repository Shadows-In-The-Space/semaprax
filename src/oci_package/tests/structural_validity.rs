//! Assert the artifact is structurally valid OCI, not merely that some bytes
//! landed on disk: the required files exist, the layout version is the real
//! OCI one, and every digest relationship (blob filename, config/layer size
//! and digest as recorded in the manifest, manifest digest as recorded in
//! the index) actually holds when independently recomputed from the bytes on
//! disk.

use std::fs;

use sha2::{Digest, Sha256};

use super::{fixture_plan, fresh_output_dir, TEST_LOCK};
use crate::oci_package::build_and_publish;

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The four required files/dirs exist with the exact OCI Image Layout
/// marker content. Removing the `oci-layout` write, or getting its bytes
/// wrong, fails this immediately.
#[test]
fn required_layout_files_exist_with_the_real_oci_marker() {
    let _guard = TEST_LOCK.lock().unwrap();
    let out = fresh_output_dir("structural-required-files");
    build_and_publish(fixture_plan(), &out).expect("build");

    assert!(out.join("index.json").is_file());
    assert!(out.join("blobs").join("sha256").is_dir());
    let layout_bytes = fs::read(out.join("oci-layout")).expect("oci-layout");
    let layout: serde_json::Value = serde_json::from_slice(&layout_bytes).expect("valid JSON");
    assert_eq!(
        layout.get("imageLayoutVersion").and_then(|v| v.as_str()),
        Some("1.0.0"),
        "oci-layout must carry the real OCI Image Layout version, not a SEMAPRAX-only one"
    );

    fs::remove_dir_all(&out).ok();
}

/// Every digest referenced anywhere in the layout matches the sha256 of the
/// bytes actually stored at that digest's blob path, and every blob's
/// filename equals its own content's digest. A broken renderer that wrote
/// the wrong digest into `index.json`, or that named a blob file after the
/// wrong content, fails one of these assertions.
#[test]
fn every_digest_relationship_holds_against_bytes_on_disk() {
    let _guard = TEST_LOCK.lock().unwrap();
    let out = fresh_output_dir("structural-digest-relationships");
    let bundle = build_and_publish(fixture_plan(), &out).expect("build");

    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index.json"))
            .expect("index.json is valid JSON");
    let manifests = index["manifests"].as_array().expect("manifests array");
    assert_eq!(manifests.len(), 1, "exactly one manifest entry");
    let manifest_entry = &manifests[0];
    let manifest_digest = manifest_entry["digest"].as_str().expect("manifest digest");
    assert_eq!(manifest_digest, bundle.manifest_digest());

    let blobs_dir = out.join("blobs").join("sha256");
    let manifest_blob_path = blobs_dir.join(manifest_digest.trim_start_matches("sha256:"));
    let manifest_bytes =
        fs::read(&manifest_blob_path).expect("manifest blob present at its own digest name");
    assert_eq!(
        format!("sha256:{}", hex_sha256(&manifest_bytes)),
        manifest_digest
    );
    assert_eq!(
        manifest_entry["size"].as_u64(),
        Some(manifest_bytes.len() as u64)
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("manifest blob is valid JSON");
    assert_eq!(manifest["schemaVersion"].as_u64(), Some(2));

    let config = &manifest["config"];
    let config_digest = config["digest"].as_str().expect("config digest");
    assert_eq!(config_digest, bundle.config_digest());
    let config_bytes = fs::read(blobs_dir.join(config_digest.trim_start_matches("sha256:")))
        .expect("config blob present at its own digest name");
    assert_eq!(
        format!("sha256:{}", hex_sha256(&config_bytes)),
        config_digest
    );
    assert_eq!(config["size"].as_u64(), Some(config_bytes.len() as u64));

    let layers = manifest["layers"].as_array().expect("layers array");
    assert_eq!(layers.len(), 1, "exactly one content layer: no base layer");
    let layer_digest = layers[0]["digest"].as_str().expect("layer digest");
    assert_eq!(layer_digest, bundle.layer_digest());
    let layer_bytes = fs::read(blobs_dir.join(layer_digest.trim_start_matches("sha256:")))
        .expect("layer blob present at its own digest name");
    assert_eq!(format!("sha256:{}", hex_sha256(&layer_bytes)), layer_digest);
    assert_eq!(layers[0]["size"].as_u64(), Some(layer_bytes.len() as u64));
    assert_eq!(layer_bytes, super::fixture_wasm());

    fs::remove_dir_all(&out).ok();
}

/// The manifest's `artifactType` marks this as a SEMAPRAX deployable
/// artifact, not a runnable OCI image: a consumer must not attempt to
/// interpret the config blob as an OCI Image Configuration or expect a
/// runnable rootfs. Losing this field would make the artifact
/// indistinguishable from (and silently misinterpretable as) a real image.
#[test]
fn manifest_declares_the_artifact_type_and_no_runnable_image_claim() {
    let _guard = TEST_LOCK.lock().unwrap();
    let out = fresh_output_dir("structural-artifact-type");
    build_and_publish(fixture_plan(), &out).expect("build");

    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index.json")).unwrap();
    let manifest_digest = index["manifests"][0]["digest"].as_str().unwrap();
    let manifest_bytes = fs::read(
        out.join("blobs")
            .join("sha256")
            .join(manifest_digest.trim_start_matches("sha256:")),
    )
    .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        manifest["artifactType"].as_str(),
        Some(crate::oci_package::ARTIFACT_TYPE)
    );

    let config_digest = manifest["config"]["digest"].as_str().unwrap();
    let config_bytes = fs::read(
        out.join("blobs")
            .join("sha256")
            .join(config_digest.trim_start_matches("sha256:")),
    )
    .unwrap();
    let config: serde_json::Value = serde_json::from_slice(&config_bytes).unwrap();
    let nonclaims: Vec<&str> = config["nonclaims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(nonclaims.contains(&"not_a_runnable_container_image"));
    assert!(nonclaims.contains(&"no_base_layer"));
    assert!(nonclaims.contains(&"unsigned"));

    fs::remove_dir_all(&out).ok();
}
