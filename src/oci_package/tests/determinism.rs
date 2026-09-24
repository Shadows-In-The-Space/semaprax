//! Determinism is the invariant this whole lane rests on. Each test here
//! would fail if any emitted byte depended on wall-clock time, process
//! order, or the output path.

use std::fs;

use super::{fixture_plan, fresh_output_dir, TEST_LOCK};
use crate::oci_package::build_and_publish;

/// The three things a byte-identical emission must reproduce exactly:
/// `oci-layout` bytes, `index.json` bytes, and every blob as
/// `(digest filename, bytes)`. The blob filenames are the digests themselves,
/// so naming this type keeps that meaning attached to it.
type LayoutBytes = (Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>);

fn read_layout(dir: &std::path::Path) -> LayoutBytes {
    let oci_layout = fs::read(dir.join("oci-layout")).expect("oci-layout");
    let index = fs::read(dir.join("index.json")).expect("index.json");
    let blobs_dir = dir.join("blobs").join("sha256");
    let mut blobs: Vec<(String, Vec<u8>)> = fs::read_dir(&blobs_dir)
        .expect("blobs/sha256 directory")
        .map(|entry| {
            let entry = entry.expect("directory entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("blob bytes");
            (name, bytes)
        })
        .collect();
    blobs.sort_by(|a, b| a.0.cmp(&b.0));
    (oci_layout, index, blobs)
}

/// Two emissions from an identical plan, into two different output
/// directories, must produce byte-identical `oci-layout`, `index.json`, and
/// every blob -- including the blob filenames, which are the digests
/// themselves. If a `created` timestamp, a random nonce, or path-derived
/// content ever leaked into a rendered file, this test would start failing
/// the moment two runs landed in a microsecond apart.
#[test]
fn two_emissions_of_the_same_plan_are_byte_identical() {
    let _guard = TEST_LOCK.lock().unwrap();
    let out_a = fresh_output_dir("determinism-a");
    let out_b = fresh_output_dir("determinism-b");

    let bundle_a = build_and_publish(fixture_plan(), &out_a).expect("first emission");
    // A real wall-clock gap between the two emissions is the whole point of
    // this test: it is the one thing a timestamp-based non-determinism bug
    // would expose.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let bundle_b = build_and_publish(fixture_plan(), &out_b).expect("second emission");

    assert_eq!(bundle_a.manifest_digest(), bundle_b.manifest_digest());
    assert_eq!(bundle_a.config_digest(), bundle_b.config_digest());
    assert_eq!(bundle_a.layer_digest(), bundle_b.layer_digest());
    assert_eq!(
        bundle_a.index_manifest_digest(),
        bundle_b.index_manifest_digest()
    );

    let (layout_a, index_a, blobs_a) = read_layout(&out_a);
    let (layout_b, index_b, blobs_b) = read_layout(&out_b);
    assert_eq!(layout_a, layout_b);
    assert_eq!(index_a, index_b);
    assert_eq!(blobs_a, blobs_b);

    fs::remove_dir_all(&out_a).ok();
    fs::remove_dir_all(&out_b).ok();
}

/// Changing one identity field (here, the entry module) must change the
/// rendered config blob and therefore every digest downstream of it. This
/// is the complementary check to same-input-same-output: it would catch an
/// emitter that silently ignored part of the plan.
#[test]
fn changing_the_plan_changes_the_digest() {
    let _guard = TEST_LOCK.lock().unwrap();
    let out_a = fresh_output_dir("determinism-distinct-a");
    let out_b = fresh_output_dir("determinism-distinct-b");

    let mut plan_b = fixture_plan();
    plan_b.entry_module = "calculator.other_entry".to_owned();

    let bundle_a = build_and_publish(fixture_plan(), &out_a).expect("first emission");
    let bundle_b = build_and_publish(plan_b, &out_b).expect("second emission");

    assert_ne!(bundle_a.config_digest(), bundle_b.config_digest());
    assert_ne!(bundle_a.manifest_digest(), bundle_b.manifest_digest());

    fs::remove_dir_all(&out_a).ok();
    fs::remove_dir_all(&out_b).ok();
}
