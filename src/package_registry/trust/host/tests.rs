use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use unix::{Point, FAIL};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "semaprax-registry-trust-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn code<T>(result: Result<T>, expected: &str) {
    match result {
        Ok(_) => panic!("unexpected acceptance"),
        Err(error) => assert_eq!(error.code, expected),
    }
}
fn setup() -> (Temp, String, String) {
    let root = super::super::tests::host_fixture(false).0;
    let pin = hash(root.as_bytes());
    (Temp::new(), root, pin)
}

#[test]
fn bootstrap_pin_private_paths_and_exclusive_lock() {
    let (temp, root, pin) = setup();
    code(
        HeldTrustStore::install(&temp.0, &root, "sha256:wrong", 100),
        "SPX-PKR626",
    );
    assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 0);
    let store = HeldTrustStore::install(&temp.0, &root, &pin, 100).unwrap();
    code(HeldTrustStore::open(&temp.0, &pin), "SPX-PKR626");
    drop(store);
    code(
        HeldTrustStore::install(&temp.0, &root, &pin, 100),
        "SPX-PKR626",
    );
    assert!(HeldTrustStore::open(&temp.0, &pin).is_ok());
    let parent = Temp::new();
    symlink(&temp.0, parent.0.join("alias")).unwrap();
    code(
        HeldTrustStore::open(&parent.0.join("alias"), &pin),
        "SPX-PKR626",
    );
    std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o750)).unwrap();
    code(HeldTrustStore::open(&temp.0, &pin), "SPX-PKR626");
}

#[test]
fn exact_update_survives_reopen_and_rejects_stale_time_and_cache_without_lock() {
    let (temp, root, pin) = setup();
    let mut store = HeldTrustStore::install(&temp.0, &root, &pin, 90).unwrap();
    let (_, timestamp, snapshot, publisher, registry, entry) =
        super::super::tests::host_fixture(false);
    let publishers = [("publisher", publisher.as_str())];
    let entries = [entry];
    let mut update = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: None,
        lock: None,
        subjects: &[],
        artifacts: &[],
        trusted_time: 100,
    };
    let receipt = store.commit_update(&update).unwrap();
    let exact_checkpoint = string(&store.generation.value["checkpoint"]).unwrap();
    assert_eq!(receipt.checkpoint_digest, hash(exact_checkpoint.as_bytes()));
    drop(store);
    let mut store = HeldTrustStore::open(&temp.0, &pin).unwrap();
    assert_eq!(store.receipt().generation_digest, receipt.generation_digest);
    let before = store.held.inventory().unwrap();
    update.trusted_time = 99;
    code(store.commit_update(&update), "SPX-PKR623");
    update.trusted_time = 300;
    code(store.commit_update(&update), "SPX-PKR623");
    update.trusted_time = 101;
    let subjects = [entries[0].publication().subject_bytes.clone()];
    update.subjects = &subjects;
    code(store.commit_update(&update), "SPX-PKR626");
    assert_eq!(before, store.held.inventory().unwrap());
}

#[test]
fn complete_bootstrap_crash_points_recover_exactly_and_partial_write_stays_failed() {
    for point in [
        Point::PartialWrite,
        Point::Staged,
        Point::Generation,
        Point::BeforeActive,
        Point::AfterActive,
    ] {
        let (temp, root, pin) = setup();
        FAIL.with(|fail| fail.set(Some(point)));
        code(
            HeldTrustStore::install(&temp.0, &root, &pin, 100),
            "SPX-PKR627",
        );
        assert!(HeldTrustStore::open(&temp.0, &pin).is_err());
        let before = std::fs::read_dir(&temp.0).unwrap().count();
        let result = HeldTrustStore::recover_install(&temp.0, &root, &pin, 100, 101);
        if point == Point::PartialWrite {
            code(result, "SPX-PKR627");
            assert_eq!(before, std::fs::read_dir(&temp.0).unwrap().count());
        } else {
            let store = result.unwrap();
            let digest = store.receipt().generation_digest;
            drop(store);
            assert_eq!(
                HeldTrustStore::open(&temp.0, &pin)
                    .unwrap()
                    .receipt()
                    .generation_digest,
                digest
            );
        }
    }
}

#[test]
fn interrupted_update_requires_exact_request_and_fresh_revalidation() {
    let (temp, root, pin) = setup();
    let mut store = HeldTrustStore::install(&temp.0, &root, &pin, 90).unwrap();
    let previous = store.receipt().generation_digest;
    let (_, timestamp, snapshot, publisher, registry, entry) =
        super::super::tests::host_fixture(false);
    let publishers = [("publisher", publisher.as_str())];
    let entries = [entry];
    let mut update = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: None,
        lock: None,
        subjects: &[],
        artifacts: &[],
        trusted_time: 100,
    };
    FAIL.with(|fail| fail.set(Some(Point::AfterActive)));
    code(store.commit_update(&update), "SPX-PKR627");
    drop(store);
    assert!(HeldTrustStore::open(&temp.0, &pin).is_err());
    update.trusted_time = 101;
    assert!(HeldTrustStore::recover_update(&temp.0, &pin, &previous, &update, 102).is_err());
    update.trusted_time = 100;
    code(
        HeldTrustStore::recover_update(&temp.0, &pin, &previous, &update, 300),
        "SPX-PKR623",
    );
    let recovered = HeldTrustStore::recover_update(&temp.0, &pin, &previous, &update, 102).unwrap();
    assert_eq!(recovered.generation.checkpoint.observed_time, 100);
    drop(recovered);
    assert!(HeldTrustStore::open(&temp.0, &pin).is_ok());
}

#[test]
fn generation_tamper_or_active_rollback_is_never_bootstrapped() {
    let (temp, root, pin) = setup();
    let store = HeldTrustStore::install(&temp.0, &root, &pin, 100).unwrap();
    let active = store.active.clone();
    drop(store);
    std::fs::write(temp.0.join(&active), "{}").unwrap();
    code(HeldTrustStore::open(&temp.0, &pin), "SPX-PKR626");
    code(
        HeldTrustStore::install(&temp.0, &root, &pin, 100),
        "SPX-PKR626",
    );
    let (temp, root, pin) = setup();
    let mut store = HeldTrustStore::install(&temp.0, &root, &pin, 90).unwrap();
    let old = store.active.clone();
    let (_, timestamp, snapshot, publisher, registry, entry) =
        super::super::tests::host_fixture(false);
    let publishers = [("publisher", publisher.as_str())];
    let entries = [entry];
    let update = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: None,
        lock: None,
        subjects: &[],
        artifacts: &[],
        trusted_time: 100,
    };
    store.commit_update(&update).unwrap();
    drop(store);
    std::fs::write(temp.0.join("ACTIVE"), old).unwrap();
    code(HeldTrustStore::open(&temp.0, &pin), "SPX-PKR627");
}

#[test]
fn yanked_selected_subject_rejects_before_first_effect() {
    let (temp, root, pin) = setup();
    let mut store = HeldTrustStore::install(&temp.0, &root, &pin, 90).unwrap();
    let (_, timestamp, snapshot, publisher, registry, entry) =
        super::super::tests::host_fixture(true);
    let publishers = [("publisher", publisher.as_str())];
    let subjects = [entry.publication().subject_bytes.clone()];
    let entries = [entry];
    let mut update = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: None,
        lock: Some("{}"),
        subjects: &subjects,
        artifacts: &[],
        trusted_time: 100,
    };
    let before = store.held.inventory().unwrap();
    code(store.commit_update(&update), "SPX-PKR625");
    let artifacts = [Artifact {
        package: "app.main",
        version: "1.0.0",
        path: "module.wasm",
        bytes: b"bad",
    }];
    update.lock = None;
    update.subjects = &[];
    update.artifacts = &artifacts;
    code(store.commit_update(&update), "SPX-PKR625");
    assert_eq!(before, store.held.inventory().unwrap());
}

#[test]
fn real_manifest_artifact_and_checkpoint_commit_together_and_tampering_has_no_effect() {
    let temp = Temp::new();
    let (root, timestamp, snapshot, publisher, registry, entry, wasm) =
        super::super::tests::host_artifact_fixture();
    let pin = hash(root.as_bytes());
    let mut store = HeldTrustStore::install(&temp.0, &root, &pin, 90).unwrap();
    let publishers = [("publisher", publisher.as_str())];
    let entries = [entry];
    let artifacts = [Artifact {
        package: "app.main",
        version: "1.0.0",
        path: "module.wasm",
        bytes: &wasm,
    }];
    let mut update = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: None,
        lock: None,
        subjects: &[],
        artifacts: &artifacts,
        trusted_time: 100,
    };
    let receipt = store.commit_update(&update).unwrap();
    drop(store);
    let mut store = HeldTrustStore::open(&temp.0, &pin).unwrap();
    assert_eq!(store.receipt().generation_digest, receipt.generation_digest);
    assert!(store.generation.value["cache"]["lock"].is_null());
    assert_eq!(store.generation.value["cache"]["subjects"], json!([]));
    let encoded = wasm
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        store.generation.value["cache"]["artifacts"][0]["hex"],
        encoded
    );
    let before = store.held.inventory().unwrap();
    let bad = [Artifact {
        package: "app.main",
        version: "1.0.0",
        path: "module.wasm",
        bytes: b"bad",
    }];
    update.artifacts = &bad;
    code(store.commit_update(&update), "SPX-PKR624");
    assert_eq!(before, store.held.inventory().unwrap());
}

#[test]
fn rotation_provenance_survives_recovery_and_old_root_metadata_is_revoked() {
    let (temp, root, pin) = setup();
    let mut store = HeldTrustStore::install(&temp.0, &root, &pin, 90).unwrap();
    let previous = store.receipt().generation_digest;
    let (rotation, timestamp, snapshot, publisher, registry, entry) =
        super::super::tests::host_rotation_fixture();
    let publishers = [("publisher", publisher.as_str())];
    let entries = [entry];
    let mut update = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: Some(&rotation),
        lock: None,
        subjects: &[],
        artifacts: &[],
        trusted_time: 100,
    };
    let mut missing_old: Value = serde_json::from_str(&rotation).unwrap();
    missing_old["signatures"].as_array_mut().unwrap().remove(0);
    let missing_old = wire(&missing_old);
    update.rotation = Some(&missing_old);
    code(store.commit_update(&update), "SPX-PKR622");
    update.rotation = Some(&rotation);
    FAIL.with(|fail| fail.set(Some(Point::Generation)));
    code(store.commit_update(&update), "SPX-PKR627");
    drop(store);
    update.rotation = None;
    assert!(HeldTrustStore::recover_update(&temp.0, &pin, &previous, &update, 101).is_err());
    update.rotation = Some(&rotation);
    let store = HeldTrustStore::recover_update(&temp.0, &pin, &previous, &update, 101).unwrap();
    assert_eq!(store.generation.root.version, 2);
    assert_eq!(store.generation.value["rotation"], rotation);
    drop(store);
    let mut store = HeldTrustStore::open(&temp.0, &pin).unwrap();
    let (_, timestamp, snapshot, publisher, registry, entry) =
        super::super::tests::host_fixture(false);
    let publishers = [("publisher", publisher.as_str())];
    let entries = [entry];
    let old = Update {
        metadata: UpdateInputs {
            timestamp: &timestamp,
            snapshot: &snapshot,
            publishers: &publishers,
            registry_snapshot: &registry,
            admitted_entries: &entries,
        },
        rotation: None,
        lock: None,
        subjects: &[],
        artifacts: &[],
        trusted_time: 102,
    };
    code(store.commit_update(&old), "SPX-PKR622");
}

#[test]
fn held_path_swap_active_link_and_unknown_recovery_effects_fail_closed() {
    let parent = Temp::new();
    let path = parent.0.join("store");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = super::super::tests::host_fixture(false).0;
    let pin = hash(root.as_bytes());
    let store = HeldTrustStore::install(&path, &root, &pin, 100).unwrap();
    std::fs::rename(&path, parent.0.join("moved")).unwrap();
    std::fs::create_dir(&path).unwrap();
    code(store.recheck(), "SPX-PKR626");
    drop(store);
    let (temp, root, pin) = setup();
    FAIL.with(|fail| fail.set(Some(Point::AfterActive)));
    code(
        HeldTrustStore::install(&temp.0, &root, &pin, 100),
        "SPX-PKR627",
    );
    std::fs::write(temp.0.join("foreign"), b"preserve me").unwrap();
    code(
        HeldTrustStore::recover_install(&temp.0, &root, &pin, 100, 101),
        "SPX-PKR627",
    );
    assert_eq!(
        std::fs::read(temp.0.join("foreign")).unwrap(),
        b"preserve me"
    );
    let (temp, root, pin) = setup();
    FAIL.with(|fail| fail.set(Some(Point::BeforeActive)));
    code(
        HeldTrustStore::install(&temp.0, &root, &pin, 100),
        "SPX-PKR627",
    );
    std::fs::write(temp.0.join("ACTIVE.next"), "wrong-generation").unwrap();
    code(
        HeldTrustStore::recover_install(&temp.0, &root, &pin, 100, 101),
        "SPX-PKR627",
    );
    assert_eq!(
        std::fs::read(temp.0.join("ACTIVE.next")).unwrap(),
        b"wrong-generation"
    );
    let (temp, root, pin) = setup();
    let store = HeldTrustStore::install(&temp.0, &root, &pin, 100).unwrap();
    drop(store);
    std::fs::rename(temp.0.join("ACTIVE"), temp.0.join("real-active")).unwrap();
    symlink("real-active", temp.0.join("ACTIVE")).unwrap();
    code(HeldTrustStore::open(&temp.0, &pin), "SPX-PKR626");
}
