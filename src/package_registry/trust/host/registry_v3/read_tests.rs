use super::*;

fn request<'a>(f: &'a Fixture, digest: &'a str) -> ArtifactRead<'a, 'a> {
    ArtifactRead {
        expected_generation_digest: digest,
        lock: &f.admitted.2,
        registry: &f.admitted.0,
        package: "app.root",
        version: "1.0.0",
        path: "module.wasm",
        trusted_time: 101,
    }
}

#[test]
fn read_returns_exact_root_leaf_bytes_and_bound_evidence_without_writes() {
    let f = Fixture::new(false, 1);
    let temp = Temp::new();
    let publishers = f.publishers();
    let artifacts = f.artifacts();
    let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
    let digest = store
        .commit_update(&f.update(&publishers, &artifacts))
        .unwrap()
        .generation_digest;
    let before = inventory(&temp);
    for (package, bytes) in [("app.root", &f.admitted.3), ("lib.leaf", &f.admitted.4)] {
        let mut read = request(&f, &digest);
        read.package = package;
        let result = store.read_artifact(&read).unwrap();
        assert_eq!(result.bytes(), bytes);
        assert_eq!(result.generation_digest(), digest);
        assert_eq!(result.lock_digest(), hash(f.admitted.2.as_bytes()));
        assert_eq!(result.artifact_digest(), hash(bytes));
        assert_eq!(result.package(), package);
        assert_eq!(result.version(), "1.0.0");
        assert_eq!(result.path(), "module.wasm");
        assert_eq!(result.verified_at(), 101);
        assert_eq!(result.into_bytes(), *bytes);
    }
    assert_eq!(inventory(&temp), before);
}

#[test]
fn wrong_generation_lock_coordinate_path_registry_and_stale_time_refuse() {
    let f = Fixture::new(false, 1);
    let yanked = Fixture::new(true, 1);
    let temp = Temp::new();
    let publishers = f.publishers();
    let artifacts = f.artifacts();
    let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
    let digest = store
        .commit_update(&f.update(&publishers, &artifacts))
        .unwrap()
        .generation_digest;
    let before = inventory(&temp);
    for mode in 0..8 {
        let mut read = request(&f, &digest);
        match mode {
            0 => read.expected_generation_digest = "sha256:wrong",
            1 => read.lock = "{}",
            2 => read.package = "unknown.package",
            3 => read.version = "2.0.0",
            4 => read.path = "../module.wasm",
            5 => read.registry = &yanked.admitted.0,
            6 => read.trusted_time = 99,
            _ => read.trusted_time = f.expired_time(),
        };
        code(
            store.read_artifact(&read),
            if mode >= 6 {
                "SPX-PKR623"
            } else {
                "SPX-PKR626"
            },
        );
    }
    assert_eq!(inventory(&temp), before);
}

#[test]
fn stored_byte_tamper_and_active_symlink_never_return_bytes() {
    let f = Fixture::new(false, 1);
    let publishers = f.publishers();
    let artifacts = f.artifacts();
    for mode in 0..2 {
        let temp = Temp::new();
        let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
        let digest = store
            .commit_update(&f.update(&publishers, &artifacts))
            .unwrap()
            .generation_digest;
        let active = std::fs::read_to_string(temp.0.join("ACTIVE")).unwrap();
        if mode == 0 {
            std::fs::write(temp.0.join(active), b"tampered").unwrap();
        } else {
            std::fs::remove_file(temp.0.join("ACTIVE")).unwrap();
            symlink(active, temp.0.join("ACTIVE")).unwrap();
        }
        assert!(store.read_artifact(&request(&f, &digest)).is_err());
    }
}

#[test]
fn final_active_and_generation_recheck_precedes_any_returned_bytes() {
    let f = Fixture::new(false, 1);
    let publishers = f.publishers();
    let artifacts = f.artifacts();
    for tamper_generation in [false, true] {
        let temp = Temp::new();
        let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
        let old_active = std::fs::read(temp.0.join("ACTIVE")).unwrap();
        let digest = store
            .commit_update(&f.update(&publishers, &artifacts))
            .unwrap()
            .generation_digest;
        let active = std::fs::read_to_string(temp.0.join("ACTIVE")).unwrap();
        let directory = temp.0.clone();
        super::super::read::BEFORE_RELEASE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                if tamper_generation {
                    std::fs::write(directory.join(active), b"changed after verification").unwrap();
                } else {
                    std::fs::write(directory.join("ACTIVE"), old_active).unwrap();
                }
            }))
        });
        assert!(store.read_artifact(&request(&f, &digest)).is_err());
    }
}

#[test]
fn current_rotated_root_replays_and_old_generation_pin_is_revoked() {
    let mut f = Fixture::new(false, 1);
    let temp = Temp::new();
    let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
    let old = store
        .commit_update(&f.update(&f.publishers(), &f.artifacts()))
        .unwrap()
        .generation_digest;
    let (rotation, timestamp, snapshot, publishers, admitted) = host_rotation_fixture();
    f.timestamp = timestamp;
    f.snapshot = snapshot;
    f.publishers = publishers;
    f.admitted = admitted;
    let publishers = f.publishers();
    let artifacts = f.artifacts();
    let mut update = f.update(&publishers, &artifacts);
    update.rotation = Some(&rotation);
    let current = store.commit_update(&update).unwrap().generation_digest;
    code(store.read_artifact(&request(&f, &old)), "SPX-PKR626");
    assert_eq!(
        store.read_artifact(&request(&f, &current)).unwrap().bytes(),
        f.admitted.3
    );
}

#[test]
fn bootstrap_and_interrupted_update_do_not_grant_reads() {
    let f = Fixture::new(false, 1);
    let temp = Temp::new();
    let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
    assert!(store
        .read_artifact(&request(&f, &store.receipt().generation_digest))
        .is_err());
    let digest = store
        .commit_update(&f.update(&f.publishers(), &f.artifacts()))
        .unwrap()
        .generation_digest;
    let higher = Fixture::new(false, 2);
    FAIL.with(|fail| fail.set(Some(Point::Staged)));
    code(
        store.commit_update(&higher.update(&higher.publishers(), &higher.artifacts())),
        "SPX-PKR627",
    );
    assert!(store.read_artifact(&request(&f, &digest)).is_err());
}
