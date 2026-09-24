use super::*;
use crate::package_resolver_v2 as resolver;

fn request<'a>(f: &'a Fixture, digest: &'a str) -> CacheFill<'a, 'a> {
    CacheFill {
        expected_generation_digest: digest,
        lock: &f.admitted.2,
        registry: &f.admitted.0,
        trusted_time: 101,
    }
}
fn setup(f: &Fixture, temp: &Temp) -> (HeldTrustStore, String) {
    let mut store = HeldTrustStore::install(&temp.0, &f.root, &f.pin, 90).unwrap();
    let digest = store
        .commit_update(&f.update(&f.publishers(), &f.artifacts()))
        .unwrap()
        .generation_digest;
    (store, digest)
}
fn name(bytes: &str) -> String {
    let verified = crate::package_lock_v3::verify_dependency_subject(bytes).unwrap();
    format!(
        "{}.json",
        verified.subject_digest.strip_prefix("sha256:").unwrap()
    )
}

#[test]
fn signed_cache_bridge_feeds_real_resolver_reproducing_exact_root_leaf_lock() {
    let f = Fixture::new(false, 1);
    let source = Temp::new();
    let destination = Temp::new();
    let cache = destination.0.join("cache");
    let (store, digest) = setup(&f, &source);
    let before = inventory(&source);
    let receipt = store
        .populate_resolver_cache(&cache, &request(&f, &digest))
        .unwrap();
    assert_eq!(receipt.generation_digest, digest);
    assert_eq!(receipt.lock_digest, hash(f.admitted.2.as_bytes()));
    assert_eq!(receipt.subjects.len(), 2);
    assert!(receipt.subjects.iter().all(|row| !row.present));
    let mut paths = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    let subjects = paths
        .iter()
        .map(|path| {
            let bytes = std::fs::read_to_string(path).unwrap();
            assert_eq!(path.file_name().unwrap(), name(&bytes).as_str());
            bytes
        })
        .collect();
    let input = resolver::ResolutionInput {
        requirements: vec![resolver::Requirement {
            package: "app.root".into(),
            range: "=1.0.0".into(),
        }],
        subjects,
        target: "wasm32".into(),
        allowed_capabilities: vec![],
    };
    let evidence = resolver::generate(&input, &Default::default()).unwrap();
    let resolved = resolver::verify(&evidence, &input, &Default::default()).unwrap();
    assert_eq!(resolved.lock, f.admitted.2);
    crate::package_registry::registry_v3::verify_lock_selection(
        &f.admitted.0,
        &resolved.lock,
        &input.subjects,
    )
    .unwrap();
    assert!(store
        .populate_resolver_cache(&cache, &request(&f, &digest))
        .unwrap()
        .subjects
        .iter()
        .all(|row| row.present));
    assert_eq!(inventory(&source), before);
}

#[test]
fn extracted_cli_route_retains_exact_receipt_bytes_and_operand_order() {
    let f = Fixture::new(false, 1);
    let destination = Temp::new();
    let cache = destination.0.join("cache");
    let lock = destination.0.join("lock.json");
    std::fs::write(&lock, &f.admitted.2).unwrap();
    let mut paths = Vec::new();
    for (i, bytes) in f.admitted.1.iter().enumerate() {
        let path = destination.0.join(format!("subject{i}.json"));
        std::fs::write(&path, bytes).unwrap();
        paths.push(path);
    }
    for state in ["added", "present"] {
        let actual = crate::package_cache_host::fetch_locked(&lock, &cache, &paths).unwrap();
        let rows = f
            .admitted
            .1
            .iter()
            .map(|bytes| {
                let subject = crate::package_lock_v3::verify_dependency_subject(bytes).unwrap();
                format!(
                    "{{\"package\":{},\"version\":{},\"digest\":{},\"state\":{}}}",
                    crate::diagnostic::quote_json(&subject.coordinate.package),
                    crate::diagnostic::quote_json(&subject.coordinate.version),
                    crate::diagnostic::quote_json(&subject.subject_digest),
                    crate::diagnostic::quote_json(state)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(actual,format!("{{\"schema\":\"semaprax.fetch-receipt.v2\",\"cache\":{},\"lock_binding\":true,\"subjects\":[{}]}}\n",crate::diagnostic::quote_json(&cache.display().to_string()),rows));
    }
}

#[test]
fn wrong_generation_lock_registry_and_time_fail_before_cache_creation() {
    let f = Fixture::new(false, 1);
    let yanked = Fixture::new(true, 1);
    let source = Temp::new();
    let destination = Temp::new();
    let (store, digest) = setup(&f, &source);
    for mode in 0..5 {
        let cache = destination.0.join(format!("cache{mode}"));
        let mut input = request(&f, &digest);
        match mode {
            0 => input.expected_generation_digest = "sha256:wrong",
            1 => input.lock = "{}",
            2 => input.registry = &yanked.admitted.0,
            3 => input.trusted_time = 99,
            _ => input.trusted_time = 300,
        };
        assert!(store.populate_resolver_cache(&cache, &input).is_err());
        assert!(!cache.exists());
    }
}

#[test]
fn cache_collision_symlink_and_unsettled_stage_are_never_repaired() {
    let f = Fixture::new(false, 1);
    let source = Temp::new();
    let (store, digest) = setup(&f, &source);
    for mode in 0..3 {
        let destination = Temp::new();
        let cache = destination.0.join("cache");
        let outside = Temp::new();
        if mode == 1 {
            symlink(&outside.0, &cache).unwrap();
        } else {
            std::fs::create_dir(&cache).unwrap();
            std::fs::write(
                cache.join(if mode == 0 {
                    name(&f.admitted.1[0])
                } else {
                    ".fetch-stage-retained".into()
                }),
                b"untrusted",
            )
            .unwrap();
        }
        let before = std::fs::read_dir(&destination.0).unwrap().count();
        assert!(store
            .populate_resolver_cache(&cache, &request(&f, &digest))
            .is_err());
        assert_eq!(std::fs::read_dir(&destination.0).unwrap().count(), before);
        assert!(inventory(&outside).is_empty());
        if mode != 1 {
            assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
        }
    }
}

#[test]
fn source_change_before_staging_never_returns_a_cache_receipt() {
    let f = Fixture::new(false, 1);
    let source = Temp::new();
    let destination = Temp::new();
    let cache = destination.0.join("cache");
    let (store, digest) = setup(&f, &source);
    let source_path = source.0.clone();
    let mut count = 0;
    super::super::cache::HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            count += 1;
            if count == 2 {
                std::fs::write(source_path.join("ACTIVE"), b"stale").unwrap();
            }
        }))
    });
    assert!(store
        .populate_resolver_cache(&cache, &request(&f, &digest))
        .is_err());
    super::super::cache::HOOK.with(|hook| hook.borrow_mut().take());
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
}

#[test]
fn source_change_after_first_publish_retains_prefix_without_receipt() {
    let f = Fixture::new(false, 1);
    let source = Temp::new();
    let destination = Temp::new();
    let cache = destination.0.join("cache");
    let (store, digest) = setup(&f, &source);
    let source_path = source.0.clone();
    let cache_path = cache.clone();
    let mut changed = false;
    super::super::cache::HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            if !changed
                && cache_path.exists()
                && std::fs::read_dir(&cache_path).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|ext| ext == "json")
                })
            {
                changed = true;
                std::fs::write(source_path.join("ACTIVE"), b"stale").unwrap();
            }
        }))
    });
    let errors = store
        .populate_resolver_cache(&cache, &request(&f, &digest))
        .err()
        .expect("must refuse receipt");
    super::super::cache::HOOK.with(|hook| hook.borrow_mut().take());
    assert!(format!("{errors:?}").contains("partially completed"));
    let names = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names.iter().filter(|name| name.ends_with(".json")).count(),
        1
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| name.starts_with(".fetch-stage-"))
            .count(),
        1
    );
}
