use super::*;
use std::os::unix::fs::symlink;

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "semaprax-held-fetch-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn cache(&self) -> std::path::PathBuf {
        self.0.join("cache")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn subjects() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(
        "aaa.json".to_owned(),
        b"authenticated subject bytes".to_vec(),
    )])
}
fn refused<T>(result: Result<T>) {
    let errors = result.err().expect("must refuse without receipt");
    assert!(format!("{errors:?}").contains("SPX-J128"));
}

#[test]
fn partial_stage_write_never_poisons_a_digest_or_deletes_a_replacement() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    refused(publish(&root, &subjects(), |point| {
        if point == Point::AfterPartialWrite {
            return Err(failure("injected partial write"));
        }
        Ok(())
    }));
    assert!(!fixture.cache().join("aaa.json").exists());
    let stages = std::fs::read_dir(fixture.cache())
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(stages.len(), 1);
    assert!(stages[0]
        .file_name()
        .to_str()
        .unwrap()
        .starts_with(".fetch-stage-"));
    assert_eq!(std::fs::read(stages[0].path()).unwrap(), b"authenticated");
    refused(publish(&root, &subjects(), |_| Ok(())));
    assert!(!fixture.cache().join("aaa.json").exists());
}

#[test]
fn settled_publication_reports_added_then_present() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    assert!(!publish(&root, &subjects(), |_| Ok(())).unwrap()["aaa.json"]);
    assert!(publish(&root, &subjects(), |_| Ok(())).unwrap()["aaa.json"]);
    assert_eq!(std::fs::read_dir(fixture.cache()).unwrap().count(), 1);
}

#[test]
fn held_input_replacement_and_missing_parent_swap_fail_before_creation() {
    let fixture = Fixture::new();
    let path = fixture.0.join("input");
    std::fs::write(&path, b"exact").unwrap();
    let mut held = input(&path, 10).unwrap();
    std::fs::rename(&path, fixture.0.join("original")).unwrap();
    std::fs::write(&path, b"exact").unwrap();
    refused(held.check());

    let parent = fixture.0.join("parent");
    let outside = fixture.0.join("outside");
    std::fs::create_dir(&parent).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let (mut root, pending) = Root::prepare(&parent.join("new-cache/nested")).unwrap();
    std::fs::rename(&parent, fixture.0.join("displaced")).unwrap();
    symlink(&outside, &parent).unwrap();
    refused(root.create(pending));
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn swapped_cache_path_cannot_redirect_creation_to_outside_directory() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    let outside = fixture.0.join("outside");
    std::fs::create_dir(&outside).unwrap();
    refused(publish(&root, &subjects(), |point| {
        if point == Point::BeforeStage {
            std::fs::rename(fixture.cache(), fixture.0.join("displaced")).unwrap();
            symlink(&outside, fixture.cache()).unwrap();
        }
        Ok(())
    }));
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(
        std::fs::read_dir(fixture.0.join("displaced"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn concurrent_destination_is_neither_overwritten_nor_reported_as_added() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    refused(publish(&root, &subjects(), |point| {
        if point == Point::BeforePublish {
            std::fs::write(fixture.cache().join("aaa.json"), b"competitor").unwrap();
        }
        Ok(())
    }));
    assert_eq!(
        std::fs::read(fixture.cache().join("aaa.json")).unwrap(),
        b"competitor"
    );
}

#[test]
fn same_bytes_replacement_after_publish_is_uncertain_and_is_never_deleted() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    let result = publish(&root, &subjects(), |point| {
        if point == Point::AfterPublish {
            std::fs::rename(
                fixture.cache().join("aaa.json"),
                fixture.cache().join("held-original"),
            )
            .unwrap();
            std::fs::write(fixture.cache().join("aaa.json"), &subjects()["aaa.json"]).unwrap();
        }
        Ok(())
    });
    let error = result.unwrap_err();
    assert!(format!("{error:?}").contains("uncertain"));
    assert_eq!(
        std::fs::read(fixture.cache().join("aaa.json")).unwrap(),
        subjects()["aaa.json"]
    );
    assert!(fixture.cache().join("held-original").exists());
}

#[test]
fn second_publication_failure_retains_authenticated_prefix_and_no_receipt() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    let mut bytes = subjects();
    bytes.insert("bbb.json".to_owned(), b"second subject".to_vec());
    let mut count = 0;
    let result = publish(&root, &bytes, |point| {
        if point == Point::BeforePublish {
            count += 1;
            if count == 2 {
                return Err(failure("second pivot failed"));
            }
        }
        Ok(())
    });
    assert!(format!("{:?}", result.unwrap_err()).contains("partially completed"));
    assert_eq!(
        std::fs::read(fixture.cache().join("aaa.json")).unwrap(),
        bytes["aaa.json"]
    );
    assert!(!fixture.cache().join("bbb.json").exists());
}

#[test]
fn cooperative_competitor_is_refused_before_staging_and_inputs_are_bounded() {
    let fixture = Fixture::new();
    let root = Root::open(&fixture.cache(), true).unwrap();
    let competing = Root::open(&fixture.cache(), false).unwrap();
    let _lock = competing.lock().unwrap();
    refused(publish(&root, &subjects(), |_| Ok(())));
    assert_eq!(std::fs::read_dir(fixture.cache()).unwrap().count(), 0);
    let path = fixture.0.join("input");
    std::fs::write(&path, b"oversized").unwrap();
    refused(input(&path, 2));
    symlink(&path, fixture.0.join("linked-input")).unwrap();
    refused(input(&fixture.0.join("linked-input"), 20));
}
