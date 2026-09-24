use super::*;
#[cfg(unix)]
use std::cell::{Cell, RefCell};

fn namespace_store(directory: &HeldDirectory) -> OutboundDeliveryStore<'_> {
    OutboundDeliveryStore::with_sync_mode(directory, OutboundCheckpointSyncMode::NamespaceSynced)
}

#[test]
fn default_file_only_does_not_call_directory_sync() {
    let temp = TempDirectory::new();
    let directory = platform::hold_directory(temp.path()).unwrap();
    let mut store = OutboundDeliveryStore::new(&directory);
    let checkpoint = empty_checkpoint();
    assert_eq!(
        store.commit_rendered_with_directory_sync(
            OutboundCheckpointKind::HttpSession,
            &checkpoint.digest(),
            &checkpoint.render(),
            platform::write_file_new,
            platform::sync_regular_file,
            |_| panic!("the default must not gain a directory-sync requirement"),
        ),
        CheckpointCommit::Committed
    );
}

#[cfg(not(unix))]
#[test]
fn unsupported_directory_sync_never_acknowledges_strong_mode() {
    let temp = TempDirectory::new();
    let directory = platform::hold_directory(temp.path()).unwrap();
    assert_eq!(
        platform::sync_directory(&directory),
        Err(platform::Error::Unsupported)
    );
    let mut store = namespace_store(&directory);
    for _ in 0..2 {
        assert_eq!(
            HttpDeliverySessionCheckpointStore::commit(&mut store, &empty_checkpoint()),
            CheckpointCommit::Uncertain
        );
    }
}

#[cfg(unix)]
#[test]
fn new_and_existing_ack_require_exact_bytes_then_file_and_directory_sync() {
    let temp = TempDirectory::new();
    let directory = platform::hold_directory(temp.path()).unwrap();
    let mut store = namespace_store(&directory);
    let checkpoint = empty_checkpoint();
    let rendered = checkpoint.render();
    for exists in [false, true] {
        let order = RefCell::new(Vec::new());
        assert_eq!(
            store.commit_rendered_with_directory_sync(
                OutboundCheckpointKind::HttpSession,
                &checkpoint.digest(),
                &rendered,
                |directory, name, bytes, mode| {
                    order.borrow_mut().push("write");
                    let result = platform::write_file_new(directory, name, bytes, mode);
                    assert_eq!(matches!(&result, Err(platform::Error::Exists)), exists);
                    result
                },
                |file| {
                    assert_eq!(&*order.borrow(), &["write"]);
                    assert_eq!(
                        platform::read_exact(file, MAX_CHECKPOINT_BYTES)?,
                        rendered.as_bytes()
                    );
                    platform::sync_regular_file(file)?;
                    order.borrow_mut().push("file");
                    Ok(())
                },
                |held| {
                    assert_eq!(&*order.borrow(), &["write", "file"]);
                    platform::sync_directory(held)?;
                    order.borrow_mut().push("directory");
                    Ok(())
                },
            ),
            CheckpointCommit::Committed
        );
        assert_eq!(&*order.borrow(), &["write", "file", "directory"]);
    }
}

#[cfg(unix)]
#[test]
fn both_sync_failures_are_uncertain_and_file_failure_precedes_directory_work() {
    for existing in [false, true] {
        for fail_file in [false, true] {
            let temp = TempDirectory::new();
            let directory = platform::hold_directory(temp.path()).unwrap();
            let mut store = namespace_store(&directory);
            let checkpoint = empty_checkpoint();
            if existing {
                assert_eq!(
                    HttpDeliverySessionCheckpointStore::commit(&mut store, &checkpoint),
                    CheckpointCommit::Committed
                );
            }
            let calls = Cell::new((0, 0));
            assert_eq!(
                store.commit_rendered_with_directory_sync(
                    OutboundCheckpointKind::HttpSession,
                    &checkpoint.digest(),
                    &checkpoint.render(),
                    platform::write_file_new,
                    |file| {
                        calls.set((calls.get().0 + 1, calls.get().1));
                        if fail_file {
                            Err(platform::Error::Changed)
                        } else {
                            platform::sync_regular_file(file)
                        }
                    },
                    |_| {
                        calls.set((calls.get().0, calls.get().1 + 1));
                        Err(platform::Error::Changed)
                    },
                ),
                CheckpointCommit::Uncertain
            );
            assert_eq!(calls.get(), (1, usize::from(!fail_file)));
        }
    }
}

#[cfg(unix)]
#[test]
fn wrong_bytes_refuse_before_sync_and_same_byte_replacement_after_sync_refuses() {
    for existing in [false, true] {
        let temp = TempDirectory::new();
        let directory = platform::hold_directory(temp.path()).unwrap();
        let mut store = namespace_store(&directory);
        let checkpoint = empty_checkpoint();
        let rendered = checkpoint.render();
        let name =
            checkpoint_filename(OutboundCheckpointKind::HttpSession, &checkpoint.digest()).unwrap();
        if existing {
            fs::write(temp.path().join(&name), &rendered).unwrap();
        }
        let synced = Cell::new(false);
        assert_eq!(
            store.commit_rendered_with_directory_sync(
                OutboundCheckpointKind::HttpSession,
                &checkpoint.digest(),
                &rendered,
                platform::write_file_new,
                platform::sync_regular_file,
                |held| {
                    platform::sync_directory(held)?;
                    synced.set(true);
                    let replacement = temp.path().join("same-bytes-new-object");
                    fs::write(&replacement, &rendered).unwrap();
                    fs::rename(replacement, temp.path().join(&name)).unwrap();
                    Ok(())
                },
            ),
            CheckpointCommit::Uncertain,
            "the final named identity check must follow directory sync even for identical content"
        );
        assert!(synced.get());
        fs::write(temp.path().join(&name), b"tampered").unwrap();
        assert_eq!(
            store.commit_rendered_with_directory_sync(
                OutboundCheckpointKind::HttpSession,
                &checkpoint.digest(),
                &rendered,
                platform::write_file_new,
                |_| panic!("exact bytes must be checked before file sync"),
                |_| panic!("exact bytes must be checked before directory sync"),
            ),
            CheckpointCommit::Uncertain
        );
    }
}

#[cfg(unix)]
mod typed_recovery;
