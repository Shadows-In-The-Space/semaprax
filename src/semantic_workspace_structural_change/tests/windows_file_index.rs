use super::*;

#[test]
fn structural_apply_rejects_windows_same_byte_file_index_substitution() {
    let (fixture, evidence_path) = application_fixture("windows-file-index");
    let active_path = fixture.root.join(".semaprax-workspace/ACTIVE");
    let active_before = std::fs::read(&active_path).unwrap();
    let identities = std::cell::RefCell::new(None::<(u64, u64)>);
    let error = diagnostic(apply_authenticated_with_hook(
        &fixture.root,
        &fixture.proposal_path,
        &evidence_path,
        |point, _, _, candidate| {
            if !matches!(
                point,
                StructuralApplyPoint::Workspace(
                    workspace::SemanticChangeApplyPoint::BeforeFirstFinalCheck
                )
            ) {
                return Ok(());
            }
            let path = candidate.unwrap().join("files/z/entry.spx");
            let before = winapi_util::Handle::from_path_any(&path)
                .and_then(winapi_util::file::information)?
                .file_index();
            let bytes = std::fs::read(&path)?;
            std::fs::remove_file(&path)?;
            std::fs::write(&path, bytes)?;
            let after = winapi_util::Handle::from_path_any(&path)
                .and_then(winapi_util::file::information)?
                .file_index();
            assert_ne!(before, after);
            *identities.borrow_mut() = Some((before, after));
            Ok(())
        },
    ));
    assert_eq!(error.code, "SPX-G153");
    assert!(identities.into_inner().is_some());
    assert_eq!(std::fs::read(&active_path).unwrap(), active_before);
    fixture.assert_exclusive_reacquire();
}
