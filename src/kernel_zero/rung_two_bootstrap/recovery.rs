//! Fail-closed recovery for local Rung-2 target candidates.
//!
//! Rust remains formatter authority. A candidate can only corroborate it: all
//! target failures and disagreements return the original Rust borrow.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TargetFailure {
    Spawn,
    Deadline,
    Nonzero,
    Parse,
    Io,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidateRefusal {
    NativeO0(TargetFailure),
    NativeO2(TargetFailure),
    Wasm(TargetFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidateDisposition {
    Matched,
    Recovered(CandidateRefusal),
}

#[derive(Debug)]
pub(super) struct Recovery<'a, T: ?Sized> {
    pub(super) disposition: CandidateDisposition,
    /// This is always the Rust-owned authoritative value. Candidate storage is
    /// never returned, including on a successful candidate match.
    pub(super) authoritative: &'a T,
}

pub(super) fn recover<'a, T: ?Sized + PartialEq>(
    rust: &'a T,
    target: Result<&T, CandidateRefusal>,
) -> Recovery<'a, T> {
    let disposition = match target {
        Ok(candidate) if candidate == rust => CandidateDisposition::Matched,
        Ok(_) => CandidateDisposition::Recovered(CandidateRefusal::Wasm(TargetFailure::Mismatch)),
        Err(refusal) => CandidateDisposition::Recovered(refusal),
    };
    Recovery {
        disposition,
        authoritative: rust,
    }
}

#[test]
fn refusals_and_mismatch_keep_the_authoritative_borrow() {
    let rust = b"rust bytes".as_slice();
    for refusal in [
        CandidateRefusal::NativeO0(TargetFailure::Deadline),
        CandidateRefusal::NativeO2(TargetFailure::Nonzero),
        CandidateRefusal::Wasm(TargetFailure::Parse),
    ] {
        let recovery = recover(rust, Err(refusal));
        assert_eq!(
            recovery.disposition,
            CandidateDisposition::Recovered(refusal)
        );
        assert!(std::ptr::eq(recovery.authoritative, rust));
    }
    let recovery = recover(rust, Ok(b"wrong bytes".as_slice()));
    assert_eq!(
        recovery.disposition,
        CandidateDisposition::Recovered(CandidateRefusal::Wasm(TargetFailure::Mismatch))
    );
    assert!(std::ptr::eq(recovery.authoritative, rust));
}
