//! Host-independent: pure ordering/classification logic, no Win32 call
//! anywhere in this file. Every closure below records whether it was called
//! in a `Cell<bool>`; the assertions on those cells are what prove a later
//! stage never runs once an earlier one has already refused, not merely
//! that the final `Result` looks right.
use super::*;
use std::cell::Cell;

#[test]
fn every_stage_succeeding_returns_all_five_results_in_order() {
    let result = admit(
        || Ok::<_, ()>("host"),
        || Ok::<_, CapsuleError>("capsule"),
        || Ok::<_, ()>("token"),
        || Ok::<_, ()>("job"),
        || Ok::<_, ()>("filesystem"),
    );
    assert_eq!(
        result,
        Ok(("host", "capsule", "token", "job", "filesystem"))
    );
}

#[test]
fn unsupported_host_refuses_before_the_capsule_is_ever_interpreted() {
    let capsule_called = Cell::new(false);
    let token_called = Cell::new(false);
    let job_called = Cell::new(false);
    let filesystem_called = Cell::new(false);
    let result = admit(
        || Err::<(), ()>(()),
        || {
            capsule_called.set(true);
            Ok::<_, CapsuleError>(())
        },
        || {
            token_called.set(true);
            Ok::<_, ()>(())
        },
        || {
            job_called.set(true);
            Ok::<_, ()>(())
        },
        || {
            filesystem_called.set(true);
            Ok::<_, ()>(())
        },
    );
    assert_eq!(result, Err(Refusal::UnsupportedHost));
    assert!(!capsule_called.get(), "capsule bytes must never be touched");
    assert!(!token_called.get());
    assert!(!job_called.get());
    assert!(!filesystem_called.get());
}

#[test]
fn malformed_capsule_refuses_after_host_but_before_any_confinement_primitive() {
    let host_called = Cell::new(false);
    let token_called = Cell::new(false);
    let job_called = Cell::new(false);
    let filesystem_called = Cell::new(false);
    let result = admit(
        || {
            host_called.set(true);
            Ok::<_, ()>(())
        },
        || Err::<(), _>(CapsuleError::Invalid),
        || {
            token_called.set(true);
            Ok::<_, ()>(())
        },
        || {
            job_called.set(true);
            Ok::<_, ()>(())
        },
        || {
            filesystem_called.set(true);
            Ok::<_, ()>(())
        },
    );
    assert_eq!(result, Err(Refusal::Capsule(CapsuleError::Invalid)));
    assert!(host_called.get());
    assert!(!token_called.get());
    assert!(!job_called.get());
    assert!(!filesystem_called.get());
}

#[test]
fn oversized_capsule_is_classified_as_a_limit_refusal_not_invalid() {
    let result = admit(
        || Ok::<_, ()>(()),
        || Err::<(), _>(CapsuleError::Limit),
        || Ok::<_, ()>(()),
        || Ok::<_, ()>(()),
        || Ok::<_, ()>(()),
    );
    assert_eq!(result, Err(Refusal::Capsule(CapsuleError::Limit)));
}

#[test]
fn token_restriction_failure_refuses_before_the_job_object_or_filesystem_stage() {
    let job_called = Cell::new(false);
    let filesystem_called = Cell::new(false);
    let result = admit(
        || Ok::<_, ()>(()),
        || Ok::<_, CapsuleError>(()),
        || Err::<(), ()>(()),
        || {
            job_called.set(true);
            Ok::<_, ()>(())
        },
        || {
            filesystem_called.set(true);
            Ok::<_, ()>(())
        },
    );
    assert_eq!(result, Err(Refusal::TokenRestriction));
    assert!(!job_called.get());
    assert!(!filesystem_called.get());
}

#[test]
fn job_object_failure_refuses_before_the_filesystem_stage() {
    let filesystem_called = Cell::new(false);
    let result = admit(
        || Ok::<_, ()>(()),
        || Ok::<_, CapsuleError>(()),
        || Ok::<_, ()>(()),
        || Err::<(), ()>(()),
        || {
            filesystem_called.set(true);
            Ok::<_, ()>(())
        },
    );
    assert_eq!(result, Err(Refusal::JobObjectLimits));
    assert!(!filesystem_called.get());
}

#[test]
fn filesystem_confinement_failure_is_the_last_stage_to_be_reachable() {
    let result = admit(
        || Ok::<_, ()>(()),
        || Ok::<_, CapsuleError>(()),
        || Ok::<_, ()>(()),
        || Ok::<_, ()>(()),
        || Err::<(), ()>(()),
    );
    assert_eq!(result, Err(Refusal::FilesystemConfinement));
}
