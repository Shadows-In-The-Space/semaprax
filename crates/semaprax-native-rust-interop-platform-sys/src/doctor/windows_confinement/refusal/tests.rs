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

#[cfg(windows)]
#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_missing_release_anchor_refuses_before_token_job_or_filesystem() {
    let architecture = super::super::capsule::windows_architecture_code().unwrap();
    let (bytes, _) = super::super::capsule::signed_test_fixture(architecture);
    let token_called = Cell::new(false);
    let job_called = Cell::new(false);
    let filesystem_called = Cell::new(false);
    let result = admit(
        || Ok::<_, ()>(()),
        || super::super::capsule::parse_with_anchor(&bytes, None),
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
    assert_eq!(
        result,
        Err(Refusal::Capsule(CapsuleError::MissingTrustAnchor))
    );
    assert!(!token_called.get());
    assert!(!job_called.get());
    assert!(!filesystem_called.get());
}

#[cfg(windows)]
#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_bad_signature_refuses_before_token_job_or_filesystem() {
    let architecture = super::super::capsule::windows_architecture_code().unwrap();
    let (mut bytes, public_key_hex) = super::super::capsule::signed_test_fixture(architecture);
    *bytes
        .last_mut()
        .expect("signed fixture has signature bytes") ^= 1;
    let token_called = Cell::new(false);
    let job_called = Cell::new(false);
    let filesystem_called = Cell::new(false);
    let result = admit(
        || Ok::<_, ()>(()),
        || super::super::capsule::parse_windows_signed_with_key(&bytes, &public_key_hex),
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
    assert_eq!(result, Err(Refusal::Capsule(CapsuleError::Signature)));
    assert!(!token_called.get());
    assert!(!job_called.get());
    assert!(!filesystem_called.get());
}

#[cfg(windows)]
#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_signed_linux_architecture_capsule_refuses_before_token_job_or_filesystem() {
    for architecture in [1, 2] {
        let (bytes, public_key_hex) = super::super::capsule::signed_test_fixture(architecture);
        let token_called = Cell::new(false);
        let job_called = Cell::new(false);
        let filesystem_called = Cell::new(false);
        let result = admit(
            || Ok::<_, ()>(()),
            || super::super::capsule::parse_windows_signed_with_key(&bytes, &public_key_hex),
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
        assert_eq!(
            result,
            Err(Refusal::Capsule(CapsuleError::ArchitectureMismatch)),
            "signed Linux architecture code {architecture}"
        );
        assert!(!token_called.get());
        assert!(!job_called.get());
        assert!(!filesystem_called.get());
    }
}
