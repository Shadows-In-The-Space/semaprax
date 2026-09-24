//! Host-independent hostile-input corpus for [`super::parse_capsule_body`].
//! These run on every host this crate builds on, including this one: no
//! Windows API, job object, token, or filesystem confinement call is made
//! anywhere in this file.
use super::*;

/// Local test-only encoder mirroring `semaprax-doctor-capsule`'s
/// `encode_body`, plus a fixed placeholder signature, so tests can build
/// well-formed fixtures without depending on that crate (see the module
/// documentation for why it is not a dependency here).
fn encode_test_body(
    architecture: u8,
    target: u8,
    selector: &str,
    artifacts: [Artifact; ARTIFACT_COUNT],
) -> Vec<u8> {
    let roles = roles_for_target(target).expect("test target has a role mapping");
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.push(VERSION);
    body.push(architecture);
    body.push(target);
    body.push(roles);
    body.push(u8::try_from(selector.len()).expect("test selector fits in a byte"));
    body.extend_from_slice(selector.as_bytes());
    for artifact in artifacts {
        body.extend_from_slice(&artifact.length.to_le_bytes());
        body.extend_from_slice(&artifact.digest);
    }
    body.extend_from_slice(&[0xAB; SIGNATURE_BYTES]);
    body
}

fn healthy_artifacts() -> [Artifact; ARTIFACT_COUNT] {
    std::array::from_fn(|index| Artifact {
        length: 1 + index as u64,
        digest: [index as u8; 32],
    })
}

#[test]
fn well_formed_body_round_trips_with_signature_left_unverified() {
    let bytes = encode_test_body(1, 0, "linux-x86-64", healthy_artifacts());
    let parsed = parse_capsule_body(&bytes).unwrap();
    assert_eq!(parsed.architecture, 1);
    assert_eq!(parsed.target, 0);
    assert_eq!(parsed.roles, 4);
    assert_eq!(parsed.selector, "linux-x86-64");
    assert_eq!(parsed.artifacts, healthy_artifacts());
    assert_eq!(parsed.unverified_signature, [0xAB; SIGNATURE_BYTES]);
}

#[test]
fn every_target_maps_to_its_fixed_role_mask() {
    for (target, roles) in [(0u8, 4u8), (1, 1), (2, 2), (3, 7)] {
        let bytes = encode_test_body(1, target, "x", healthy_artifacts());
        assert_eq!(parse_capsule_body(&bytes).unwrap().roles, roles);
    }
    assert_eq!(roles_for_target(4), None);
}

#[test]
fn oversized_bytes_are_rejected_as_limit_before_any_field_is_read() {
    let bytes = vec![0u8; MAX_CAPSULE_BYTES + 1];
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Limit));
}

#[test]
fn truncated_bytes_below_the_fixed_frame_are_invalid_not_a_panic() {
    for length in [0, 1, MAGIC.len(), MAGIC.len() + 5] {
        assert_eq!(
            parse_capsule_body(&vec![0u8; length]),
            Err(CapsuleError::Invalid)
        );
    }
}

#[test]
fn wrong_magic_or_version_is_rejected() {
    let mut bytes = encode_test_body(1, 0, "x", healthy_artifacts());
    bytes[0] = b'Z';
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));

    let mut bytes = encode_test_body(1, 0, "x", healthy_artifacts());
    bytes[MAGIC.len()] = VERSION + 1;
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn unknown_architecture_is_rejected() {
    let bytes = encode_test_body(0, 0, "x", healthy_artifacts());
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
    let bytes = encode_test_body(5, 0, "x", healthy_artifacts());
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn capsule_v1_architecture_bytes_are_closed_and_distinct_by_native_os() {
    for architecture in [1, 2, 3, 4] {
        let bytes = encode_test_body(architecture, 0, "x", healthy_artifacts());
        assert_eq!(
            parse_capsule_body(&bytes).unwrap().architecture,
            architecture
        );
    }
    for architecture in [0, 5, 255] {
        let bytes = encode_test_body(architecture, 0, "x", healthy_artifacts());
        assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
    }
}

#[test]
fn unknown_target_is_rejected() {
    let mut bytes = encode_test_body(1, 0, "x", healthy_artifacts());
    // Target byte, after magic/version/architecture.
    bytes[MAGIC.len() + 2] = 9;
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn roles_byte_disagreeing_with_the_target_is_rejected() {
    let mut bytes = encode_test_body(1, 0, "x", healthy_artifacts());
    // Roles byte, after magic/version/architecture/target.
    bytes[MAGIC.len() + 3] = 0xFF;
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn empty_selector_is_rejected() {
    let bytes = encode_test_body(1, 0, "", healthy_artifacts());
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn selector_at_the_length_ceiling_is_admitted() {
    let selector = "a".repeat(64);
    let bytes = encode_test_body(1, 0, &selector, healthy_artifacts());
    // `MAX_CAPSULE_BYTES` is exactly calibrated for a 64-byte selector: this
    // is the largest well-formed capsule this format admits.
    assert_eq!(bytes.len(), MAX_CAPSULE_BYTES);
    assert!(parse_capsule_body(&bytes).is_ok());
}

#[test]
fn selector_length_byte_over_the_ceiling_is_rejected_as_invalid() {
    // A real 65-byte selector would also overflow `MAX_CAPSULE_BYTES` (which
    // is calibrated exactly for the 64-byte ceiling), so the total-size
    // `Limit` check would fire first and this would not isolate the selector
    // length check. Instead, keep the encoded selector at 64 real bytes and
    // only lie about its declared length, so `validate_selector`'s own
    // length rule is what rejects this, not the capsule-size ceiling.
    let selector = "a".repeat(64);
    let mut bytes = encode_test_body(1, 0, &selector, healthy_artifacts());
    bytes[MAGIC.len() + 4] = 65;
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn selector_with_uppercase_or_symbol_bytes_is_rejected() {
    for selector in ["Linux", "linux_x86", "-linux", "linux!"] {
        let bytes = encode_test_body(1, 0, selector, healthy_artifacts());
        assert_eq!(
            parse_capsule_body(&bytes),
            Err(CapsuleError::Invalid),
            "{selector}"
        );
    }
}

#[test]
fn zero_length_artifact_is_rejected_as_limit() {
    let mut artifacts = healthy_artifacts();
    artifacts[2].length = 0;
    let bytes = encode_test_body(1, 0, "x", artifacts);
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Limit));
}

#[test]
fn artifact_length_over_the_ceiling_is_rejected_as_limit() {
    let mut artifacts = healthy_artifacts();
    artifacts[4].length = MAX_ARTIFACT_BYTES + 1;
    let bytes = encode_test_body(1, 0, "x", artifacts);
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Limit));
}

#[test]
fn artifact_length_at_the_exact_ceiling_is_admitted() {
    let mut artifacts = healthy_artifacts();
    artifacts[4].length = MAX_ARTIFACT_BYTES;
    let bytes = encode_test_body(1, 0, "x", artifacts);
    assert!(parse_capsule_body(&bytes).is_ok());
}

#[test]
fn trailing_garbage_after_a_well_formed_body_is_rejected() {
    let mut bytes = encode_test_body(1, 0, "x", healthy_artifacts());
    // Insert a stray byte before the trailing signature so `cursor` never
    // reaches `body.len()`; splitting on `SIGNATURE_BYTES` from the end keeps
    // the (unverified) signature framing intact.
    let insert_at = bytes.len() - SIGNATURE_BYTES;
    bytes.insert(insert_at, 0x42);
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}

#[test]
fn selector_length_byte_claiming_more_bytes_than_remain_is_rejected_not_a_panic() {
    let mut bytes = encode_test_body(1, 0, "x", healthy_artifacts());
    // Selector length byte, after magic/version/architecture/target/roles.
    // The body is 214 bytes total with a 1-byte selector; 255 always runs
    // past the end regardless of artifact contents, exercising the bounds
    // check in `take` rather than `validate_selector`'s character check.
    bytes[MAGIC.len() + 4] = 255;
    assert_eq!(parse_capsule_body(&bytes), Err(CapsuleError::Invalid));
}
