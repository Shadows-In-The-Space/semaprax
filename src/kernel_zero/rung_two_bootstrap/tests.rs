use sha2::{Digest, Sha256};

use super::artifact::{Artifact, BootstrapRefusal, COMPONENT_COUNT, SCHEMA};
use super::decode::{
    decode_and_replay, maximum_artifact_bytes, maximum_term_bytes, reencode_for_test,
};

#[test]
fn two_exact_local_builds_produce_one_digest_bound_artifact() {
    let first = Artifact::derive().expect("all five checked renderer sources must build");
    let second = Artifact::derive().expect("a second local build must also succeed");
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(decode_and_replay(first.bytes()), Ok(first.digest()));
    assert_eq!(first.components().len(), COMPONENT_COUNT);
    assert!(first
        .bytes()
        .windows(SCHEMA.len())
        .any(|bytes| bytes == SCHEMA.as_bytes()));
}

#[test]
fn artifact_retains_all_real_target_payloads_but_does_not_claim_execution() {
    let artifact = Artifact::derive().expect("renderer artifact must derive");
    for component in artifact.components() {
        assert!(
            component
                .c_source
                .windows(b"#include".len())
                .any(|bytes| bytes == b"#include"),
            "{} must retain the ordinary generated C11 translation unit",
            component.name
        );
        assert!(
            component.wasm.starts_with(b"\0asm"),
            "{} must retain an ordinary raw Core-Wasm module",
            component.name
        );
        assert!(
            component.term.starts_with(b"SPX-KERNEL-TERM-V1\0"),
            "{} must retain a bounded canonical reification payload",
            component.name
        );
    }
}

#[test]
fn decoder_refuses_noncanonical_order_duplicates_and_replaced_compiler_outputs() {
    let artifact = Artifact::derive().expect("renderer artifact must derive");
    let mut reordered = artifact.components().to_vec();
    reordered.swap(0, 1);
    let reordered = reencode_for_test(&reordered).expect("test wire re-encoding must work");
    assert_eq!(decode_and_replay(&reordered), Err(BootstrapRefusal::Drift));

    let mut duplicated = artifact.components().to_vec();
    duplicated[1] = duplicated[0].clone();
    let duplicated = reencode_for_test(&duplicated).expect("test wire re-encoding must work");
    assert_eq!(decode_and_replay(&duplicated), Err(BootstrapRefusal::Drift));

    let mut replaced_term = artifact.components().to_vec();
    replaced_term[0].term[0] ^= 1;
    let replaced_term = reencode_for_test(&replaced_term).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&replaced_term),
        Err(BootstrapRefusal::TermEncoding)
    );

    let mut replaced_c = artifact.components().to_vec();
    replaced_c[1].c_source[0] ^= 1;
    let replaced_c = reencode_for_test(&replaced_c).expect("test wire re-encoding must work");
    assert_eq!(decode_and_replay(&replaced_c), Err(BootstrapRefusal::Drift));

    let mut replaced_wasm = artifact.components().to_vec();
    replaced_wasm[2].wasm[0] ^= 1;
    let replaced_wasm = reencode_for_test(&replaced_wasm).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&replaced_wasm),
        Err(BootstrapRefusal::Drift)
    );
}

#[test]
fn decoder_refuses_digest_schema_source_length_and_trailing_hostility() {
    let artifact = Artifact::derive().expect("renderer artifact must derive");

    let mut bad_digest = artifact.bytes().to_vec();
    let final_byte = bad_digest.len() - 1;
    bad_digest[final_byte] ^= 1;
    assert_eq!(
        decode_and_replay(&bad_digest),
        Err(BootstrapRefusal::Digest)
    );

    let bad_magic = mutate_body(artifact.bytes(), |body| body[0] ^= 1);
    assert_eq!(
        decode_and_replay(&bad_magic),
        Err(BootstrapRefusal::Encoding)
    );

    let bad_schema = mutate_body(artifact.bytes(), |body| {
        let offset = find(body, SCHEMA.as_bytes());
        body[offset] = b'x';
    });
    assert_eq!(
        decode_and_replay(&bad_schema),
        Err(BootstrapRefusal::Encoding)
    );

    let mut source_drift = artifact.components().to_vec();
    source_drift[0].source[0] = b'M';
    let bad_source = reencode_for_test(&source_drift).expect("test wire re-encoding must work");
    assert_eq!(decode_and_replay(&bad_source), Err(BootstrapRefusal::Drift));

    let bad_source_length = mutate_body(artifact.bytes(), |body| {
        let offset = first_source_length_offset(body);
        body[offset..offset + 4].copy_from_slice(
            &(u32::try_from(super::artifact::MAX_COMPONENT_BYTES + 1).unwrap()).to_le_bytes(),
        );
    });
    assert_eq!(
        decode_and_replay(&bad_source_length),
        Err(BootstrapRefusal::Bounds)
    );

    let truncated = truncate_body_payload(artifact.bytes());
    assert_eq!(
        decode_and_replay(&truncated),
        Err(BootstrapRefusal::Encoding)
    );

    let trailing = append_body_trailing_byte(artifact.bytes());
    assert_eq!(
        decode_and_replay(&trailing),
        Err(BootstrapRefusal::Encoding)
    );

    let oversized = vec![0; maximum_artifact_bytes() + 1];
    assert_eq!(decode_and_replay(&oversized), Err(BootstrapRefusal::Bounds));
}

#[test]
fn decoder_owns_term_structure_validation_before_compiler_regeneration() {
    let artifact = Artifact::derive().expect("renderer artifact must derive");

    let mut bad_tag = artifact.components().to_vec();
    let offset = first_term_tag_offset(&bad_tag[0].term);
    bad_tag[0].term[offset] = 0;
    let bad_tag = reencode_for_test(&bad_tag).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&bad_tag),
        Err(BootstrapRefusal::TermEncoding)
    );

    let mut bad_count = artifact.components().to_vec();
    bad_count[0].term[TERM_MAGIC.len()] = 0;
    let bad_count = reencode_for_test(&bad_count).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&bad_count),
        Err(BootstrapRefusal::TermBounds)
    );

    let mut bad_depth = artifact.components().to_vec();
    bad_depth[0].term = too_deep_term();
    let bad_depth = reencode_for_test(&bad_depth).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&bad_depth),
        Err(BootstrapRefusal::TermBounds)
    );

    let mut trailing = artifact.components().to_vec();
    trailing[0].term.push(0);
    let trailing = reencode_for_test(&trailing).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&trailing),
        Err(BootstrapRefusal::TermEncoding)
    );

    let mut oversized = artifact.components().to_vec();
    oversized[0].term = vec![0; maximum_term_bytes() + 1];
    let oversized = reencode_for_test(&oversized).expect("test wire re-encoding must work");
    assert_eq!(
        decode_and_replay(&oversized),
        Err(BootstrapRefusal::TermBounds)
    );
}

fn mutate_body(bytes: &[u8], mutate: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut result = bytes.to_vec();
    let body_len = result.len() - 32;
    mutate(&mut result[..body_len]);
    let replacement: [u8; 32] = Sha256::digest(&result[..body_len]).into();
    result[body_len..].copy_from_slice(&replacement);
    result
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|candidate| candidate == needle)
        .expect("known exact artifact field must be present")
}

const TERM_MAGIC: &[u8] = b"SPX-KERNEL-TERM-V1\0";

fn first_source_length_offset(body: &[u8]) -> usize {
    let mut offset = 8;
    offset = after_text(body, offset);
    offset = after_text(body, offset);
    offset += 32;
    offset += 1;
    offset = after_text(body, offset);
    after_text(body, offset)
}

fn first_term_tag_offset(bytes: &[u8]) -> usize {
    let mut offset = TERM_MAGIC.len() + 1;
    offset = after_text(bytes, offset);
    let count = usize::from(bytes[offset]);
    offset += 1;
    for _ in 0..count {
        offset = after_text(bytes, offset);
        offset += 1;
    }
    offset + 1
}

fn after_text(bytes: &[u8], offset: usize) -> usize {
    let length = usize::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]));
    offset + 2 + length
}

fn too_deep_term() -> Vec<u8> {
    let mut term = TERM_MAGIC.to_vec();
    term.push(1);
    push_term_text(&mut term, "f");
    term.push(0);
    term.push(1);
    for _ in 0..=128 {
        term.extend([4, 1]);
    }
    term.push(1);
    term.extend_from_slice(&0i64.to_le_bytes());
    term
}

fn push_term_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn truncate_body_payload(bytes: &[u8]) -> Vec<u8> {
    let mut body = bytes[..bytes.len() - 32].to_vec();
    body.pop().expect("artifact body is nonempty");
    let digest: [u8; 32] = Sha256::digest(&body).into();
    body.extend_from_slice(&digest);
    body
}

fn append_body_trailing_byte(bytes: &[u8]) -> Vec<u8> {
    let mut body = bytes[..bytes.len() - 32].to_vec();
    body.push(0);
    let digest: [u8; 32] = Sha256::digest(&body).into();
    body.extend_from_slice(&digest);
    body
}
