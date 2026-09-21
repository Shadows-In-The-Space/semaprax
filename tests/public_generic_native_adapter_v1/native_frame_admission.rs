//! Issue #173: native-only admission of descriptor-bound logical carrier
//! frames. Physical consumer dispatch/transfer integration remains open.

use std::path::Path;

use semaprax::public_generic_abi::carrier::frame::{CarrierLeaf, LeafKind};
use semaprax::public_generic_abi::carrier::{
    CARRIER_CAPACITY, CARRIER_REPLAY_MISMATCH, HANDLE_GENERATION_MISMATCH, ILLEGAL_TRANSITION,
    MALFORMED_CARRIER,
};
use semaprax::public_generic_abi::descriptor::producer;
use semaprax::public_generic_abi::descriptor::verify::{
    verify_public_generic_descriptor, VerificationOptions, VerifiedPublicGenericDescriptor,
};
use semaprax::public_generic_abi::native::admission::{
    NativeCarrierOwnership, NativeInputAdmission, NativeInputTicket,
};
use sha2::{Digest as _, Sha256};

const SOURCE: &str = r#"
module test.public_generic_native_admission;

@id("native.admission.leaf")
record Leaf {
    @id("native.admission.leaf.bytes")
    bytes: Bytes,
}

@id("native.admission.box")
record Box<T> {
    @id("native.admission.box.value")
    value: T,
}

@id("native.admission.transform")
fn transform(value: own Box<Leaf>) -> Box<Leaf> { value }

@id("app.main")
fn main() -> i64 { 0 }
"#;

const REVISION: &str = "issue173-native-admission-v1";

fn program_root(program: &semaprax::hir::ResolvedProgram) -> String {
    let mut ids = Vec::new();
    ids.extend(program.types.iter().map(|item| item.id.as_str()));
    ids.extend(
        program
            .function_templates
            .iter()
            .map(|item| item.id.as_str()),
    );
    ids.extend(program.functions.iter().map(|item| item.id.as_str()));
    ids.extend(
        program
            .function_instances
            .iter()
            .map(|item| item.id.as_str()),
    );
    ids.sort_unstable();
    ids.dedup();
    let mut preimage = Vec::new();
    let mut append = |bytes: &[u8]| {
        preimage.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(bytes);
    };
    append(&(ids.len() as u64).to_le_bytes());
    for id in ids {
        append(id.as_bytes());
    }
    drop(append);
    let mut hasher = Sha256::new();
    hasher.update(b"semaprax.public-generic-descriptor.v1.program-root\0");
    hasher.update((preimage.len() as u64).to_le_bytes());
    hasher.update(preimage);
    format!(
        "sha256:{:x}",
        semaprax::digest_hex::LowerHex(hasher.finalize())
    )
}

fn verified_descriptor() -> VerifiedPublicGenericDescriptor {
    let parsed = semaprax::parse(SOURCE, Path::new("issue173-native-admission.spx"))
        .expect("the native admission fixture must parse");
    let program =
        semaprax::hir::resolve(&parsed).expect("the native admission fixture must resolve");
    let generated = producer::generate_public_generic_descriptor(
        &program,
        REVISION,
        "native.admission.transform",
    )
    .expect("the native admission fixture must generate a descriptor");
    verify_public_generic_descriptor(
        &program,
        REVISION,
        "native.admission.transform",
        &program_root(&program),
        generated.wire_bytes(),
        &VerificationOptions::default(),
    )
    .expect("the generated native admission descriptor must independently verify")
}

const CASES: &[(&str, &str)] = &[
    (
        "native_carrier_stale_generation",
        HANDLE_GENERATION_MISMATCH,
    ),
    ("native_carrier_provider_owned_input", ILLEGAL_TRANSITION),
    (
        "native_carrier_substituted_field_path",
        CARRIER_REPLAY_MISMATCH,
    ),
    ("native_carrier_unknown_leaf_kind_tag", MALFORMED_CARRIER),
    ("native_carrier_overlong_leaf", CARRIER_CAPACITY),
    (
        "native_carrier_substituted_cleanup_plan",
        CARRIER_REPLAY_MISMATCH,
    ),
];

#[test]
fn native_descriptor_bound_admission_refuses_hostile_tickets() {
    let descriptor = verified_descriptor();
    let admission = NativeInputAdmission::from_verified_descriptor(&descriptor, 41)
        .expect("a verified descriptor creates the native input boundary");
    let leaves = admission
        .binding()
        .leaf_paths()
        .iter()
        .enumerate()
        .map(|(index, path)| {
            CarrierLeaf::new(path.clone(), LeafKind::Bytes, vec![index as u8, 0xff])
        })
        .collect::<Vec<_>>();
    assert!(
        !leaves.is_empty(),
        "the fixture must expose an owned input leaf"
    );
    let valid_frame = admission
        .binding()
        .frame_with_leaves(leaves.clone())
        .encode();
    let valid_ticket = || {
        NativeInputTicket::new(
            admission.generation(),
            NativeCarrierOwnership::Caller,
            admission.cleanup_plan_digest(),
            valid_frame.clone(),
        )
    };

    let mut path_substitution = leaves.clone();
    path_substitution[0] = CarrierLeaf::new(
        "native.admission.hostile.substituted.path",
        LeafKind::Bytes,
        path_substitution[0].payload().to_vec(),
    );
    let field_path_frame = admission
        .binding()
        .frame_with_leaves(path_substitution)
        .encode();
    let first_path = admission.binding().leaf_paths()[0].as_bytes();
    let path_offset = valid_frame
        .windows(first_path.len())
        .position(|window| window == first_path)
        .expect("the first trusted path occurs verbatim in its encoded leaf")
        + first_path.len();
    let mut unknown_tag_frame = valid_frame.clone();
    assert_eq!(
        unknown_tag_frame[path_offset], 0,
        "the valid Bytes leaf uses tag zero"
    );
    unknown_tag_frame[path_offset] = 1;
    let mut overlong_leaf_frame = valid_frame.clone();
    let length_offset = path_offset + 1;
    overlong_leaf_frame[length_offset..length_offset + 8]
        .copy_from_slice(&(65_537u64).to_le_bytes());

    let cleanup = format!("{}-substituted", admission.cleanup_plan_digest());
    let cases = vec![
        (
            CASES[0],
            NativeInputTicket::new(
                admission.generation() + 1,
                NativeCarrierOwnership::Caller,
                admission.cleanup_plan_digest(),
                valid_frame.clone(),
            ),
        ),
        (
            CASES[1],
            NativeInputTicket::new(
                admission.generation(),
                NativeCarrierOwnership::Provider,
                admission.cleanup_plan_digest(),
                valid_frame.clone(),
            ),
        ),
        (
            CASES[2],
            NativeInputTicket::new(
                admission.generation(),
                NativeCarrierOwnership::Caller,
                admission.cleanup_plan_digest(),
                field_path_frame,
            ),
        ),
        (
            CASES[3],
            NativeInputTicket::new(
                admission.generation(),
                NativeCarrierOwnership::Caller,
                admission.cleanup_plan_digest(),
                unknown_tag_frame,
            ),
        ),
        (
            CASES[4],
            NativeInputTicket::new(
                admission.generation(),
                NativeCarrierOwnership::Caller,
                admission.cleanup_plan_digest(),
                overlong_leaf_frame,
            ),
        ),
        (
            CASES[5],
            NativeInputTicket::new(
                admission.generation(),
                NativeCarrierOwnership::Caller,
                cleanup,
                valid_frame.clone(),
            ),
        ),
    ];

    for ((name, expected_code), ticket) in cases {
        let error = admission
            .admit(&ticket)
            .expect_err("hostile ticket must fail native admission");
        assert_eq!(error.code, expected_code, "{name}: stable refusal class");
    }

    let admitted = admission
        .admit(&valid_ticket())
        .expect("the unmodified frame must admit");
    assert_eq!(admitted, leaves, "the valid control exposes the bound leaves");
}
