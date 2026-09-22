//! One compiler-derived, independently verified public-generic subject shared
//! by the native physical-provider and generated-caller integration tests.
//!
//! The native provider remains the deliberately fixed byte-reversal fixture.
//! This helper narrows a different, previously hidden gap: its descriptor and
//! binding are no longer hand-assembled placeholders.  Every caller first
//! parses and resolves a real generic owned-record export, derives its
//! descriptor, publishes the source into the retained-subject verifier, and
//! accepts only the verifier's exact canonical bytes before constructing the
//! physical binding.

// This support file is included independently by several harness modules;
// each consumer intentionally uses only the facts its own route can observe.
#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::hir;
use semaprax::parse;
use semaprax::public_generic_abi::carrier::{CarrierBindingV1, TargetProfile};
use semaprax::public_generic_abi::descriptor::producer::generate_public_generic_descriptor;
use semaprax::public_generic_abi::descriptor::verify::retained_store::{
    verify_public_generic_descriptor_against_store, RetainedProgramStore,
};
use semaprax::public_generic_abi::descriptor::verify::VerificationOptions;
use semaprax::public_generic_abi::native::binding::NativeProviderBindingV1;

const EXPORT_ID: &str = "admitted.subject.transform";
const SOURCE_REVISION: &str = "public-generic-admitted-subject-v1";
const MAX_OWNED_LEAVES: usize = 256;
static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

/// Trusted test inputs for one native reference-provider rendering.
///
/// `binding` is derived from the independently verified descriptor identity.
/// Its endpoint stays the native adapter's fixture endpoint; callers must not
/// describe this helper as generated endpoint code.
pub(crate) struct NativeAdmittedSubject {
    descriptor_bytes: Vec<u8>,
    binding: NativeProviderBindingV1,
    leaf_identities: Vec<String>,
    descriptor_digest: String,
    input_instance_term: String,
    result_instance_term: String,
    cleanup_plan_digest: String,
}

impl NativeAdmittedSubject {
    pub(crate) fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    pub(crate) fn binding(&self) -> &NativeProviderBindingV1 {
        &self.binding
    }

    pub(crate) fn leaf_identities(&self) -> &[String] {
        &self.leaf_identities
    }

    pub(crate) fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub(crate) fn input_instance_term(&self) -> &str {
        &self.input_instance_term
    }

    pub(crate) fn result_instance_term(&self) -> &str {
        &self.result_instance_term
    }

    pub(crate) fn cleanup_plan_digest(&self) -> &str {
        &self.cleanup_plan_digest
    }
}

fn source(owned_leaf_count: usize) -> String {
    assert!(
        (1..=MAX_OWNED_LEAVES).contains(&owned_leaf_count),
        "the admitted subject must have 1..={MAX_OWNED_LEAVES} owned leaves"
    );
    let mut text = String::from(
        "module test.public_generic_admitted_subject;\n\n\
         @id(\"admitted.subject.leaf\")\n\
         record Leaf {\n",
    );
    for index in 0..owned_leaf_count {
        text.push_str(&format!(
            "    @id(\"admitted.subject.leaf.{index}\")\n    leaf_{index}: Bytes,\n"
        ));
    }
    text.push_str(
        "}\n\n\
         @id(\"admitted.subject.envelope\")\n\
         record Envelope<T> {\n\
             @id(\"admitted.subject.envelope.payload\")\n\
             payload: T,\n\
             @id(\"admitted.subject.envelope.marker\")\n\
             marker: i64,\n\
         }\n\n\
         @id(\"admitted.subject.transform\")\n\
         fn transform(value: own Envelope<Leaf>) -> Envelope<Leaf> { value }\n\n\
         @id(\"app.main\")\n\
         fn main() -> i64 { 0 }\n",
    );
    text
}

fn store_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "semaprax-public-generic-admitted-subject-{}-{}",
        std::process::id(),
        NEXT_STORE.fetch_add(1, Ordering::Relaxed)
    ))
}

struct TemporaryStore(std::path::PathBuf);

impl TemporaryStore {
    fn new() -> Self {
        Self(store_root())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Derive and independently verify a real generic owned-record descriptor.
///
/// The temporary retained store is an input to verification only. Its drop
/// guard removes it on both successful verification and every panic path.
pub(crate) fn native_admitted_subject(owned_leaf_count: usize) -> NativeAdmittedSubject {
    let source = source(owned_leaf_count);
    let program = hir::resolve(
        &parse(&source, Path::new("public-generic-admitted-subject.spx"))
            .expect("the admitted-subject source must parse"),
    )
    .expect("the admitted-subject source must resolve");
    let generated = generate_public_generic_descriptor(&program, SOURCE_REVISION, EXPORT_ID)
        .expect("the admitted generic export must generate a descriptor");

    let root = TemporaryStore::new();
    let store = RetainedProgramStore::open(root.path()).expect("open retained-subject store");
    let expected_root = store
        .publish_current(&source, SOURCE_REVISION)
        .expect("publish the exact trusted source");
    let verified = verify_public_generic_descriptor_against_store(
        &store,
        &expected_root,
        EXPORT_ID,
        generated.wire_bytes(),
        &VerificationOptions::current_head(),
    )
    .expect("independent retained-subject verification must accept generated bytes");
    let cleanup_plan_digest = verified.settlement().digest().to_owned();
    let input_instance_term = verified.input_facts().term.clone();
    let result_instance_term = verified.result_facts().term.clone();
    let descriptor_digest = verified.descriptor_digest();
    let descriptor_bytes = verified.accepted_bytes().to_vec();

    let binding = NativeProviderBindingV1::new(
        CarrierBindingV1::new(
            descriptor_digest.clone(),
            TargetProfile::NativeC11,
            "runtime:native-c11-compiler-derived-subject-v1",
        ),
        "sha256:1df9d5c0e52b38de37bb2a62e971cd2ce6cbf4f5f4c0832b0fd8e8ca7d86f921",
        "spx_pg_endpoint_reverse_bytes_v1",
        "semaprax-native-reference-fixture-v1",
    );

    NativeAdmittedSubject {
        descriptor_bytes,
        binding,
        leaf_identities: (0..owned_leaf_count)
            .map(|index| format!("admitted.subject.leaf.{index}"))
            .collect(),
        descriptor_digest,
        input_instance_term,
        result_instance_term,
        cleanup_plan_digest,
    }
}
