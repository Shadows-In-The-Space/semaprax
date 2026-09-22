//! Issue #173: [Hostile Carrier Corpus
//! v1](../../docs/PUBLIC-GENERIC-CARRIER-HOSTILE-CORPUS-V1.md) driven
//! against a **real** `VerifiedPublicGenericDescriptor` rather than the
//! corpus's own published fixture, with a five-counter effect ledger.
//!
//! The corpus module's own tests pin the manifest and cross-check two
//! independent readers against a fixed fixture plan. That proves the readers
//! agree; it does not prove the fixture's derivation rule is the one a real
//! descriptor produces, nor that a hostile ticket stops before any effect.
//! Both are proved here:
//!
//! 1. the production `CarrierFrameBinding::from_verified_descriptor` is
//!    shown to derive exactly the identities the independent reference
//!    recomputes from the same real descriptor's trusted roots;
//! 2. every hostile ticket, re-expressed against that real plan, is refused
//!    by `NativeInputAdmission` and by the independent reference guard with
//!    the same closed public class, and leaves an allocation, target
//!    invocation, ownership commit, host call and cleanup counter all at
//!    zero.
//!
//! Scope, stated rather than implied: `admit_then`'s callback is the only
//! sequencing point an installer has, so a zero callback count is real
//! evidence that admission precedes any installer effect. It is **not**
//! evidence that the rendered C11 provider, the Core Wasm provider, or any
//! generated calling consumer is guarded at its own physical handoff. No
//! production caller installs this guard there yet; that integration remains
//! open and overlaps issue #229.

use std::cell::Cell;

use semaprax::diagnostic::Diagnostic;
use semaprax::public_generic_abi::carrier::frame::{CarrierFrameBinding, CarrierLeaf, LeafKind};
use semaprax::public_generic_abi::carrier::hostile_corpus::{
    self, layout, CarrierHostileCase, Expected, CARRIER_HOSTILE_CORPUS_CASE_COUNT,
    CARRIER_HOSTILE_CORPUS_SCHEMA,
};
use semaprax::public_generic_abi::carrier::reference_decoder::{
    endpoint_identity_digest, leaf_inventory_digest, remint_facts_digest, CarrierRefusal,
    ReferenceAdmission, ReferenceOwnership, ReferencePlan, ReferenceTicket,
};
use semaprax::public_generic_abi::carrier::trace::Direction;
use semaprax::public_generic_abi::descriptor::verify::VerifiedPublicGenericDescriptor;
use semaprax::public_generic_abi::native::admission::{
    NativeCarrierOwnership, NativeInputAdmission, NativeInputTicket,
};

use crate::native_frame_admission::verified_descriptor;

/// The live attempt identity this module's guard is built for. Deliberately
/// greater than one, so both a stale and a future neighbour exist.
const GENERATION: u64 = 41;

/// A different deployed export, used for cross-endpoint replay.
const ALTERNATE_EXPORT_ID: &str = "native.admission.other_transform";
/// A different artifact's descriptor identity.
const ALTERNATE_DESCRIPTOR_DIGEST: &str =
    "sha256:9999999999999999999999999999999999999999999999999999999999999999";
/// A different concrete instantiation's identity.
const ALTERNATE_INSTANCE_DIGEST: &str =
    "sha256:8888888888888888888888888888888888888888888888888888888888888888";

/// Every effect an installer could perform after admission. A hostile ticket
/// must leave all five at zero: issue #173's "no hostile case increments
/// call, allocation, transfer, or cleanup counters".
#[derive(Default)]
struct EffectLedger {
    allocations: Cell<u32>,
    target_invocations: Cell<u32>,
    ownership_commits: Cell<u32>,
    host_calls: Cell<u32>,
    cleanups: Cell<u32>,
}

impl EffectLedger {
    /// The single place any effect is recorded. Called only from inside an
    /// `admit_then` callback, so reaching it at all means admission
    /// succeeded first.
    fn record_full_installation(&self, leaves: usize) {
        self.allocations.set(self.allocations.get() + leaves as u32);
        self.target_invocations
            .set(self.target_invocations.get() + 1);
        self.ownership_commits.set(self.ownership_commits.get() + 1);
        self.host_calls.set(self.host_calls.get() + 1);
        self.cleanups.set(self.cleanups.get() + 1);
    }

    fn totals(&self) -> [u32; 5] {
        [
            self.allocations.get(),
            self.target_invocations.get(),
            self.ownership_commits.get(),
            self.host_calls.get(),
            self.cleanups.get(),
        ]
    }

    fn assert_untouched(&self, case: &str) {
        assert_eq!(
            self.totals(),
            [0, 0, 0, 0, 0],
            "{case}: a refused ticket reached allocation, target invocation, \
             ownership commit, a host call, or cleanup"
        );
    }
}

/// The trusted production binding for the real descriptor's input side.
fn production_binding(descriptor: &VerifiedPublicGenericDescriptor) -> CarrierFrameBinding {
    CarrierFrameBinding::from_verified_descriptor(descriptor, Direction::Input)
}

/// The independent reference plan for the same real descriptor, built from
/// its trusted roots only.
fn reference_plan(descriptor: &VerifiedPublicGenericDescriptor) -> ReferencePlan {
    ReferencePlan::new(
        Direction::Input,
        descriptor.descriptor_digest(),
        descriptor.export_id(),
        descriptor.input_facts().instance_digest.clone(),
        descriptor.input_facts().owned_leaves.clone(),
    )
}

/// Canonical leaf values for the real descriptor's inventory. Includes an
/// empty leaf and a leaf with an embedded zero and a non-UTF-8 byte, so an
/// encoder that treats payloads as text fails here too.
fn canonical_leaves(binding: &CarrierFrameBinding) -> Vec<CarrierLeaf> {
    binding
        .leaf_paths()
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let payload = if index % 2 == 0 {
                vec![0x00, 0x80, 0xff]
            } else {
                Vec::new()
            };
            CarrierLeaf::new(path.clone(), LeafKind::Bytes, payload)
        })
        .collect()
}

/// One hostile entry expressed against the real descriptor's plan.
struct RealCase {
    id: &'static str,
    /// The single closed class both readers must publish.
    expected: CarrierRefusal,
    generation: u64,
    ownership: NativeCarrierOwnership,
    cleanup_plan_digest: String,
    document: Vec<u8>,
}

/// Build every hostile entry against the real plan. The document edits
/// mirror the corpus's own recorded mutation vocabulary; only the fixture
/// they are applied to differs.
fn real_cases(descriptor: &VerifiedPublicGenericDescriptor) -> Vec<RealCase> {
    let binding = production_binding(descriptor);
    let plan = reference_plan(descriptor);
    let leaves = canonical_leaves(&binding);
    let canonical = binding.frame_with_leaves(leaves.clone()).encode();
    let cleanup = descriptor.settlement().digest().to_owned();

    let entry = |id: &'static str, expected: CarrierRefusal, document: Vec<u8>| RealCase {
        id,
        expected,
        generation: GENERATION,
        ownership: NativeCarrierOwnership::Caller,
        cleanup_plan_digest: cleanup.clone(),
        document,
    };
    let envelope = |id: &'static str,
                    expected: CarrierRefusal,
                    generation: u64,
                    ownership: NativeCarrierOwnership,
                    cleanup_plan_digest: String| RealCase {
        id,
        expected,
        generation,
        ownership,
        cleanup_plan_digest,
        document: canonical.clone(),
    };

    let places = layout(&canonical);
    let mut cases = Vec::new();

    // -- Framing -----------------------------------------------------
    let mut truncated = canonical.clone();
    truncated.pop();
    cases.push(entry(
        "truncated_final_byte",
        CarrierRefusal::Malformed,
        truncated,
    ));

    let mut trailing = canonical.clone();
    trailing.push(0xa5);
    cases.push(entry(
        "trailing_byte_after_self_digest",
        CarrierRefusal::Malformed,
        trailing,
    ));

    let mut inside_count = canonical.clone();
    inside_count.truncate(places.leaf_count + 4);
    cases.push(entry(
        "truncated_inside_declared_leaf_count",
        CarrierRefusal::Malformed,
        inside_count,
    ));

    // -- Frozen literals and closed vocabularies ---------------------
    let mut schema = canonical.clone();
    schema[places.schema.end - 1] = b'2';
    cases.push(entry(
        "unknown_schema_literal",
        CarrierRefusal::Malformed,
        schema,
    ));

    let mut direction = canonical.clone();
    direction[places.direction.end - 1] = b'X';
    cases.push(entry(
        "unknown_direction_literal",
        CarrierRefusal::Malformed,
        direction,
    ));

    let mut bad_utf8 = canonical.clone();
    bad_utf8[places.leaves[0].0.start] = 0xff;
    cases.push(entry(
        "invalid_utf8_leaf_path",
        CarrierRefusal::Malformed,
        bad_utf8,
    ));

    let mut unknown_tag = canonical.clone();
    assert_eq!(
        unknown_tag[places.leaves[0].1], 0,
        "the canonical Bytes leaf uses variant tag zero"
    );
    unknown_tag[places.leaves[0].1] = 0xff;
    cases.push(entry(
        "unknown_leaf_kind_tag",
        CarrierRefusal::Malformed,
        unknown_tag,
    ));

    // -- Bounds: exact maximum versus maximum plus one ---------------
    let mut count_at_bound = canonical.clone();
    count_at_bound[places.leaf_count..places.leaf_count + 8].copy_from_slice(&256u64.to_le_bytes());
    cases.push(entry(
        "declared_leaf_count_at_exact_bound",
        CarrierRefusal::Malformed,
        count_at_bound,
    ));

    let mut count_over_bound = canonical.clone();
    count_over_bound[places.leaf_count..places.leaf_count + 8]
        .copy_from_slice(&257u64.to_le_bytes());
    cases.push(entry(
        "declared_leaf_count_one_over_bound",
        CarrierRefusal::Capacity,
        count_over_bound,
    ));

    let mut count_saturated = canonical.clone();
    count_saturated[places.leaf_count..places.leaf_count + 8]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    cases.push(entry(
        "declared_leaf_count_u64_max",
        CarrierRefusal::Capacity,
        count_saturated,
    ));

    let mut total_over_bound = canonical.clone();
    total_over_bound[places.total_payload..places.total_payload + 8]
        .copy_from_slice(&(16u64 * 1024 * 1024 + 1).to_le_bytes());
    cases.push(entry(
        "declared_total_payload_one_over_bound",
        CarrierRefusal::Capacity,
        total_over_bound,
    ));

    let mut total_mismatch = canonical.clone();
    total_mismatch[places.total_payload..places.total_payload + 8]
        .copy_from_slice(&(16u64 * 1024 * 1024).to_le_bytes());
    cases.push(entry(
        "declared_total_payload_at_exact_bound",
        CarrierRefusal::Malformed,
        total_mismatch,
    ));

    let payload_length = places.leaves[0].2;
    let mut leaf_over_bound = canonical.clone();
    leaf_over_bound[payload_length..payload_length + 8].copy_from_slice(&65_537u64.to_le_bytes());
    cases.push(entry(
        "declared_leaf_payload_one_over_bound",
        CarrierRefusal::Capacity,
        leaf_over_bound,
    ));

    let mut leaf_at_bound = canonical.clone();
    leaf_at_bound[payload_length..payload_length + 8].copy_from_slice(&65_536u64.to_le_bytes());
    cases.push(entry(
        "declared_leaf_payload_at_exact_bound",
        CarrierRefusal::Malformed,
        leaf_at_bound,
    ));

    let mut leaf_saturated = canonical.clone();
    leaf_saturated[payload_length..payload_length + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    cases.push(entry(
        "declared_leaf_payload_u64_max",
        CarrierRefusal::Capacity,
        leaf_saturated,
    ));

    // -- Self-digest -------------------------------------------------
    let mut corrupt_digest = canonical.clone();
    let at = places.facts_digest.end - 1;
    corrupt_digest[at] = if corrupt_digest[at] == b'0' {
        b'1'
    } else {
        b'0'
    };
    cases.push(entry(
        "corrupted_self_digest",
        CarrierRefusal::ReplayMismatch,
        corrupt_digest,
    ));

    // -- Cross-artifact, cross-endpoint, cross-instance, cross-runtime --
    // Each is a fully well-formed, internally self-consistent document: a
    // legitimate credential for a different subject, never a corrupted byte
    // string.
    let alternate = |descriptor_digest: &str, endpoint: String, instance: &str| {
        CarrierFrameBinding::new(
            Direction::Input,
            descriptor_digest,
            endpoint,
            instance,
            binding.leaf_paths().to_vec(),
        )
        .frame_with_leaves(leaves.clone())
        .encode()
    };
    cases.push(entry(
        "cross_artifact_descriptor_identity",
        CarrierRefusal::ReplayMismatch,
        alternate(
            ALTERNATE_DESCRIPTOR_DIGEST,
            endpoint_identity_digest(descriptor.export_id()),
            &descriptor.input_facts().instance_digest,
        ),
    ));
    cases.push(entry(
        "cross_endpoint_identity",
        CarrierRefusal::ReplayMismatch,
        alternate(
            &descriptor.descriptor_digest(),
            endpoint_identity_digest(ALTERNATE_EXPORT_ID),
            &descriptor.input_facts().instance_digest,
        ),
    ));
    cases.push(entry(
        "cross_instance_identity",
        CarrierRefusal::ReplayMismatch,
        alternate(
            &descriptor.descriptor_digest(),
            endpoint_identity_digest(descriptor.export_id()),
            ALTERNATE_INSTANCE_DIGEST,
        ),
    ));

    // A result-direction document submitted to an input-direction plan.
    cases.push(entry(
        "cross_direction_result_document",
        CarrierRefusal::ReplayMismatch,
        CarrierFrameBinding::from_verified_descriptor(descriptor, Direction::Result)
            .frame_with_leaves(
                CarrierFrameBinding::from_verified_descriptor(descriptor, Direction::Result)
                    .leaf_paths()
                    .iter()
                    .map(|path| CarrierLeaf::new(path.clone(), LeafKind::Bytes, Vec::new()))
                    .collect(),
            )
            .encode(),
    ));

    // A reminted forgery: the inventory identity names a different shape and
    // the trailing digest was recomputed over that change, so the document is
    // self-consistent end to end. Only recomputing the inventory identity
    // from the trusted path list refuses it.
    let foreign_inventory = leaf_inventory_digest(&[
        "other.head".to_owned(),
        "other.middle".to_owned(),
        "other.tail".to_owned(),
    ]);
    let mut reminted = canonical.clone();
    let inventory_range = sixth_field_range(&reminted);
    assert_eq!(inventory_range.len(), foreign_inventory.len());
    reminted[inventory_range].copy_from_slice(foreign_inventory.as_bytes());
    let reminted =
        remint_facts_digest(&reminted).expect("the mutated body still parses structurally");
    cases.push(entry(
        "reminted_foreign_inventory_identity",
        CarrierRefusal::ReplayMismatch,
        reminted,
    ));

    // A substituted leaf path, carrying the trusted inventory identity and a
    // reminted digest, so only the path sequence betrays the substitution.
    let mut substituted = leaves.clone();
    substituted[0] = CarrierLeaf::new(
        format!("{}.substituted", binding.leaf_paths()[0]),
        LeafKind::Bytes,
        substituted[0].payload().to_vec(),
    );
    let mut substituted_document = CarrierFrameBinding::new(
        Direction::Input,
        descriptor.descriptor_digest(),
        endpoint_identity_digest(descriptor.export_id()),
        descriptor.input_facts().instance_digest.clone(),
        substituted
            .iter()
            .map(|leaf| leaf.path().to_owned())
            .collect(),
    )
    .frame_with_leaves(substituted)
    .encode();
    let trusted_inventory = leaf_inventory_digest(plan.leaf_paths());
    let inventory_range = sixth_field_range(&substituted_document);
    substituted_document[inventory_range].copy_from_slice(trusted_inventory.as_bytes());
    cases.push(entry(
        "substituted_leaf_path",
        CarrierRefusal::ReplayMismatch,
        remint_facts_digest(&substituted_document).expect("a canonical body"),
    ));

    // -- Admission envelope ------------------------------------------
    cases.push(envelope(
        "stale_generation_replay",
        CarrierRefusal::GenerationMismatch,
        GENERATION - 1,
        NativeCarrierOwnership::Caller,
        cleanup.clone(),
    ));
    cases.push(envelope(
        "future_generation_replay",
        CarrierRefusal::GenerationMismatch,
        GENERATION + 1,
        NativeCarrierOwnership::Caller,
        cleanup.clone(),
    ));
    cases.push(envelope(
        "zero_generation_replay",
        CarrierRefusal::GenerationMismatch,
        0,
        NativeCarrierOwnership::Caller,
        cleanup.clone(),
    ));
    cases.push(envelope(
        "provider_owned_before_transfer",
        CarrierRefusal::IllegalTransition,
        GENERATION,
        NativeCarrierOwnership::Provider,
        cleanup.clone(),
    ));
    cases.push(envelope(
        "substituted_cleanup_plan",
        CarrierRefusal::ReplayMismatch,
        GENERATION,
        NativeCarrierOwnership::Caller,
        format!("{cleanup}-substituted"),
    ));

    cases
}

/// The content range of the sixth framed field — the leaf-inventory
/// identity — of a canonical document.
fn sixth_field_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut offset = 0usize;
    let mut range = 0..0;
    for field in 0..6 {
        let length = usize::try_from(u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("an 8-byte length header"),
        ))
        .expect("a canonical field length fits in usize");
        let start = offset + 8;
        offset = start + length;
        if field == 5 {
            range = start..offset;
        }
    }
    range
}

#[test]
fn the_production_binding_derives_exactly_the_independently_recomputed_identities() {
    // The corpus's published fixture is only meaningful if its derivation
    // rule is the one a real verified descriptor produces. Pin that here,
    // against the real thing, rather than assuming it.
    let descriptor = verified_descriptor();
    let binding = production_binding(&descriptor);
    let plan = reference_plan(&descriptor);

    assert_eq!(binding.leaf_paths(), plan.leaf_paths());
    assert_eq!(
        plan.endpoint_identity_digest(),
        endpoint_identity_digest(descriptor.export_id()),
        "the endpoint identity must be recomputed from the trusted export \
         identity, never read from a document"
    );
    assert_eq!(
        plan.leaf_inventory_digest(),
        leaf_inventory_digest(binding.leaf_paths()),
        "the inventory identity must be recomputed from the trusted canonical \
         path list"
    );

    // The decisive check: a document the PRODUCTION binding forms is
    // admitted by the INDEPENDENT reader against the plan derived from the
    // same descriptor. If the two derivations disagreed anywhere, this fails.
    let document = binding
        .frame_with_leaves(canonical_leaves(&binding))
        .encode();
    let admitted =
        semaprax::public_generic_abi::carrier::reference_decoder::decode_and_bind(&document, &plan)
            .expect("the independent reader admits a production-formed document");
    assert_eq!(
        admitted
            .iter()
            .map(|leaf| leaf.path.as_str())
            .collect::<Vec<_>>(),
        binding
            .leaf_paths()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_hostile_ticket_is_refused_identically_by_both_guards_with_no_effect() {
    let descriptor = verified_descriptor();
    let admission = NativeInputAdmission::from_verified_descriptor(&descriptor, GENERATION)
        .expect("a verified descriptor creates the native input boundary");
    let reference = ReferenceAdmission::new(
        reference_plan(&descriptor),
        GENERATION,
        descriptor.settlement().digest(),
    )
    .expect("the live generation is nonzero");

    let cases = real_cases(&descriptor);
    assert!(
        cases.len() >= 25,
        "the real-descriptor hostile table must stay broad"
    );

    let ledger = EffectLedger::default();
    let mut divergences = Vec::new();
    for case in &cases {
        let native = NativeInputTicket::new(
            case.generation,
            case.ownership,
            case.cleanup_plan_digest.clone(),
            case.document.clone(),
        );
        let error = admission
            .admit_then(&native, |leaves| {
                ledger.record_full_installation(leaves.len());
                Ok::<_, Diagnostic>(())
            })
            .expect_err("a hostile ticket must never reach the installer callback");
        let native_class = CarrierRefusal::from_code(&error.code).unwrap_or_else(|| {
            panic!(
                "{}: the native guard refused with {}, outside the closed carrier class",
                case.id, error.code
            )
        });
        ledger.assert_untouched(case.id);

        let reference_class = reference
            .admit(&ReferenceTicket {
                generation: case.generation,
                ownership: match case.ownership {
                    NativeCarrierOwnership::Caller => ReferenceOwnership::Caller,
                    NativeCarrierOwnership::Provider => ReferenceOwnership::Provider,
                },
                cleanup_plan_digest: case.cleanup_plan_digest.clone(),
                frame_bytes: case.document.clone(),
            })
            .expect_err("a hostile ticket must fail closed in the reference guard");

        if native_class != case.expected
            || reference_class != case.expected
            || native_class != reference_class
        {
            divergences.push(format!(
                "{}\texpected {:?}\tnative {:?}\treference {:?}",
                case.id, case.expected, native_class, reference_class
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "two guards that share no code disagreed, or disagreed with the \
         manifest:\n{}",
        divergences.join("\n")
    );
    ledger.assert_untouched("the whole hostile table");
}

#[test]
fn the_canonical_control_reaches_the_installer_and_records_every_effect_once() {
    // A guard that refused everything would pass the test above. The control
    // proves the ledger can move at all, and that it moves exactly once.
    let descriptor = verified_descriptor();
    let admission = NativeInputAdmission::from_verified_descriptor(&descriptor, GENERATION)
        .expect("a verified descriptor creates the native input boundary");
    let binding = production_binding(&descriptor);
    let leaves = canonical_leaves(&binding);
    let document = binding.frame_with_leaves(leaves.clone()).encode();

    let ledger = EffectLedger::default();
    let admitted = admission
        .admit_then(
            &NativeInputTicket::new(
                GENERATION,
                NativeCarrierOwnership::Caller,
                descriptor.settlement().digest(),
                document,
            ),
            |admitted| {
                ledger.record_full_installation(admitted.len());
                Ok::<_, Diagnostic>(admitted.to_vec())
            },
        )
        .expect("the canonical control reaches the installer callback");
    assert_eq!(admitted, leaves);
    assert_eq!(
        ledger.totals(),
        [leaves.len() as u32, 1, 1, 1, 1],
        "the control must record exactly one of each effect"
    );
}

#[test]
fn the_published_corpus_manifest_is_bound_into_this_harness() {
    // Binding the corpus version here means a corpus edit that forgets to
    // mint a new version, or that drops cases, fails in the harness that
    // claims to drive it -- not only in the corpus's own module.
    assert_eq!(
        CARRIER_HOSTILE_CORPUS_SCHEMA,
        "semaprax.public-generic-carrier-hostile-corpus.v1"
    );
    let cases: Vec<CarrierHostileCase> = hostile_corpus::cases();
    assert_eq!(cases.len(), CARRIER_HOSTILE_CORPUS_CASE_COUNT);
    let admitted = cases
        .iter()
        .filter(|case| matches!(case.expected, Expected::Admitted))
        .count();
    assert_eq!(
        admitted, 3,
        "the corpus must keep its positive controls: a reader that refuses \
         everything must fail it"
    );
    assert!(
        cases.iter().all(|case| case.expected_code().is_none()
            || case
                .expected_code()
                .is_some_and(|code| CarrierRefusal::from_code(code).is_some())),
        "every published expectation must lie inside the closed carrier class"
    );
}
