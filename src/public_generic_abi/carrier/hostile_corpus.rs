//! Issue #173: [Hostile Carrier Corpus
//! v1](../../../docs/PUBLIC-GENERIC-CARRIER-HOSTILE-CORPUS-V1.md) — the one
//! canonical, versioned manifest of hostile logical-carrier documents and
//! admission tickets.
//!
//! # The contract this module encodes
//!
//! Every entry is a [`CarrierHostileCase`]. Each one:
//!
//! 1. names **exactly one** violated invariant ([`CarrierInvariant`]) — never
//!    a bundle, so a reader that refuses for the wrong reason cannot be
//!    scored as agreeing;
//! 2. carries its hostile bytes as a **recorded mutation**
//!    ([`CarrierMutation`], [`TicketMutation`]) of the canonical valid
//!    fixture, not as an opaque literal, so the corpus regenerates
//!    deterministically on any host;
//! 3. pins the SHA-256 of the produced document, so a regenerated corpus
//!    that silently drifts fails its known-answer instead of quietly
//!    covering less;
//! 4. states the single expected outcome as a closed
//!    [`CarrierRefusal`](super::reference_decoder::CarrierRefusal) class, or
//!    as deliberate admission for a positive control.
//!
//! The whole manifest is itself bound by [`CARRIER_HOSTILE_CORPUS_DIGEST`].
//!
//! # Two independent readers, one expected class
//!
//! Each case is driven through two implementations that share no code: the
//! production codec ([`super::frame::parse_bounded`] plus
//! [`super::frame::CarrierFrameBinding::validate_frame`], wrapped by
//! [`crate::public_generic_abi::native::admission::NativeInputAdmission`])
//! and the independent
//! [reference decoder](super::reference_decoder). Both must publish the same
//! closed class. A defect that a self-checking corpus would mirror is
//! therefore caught by disagreement between the two readers.
//!
//! # Reminting: manufacturing the forgery a digest-only reader accepts
//!
//! Several cases set [`Remint::Recompute`]. After the body is mutated, the
//! trailing `carrier_facts_digest` is recomputed over the *mutated* body, so
//! the document is fully internally self-consistent: every structural check,
//! every bound, and the document's own self-digest all succeed. Such a
//! document is refused only because both readers recompute the endpoint and
//! inventory identities from the **trusted plan's roots** rather than
//! accepting the wire's copies. These are the cases that discriminate a real
//! trusted-root replay from a digest-only check, which is the first failure
//! mode issue #173 names.
//!
//! # Scope, stated rather than implied
//!
//! This corpus covers the target-neutral logical carrier frame and the
//! native pre-dispatch admission envelope. It is not driven through the four
//! generated calling consumers, which speak the compact flat-leaf result
//! carrier rather than this frame; that corpus is
//! `tests/support/public_generic_hostile_corpus.rs` and remains separate and
//! unchanged. Nothing here allocates on a hostile claim, mints a handle,
//! transfers ownership, invokes an endpoint, calls a host function, or runs
//! cleanup — and admitting a document here grants none of those.

use super::reference_decoder::{
    encode_canonical, leaf_inventory_digest, remint_facts_digest, CarrierRefusal,
    ReferenceOwnership, ReferencePlan, ReferenceTicket,
};
use super::trace::Direction;

/// The versioned identity of this corpus. A change to any case id, mutation,
/// expected class, or produced byte string must mint a new version rather
/// than silently redefine this one.
pub const CARRIER_HOSTILE_CORPUS_SCHEMA: &str = "semaprax.public-generic-carrier-hostile-corpus.v1";

/// SHA-256 of the deterministic manifest rendered by
/// [`manifest_payload`]. Pinned; see the module doc.
pub const CARRIER_HOSTILE_CORPUS_DIGEST: &str =
    "sha256:598cc88b46e7df99e32c0e97353e68a5657b1645d327e83f5aee67fceb998c9f";

/// The closed number of cases this corpus version publishes.
pub const CARRIER_HOSTILE_CORPUS_CASE_COUNT: usize = 38;

// ---------------------------------------------------------------------
// The canonical valid fixture every hostile document is a mutation of
// ---------------------------------------------------------------------

/// The trusted export identity the fixture plan derives its endpoint
/// identity from.
pub const FIXTURE_EXPORT_ID: &str = "issue173.carrier.corpus.transform";
/// A *different* deployed export. Used for cross-artifact endpoint replay.
pub const ALTERNATE_EXPORT_ID: &str = "issue173.carrier.corpus.other_transform";
/// The fixture's trusted descriptor identity.
pub const FIXTURE_DESCRIPTOR_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
/// A different artifact's descriptor identity. Used for cross-artifact
/// descriptor replay.
pub const ALTERNATE_DESCRIPTOR_DIGEST: &str =
    "sha256:9999999999999999999999999999999999999999999999999999999999999999";
/// The fixture's trusted instance identity.
pub const FIXTURE_INSTANCE_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
/// A different concrete instantiation's instance identity. Used for
/// cross-instance replay.
pub const ALTERNATE_INSTANCE_DIGEST: &str =
    "sha256:8888888888888888888888888888888888888888888888888888888888888888";
/// The fixture's trusted settlement plan digest.
pub const FIXTURE_CLEANUP_PLAN_DIGEST: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
/// A different settlement plan. Used for cleanup-plan substitution.
pub const ALTERNATE_CLEANUP_PLAN_DIGEST: &str =
    "sha256:7777777777777777777777777777777777777777777777777777777777777777";
/// The live attempt identity the fixture guard is built for. Deliberately
/// not 1, so both a stale (`- 1`) and a future (`+ 1`) neighbour exist.
pub const FIXTURE_GENERATION: u64 = 41;

/// The fixture's canonical ordered owned-leaf inventory.
pub fn fixture_leaf_paths() -> Vec<String> {
    vec![
        "value.head".to_owned(),
        "value.middle".to_owned(),
        "value.tail".to_owned(),
    ]
}

/// A different shape's canonical inventory, used to derive a forged
/// inventory identity that is well formed but names another value.
pub fn alternate_leaf_paths() -> Vec<String> {
    vec![
        "other.head".to_owned(),
        "other.middle".to_owned(),
        "other.tail".to_owned(),
    ]
}

/// The fixture's canonical leaf payloads, in inventory order. Deliberately
/// includes an empty leaf and a leaf carrying an embedded zero byte and a
/// non-UTF-8 byte, so an encoder that treats payloads as text fails here.
pub fn fixture_payloads() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0x00, 0x80, 0xff],
        b"canonical-tail".to_vec(),
    ]
}

/// The trusted plan every case is replayed against.
pub fn fixture_plan() -> ReferencePlan {
    ReferencePlan::new(
        Direction::Input,
        FIXTURE_DESCRIPTOR_DIGEST,
        FIXTURE_EXPORT_ID,
        FIXTURE_INSTANCE_DIGEST,
        fixture_leaf_paths(),
    )
}

/// The canonical valid document. Every hostile document in this corpus is a
/// recorded mutation of exactly these bytes.
pub fn canonical_document() -> Vec<u8> {
    encode_canonical(&fixture_plan(), &fixture_payloads())
        .expect("the fixture payloads match the fixture inventory by construction")
}

// ---------------------------------------------------------------------
// The closed invariant vocabulary
// ---------------------------------------------------------------------

/// Exactly one violated invariant per case. Naming the invariant separately
/// from the refusal class is what stops two different defects collapsing
/// into one indistinguishable "rejected" outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CarrierInvariant {
    /// The document is the canonical fixture, or an admissible variation of
    /// it. Used by positive controls.
    CanonicalDocumentIsAdmitted,
    /// Every length-framed field is fully present within the document.
    FramingIsComplete,
    /// No bytes remain after the trailing digest field.
    NoTrailingBytes,
    /// The schema literal is the frozen carrier schema.
    SchemaLiteralIsFrozen,
    /// The direction literal is one of the two admitted values.
    DirectionLiteralIsClosed,
    /// Every textual field is valid UTF-8.
    TextFieldsAreUtf8,
    /// The leaf-kind variant tag is one this version admits.
    LeafKindTagIsAdmitted,
    /// The declared leaf count is within the frozen bound.
    LeafCountWithinBound,
    /// The declared aggregate payload length is within the frozen bound.
    TotalPayloadWithinBound,
    /// Each declared per-leaf payload length is within the frozen bound.
    LeafPayloadWithinBound,
    /// The whole document is within the frozen wire bound.
    WireBytesWithinBound,
    /// The declared aggregate payload length equals the sum of the leaves.
    DeclaredTotalMatchesLeaves,
    /// No leaf path appears twice.
    LeafPathsAreUnique,
    /// The trailing digest equals an independent recomputation over the
    /// document's own body.
    SelfDigestIsConsistent,
    /// The document's descriptor identity is the trusted one.
    DescriptorIdentityIsBound,
    /// The document's endpoint identity equals one recomputed from the
    /// trusted export identity.
    EndpointIdentityIsRecomputed,
    /// The document's instance identity is the trusted one.
    InstanceIdentityIsBound,
    /// The document's inventory identity equals one recomputed from the
    /// trusted canonical path list.
    InventoryIdentityIsRecomputed,
    /// The leaf sequence is exactly the trusted canonical inventory, in
    /// order, with no missing, extra, or reordered leaf.
    LeafSequenceMatchesInventory,
    /// The document's direction is the direction the plan admits.
    DirectionMatchesPlan,
    /// The submitted attempt identity is the live one.
    GenerationIsLive,
    /// The submitted frame is caller-owned before the transfer point.
    OwnershipIsCallerHeld,
    /// The submitted settlement plan is the already-verified one.
    CleanupPlanIsBound,
}

impl CarrierInvariant {
    /// A stable single-line description, used in the rendered manifest so a
    /// reviewer reads the invariant rather than an opaque enum name.
    pub fn describe(self) -> &'static str {
        match self {
            Self::CanonicalDocumentIsAdmitted => "a canonical bound document is admitted",
            Self::FramingIsComplete => "every framed field lies wholly within the document",
            Self::NoTrailingBytes => "no bytes follow the trailing digest field",
            Self::SchemaLiteralIsFrozen => "the schema literal is the frozen carrier schema",
            Self::DirectionLiteralIsClosed => "the direction literal is one of two admitted values",
            Self::TextFieldsAreUtf8 => "every textual field is valid UTF-8",
            Self::LeafKindTagIsAdmitted => "the leaf-kind variant tag is admitted by this version",
            Self::LeafCountWithinBound => "the declared leaf count is within the frozen bound",
            Self::TotalPayloadWithinBound => {
                "the declared total payload is within the frozen bound"
            }
            Self::LeafPayloadWithinBound => "each declared leaf payload is within the frozen bound",
            Self::WireBytesWithinBound => "the document is within the frozen wire bound",
            Self::DeclaredTotalMatchesLeaves => "the declared total equals the sum of the leaves",
            Self::LeafPathsAreUnique => "no leaf path appears twice",
            Self::SelfDigestIsConsistent => {
                "the trailing digest equals an independent recomputation"
            }
            Self::DescriptorIdentityIsBound => "the descriptor identity is the trusted one",
            Self::EndpointIdentityIsRecomputed => {
                "the endpoint identity equals one recomputed from the trusted export identity"
            }
            Self::InstanceIdentityIsBound => "the instance identity is the trusted one",
            Self::InventoryIdentityIsRecomputed => {
                "the inventory identity equals one recomputed from the trusted path list"
            }
            Self::LeafSequenceMatchesInventory => {
                "the leaf sequence is exactly the trusted canonical inventory, in order"
            }
            Self::DirectionMatchesPlan => "the direction is the one the plan admits",
            Self::GenerationIsLive => "the submitted attempt identity is the live one",
            Self::OwnershipIsCallerHeld => "the frame is caller-owned before the transfer point",
            Self::CleanupPlanIsBound => "the settlement plan is the already-verified one",
        }
    }
}

// ---------------------------------------------------------------------
// The recorded mutation vocabulary
// ---------------------------------------------------------------------

/// Whether the trailing `carrier_facts_digest` is left as the canonical
/// document computed it, or recomputed over the mutated body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Remint {
    /// Leave the original digest in place. A body mutation is then also a
    /// self-digest violation, and the document is refused structurally.
    Keep,
    /// Recompute the digest over the mutated body, manufacturing a fully
    /// self-consistent forgery. See the module doc.
    Recompute,
}

/// One recorded, replayable edit of the canonical document. Structural edits
/// are re-encoded canonically; byte edits patch the encoded document in
/// place at a field located by walking its own framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierMutation {
    /// No edit. The canonical document itself.
    None,
    /// Drop `n` bytes from the end.
    DropTrailingBytes(usize),
    /// Append `n` bytes of `0xa5` after the trailing digest.
    AppendTrailingBytes(usize),
    /// Rewrite the last byte of the schema literal, keeping its length.
    CorruptSchemaLiteral,
    /// Rewrite the last byte of the direction literal, keeping its length.
    CorruptDirectionLiteral,
    /// Re-encode the whole document for the other direction.
    OtherDirection,
    /// Set the first byte of leaf `index`'s path to `0xff`.
    InvalidUtf8LeafPath(usize),
    /// Overwrite leaf `index`'s kind tag byte.
    LeafKindTag(usize, u8),
    /// Overwrite the declared leaf count.
    DeclaredLeafCount(u64),
    /// Overwrite the declared aggregate payload length.
    DeclaredTotalPayload(u64),
    /// Overwrite leaf `index`'s declared payload length.
    DeclaredLeafPayloadLength(usize, u64),
    /// Truncate the document in the middle of the declared leaf count.
    TruncateInsideLeafCount,
    /// Re-encode with leaf `index` renamed to a path of the same length.
    RenameLeafPath(usize),
    /// Re-encode with two leaves carrying the same path.
    DuplicateLeafPath,
    /// Re-encode with the first two leaves swapped.
    ReorderLeaves,
    /// Re-encode with the last leaf removed.
    DropLastLeaf,
    /// Re-encode with an extra leaf appended.
    AppendExtraLeaf,
    /// Re-encode with an alternate artifact's descriptor identity.
    AlternateDescriptorIdentity,
    /// Re-encode with an endpoint identity recomputed from a different
    /// export identity — a well-formed credential for another endpoint.
    AlternateEndpointIdentity,
    /// Re-encode with a different concrete instantiation's identity.
    AlternateInstanceIdentity,
    /// Re-encode with an inventory identity recomputed from a different
    /// canonical path list.
    AlternateInventoryIdentity,
    /// Flip one byte inside the trailing digest field.
    CorruptFactsDigest,
    /// Re-encode leaf `index` with `len` bytes of `0xa5`.
    LeafPayloadOfLength(usize, usize),
    /// Append enough trailing bytes to exceed the frozen wire bound.
    ExceedWireBound,
}

/// A recorded edit of the admission envelope, orthogonal to the document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketMutation {
    /// The canonical envelope.
    None,
    /// The previous attempt identity — a replayed stale ticket.
    StaleGeneration,
    /// A later attempt identity that is not live yet.
    FutureGeneration,
    /// The zero attempt identity, which is reserved as invalid.
    ZeroGeneration,
    /// Claims the provider is already accountable before the transfer point.
    ProviderOwned,
    /// Substitutes a different settlement plan.
    AlternateCleanupPlan,
}

/// The single expected outcome of one case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expected {
    /// Deliberately admitted: a positive control proving the readers do not
    /// simply refuse everything.
    Admitted,
    /// Refused with exactly this closed public class.
    Refused(CarrierRefusal),
}

/// One corpus entry.
#[derive(Clone, Copy, Debug)]
pub struct CarrierHostileCase {
    /// The stable case identity.
    pub id: &'static str,
    /// The single invariant this case violates, or asserts for a control.
    pub invariant: CarrierInvariant,
    /// The recorded document edit.
    pub mutation: CarrierMutation,
    /// Whether the trailing digest is recomputed after the edit.
    pub remint: Remint,
    /// The recorded envelope edit.
    pub ticket: TicketMutation,
    /// The single expected outcome.
    pub expected: Expected,
    /// SHA-256 of the produced document, `sha256:<hex>`.
    pub bytes_sha256: &'static str,
}

impl CarrierHostileCase {
    /// Produce this case's exact document bytes.
    pub fn document(&self) -> Vec<u8> {
        let bytes = apply_mutation(self.mutation);
        match self.remint {
            Remint::Keep => bytes,
            Remint::Recompute => remint_facts_digest(&bytes)
                .expect("a reminted case's mutated body must still parse structurally"),
        }
    }

    /// Produce this case's full admission ticket.
    pub fn reference_ticket(&self) -> ReferenceTicket {
        let (generation, ownership, cleanup_plan_digest) = match self.ticket {
            TicketMutation::None => (
                FIXTURE_GENERATION,
                ReferenceOwnership::Caller,
                FIXTURE_CLEANUP_PLAN_DIGEST,
            ),
            TicketMutation::StaleGeneration => (
                FIXTURE_GENERATION - 1,
                ReferenceOwnership::Caller,
                FIXTURE_CLEANUP_PLAN_DIGEST,
            ),
            TicketMutation::FutureGeneration => (
                FIXTURE_GENERATION + 1,
                ReferenceOwnership::Caller,
                FIXTURE_CLEANUP_PLAN_DIGEST,
            ),
            TicketMutation::ZeroGeneration => {
                (0, ReferenceOwnership::Caller, FIXTURE_CLEANUP_PLAN_DIGEST)
            }
            TicketMutation::ProviderOwned => (
                FIXTURE_GENERATION,
                ReferenceOwnership::Provider,
                FIXTURE_CLEANUP_PLAN_DIGEST,
            ),
            TicketMutation::AlternateCleanupPlan => (
                FIXTURE_GENERATION,
                ReferenceOwnership::Caller,
                ALTERNATE_CLEANUP_PLAN_DIGEST,
            ),
        };
        ReferenceTicket {
            generation,
            ownership,
            cleanup_plan_digest: cleanup_plan_digest.to_owned(),
            frame_bytes: self.document(),
        }
    }

    /// The stable diagnostic code a reader must publish, or `None` for a
    /// positive control.
    pub fn expected_code(&self) -> Option<&'static str> {
        match self.expected {
            Expected::Admitted => None,
            Expected::Refused(class) => Some(class.code()),
        }
    }
}

// ---------------------------------------------------------------------
// Locating fields inside an encoded document
// ---------------------------------------------------------------------

/// Byte ranges of one encoded document's fields, produced by walking its own
/// framing. Byte-level mutations address fields through this rather than
/// through hard-coded offsets, so the corpus survives a fixture change.
#[derive(Clone, Debug)]
pub struct DocumentLayout {
    /// Content range of the schema literal.
    pub schema: std::ops::Range<usize>,
    /// Content range of the direction literal.
    pub direction: std::ops::Range<usize>,
    /// Offset of the 8-byte declared leaf count.
    pub leaf_count: usize,
    /// Offset of the 8-byte declared aggregate payload length.
    pub total_payload: usize,
    /// Per leaf: the path content range, the kind tag offset, and the
    /// offset of the 8-byte declared payload length.
    pub leaves: Vec<(std::ops::Range<usize>, usize, usize)>,
    /// Content range of the trailing digest.
    pub facts_digest: std::ops::Range<usize>,
}

/// Walk a canonical document's framing. Panics on a malformed document,
/// which is correct here: it is only ever called on the corpus's own
/// canonical encoding, before mutation.
pub fn layout(bytes: &[u8]) -> DocumentLayout {
    let mut offset = 0usize;
    let mut next_field = |offset: &mut usize| -> std::ops::Range<usize> {
        let length = usize::try_from(u64::from_le_bytes(
            bytes[*offset..*offset + 8]
                .try_into()
                .expect("an 8-byte length header"),
        ))
        .expect("a canonical field length fits in usize");
        let start = *offset + 8;
        *offset = start + length;
        start..start + length
    };
    let schema = next_field(&mut offset);
    let direction = next_field(&mut offset);
    let _descriptor = next_field(&mut offset);
    let _endpoint = next_field(&mut offset);
    let _instance = next_field(&mut offset);
    let _inventory = next_field(&mut offset);
    let leaf_count_offset = offset;
    let count = u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("an 8-byte leaf count"),
    );
    offset += 8;
    let total_payload_offset = offset;
    offset += 8;
    let mut leaves = Vec::new();
    for _ in 0..count {
        let path = next_field(&mut offset);
        let kind_offset = offset;
        offset += 1;
        let payload_length_offset = offset;
        let _payload = next_field(&mut offset);
        leaves.push((path, kind_offset, payload_length_offset));
    }
    let facts_digest = next_field(&mut offset);
    assert_eq!(offset, bytes.len(), "the canonical document is exact");
    DocumentLayout {
        schema,
        direction,
        leaf_count: leaf_count_offset,
        total_payload: total_payload_offset,
        leaves,
        facts_digest,
    }
}

/// Apply one recorded mutation to the canonical document.
fn apply_mutation(mutation: CarrierMutation) -> Vec<u8> {
    let canonical = canonical_document();
    let plan = fixture_plan();
    let payloads = fixture_payloads();

    // Re-encoding helper for the structural edits: build an alternate plan
    // and payload list, then encode canonically so the result is a fully
    // well-formed document that differs only semantically.
    let re_encode = |plan: &ReferencePlan, payloads: &[Vec<u8>]| -> Vec<u8> {
        encode_canonical(plan, payloads).expect("a structural edit keeps payloads and paths paired")
    };

    match mutation {
        CarrierMutation::None => canonical,
        CarrierMutation::DropTrailingBytes(n) => {
            let mut bytes = canonical;
            bytes.truncate(bytes.len() - n);
            bytes
        }
        CarrierMutation::AppendTrailingBytes(n) => {
            let mut bytes = canonical;
            bytes.extend(std::iter::repeat(0xa5u8).take(n));
            bytes
        }
        CarrierMutation::ExceedWireBound => {
            let mut bytes = canonical;
            // One byte past the frozen wire bound, so the bound itself is
            // what refuses the document rather than any later field check.
            let target = super::reference_decoder::REFERENCE_MAX_WIRE_BYTES as usize + 1;
            bytes.resize(target, 0xa5);
            bytes
        }
        CarrierMutation::CorruptSchemaLiteral => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes[places.schema.end - 1] = b'2';
            bytes
        }
        CarrierMutation::CorruptDirectionLiteral => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes[places.direction.end - 1] = b'X';
            bytes
        }
        CarrierMutation::OtherDirection => {
            let other = ReferencePlan::new(
                Direction::Result,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                fixture_leaf_paths(),
            );
            re_encode(&other, &payloads)
        }
        CarrierMutation::InvalidUtf8LeafPath(index) => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes[places.leaves[index].0.start] = 0xff;
            bytes
        }
        CarrierMutation::LeafKindTag(index, tag) => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes[places.leaves[index].1] = tag;
            bytes
        }
        CarrierMutation::DeclaredLeafCount(count) => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes[places.leaf_count..places.leaf_count + 8].copy_from_slice(&count.to_le_bytes());
            bytes
        }
        CarrierMutation::DeclaredTotalPayload(total) => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes[places.total_payload..places.total_payload + 8]
                .copy_from_slice(&total.to_le_bytes());
            bytes
        }
        CarrierMutation::DeclaredLeafPayloadLength(index, length) => {
            let places = layout(&canonical);
            let at = places.leaves[index].2;
            let mut bytes = canonical;
            bytes[at..at + 8].copy_from_slice(&length.to_le_bytes());
            bytes
        }
        CarrierMutation::TruncateInsideLeafCount => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            bytes.truncate(places.leaf_count + 4);
            bytes
        }
        CarrierMutation::RenameLeafPath(index) => {
            let mut paths = fixture_leaf_paths();
            // Same length, different identity: the rename cannot be
            // mistaken for a framing change.
            paths[index] = paths[index].to_uppercase();
            let renamed = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                paths,
            );
            // Keep the *trusted* inventory identity so only the path
            // sequence differs; otherwise two invariants would break at once.
            let bytes = re_encode(&renamed, &payloads);
            overwrite_inventory_identity(bytes, plan.leaf_inventory_digest())
        }
        CarrierMutation::DuplicateLeafPath => {
            let mut paths = fixture_leaf_paths();
            paths[1] = paths[0].clone();
            let duplicated = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                paths,
            );
            let bytes = re_encode(&duplicated, &payloads);
            overwrite_inventory_identity(bytes, plan.leaf_inventory_digest())
        }
        CarrierMutation::ReorderLeaves => {
            let mut paths = fixture_leaf_paths();
            paths.swap(0, 1);
            let mut reordered_payloads = payloads.clone();
            reordered_payloads.swap(0, 1);
            let reordered = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                paths,
            );
            let bytes = re_encode(&reordered, &reordered_payloads);
            overwrite_inventory_identity(bytes, plan.leaf_inventory_digest())
        }
        CarrierMutation::DropLastLeaf => {
            let mut paths = fixture_leaf_paths();
            paths.pop();
            let mut shortened = payloads.clone();
            shortened.pop();
            let dropped = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                paths,
            );
            let bytes = re_encode(&dropped, &shortened);
            overwrite_inventory_identity(bytes, plan.leaf_inventory_digest())
        }
        CarrierMutation::AppendExtraLeaf => {
            let mut paths = fixture_leaf_paths();
            paths.push("value.extra".to_owned());
            let mut extended = payloads.clone();
            extended.push(b"extra".to_vec());
            let appended = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                paths,
            );
            let bytes = re_encode(&appended, &extended);
            overwrite_inventory_identity(bytes, plan.leaf_inventory_digest())
        }
        CarrierMutation::AlternateDescriptorIdentity => {
            let other = ReferencePlan::new(
                Direction::Input,
                ALTERNATE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                fixture_leaf_paths(),
            );
            re_encode(&other, &payloads)
        }
        CarrierMutation::AlternateEndpointIdentity => {
            let other = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                ALTERNATE_EXPORT_ID,
                FIXTURE_INSTANCE_DIGEST,
                fixture_leaf_paths(),
            );
            re_encode(&other, &payloads)
        }
        CarrierMutation::AlternateInstanceIdentity => {
            let other = ReferencePlan::new(
                Direction::Input,
                FIXTURE_DESCRIPTOR_DIGEST,
                FIXTURE_EXPORT_ID,
                ALTERNATE_INSTANCE_DIGEST,
                fixture_leaf_paths(),
            );
            re_encode(&other, &payloads)
        }
        CarrierMutation::AlternateInventoryIdentity => {
            let bytes = canonical;
            overwrite_inventory_identity(bytes, &leaf_inventory_digest(&alternate_leaf_paths()))
        }
        CarrierMutation::CorruptFactsDigest => {
            let places = layout(&canonical);
            let mut bytes = canonical;
            let at = places.facts_digest.end - 1;
            bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
            bytes
        }
        CarrierMutation::LeafPayloadOfLength(index, length) => {
            let mut sized = payloads.clone();
            sized[index] = vec![0xa5; length];
            re_encode(&plan, &sized)
        }
    }
}

/// Replace the sixth framed field — the inventory identity — in place.
/// Every identity field is the same 71-byte `sha256:<64 hex>` shape, so the
/// substitution never changes the document's framing.
fn overwrite_inventory_identity(mut bytes: Vec<u8>, digest: &str) -> Vec<u8> {
    let mut offset = 0usize;
    let mut inventory = 0..0usize;
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
            inventory = start..offset;
        }
    }
    assert_eq!(
        inventory.len(),
        digest.len(),
        "identity fields share one fixed width"
    );
    bytes[inventory].copy_from_slice(digest.as_bytes());
    bytes
}

/// The independent admission guard the corpus is replayed against.
pub fn reference_admission() -> super::reference_decoder::ReferenceAdmission {
    super::reference_decoder::ReferenceAdmission::new(
        fixture_plan(),
        FIXTURE_GENERATION,
        FIXTURE_CLEANUP_PLAN_DIGEST,
    )
    .expect("the fixture generation is nonzero")
}

/// Render the deterministic manifest [`CARRIER_HOSTILE_CORPUS_DIGEST`] is
/// computed over: the schema, the canonical document's digest, and one
/// tab-separated line per case naming its id, invariant, mutation, remint
/// mode, ticket mutation, expected class and pinned document digest.
pub fn manifest_payload() -> Vec<u8> {
    use sha2::{Digest as _, Sha256};

    let mut manifest = String::new();
    manifest.push_str(CARRIER_HOSTILE_CORPUS_SCHEMA);
    manifest.push('\n');
    manifest.push_str(&format!(
        "canonical\tsha256:{:x}\n",
        crate::digest_hex::LowerHex(Sha256::digest(canonical_document()))
    ));
    for case in cases() {
        manifest.push_str(&format!(
            "case\t{}\t{:?}\t{:?}\t{:?}\t{:?}\t{}\t{}\n",
            case.id,
            case.invariant,
            case.mutation,
            case.remint,
            case.ticket,
            case.expected_code().unwrap_or("ADMITTED"),
            case.bytes_sha256,
        ));
    }
    manifest.into_bytes()
}

/// The closed, ordered corpus. Every entry is unique by id, by produced
/// document, and — except where two cases deliberately reach one shared
/// branch from different provenance, which the comments below call out — by
/// the (invariant, refusal class) pair it proves.
pub fn cases() -> Vec<CarrierHostileCase> {
    CASES.to_vec()
}

const fn refused(class: CarrierRefusal) -> Expected {
    Expected::Refused(class)
}

/// One case per line. Read as: id, the single invariant, the recorded
/// document edit, whether the trailing digest is recomputed, the recorded
/// envelope edit, the expected outcome, and the pinned document digest.
pub static CASES: &[CarrierHostileCase] = &[
    // -- Positive controls -------------------------------------------
    // A corpus whose readers refuse everything would prove nothing, so the
    // manifest opens with documents that must be admitted.
    CarrierHostileCase {
        id: "canonical_document_admitted",
        invariant: CarrierInvariant::CanonicalDocumentIsAdmitted,
        mutation: CarrierMutation::None,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: Expected::Admitted,
        bytes_sha256: "sha256:2b642373f598522e244048045463385740bd6e31659232bb1337a53aaecb52ed",
    },
    // Exactly the frozen per-leaf bound, not one byte less: the neighbour of
    // `leaf_payload_one_byte_over_bound` below.
    CarrierHostileCase {
        id: "leaf_payload_at_exact_bound_admitted",
        invariant: CarrierInvariant::CanonicalDocumentIsAdmitted,
        mutation: CarrierMutation::LeafPayloadOfLength(1, 65_536),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: Expected::Admitted,
        bytes_sha256: "sha256:fcb5c275e4ae75e882b3b5c64e093fdef4402db6013bd0e8081ca30a353b5c2e",
    },
    // A zero-length trailing payload is a value, never an absence: the
    // canonical fixture already carries a leading empty leaf, so this
    // control also proves two empty leaves in one document are admitted.
    CarrierHostileCase {
        id: "trailing_empty_payload_admitted",
        invariant: CarrierInvariant::CanonicalDocumentIsAdmitted,
        mutation: CarrierMutation::LeafPayloadOfLength(2, 0),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: Expected::Admitted,
        bytes_sha256: "sha256:5f94e34fe8571f115aad728f711daded9c3bce554a8514e502cd431165a0567d",
    },
    // -- Framing -----------------------------------------------------
    CarrierHostileCase {
        id: "truncated_final_byte",
        invariant: CarrierInvariant::FramingIsComplete,
        mutation: CarrierMutation::DropTrailingBytes(1),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:d23a976377d6f986db71b12ff364202bf5d8a948c16653790337bdae92bab634",
    },
    // Truncated in the middle of a fixed-width integer rather than a framed
    // field: a reader that bounds only framed fields admits this one.
    CarrierHostileCase {
        id: "truncated_inside_declared_leaf_count",
        invariant: CarrierInvariant::FramingIsComplete,
        mutation: CarrierMutation::TruncateInsideLeafCount,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:a032318a3175a66e4cff71376a092c6c2f853fc53bd9c5fbd2c4c525ba2d9599",
    },
    CarrierHostileCase {
        id: "trailing_byte_after_self_digest",
        invariant: CarrierInvariant::NoTrailingBytes,
        mutation: CarrierMutation::AppendTrailingBytes(1),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:685c16d7a2836cb623d89c68d995d73d167bb80accbba7b677292e07dbc979ee",
    },
    CarrierHostileCase {
        id: "wire_bytes_one_over_bound",
        invariant: CarrierInvariant::WireBytesWithinBound,
        mutation: CarrierMutation::ExceedWireBound,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:151e2f65cef5f81ae1c6a73861887459bda3adc6585a9138bd81b256dfe81603",
    },
    // -- Frozen literals and closed vocabularies ---------------------
    CarrierHostileCase {
        id: "unknown_schema_literal",
        invariant: CarrierInvariant::SchemaLiteralIsFrozen,
        mutation: CarrierMutation::CorruptSchemaLiteral,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:a75edb6ae61f9591b824c2a5e94e8cc1dec6c7736c890701f6eb13dd2c1f1059",
    },
    CarrierHostileCase {
        id: "unknown_direction_literal",
        invariant: CarrierInvariant::DirectionLiteralIsClosed,
        mutation: CarrierMutation::CorruptDirectionLiteral,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:b331174f44ba01c73e75c9ae50ed5c2b8b6e00f805ebc6ff5568fed325c56832",
    },
    CarrierHostileCase {
        id: "invalid_utf8_leaf_path",
        invariant: CarrierInvariant::TextFieldsAreUtf8,
        mutation: CarrierMutation::InvalidUtf8LeafPath(0),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:0e44b2e4472c443baf801891306379ff74469d9eea45032bb0b42d93efaa3d4c",
    },
    // The variant-tag domain has exactly one admitted member this version.
    // Both an adjacent tag and the saturated byte are pinned, because a
    // reader that range-checks instead of matching admits one of them.
    CarrierHostileCase {
        id: "unknown_leaf_kind_tag_one_over",
        invariant: CarrierInvariant::LeafKindTagIsAdmitted,
        mutation: CarrierMutation::LeafKindTag(1, 1),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:b172730eb92cdec944d8e7a6de4714e0595a4f010c772d36ec89f5445a77fb75",
    },
    CarrierHostileCase {
        id: "unknown_leaf_kind_tag_u8_max",
        invariant: CarrierInvariant::LeafKindTagIsAdmitted,
        mutation: CarrierMutation::LeafKindTag(2, 0xff),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:2623da68efd0b13daba74e90a9cc659b1dff89144a373ff5bff1f306844c2a89",
    },
    // -- Bounds: exact maximum versus maximum plus one ---------------
    // At the bound the count is admissible, so the document is refused for
    // running out of leaves; one over, the bound itself refuses it. A
    // reader with an off-by-one bound swaps these two classes.
    CarrierHostileCase {
        id: "declared_leaf_count_at_exact_bound",
        invariant: CarrierInvariant::FramingIsComplete,
        mutation: CarrierMutation::DeclaredLeafCount(256),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:e1edb1b9d2ed1d36f819ecaff45b72926247bf6f7873aa53e57dde6b1c7f1502",
    },
    CarrierHostileCase {
        id: "declared_leaf_count_one_over_bound",
        invariant: CarrierInvariant::LeafCountWithinBound,
        mutation: CarrierMutation::DeclaredLeafCount(257),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:1583151474f718cc771c658753568eb2d826fe62f928f1aa2a3ced1c6cd16f8c",
    },
    // Exact-width handling, not a host `usize` narrowing accident.
    CarrierHostileCase {
        id: "declared_leaf_count_u64_max",
        invariant: CarrierInvariant::LeafCountWithinBound,
        mutation: CarrierMutation::DeclaredLeafCount(u64::MAX),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:580e6d7045d08f7c1586f9117502ed2abbee72d3947db94bb2fc12d07aaeef17",
    },
    CarrierHostileCase {
        id: "declared_total_payload_at_exact_bound",
        invariant: CarrierInvariant::DeclaredTotalMatchesLeaves,
        mutation: CarrierMutation::DeclaredTotalPayload(16 * 1024 * 1024),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:ff47980855674f20510cd266d67eee1224d02858e759c06465ca203b0a906941",
    },
    CarrierHostileCase {
        id: "declared_total_payload_one_over_bound",
        invariant: CarrierInvariant::TotalPayloadWithinBound,
        mutation: CarrierMutation::DeclaredTotalPayload(16 * 1024 * 1024 + 1),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:edad5a90b85675ab1fc93b4fe5b86c8413b70735519bda82191de1896dbb5aca",
    },
    CarrierHostileCase {
        id: "declared_total_payload_u64_max",
        invariant: CarrierInvariant::TotalPayloadWithinBound,
        mutation: CarrierMutation::DeclaredTotalPayload(u64::MAX),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:9cc4678dadcb6d882ee74f572eb0adab149f91c955e315fd42a580ecd6562c27",
    },
    // A declared per-leaf length exactly at the bound is admissible, so the
    // document is refused for not carrying those bytes; one over, the bound
    // refuses it before any read is attempted.
    CarrierHostileCase {
        id: "declared_leaf_payload_at_exact_bound",
        invariant: CarrierInvariant::FramingIsComplete,
        mutation: CarrierMutation::DeclaredLeafPayloadLength(0, 65_536),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:cc8b2d092b9fbe5657709814b2dfaf3d8871be51805198394d67410485fe12d0",
    },
    CarrierHostileCase {
        id: "declared_leaf_payload_one_over_bound",
        invariant: CarrierInvariant::LeafPayloadWithinBound,
        mutation: CarrierMutation::DeclaredLeafPayloadLength(0, 65_537),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:027b07b42b068ed889b8639464ede5ca58c3a2aafbc6afbfe24add76120f16c4",
    },
    CarrierHostileCase {
        id: "declared_leaf_payload_u64_max",
        invariant: CarrierInvariant::LeafPayloadWithinBound,
        mutation: CarrierMutation::DeclaredLeafPayloadLength(1, u64::MAX),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:a4856722dda108d2c6d401b4d7d0c2a972577b3db379988ac9ba335f780f85c4",
    },
    // The complete document really carries the over-bound payload, so
    // truncation cannot mask a missing capacity check. Neighbour of the
    // admitted `leaf_payload_at_exact_bound_admitted` control above.
    CarrierHostileCase {
        id: "leaf_payload_one_byte_over_bound",
        invariant: CarrierInvariant::LeafPayloadWithinBound,
        mutation: CarrierMutation::LeafPayloadOfLength(1, 65_537),
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Capacity),
        bytes_sha256: "sha256:462487e3adbd1dabde1e07d0e9f8c52bac6284b648a112795f5c34f0aebb68c8",
    },
    // -- Structural uniqueness and self-consistency ------------------
    CarrierHostileCase {
        id: "duplicate_leaf_path",
        invariant: CarrierInvariant::LeafPathsAreUnique,
        mutation: CarrierMutation::DuplicateLeafPath,
        remint: Remint::Recompute,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::Malformed),
        bytes_sha256: "sha256:4cd609c34d9737398d7a69c3530d2d53e04d7aed2ab0b113bc2a1147eecd12c4",
    },
    CarrierHostileCase {
        id: "corrupted_self_digest",
        invariant: CarrierInvariant::SelfDigestIsConsistent,
        mutation: CarrierMutation::CorruptFactsDigest,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:616519212bdb2cc3b15a74129575286f259801e95c28a721ea8b40bcfb27e87b",
    },
    // -- Cross-artifact, cross-endpoint, cross-instance, cross-runtime --
    // Every one of these is a fully well-formed, internally self-consistent
    // document: a legitimate credential for a different subject, never a
    // corrupted byte string. They are the cases a digest-only reader admits.
    CarrierHostileCase {
        id: "cross_artifact_descriptor_identity",
        invariant: CarrierInvariant::DescriptorIdentityIsBound,
        mutation: CarrierMutation::AlternateDescriptorIdentity,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:e7ba03691a3214f92965f7e4a233d8cf84944e8b12df88142c1d4ce3b334dcc1",
    },
    CarrierHostileCase {
        id: "cross_endpoint_identity",
        invariant: CarrierInvariant::EndpointIdentityIsRecomputed,
        mutation: CarrierMutation::AlternateEndpointIdentity,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:3d1f63126d9d0b5b6f92ff9bf55967341435788be62199f0add21cb03f49f3f4",
    },
    CarrierHostileCase {
        id: "cross_instance_identity",
        invariant: CarrierInvariant::InstanceIdentityIsBound,
        mutation: CarrierMutation::AlternateInstanceIdentity,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:75203c3a7cfb5c4ec11410f538bebb7b914ae0a734bbf5dc55ad892606f48521",
    },
    // Reminted: the inventory identity names a different shape and the
    // trailing digest was recomputed over that change, so the document is
    // self-consistent end to end. Only recomputing the inventory identity
    // from the trusted path list refuses it.
    CarrierHostileCase {
        id: "reminted_foreign_inventory_identity",
        invariant: CarrierInvariant::InventoryIdentityIsRecomputed,
        mutation: CarrierMutation::AlternateInventoryIdentity,
        remint: Remint::Recompute,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:08906deba3ceac215a42eb24beb239a3fef4bc1fed57a510818f9d629a359909",
    },
    // A result-direction document submitted to an input-direction plan:
    // cross-direction replay of an otherwise perfect document.
    CarrierHostileCase {
        id: "cross_direction_result_document",
        invariant: CarrierInvariant::DirectionMatchesPlan,
        mutation: CarrierMutation::OtherDirection,
        remint: Remint::Keep,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:88d4a7822b208ed69825eb57006daf981af8d8d934ab671e2d691a12a7d4e47a",
    },
    // -- Leaf inventory substitution ---------------------------------
    // Each carries the trusted inventory identity and a reminted digest, so
    // only the path sequence itself betrays the substitution.
    CarrierHostileCase {
        id: "substituted_leaf_path",
        invariant: CarrierInvariant::LeafSequenceMatchesInventory,
        mutation: CarrierMutation::RenameLeafPath(1),
        remint: Remint::Recompute,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:d0efb829d499c84e78b1ab8fbc40139ded75853bdc2daa2c8568c5faf1bd87cc",
    },
    CarrierHostileCase {
        id: "reordered_leaves",
        invariant: CarrierInvariant::LeafSequenceMatchesInventory,
        mutation: CarrierMutation::ReorderLeaves,
        remint: Remint::Recompute,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:432e62047f498d264e411aa43befa1a6e25f991da5a25b826b72a84a82de8ecb",
    },
    CarrierHostileCase {
        id: "missing_leaf",
        invariant: CarrierInvariant::LeafSequenceMatchesInventory,
        mutation: CarrierMutation::DropLastLeaf,
        remint: Remint::Recompute,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:05b42c908b7af3913e96654ce74978de82794550d67f02056f2ff73f9091024f",
    },
    CarrierHostileCase {
        id: "extra_leaf",
        invariant: CarrierInvariant::LeafSequenceMatchesInventory,
        mutation: CarrierMutation::AppendExtraLeaf,
        remint: Remint::Recompute,
        ticket: TicketMutation::None,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:b467a9ab7d387d9770f7611177ac7245237670e5c2a45683151189500e1ff5f6",
    },
    // -- Admission envelope: cross-runtime generation and ownership ---
    // The document is the canonical one in every case below. Only the
    // attempt envelope is hostile, so a reader that authenticates bytes but
    // forgets the envelope admits all five.
    CarrierHostileCase {
        id: "stale_generation_replay",
        invariant: CarrierInvariant::GenerationIsLive,
        mutation: CarrierMutation::None,
        remint: Remint::Keep,
        ticket: TicketMutation::StaleGeneration,
        expected: refused(CarrierRefusal::GenerationMismatch),
        bytes_sha256: "sha256:2b642373f598522e244048045463385740bd6e31659232bb1337a53aaecb52ed",
    },
    CarrierHostileCase {
        id: "future_generation_replay",
        invariant: CarrierInvariant::GenerationIsLive,
        mutation: CarrierMutation::None,
        remint: Remint::Keep,
        ticket: TicketMutation::FutureGeneration,
        expected: refused(CarrierRefusal::GenerationMismatch),
        bytes_sha256: "sha256:2b642373f598522e244048045463385740bd6e31659232bb1337a53aaecb52ed",
    },
    CarrierHostileCase {
        id: "zero_generation_replay",
        invariant: CarrierInvariant::GenerationIsLive,
        mutation: CarrierMutation::None,
        remint: Remint::Keep,
        ticket: TicketMutation::ZeroGeneration,
        expected: refused(CarrierRefusal::GenerationMismatch),
        bytes_sha256: "sha256:2b642373f598522e244048045463385740bd6e31659232bb1337a53aaecb52ed",
    },
    CarrierHostileCase {
        id: "provider_owned_before_transfer",
        invariant: CarrierInvariant::OwnershipIsCallerHeld,
        mutation: CarrierMutation::None,
        remint: Remint::Keep,
        ticket: TicketMutation::ProviderOwned,
        expected: refused(CarrierRefusal::IllegalTransition),
        bytes_sha256: "sha256:2b642373f598522e244048045463385740bd6e31659232bb1337a53aaecb52ed",
    },
    CarrierHostileCase {
        id: "substituted_cleanup_plan",
        invariant: CarrierInvariant::CleanupPlanIsBound,
        mutation: CarrierMutation::None,
        remint: Remint::Keep,
        ticket: TicketMutation::AlternateCleanupPlan,
        expected: refused(CarrierRefusal::ReplayMismatch),
        bytes_sha256: "sha256:2b642373f598522e244048045463385740bd6e31659232bb1337a53aaecb52ed",
    },
];

#[cfg(test)]
mod tests;
