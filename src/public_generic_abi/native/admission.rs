//! Native pre-dispatch admission for a descriptor-bound logical input frame.
//!
//! The C11 physical provider intentionally owns only its compact flat-leaf
//! ABI. This reusable guard authenticates the richer target-neutral
//! [`LogicalCarrierFrame`] against a real [`VerifiedPublicGenericDescriptor`],
//! then exposes its leaves for a caller to lower into the physical adapter. It
//! performs no physical handle mint, ownership transfer, or endpoint
//! invocation itself. The additive [`super::authenticated`] profile embeds the
//! same verified-descriptor-derived frame plan in its physical C entry point;
//! this Rust callback helper remains independently useful admission plumbing.
//!
//! This is deliberately native-only plumbing, not a new public C ABI.  The
//! Core-Wasm provider still lacks the compiled provider ABI required to make
//! the same boundary physical there (#229).

use crate::diagnostic::Diagnostic;
use crate::public_generic_abi::carrier::frame::{
    parse_bounded, CarrierFrameBinding, CarrierLeaf, LogicalCarrierFrame,
};
use crate::public_generic_abi::carrier::trace::Direction;
use crate::public_generic_abi::carrier::{
    CARRIER_REPLAY_MISMATCH, HANDLE_GENERATION_MISMATCH, ILLEGAL_TRANSITION, MALFORMED_CARRIER,
};
use crate::public_generic_abi::descriptor::verify::VerifiedPublicGenericDescriptor;

fn refusal(subject: &str) -> Diagnostic {
    Diagnostic::io(
        CARRIER_REPLAY_MISMATCH,
        format!("native logical-carrier admission refused: {subject}"),
    )
}

/// Which side is still accountable for the prepared frame.  Only a caller
/// owned frame can cross the native pre-dispatch boundary; provider ownership
/// is acquired later, at the physical adapter's existing transfer point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCarrierOwnership {
    Caller,
    Provider,
}

/// A caller-supplied native admission envelope.  `generation` and
/// `cleanup_plan_digest` are deliberately outside `LogicalCarrierFrame`: they
/// bind this one native attempt and its already-checked settlement plan, not
/// the target-neutral value bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeInputTicket {
    generation: u64,
    ownership: NativeCarrierOwnership,
    cleanup_plan_digest: String,
    frame_bytes: Vec<u8>,
}

impl NativeInputTicket {
    pub fn new(
        generation: u64,
        ownership: NativeCarrierOwnership,
        cleanup_plan_digest: impl Into<String>,
        frame_bytes: Vec<u8>,
    ) -> Self {
        Self {
            generation,
            ownership,
            cleanup_plan_digest: cleanup_plan_digest.into(),
            frame_bytes,
        }
    }
}

/// An immutable, descriptor-derived native boundary guard.  Construction
/// requires the verifier's sealed descriptor type, so raw descriptor bytes
/// cannot choose the expected leaf paths, endpoint identity, or cleanup plan.
#[derive(Clone, Debug)]
pub struct NativeInputAdmission {
    binding: CarrierFrameBinding,
    generation: u64,
    cleanup_plan_digest: String,
}

impl NativeInputAdmission {
    /// Build the input-side guard from a descriptor the independent verifier
    /// already accepted.  Generation zero is reserved as an invalid native
    /// attempt identity and therefore cannot be used to create a guard.
    pub fn from_verified_descriptor(
        descriptor: &VerifiedPublicGenericDescriptor,
        generation: u64,
    ) -> Result<Self, Diagnostic> {
        if generation == 0 {
            return Err(Diagnostic::io(
                MALFORMED_CARRIER,
                "native logical-carrier admission requires a nonzero generation",
            ));
        }
        Ok(Self {
            binding: CarrierFrameBinding::from_verified_descriptor(descriptor, Direction::Input),
            generation,
            cleanup_plan_digest: descriptor.settlement().digest().to_owned(),
        })
    }

    /// The canonical input plan, exposed for a caller that needs to produce a
    /// frame before submitting it back through [`Self::admit`].  It is a
    /// value-only plan: exposing it never grants transfer or dispatch
    /// authority.
    pub fn binding(&self) -> &CarrierFrameBinding {
        &self.binding
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn cleanup_plan_digest(&self) -> &str {
        &self.cleanup_plan_digest
    }

    /// Parse and bind a caller-owned input ticket. The returned leaves borrow
    /// no ticket state and remain ordinary value bytes; installing this guard
    /// before allocation, transfer, or dispatch and then committing the leaves
    /// to a physical provider are separate operations. The authenticated native
    /// profile implements its own C entry check before that handoff.
    pub fn admit(&self, ticket: &NativeInputTicket) -> Result<Vec<CarrierLeaf>, Diagnostic> {
        if ticket.generation != self.generation {
            return Err(Diagnostic::io(
                HANDLE_GENERATION_MISMATCH,
                "native logical-carrier admission generation does not match the live native attempt",
            ));
        }
        if ticket.ownership != NativeCarrierOwnership::Caller {
            return Err(Diagnostic::io(
                ILLEGAL_TRANSITION,
                "input is not caller-owned before the physical transfer point",
            ));
        }
        if ticket.cleanup_plan_digest != self.cleanup_plan_digest {
            return Err(refusal(
                "cleanup-plan digest does not match the verified settlement plan",
            ));
        }
        let frame: LogicalCarrierFrame = parse_bounded(&ticket.frame_bytes)?;
        self.binding.validate_frame(&frame)?;
        Ok(frame.leaves().to_vec())
    }

    /// Admit a ticket and invoke `effect` only after every admission check has
    /// succeeded. This gives an installer one narrow, auditable sequencing
    /// point: malformed or wrongly bound tickets cannot reach its callback.
    ///
    /// The callback is still caller-provided plumbing, not the C11 provider's
    /// physical allocation, transfer, or dispatch path. In particular, this
    /// method does not claim that the currently rendered provider is guarded;
    /// installing it there remains follow-on physical integration work.
    pub fn admit_then<T>(
        &self,
        ticket: &NativeInputTicket,
        effect: impl FnOnce(&[CarrierLeaf]) -> Result<T, Diagnostic>,
    ) -> Result<T, Diagnostic> {
        let leaves = self.admit(ticket)?;
        effect(&leaves)
    }
}
