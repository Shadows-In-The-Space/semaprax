//! Per-effect typed signatures and the refusal of a resume that does not
//! answer the suspension it claims to answer (issue #204's "a suspension
//! carries a type that says what it is waiting for and what resuming it
//! must supply").
//!
//! # What `core` already types, and the hole this closes
//!
//! [`super::core::ResumableEffectProgram`] fixes exactly *one*
//! `Request`/`Observation` pair per program, so Rust's own type system
//! already refuses an observation of the wrong Rust type (the crate-level
//! `compile_fail` doctest). That is a whole-program channel type, not a
//! per-effect one. A realistic resumable computation waits on several
//! distinct effects -- "ask the model", "read the clock", "read a file" --
//! and must therefore model `Request`/`Observation` as enums or as tagged
//! records. At that point Rust sees one type and checks nothing about
//! *which* effect a given answer answers: an `AskModel` suspension can be
//! resumed with a `ReadClock` answer, and both the handler boundary and a
//! recovered journal accept it silently.
//!
//! This module is that missing check, and only that check. An
//! [`EffectSignatureTable`] declares, per effect id, the shape a request of
//! that effect has and the shape resuming it must supply. Two refusal
//! points enforce it:
//!
//! 1. [`SignatureCheckedHandler`] wraps an already-injected
//!    [`EffectHandler`] and refuses an unknown effect id or a mismatched
//!    request shape *before* the wrapped handler -- the only real physical
//!    effect boundary -- is called at all, and refuses an answer that names
//!    a different effect, or the right effect in the wrong shape, before it
//!    can become the observation a `transition` reads. Both refusals travel
//!    the driver's existing `HandlerFailed` path, so the driver is
//!    unchanged, the refusal is journalled rather than silently discarded,
//!    and it cannot replace an already-selected terminal status.
//! 2. [`validate_journal_signatures`] re-checks a *recovered* journal:
//!    every recorded request against its declared shape and every recorded
//!    observation against the answer shape its own recorded request
//!    declares. [`super::core::Journal::validate`] checks scope, ordering
//!    and request identity; it cannot see that an `Observed` entry's
//!    observation answers a different effect than its request asked for,
//!    because both are the same Rust type. A hand-tampered or corrupted
//!    checkpoint can therefore pass `Journal::validate` and still be
//!    refused here, which is exactly the "resuming after code change can
//!    execute state under incompatible semantics" and "checkpoint
//!    corruption" case #204 requires.
//!
//! # What this module deliberately is not
//!
//! Nothing here runs anything. Constructing a table, checking a shape and
//! validating a journal are pure functions over caller-supplied data: they
//! dispatch no effect, spawn no work, and mint no authority. A signature is
//! proof data about what an answer must look like, never permission for
//! anything to produce one -- the wrapped handler must still be genuinely
//! injected by the caller for any effect to happen at all.
//!
//! Shapes in this general Rust-level API are caller-supplied opaque strings
//! compared for exact equality. Source callers must not invent that mapping:
//! [`super::source_signature`] derives a versioned shape and table from the
//! checked `.spx` `yields` clause and binds it to the exact resumable lowering
//! identity. This module remains the representation-independent checking
//! discipline that derivation lowers into.
//!
//! [`SignatureCheckedHandler`] and [`super::capability::CapabilityGatedHandler`]
//! are independent decorators over the same `EffectHandler` seam and compose
//! in either order: one answers "may this effect be requested at all", the
//! other "does this request, and this answer, have the declared shape".

use super::core::{EffectHandler, Journal, JournalEntry, ResumableEffectProgram};

/// One concrete request or observation, described for signature checking:
/// which effect it belongs to and what shape it presents. Supplied by the
/// caller's own pure projection function, the same way
/// [`super::capability::CapabilityGatedHandler`]'s `capability_of` is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectTag {
    /// The effect this value belongs to. For an answer this is the effect
    /// it claims to answer.
    pub effect_id: String,
    /// The value's shape, compared for exact equality against the shape the
    /// table declares. Any deterministic caller-chosen encoding works so
    /// long as two values of different shape never render the same string.
    pub shape: String,
}

impl EffectTag {
    pub fn new(effect_id: impl Into<String>, shape: impl Into<String>) -> Self {
        Self {
            effect_id: effect_id.into(),
            shape: shape.into(),
        }
    }
}

/// The declared signature of one effect: what a request of it looks like,
/// and what resuming it must supply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectSignature {
    pub effect_id: String,
    /// The shape every request of this effect must present.
    pub request_shape: String,
    /// The shape every answer resuming this effect must present. This is
    /// the "what resuming it must supply" half of the typed suspension.
    pub answer_shape: String,
}

impl EffectSignature {
    pub fn new(
        effect_id: impl Into<String>,
        request_shape: impl Into<String>,
        answer_shape: impl Into<String>,
    ) -> Self {
        Self {
            effect_id: effect_id.into(),
            request_shape: request_shape.into(),
            answer_shape: answer_shape.into(),
        }
    }
}

/// Why an [`EffectSignatureTable`] could not be constructed. Distinct,
/// stable reasons, kept separate rather than merged for the same reason
/// [`super::core::JournalError`]'s variants are.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureTableError {
    /// More entries than the bounded registry allows.
    TooManyEffects { count: usize },
    /// The same effect id declared twice. Two signatures for one effect id
    /// would make "the declared answer shape" ambiguous.
    DuplicateEffect { id: String },
    /// An effect id that names nothing.
    EmptyEffectId,
    /// A request or answer shape that describes nothing, which would make
    /// every value of that effect trivially match.
    EmptyShape { id: String },
}

/// The bounded, ordered set of effect signatures in force for one resumable
/// computation. Order is the caller's declaration order and is never sorted
/// or repaired; lookup is by exact effect id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectSignatureTable {
    signatures: Vec<EffectSignature>,
}

impl EffectSignatureTable {
    /// The bounded registry's ceiling, mirroring
    /// [`super::capability::CapabilityPolicy::MAX_CAPABILITIES`] and the
    /// existing Agent typed-effects operation registry
    /// (`docs/AGENT-TYPED-EFFECTS-V3.md`: "The registry contains at most 64
    /// operations").
    pub const MAX_EFFECTS: usize = 64;

    /// Construct a table from an explicit, caller-supplied declaration
    /// list. Rejects an over-long table, a duplicate or empty effect id, or
    /// an empty shape, rather than silently accepting a table that would
    /// later misreport which answers actually match.
    pub fn new(signatures: Vec<EffectSignature>) -> Result<Self, SignatureTableError> {
        if signatures.len() > Self::MAX_EFFECTS {
            return Err(SignatureTableError::TooManyEffects {
                count: signatures.len(),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for signature in &signatures {
            if signature.effect_id.is_empty() {
                return Err(SignatureTableError::EmptyEffectId);
            }
            if signature.request_shape.is_empty() || signature.answer_shape.is_empty() {
                return Err(SignatureTableError::EmptyShape {
                    id: signature.effect_id.clone(),
                });
            }
            if !seen.insert(signature.effect_id.clone()) {
                return Err(SignatureTableError::DuplicateEffect {
                    id: signature.effect_id.clone(),
                });
            }
        }
        Ok(Self { signatures })
    }

    /// An empty table: declares nothing, so every effect id is unknown.
    /// Never a default that silently admits any shape.
    pub fn none() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// The declared signatures, in exact declaration order.
    pub fn signatures(&self) -> &[EffectSignature] {
        &self.signatures
    }

    /// The signature declared for `effect_id`, if any.
    pub fn lookup(&self, effect_id: &str) -> Option<&EffectSignature> {
        self.signatures
            .iter()
            .find(|signature| signature.effect_id == effect_id)
    }

    /// Check one request tag against its declared signature. Pure: performs
    /// no dispatch.
    pub fn check_request(
        &self,
        request: &EffectTag,
    ) -> Result<&EffectSignature, SignatureMismatch> {
        let signature =
            self.lookup(&request.effect_id)
                .ok_or_else(|| SignatureMismatch::UnknownEffect {
                    effect_id: request.effect_id.clone(),
                })?;
        if signature.request_shape != request.shape {
            return Err(SignatureMismatch::RequestShapeMismatch {
                effect_id: request.effect_id.clone(),
                declared: signature.request_shape.clone(),
                presented: request.shape.clone(),
            });
        }
        Ok(signature)
    }

    /// Check one answer tag against the request it claims to answer. The
    /// answer must name the same effect and present that effect's declared
    /// answer shape. Pure: performs no dispatch.
    pub fn check_answer(
        &self,
        request: &EffectTag,
        answer: &EffectTag,
    ) -> Result<(), SignatureMismatch> {
        let signature = self.check_request(request)?;
        if answer.effect_id != request.effect_id {
            return Err(SignatureMismatch::AnswerForWrongEffect {
                requested: request.effect_id.clone(),
                answered: answer.effect_id.clone(),
            });
        }
        if signature.answer_shape != answer.shape {
            return Err(SignatureMismatch::AnswerShapeMismatch {
                effect_id: request.effect_id.clone(),
                declared: signature.answer_shape.clone(),
                presented: answer.shape.clone(),
            });
        }
        Ok(())
    }
}

/// Why a request or an answer was refused. Each variant is a distinct,
/// stable reason so a caller (or a test) can tell an undeclared effect
/// apart from a malformed request, an answer to the wrong suspension, and
/// an answer of the wrong shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureMismatch {
    /// The request names an effect the table does not declare. Refused
    /// before any dispatch.
    UnknownEffect { effect_id: String },
    /// The request names a declared effect but does not have that effect's
    /// declared request shape. Refused before any dispatch.
    RequestShapeMismatch {
        effect_id: String,
        declared: String,
        presented: String,
    },
    /// The answer claims to answer a different effect than the one the
    /// suspension is waiting on. This is the resume-does-not-match refusal
    /// a single whole-program `Observation` type cannot express.
    AnswerForWrongEffect { requested: String, answered: String },
    /// The answer answers the right effect in the wrong shape.
    AnswerShapeMismatch {
        effect_id: String,
        declared: String,
        presented: String,
    },
}

impl std::fmt::Display for SignatureMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureMismatch::UnknownEffect { effect_id } => {
                write!(f, "undeclared effect: {effect_id}")
            }
            SignatureMismatch::RequestShapeMismatch {
                effect_id,
                declared,
                presented,
            } => write!(
                f,
                "request shape mismatch for {effect_id}: declared {declared}, presented {presented}"
            ),
            SignatureMismatch::AnswerForWrongEffect {
                requested,
                answered,
            } => write!(
                f,
                "answer for wrong effect: suspension awaits {requested}, answer names {answered}"
            ),
            SignatureMismatch::AnswerShapeMismatch {
                effect_id,
                declared,
                presented,
            } => write!(
                f,
                "answer shape mismatch for {effect_id}: declared {declared}, presented {presented}"
            ),
        }
    }
}

/// Wraps an injected [`EffectHandler`], refusing a request whose effect is
/// undeclared or whose shape disagrees with its declaration *before* the
/// wrapped handler is ever called, and refusing an answer that does not
/// answer that exact suspension in its declared shape before that answer
/// can become an observation.
///
/// The answer check necessarily runs after the wrapped handler returns --
/// an answer cannot be inspected before it exists -- so a physical effect
/// the caller genuinely authorized may already have happened when an answer
/// is refused. What the refusal guarantees is that a mismatched answer
/// never becomes the observation a `transition` reads, and never lands in
/// the journal as an `Observed` entry: the driver records the refusal as an
/// `ObservationFailed` on its existing `HandlerFailed` path instead.
pub struct SignatureCheckedHandler<'a, Req, Obs> {
    inner: &'a mut dyn EffectHandler<Req, Obs>,
    table: EffectSignatureTable,
    request_tag: Box<dyn Fn(&Req) -> EffectTag + 'a>,
    answer_tag: Box<dyn Fn(&Obs) -> EffectTag + 'a>,
    mismatches: Vec<SignatureMismatch>,
}

impl<'a, Req, Obs> SignatureCheckedHandler<'a, Req, Obs> {
    /// `request_tag` and `answer_tag` are the caller's pure, deterministic
    /// projections from its own `Request`/`Observation` types to the
    /// effect id and shape each value presents.
    pub fn new(
        inner: &'a mut dyn EffectHandler<Req, Obs>,
        table: EffectSignatureTable,
        request_tag: impl Fn(&Req) -> EffectTag + 'a,
        answer_tag: impl Fn(&Obs) -> EffectTag + 'a,
    ) -> Self {
        Self {
            inner,
            table,
            request_tag: Box::new(request_tag),
            answer_tag: Box::new(answer_tag),
            mismatches: Vec::new(),
        }
    }

    /// Every mismatch this handler refused, in the exact order it refused
    /// them, for a caller (or a test) to inspect after a driver call
    /// returns.
    pub fn mismatches(&self) -> &[SignatureMismatch] {
        &self.mismatches
    }
}

impl<Req, Obs> EffectHandler<Req, Obs> for SignatureCheckedHandler<'_, Req, Obs> {
    fn dispatch(&mut self, request: &Req) -> Result<Obs, String> {
        let request_tag = (self.request_tag)(request);
        if let Err(mismatch) = self.table.check_request(&request_tag) {
            let rendered = mismatch.to_string();
            self.mismatches.push(mismatch);
            return Err(rendered);
        }
        let observation = self.inner.dispatch(request)?;
        let answer_tag = (self.answer_tag)(&observation);
        if let Err(mismatch) = self.table.check_answer(&request_tag, &answer_tag) {
            let rendered = mismatch.to_string();
            self.mismatches.push(mismatch);
            return Err(rendered);
        }
        Ok(observation)
    }
}

/// Why a recovered journal was refused by signature checking: the exact
/// entry index and the mismatch found there. Reported for the first
/// offending entry in journal order; the journal is never sorted, skipped
/// past, or repaired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSignatureError {
    pub at: usize,
    pub mismatch: SignatureMismatch,
}

/// Re-check every recorded request and observation in a recovered journal
/// against the signature table currently in force.
///
/// [`Journal::validate`] already rejects a journal on scope, ordering and
/// request identity, but it compares an `Observed` entry's observation
/// against nothing: observation and request are the program's own two Rust
/// types and any pair of them is structurally legal. This function is the
/// per-effect check -- a recorded answer must answer the effect its own
/// recorded request asked for, in that effect's declared shape -- so a
/// tampered or corrupted checkpoint that passes structural validation is
/// still refused before it is trusted for replay.
///
/// Pure: dispatches nothing and mints nothing. Call it alongside
/// `Journal::validate`, before `resume`.
pub fn validate_journal_signatures<P: ResumableEffectProgram>(
    journal: &Journal<P>,
    table: &EffectSignatureTable,
    request_tag: impl Fn(&P::Request) -> EffectTag,
    answer_tag: impl Fn(&P::Observation) -> EffectTag,
) -> Result<(), JournalSignatureError> {
    for (at, entry) in journal.entries().iter().enumerate() {
        match entry {
            JournalEntry::Intent { request, .. }
            | JournalEntry::ObservationFailed { request, .. } => {
                table
                    .check_request(&request_tag(request))
                    .map(|_| ())
                    .map_err(|mismatch| JournalSignatureError { at, mismatch })?;
            }
            JournalEntry::Observed {
                request,
                observation,
                ..
            } => {
                table
                    .check_answer(&request_tag(request), &answer_tag(observation))
                    .map_err(|mismatch| JournalSignatureError { at, mismatch })?;
            }
            JournalEntry::Transition { .. } => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
