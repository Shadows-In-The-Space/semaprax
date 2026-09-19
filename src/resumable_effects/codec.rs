//! Checkpoint byte-wire codec for a resumable-effects [`Journal`] (issue
//! #204's "Checkpoint serialization" scope bullet and implementation-
//! sequence step 6), left open by every prior tranche on this module
//! specifically because a wire format needs its own versioned schema, an
//! independent decoder, hostile-input tests and explicit bounds as one
//! unit rather than being folded into a slice about something else.
//! `docs/RESUMABLE-EFFECTS-V1.md`'s "No checkpoint byte-wire format" bullet
//! names exactly this gap.
//!
//! # What this is, and is not
//!
//! [`encode_checkpoint`]/[`decode_checkpoint`] turn a [`Journal`], bound to
//! its [`EffectScope`], into closed, deterministic JSON bytes and back --
//! the same "closed deterministic JSON, canonical byte equality rejects
//! duplicate keys" discipline `agent_runtime_v2::checkpoint::codec` already
//! uses for the six-role Agent shape, applied here to an arbitrary
//! [`ResumableEffectProgram`]. Every entry's caller-chosen
//! `State`/`Request`/`Observation`/`Result` value is encoded through the
//! new [`EffectCodec`] trait, a second, narrower bound than
//! `ResumableEffectProgram`'s own `Clone + Eq + Debug + 'static`: most
//! programs never need to persist a checkpoint, so paying for a codec is
//! opt-in per type rather than forced onto every program by the base
//! trait.
//!
//! One journal is bound to exactly one [`EffectScope`] for its whole
//! lifetime -- `run`/`resume` push an identical `scope.clone()` onto every
//! entry of one drive call -- so this format stores the scope once, at the
//! top level, rather than repeating it per entry.
//!
//! Decoding never establishes trust by itself. [`decode_checkpoint`] checks
//! the wire schema, the size and entry-count bounds, its own digest, and
//! the decoded [`EffectScope`] against a caller-supplied `expected` scope
//! *before* reconstructing any entry -- the same "the caller supplies the
//! scope it independently expects right now" rule
//! [`super::core::Journal::validate`] documents for its own `expected`
//! parameter -- but it performs none of `validate`'s ordering,
//! turn-sequencing, or request-identity checks. A decoded journal is
//! recovered bytes, not a trusted journal: the caller must still call
//! [`super::core::Journal::validate`] (and, to actually resume, drive it
//! through [`super::core::resume`]) before anything here grants authority.
//! Recovery mints no effect authority, matching every other seam in this
//! module.
//!
//! # Nonclaims
//!
//! This is a reference-level wire format for the Rust-trait driver only:
//! there is no `.spx` syntax, no ProgramRoot-derived schema hash, and no
//! attempt to bind the wire schema to a real checked source type. Adding
//! that belongs to the parser/HIR/graph tranche this module's crate doc
//! already describes as out of scope for one bounded slice.

use super::core::{EffectScope, Journal, JournalEntry, ResumableEffectProgram, Step};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

/// The exact wire schema name this codec reads and writes. Bumping the
/// version is a breaking wire change, never an in-place reinterpretation.
pub const RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA: &str = "semaprax.resumable-effects-checkpoint.v1";

/// Bound on the whole encoded document. Chosen to match the order of
/// magnitude `agent_runtime_v2::checkpoint`'s own `MAX_BYTES` already uses
/// for a comparable per-computation journal.
const MAX_CHECKPOINT_BYTES: usize = 1_048_576;
/// Bound on the number of journal entries a single checkpoint may carry.
const MAX_CHECKPOINT_ENTRIES: usize = 4096;

/// Encode/decode one caller-chosen effect-carrier type to/from the closed
/// JSON value this checkpoint format uses. A second, narrower bound than
/// [`ResumableEffectProgram`]'s own `Clone + Eq + Debug + 'static`: a
/// program opts in per type only when it actually needs checkpoint
/// persistence.
pub trait EffectCodec: Sized {
    fn encode_effect(&self) -> Value;
    fn decode_effect(value: &Value) -> Result<Self, String>;
}

impl EffectCodec for () {
    fn encode_effect(&self) -> Value {
        Value::Null
    }
    fn decode_effect(value: &Value) -> Result<Self, String> {
        if value.is_null() {
            Ok(())
        } else {
            Err("expected null for ()".to_string())
        }
    }
}

impl EffectCodec for i64 {
    fn encode_effect(&self) -> Value {
        json!(*self)
    }
    fn decode_effect(value: &Value) -> Result<Self, String> {
        value.as_i64().ok_or_else(|| "expected an i64".to_string())
    }
}

impl EffectCodec for u32 {
    fn encode_effect(&self) -> Value {
        json!(*self)
    }
    fn decode_effect(value: &Value) -> Result<Self, String> {
        let n = value.as_u64().ok_or_else(|| "expected a u32".to_string())?;
        u32::try_from(n).map_err(|_| "u32 out of range".to_string())
    }
}

impl EffectCodec for String {
    fn encode_effect(&self) -> Value {
        json!(self)
    }
    fn decode_effect(value: &Value) -> Result<Self, String> {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "expected a string".to_string())
    }
}

impl EffectCodec for Vec<String> {
    fn encode_effect(&self) -> Value {
        json!(self)
    }
    fn decode_effect(value: &Value) -> Result<Self, String> {
        value
            .as_array()
            .ok_or_else(|| "expected an array".to_string())?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "expected a string element".to_string())
            })
            .collect()
    }
}

/// Why decoding a checkpoint document was refused before it was
/// reconstructed. Each variant is a distinct, stable reason, mirroring
/// [`super::core::JournalError`]'s discipline of never merging a stale
/// program root, a wrong invocation, and a wrong policy epoch into one
/// underspecified rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The encoded document exceeded [`MAX_CHECKPOINT_BYTES`].
    TooLarge,
    /// The document was not valid UTF-8/JSON, or did not match this
    /// format's closed shape (unexpected/missing keys, wrong value type,
    /// unrecognized tag). Carries a short, non-exhaustive description.
    Malformed(String),
    /// The document's `schema` field did not name
    /// [`RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA`].
    SchemaMismatch,
    /// The document's entry count exceeded [`MAX_CHECKPOINT_ENTRIES`].
    TooManyEntries,
    /// The document's own recomputed digest did not match its claimed
    /// `digest` field: the bytes were tampered with or corrupted.
    DigestMismatch,
    /// The document named a different `program_root` than the caller's
    /// independently derived `expected` scope.
    StaleProgramRoot,
    /// The document named a different `invocation_id`.
    WrongInvocation,
    /// The document named a different `policy_epoch`. A checkpoint minted
    /// under an old epoch cannot become a bearer credential for a new one.
    WrongPolicyEpoch,
}

fn keys(v: &Value, expected: &[&str]) -> Result<(), String> {
    let map = v
        .as_object()
        .ok_or_else(|| "expected a JSON object".to_string())?;
    if map.len() != expected.len() || !expected.iter().all(|k| map.contains_key(*k)) {
        return Err("unexpected or missing object keys".to_string());
    }
    Ok(())
}

fn scope_json(scope: &EffectScope) -> Value {
    json!({
        "program_root": scope.program_root,
        "invocation_id": scope.invocation_id,
        "policy_epoch": scope.policy_epoch,
    })
}

fn checkpoint_digest(schema: &str, scope_value: &Value, entries_value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(schema.as_bytes());
    hasher.update(b"\0");
    hasher.update(scope_value.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(entries_value.to_string().as_bytes());
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

fn step_json<P>(step: &Step<P::State, P::Result>) -> Value
where
    P: ResumableEffectProgram,
    P::State: EffectCodec,
    P::Result: EffectCodec,
{
    match step {
        Step::Continue(s) => json!({"tag": "continue", "state": s.encode_effect()}),
        Step::Suspend(s) => json!({"tag": "suspend", "state": s.encode_effect()}),
        Step::Complete(r) => json!({"tag": "complete", "result": r.encode_effect()}),
        Step::Fail(code) => json!({"tag": "fail", "code": code}),
    }
}

fn decode_step<P>(value: &Value) -> Result<Step<P::State, P::Result>, String>
where
    P: ResumableEffectProgram,
    P::State: EffectCodec,
    P::Result: EffectCodec,
{
    let tag = value["tag"]
        .as_str()
        .ok_or_else(|| "step.tag".to_string())?;
    match tag {
        "continue" => {
            keys(value, &["tag", "state"])?;
            Ok(Step::Continue(P::State::decode_effect(&value["state"])?))
        }
        "suspend" => {
            keys(value, &["tag", "state"])?;
            Ok(Step::Suspend(P::State::decode_effect(&value["state"])?))
        }
        "complete" => {
            keys(value, &["tag", "result"])?;
            Ok(Step::Complete(P::Result::decode_effect(&value["result"])?))
        }
        "fail" => {
            keys(value, &["tag", "code"])?;
            let code = value["code"]
                .as_i64()
                .ok_or_else(|| "step.code".to_string())?;
            Ok(Step::Fail(code))
        }
        other => Err(format!("unknown step tag {other:?}")),
    }
}

fn entry_json<P>(entry: &JournalEntry<P>) -> Value
where
    P: ResumableEffectProgram,
    P::State: EffectCodec,
    P::Request: EffectCodec,
    P::Observation: EffectCodec,
    P::Result: EffectCodec,
{
    match entry {
        JournalEntry::Intent { turn, request, .. } => {
            json!({"kind": "intent", "turn": turn, "request": request.encode_effect()})
        }
        JournalEntry::Observed {
            turn,
            request,
            observation,
            ..
        } => {
            json!({
                "kind": "observed",
                "turn": turn,
                "request": request.encode_effect(),
                "observation": observation.encode_effect(),
            })
        }
        JournalEntry::ObservationFailed {
            turn,
            request,
            reason,
            ..
        } => {
            json!({
                "kind": "observation_failed",
                "turn": turn,
                "request": request.encode_effect(),
                "reason": reason,
            })
        }
        JournalEntry::Transition { turn, step, .. } => {
            json!({"kind": "transition", "turn": turn, "step": step_json::<P>(step)})
        }
    }
}

fn decode_entry<P>(value: &Value, scope: &EffectScope) -> Result<JournalEntry<P>, String>
where
    P: ResumableEffectProgram,
    P::State: EffectCodec,
    P::Request: EffectCodec,
    P::Observation: EffectCodec,
    P::Result: EffectCodec,
{
    let kind = value["kind"]
        .as_str()
        .ok_or_else(|| "entry.kind".to_string())?;
    let raw_turn = value["turn"]
        .as_u64()
        .ok_or_else(|| "entry.turn".to_string())?;
    let turn = u32::try_from(raw_turn).map_err(|_| "entry.turn out of range".to_string())?;
    match kind {
        "intent" => {
            keys(value, &["kind", "turn", "request"])?;
            Ok(JournalEntry::Intent {
                turn,
                scope: scope.clone(),
                request: P::Request::decode_effect(&value["request"])?,
            })
        }
        "observed" => {
            keys(value, &["kind", "turn", "request", "observation"])?;
            Ok(JournalEntry::Observed {
                turn,
                scope: scope.clone(),
                request: P::Request::decode_effect(&value["request"])?,
                observation: P::Observation::decode_effect(&value["observation"])?,
            })
        }
        "observation_failed" => {
            keys(value, &["kind", "turn", "request", "reason"])?;
            Ok(JournalEntry::ObservationFailed {
                turn,
                scope: scope.clone(),
                request: P::Request::decode_effect(&value["request"])?,
                reason: value["reason"]
                    .as_str()
                    .ok_or_else(|| "entry.reason".to_string())?
                    .to_string(),
            })
        }
        "transition" => {
            keys(value, &["kind", "turn", "step"])?;
            Ok(JournalEntry::Transition {
                turn,
                scope: scope.clone(),
                step: decode_step::<P>(&value["step"])?,
            })
        }
        other => Err(format!("unknown entry kind {other:?}")),
    }
}

/// Encode `journal`, bound to `scope`, into closed deterministic JSON
/// bytes. Performs no validation of `journal` itself (an already-invalid
/// journal encodes exactly as given); callers wanting a trusted checkpoint
/// should call [`super::core::Journal::validate`] first, the same
/// discipline `run`/`resume` already apply to journals before trusting
/// them.
pub fn encode_checkpoint<P>(scope: &EffectScope, journal: &Journal<P>) -> Vec<u8>
where
    P: ResumableEffectProgram,
    P::State: EffectCodec,
    P::Request: EffectCodec,
    P::Observation: EffectCodec,
    P::Result: EffectCodec,
{
    let entries_value = Value::Array(journal.entries().iter().map(entry_json::<P>).collect());
    let scope_value = scope_json(scope);
    let digest = checkpoint_digest(
        RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA,
        &scope_value,
        &entries_value,
    );
    let doc = json!({
        "schema": RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA,
        "scope": scope_value,
        "digest": digest,
        "entries": entries_value,
    });
    format!("{doc}\n").into_bytes()
}

/// Decode a checkpoint document previously produced by [`encode_checkpoint`]
/// (or any bytes claiming to be one). `expected` is the scope the *caller*
/// independently derived right now; a document naming any other scope is
/// refused before a single entry is reconstructed, exactly the way
/// [`super::core::resume`] refuses a journal under the wrong scope. The
/// returned [`Journal`] is recovered data, not yet a trusted one: call
/// [`super::core::Journal::validate`] before using it for replay or resume.
pub fn decode_checkpoint<P>(bytes: &[u8], expected: &EffectScope) -> Result<Journal<P>, CodecError>
where
    P: ResumableEffectProgram,
    P::State: EffectCodec,
    P::Request: EffectCodec,
    P::Observation: EffectCodec,
    P::Result: EffectCodec,
{
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(CodecError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let doc: Value =
        serde_json::from_str(text).map_err(|e| CodecError::Malformed(e.to_string()))?;
    keys(&doc, &["schema", "scope", "digest", "entries"]).map_err(CodecError::Malformed)?;

    let schema = doc["schema"]
        .as_str()
        .ok_or_else(|| CodecError::Malformed("schema".to_string()))?;
    if schema != RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA {
        return Err(CodecError::SchemaMismatch);
    }

    let scope_value = doc["scope"].clone();
    keys(
        &scope_value,
        &["program_root", "invocation_id", "policy_epoch"],
    )
    .map_err(CodecError::Malformed)?;
    let program_root = scope_value["program_root"]
        .as_str()
        .ok_or_else(|| CodecError::Malformed("scope.program_root".to_string()))?
        .to_string();
    let invocation_id = scope_value["invocation_id"]
        .as_str()
        .ok_or_else(|| CodecError::Malformed("scope.invocation_id".to_string()))?
        .to_string();
    let policy_epoch = scope_value["policy_epoch"]
        .as_u64()
        .ok_or_else(|| CodecError::Malformed("scope.policy_epoch".to_string()))?;

    let entries_value = doc["entries"].clone();
    let entries_array = entries_value
        .as_array()
        .ok_or_else(|| CodecError::Malformed("entries".to_string()))?;
    if entries_array.len() > MAX_CHECKPOINT_ENTRIES {
        return Err(CodecError::TooManyEntries);
    }

    let claimed_digest = doc["digest"]
        .as_str()
        .ok_or_else(|| CodecError::Malformed("digest".to_string()))?;
    let recomputed_digest = checkpoint_digest(schema, &scope_value, &entries_value);
    if claimed_digest != recomputed_digest {
        return Err(CodecError::DigestMismatch);
    }

    // Three distinct checks against the caller's own freshly derived
    // scope, never merged into one, mirroring `JournalError`'s
    // StaleProgramRoot/WrongInvocation/WrongPolicyEpoch split: a document
    // cannot mint its own authority to be trusted merely by decoding.
    if program_root != expected.program_root {
        return Err(CodecError::StaleProgramRoot);
    }
    if invocation_id != expected.invocation_id {
        return Err(CodecError::WrongInvocation);
    }
    if policy_epoch != expected.policy_epoch {
        return Err(CodecError::WrongPolicyEpoch);
    }

    let mut entries = Vec::with_capacity(entries_array.len());
    for raw in entries_array {
        entries.push(decode_entry::<P>(raw, expected).map_err(CodecError::Malformed)?);
    }
    Ok(Journal::from_entries(entries))
}
