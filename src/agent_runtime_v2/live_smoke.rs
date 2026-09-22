//! Live Repair Smoke v1 -- the operator-gated, opt-in route for running the
//! checked repair workflow against a real provider.
//!
//! Everything else in the repair workflow runs offline against a fixture
//! provider. This module is the one place where a *paid, real* provider call
//! becomes reachable, and it is deliberately built as a gate rather than as a
//! convenience:
//!
//! 1. [`LiveRepairSmokeTarget`] names the exact retained Project facts the
//!    smoke will run against. A source path is resolved *inside* the retained
//!    [`ProjectRevision`](crate::project::ProjectRevision) inventory, so a
//!    caller cannot select a host path outside the project, an absolute path,
//!    or a traversal.
//! 2. [`LiveRepairSmokePlan`] joins that target to one already-bound
//!    [`SourceModelBinding`](super::SourceModelBinding) and derives -- never
//!    accepts -- the effective #179 budget by calling the existing
//!    `policy_binding` intersection. A plan therefore cannot carry a budget
//!    wider than the source Agent and deployment already admitted.
//! 3. [`LiveRepairSmokePlan::preflight`] produces a complete readiness receipt
//!    that dispatches nothing. This is the documented "built but unexecuted"
//!    state: a fresh operator can run it with no credentials, read exactly
//!    which prerequisites are satisfied, and see `dispatched: false` and
//!    `provider_dispatch_count: 0` on the receipt itself.
//! 4. [`OperatorLiveSmokeGrant`] is the separate, explicit operator act. It is
//!    minted only by [`OperatorLiveSmokeGrant::grant`], binds one exact plan
//!    digest, and may only *narrow* the plan's effective ceilings. A grant for
//!    plan A never authorizes plan B, and replaying a grant across a session
//!    boundary re-checks its canonical bytes and digest.
//! 5. [`LiveRepairSmokeRecord`] records the *true* outcome, including failure.
//!    A provider failure, an exhausted budget and a cancellation are all valid
//!    recorded results; there is no constructor that turns a fixture run into
//!    a live record, and a record whose reported usage exceeds the authorized
//!    ceiling is refused rather than stored.
//!
//! This module holds no credential, endpoint, prompt or response body, opens
//! no socket and performs no filesystem write. It grants no publication
//! authority: publishing a reviewed repair candidate goes through
//! [`super::repair_approval`], which requires its own separate approval bound
//! to one exact candidate digest.
//!
//! See `docs/LIVE-REPAIR-SMOKE-V1.md`.

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::diagnostic::Diagnostic;

mod authorization;
mod plan;
mod preflight;
mod record;
mod target;

#[cfg(test)]
mod tests;

pub use authorization::{AuthorizedLiveRepairSmoke, OperatorLiveSmokeGrant};
pub use plan::LiveRepairSmokePlan;
pub use preflight::{LiveRepairSmokePreflight, LiveRepairSmokePrerequisite};
pub use record::{LiveRepairSmokeOutcome, LiveRepairSmokeRecord, LiveRepairSmokeUsage};
pub use target::LiveRepairSmokeTarget;

/// Canonical schema identities. Each document is self-describing so a receipt
/// read out of a log cannot be mistaken for a different one.
pub const LIVE_REPAIR_SMOKE_TARGET_SCHEMA: &str = "semaprax.live-repair-smoke-target.v1";
pub const LIVE_REPAIR_SMOKE_PLAN_SCHEMA: &str = "semaprax.live-repair-smoke-plan.v1";
pub const LIVE_REPAIR_SMOKE_PREFLIGHT_SCHEMA: &str = "semaprax.live-repair-smoke-preflight.v1";
pub const LIVE_REPAIR_SMOKE_GRANT_SCHEMA: &str = "semaprax.live-repair-smoke-operator-grant.v1";
pub const LIVE_REPAIR_SMOKE_RECORD_SCHEMA: &str = "semaprax.live-repair-smoke-record.v1";

/// Transport bound shared by every document in this contract. These are small
/// commitment documents, never transcripts.
pub const MAX_LIVE_REPAIR_SMOKE_BYTES: usize = 64 * 1024;

/// Bound on every free-form identity label this contract accepts.
pub(crate) const MAX_LABEL_BYTES: usize = 256;

/// Bound on the operator's own justification text. Long enough to be a real
/// sentence, short enough that it can never become a channel.
pub(crate) const MAX_JUSTIFICATION_BYTES: usize = 1024;

/// A live smoke exercises the wrong-then-corrected loop, so it needs at least
/// two provider turns to mean anything at all.
pub(crate) const MIN_SMOKE_TURNS: u32 = 2;

/// A smoke is a smoke, not a soak. Refuse a plan that quietly asks for an
/// open-ended number of paid turns.
pub(crate) const MAX_SMOKE_TURNS: u32 = 16;

pub(crate) type Result<T> = std::result::Result<T, Vec<Diagnostic>>;

pub(crate) fn refused(detail: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::io(
        "SPX-G583",
        format!("live repair smoke refused: {detail}"),
    )]
}

pub(crate) fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

/// Render one document as canonical JSON with a trailing LF, refusing anything
/// that does not fit the shared transport bound. `serde_json::Value` orders
/// object keys, so the rendering is deterministic for a given input.
pub(crate) fn render(value: &Value) -> Result<String> {
    let mut json =
        serde_json::to_string(value).map_err(|_| refused("document is not renderable JSON"))?;
    json.push('\n');
    if json.len() > MAX_LIVE_REPAIR_SMOKE_BYTES {
        return Err(refused("document exceeds its transport bound"));
    }
    Ok(json)
}

/// Reparse a document that crossed a session boundary, requiring its exact
/// canonical bytes, its declared schema and its expected digest. Tampering in
/// transit fails closed rather than producing a weaker document.
pub(crate) fn replay_document(
    domain: &[u8],
    schema: &str,
    expected_digest: &str,
    bytes: &[u8],
) -> Result<Value> {
    validate_digest_label(expected_digest)?;
    if bytes.is_empty() || bytes.len() > MAX_LIVE_REPAIR_SMOKE_BYTES {
        return Err(refused("replayed document is empty or exceeds its bound"));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| refused("replayed document is not JSON"))?;
    if value.get("schema").and_then(Value::as_str) != Some(schema) {
        return Err(refused("replayed document has a different schema"));
    }
    if render(&value)?.as_bytes() != bytes {
        return Err(refused("replayed document is not canonical JSON"));
    }
    if digest(domain, bytes) != expected_digest {
        return Err(refused("replayed document digest is stale"));
    }
    Ok(value)
}

/// A bounded, control-character-free identity label. Identities in this
/// contract are commitments a reader compares, never text a provider renders.
pub(crate) fn validate_label(label: &str, detail: &'static str) -> Result<()> {
    if label.is_empty()
        || label.len() > MAX_LABEL_BYTES
        || label.chars().any(char::is_control)
        || label.trim() != label
    {
        return Err(refused(detail));
    }
    Ok(())
}

/// The repository's canonical `sha256:<64 lowercase hex>` digest label. Every
/// digest this contract stores or compares -- its own documents' digests, the
/// bound model and policy digests, the project revision and the candidate
/// digest -- uses this one shape, so a reader never has to guess which
/// encoding a field is in.
pub(crate) fn validate_digest_label(value: &str) -> Result<()> {
    if value.len() != 71 || !value.starts_with("sha256:") {
        return Err(refused("digest label is not a canonical SHA-256 digest"));
    }
    if !value.as_bytes()[7..]
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(refused("digest label is not lowercase hexadecimal"));
    }
    Ok(())
}

pub(crate) fn string_field(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| refused("replayed document is missing a required string field"))
}

pub(crate) fn u64_field(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("replayed document is missing a required unsigned field"))
}

pub(crate) fn i64_field(value: &Value, key: &str) -> Result<i64> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| refused("replayed document is missing a required signed field"))
}

pub(crate) fn u32_field(value: &Value, key: &str) -> Result<u32> {
    u32::try_from(u64_field(value, key)?)
        .map_err(|_| refused("replayed document field exceeds its declared width"))
}
