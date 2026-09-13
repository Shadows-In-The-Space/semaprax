//! Bounded exact-byte audit-view projection and independent replay.
use super::*;
use serde_json::json;

pub const MAX_AUDIT_VIEW_BYTES: usize = 1_048_576;

/// Canonical v1 JSON uses hex for disclosed arbitrary byte payloads, preserving
/// invalid UTF-8 without lossy repair. The review renderer is display-only.
pub fn render_canonical_view(
    receipt: &ModelCallReceipt,
    extras: &ReceiptPrivateExtras,
    policy: &RedactionPolicy,
) -> Result<String, AuditViewError> {
    let view = checked_redact(receipt, extras, policy)?;
    let encode =
        |bytes: &Option<Vec<u8>>| bytes.as_deref().map(crate::live_invocation::identity::hex);
    let canonical = json!({
        "schema": AUDIT_VIEW_SCHEMA,
        "receipt_digest": view.receipt_digest,
        "redacted_fields": view.redacted_fields.iter().map(|f| json!({"name": f.name, "commitment_digest": f.commitment_digest})).collect::<Vec<_>>(),
        "task_preview_hex": encode(&view.task_preview),
        "observation_preview_hex": encode(&view.observation_preview),
        "response_preview_hex": encode(&view.response_preview),
        "private_reference_material": view.private_reference_material,
        "adapter_diagnostic_hint": view.adapter_diagnostic_hint,
        "provider_error_detail": view.provider_error_detail,
        "authorization_header_echo": view.authorization_header_echo,
        "task_privacy_claim": view.task_privacy_claim.as_str(),
        "observation_privacy_claim": view.observation_privacy_claim.as_str(),
        "response_privacy_claim": view.response_privacy_claim.map(PayloadPrivacyClaim::as_str),
    }).to_string() + "\n";
    if canonical.len() > MAX_AUDIT_VIEW_BYTES {
        return Err(AuditViewError::Limit);
    }
    Ok(canonical)
}

/// Regenerates from independently retained receipt, payloads and disclosure
/// policy. No provider, tool, or private-storage handler can be passed here.
pub fn replay_canonical_view(
    submitted: &[u8],
    receipt: &ModelCallReceipt,
    extras: &ReceiptPrivateExtras,
    policy: &RedactionPolicy,
) -> Result<(), AuditViewError> {
    if submitted.len() > MAX_AUDIT_VIEW_BYTES {
        return Err(AuditViewError::Limit);
    }
    let expected = render_canonical_view(receipt, extras, policy)?;
    if submitted != expected.as_bytes() {
        return Err(AuditViewError::CanonicalMismatch);
    }
    Ok(())
}
