use super::tests::{bound_receipt, clean_extras};
use super::*;
use crate::model_call_receipt::audit_view::canonical::{
    render_canonical_view, replay_canonical_view,
};

#[test]
fn audit_verification_requires_complete_exclusive_disclosure() {
    let extras = clean_extras();
    let receipt = bound_receipt(&extras);
    let view = checked_redact(&receipt, &extras, &RedactionPolicy::fully_redacted()).unwrap();
    for mode in 0..3 {
        let mut altered = view.clone();
        match mode {
            0 => altered.redacted_fields.clear(),
            1 => altered
                .redacted_fields
                .push(altered.redacted_fields[0].clone()),
            _ => altered.task_preview = Some(extras.task.clone()),
        }
        assert_eq!(
            verify_audit_view(&altered, &receipt, &extras),
            Err(AuditViewError::IncompleteRedaction)
        );
    }
    let mut stale_extras = extras.clone();
    stale_extras.task.push(b'!');
    assert_eq!(
        verify_audit_view(&view, &receipt, &stale_extras),
        Err(AuditViewError::PayloadMismatch { field: "task" })
    );
}

#[test]
fn audit_verification_checks_all_text_previews_and_privacy_claims() {
    let extras = ReceiptPrivateExtras {
        private_payload_reference_material: Some("unverified reference".into()),
        adapter_diagnostic_hint: Some("adapter detail".into()),
        provider_error_detail: Some("provider detail".into()),
        authorization_header_echo: Some("secret".into()),
        ..clean_extras()
    };
    let receipt = bound_receipt(&extras);
    let original = checked_redact(&receipt, &extras, &RedactionPolicy::fully_revealed()).unwrap();
    for name in [
        "private_payload_reference_material",
        "adapter_diagnostic_hint",
        "provider_error_detail",
        "authorization_header_echo",
    ] {
        let mut view = original.clone();
        let field = match name {
            "private_payload_reference_material" => &mut view.private_reference_material,
            "adapter_diagnostic_hint" => &mut view.adapter_diagnostic_hint,
            "provider_error_detail" => &mut view.provider_error_detail,
            _ => &mut view.authorization_header_echo,
        };
        *field = Some("forged".into());
        assert_eq!(
            verify_audit_view(&view, &receipt, &extras),
            Err(AuditViewError::RevealedFieldTampered { field: name })
        );
    }
    let mut view = original;
    view.task_privacy_claim = PayloadPrivacyClaim::Withheld;
    assert_eq!(
        verify_audit_view(&view, &receipt, &extras),
        Err(AuditViewError::PrivacyClaimMismatch)
    );
}

#[test]
fn canonical_audit_replays_exact_bytes_and_never_repairs_disclosed_utf8() {
    let extras = ReceiptPrivateExtras {
        task: vec![0xff, 0],
        ..clean_extras()
    };
    let receipt = bound_receipt(&extras);
    let policy = RedactionPolicy::fully_revealed();
    let canonical = render_canonical_view(&receipt, &extras, &policy).unwrap();
    assert!(canonical.contains("\"task_preview_hex\":\"ff00\""));
    replay_canonical_view(canonical.as_bytes(), &receipt, &extras, &policy).unwrap();
    let mut altered = canonical.into_bytes();
    altered[0] ^= 1;
    assert_eq!(
        replay_canonical_view(&altered, &receipt, &extras, &policy),
        Err(AuditViewError::CanonicalMismatch)
    );
    let mut oversized = extras;
    oversized.task = vec![0; 65_537];
    assert_eq!(
        checked_redact(&receipt, &oversized, &policy),
        Err(AuditViewError::Limit)
    );
}
