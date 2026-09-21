use super::*;

#[test]
fn exporter_requires_redaction_for_every_protected_name_alias_before_transport() {
    for name in [
        "PASSWORD",
        "Api-Key",
        "bearer_token",
        "Session-Token",
        "webhook_signing_secret",
        "SMTP-CREDENTIAL",
        "authorization",
        "Cookie",
        "set-cookie",
        "Proxy-Authorization",
        "access_token",
        "Refresh-Token",
    ] {
        for event in [
            ExportEvent {
                stable_event_id: "event.protected-label".into(),
                labels: vec![(name.into(), "plaintext-secret".into())],
                fields: Vec::new(),
            },
            ExportEvent {
                stable_event_id: "event.protected-field".into(),
                labels: Vec::new(),
                fields: vec![ExportField {
                    name: name.into(),
                    value: ExportFieldValue::Public("plaintext-secret".into()),
                }],
            },
        ] {
            let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
                status: 204,
                body: Vec::new(),
            });
            assert_eq!(
                export_event(
                    capability(),
                    "https://hooks.example.test/collect".into(),
                    1_000,
                    event,
                    &mut adapter,
                ),
                Err(Refusal::ProtectedValue),
                "protected export name {name} escaped redaction"
            );
            assert!(adapter.calls.is_empty());
        }
    }
}

#[test]
fn exporter_admits_exact_redaction_and_does_not_guess_from_name_substrings() {
    let event = ExportEvent {
        stable_event_id: "event.protected-boundary".into(),
        labels: vec![("password_hash".into(), "public-algorithm-id".into())],
        fields: vec![ExportField {
            name: "Proxy-Authorization".into(),
            value: ProtectedExportValue::from_host_bytes(b"private".to_vec())
                .unwrap()
                .into_redacted(false),
        }],
    };
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    export_event(
        capability(),
        "https://hooks.example.test/collect".into(),
        1_000,
        event,
        &mut adapter,
    )
    .unwrap();
    assert_eq!(adapter.calls.len(), 1);
    let body = std::str::from_utf8(adapter.calls[0].body()).unwrap();
    assert!(body.contains("password_hash"));
    assert!(body.contains("public-algorithm-id"));
    assert!(body.contains("[REDACTED]"));
    assert!(!body.contains("private"));
}
