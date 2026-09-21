//! Private-root TLS evidence for the typed webhook and email delivery sessions.
//!
//! This deliberately repeats the test certificate setup rather than making a
//! sibling test module a mutable support API. The only authority here is an
//! explicitly constructed policy for one held loopback listener.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::*;

const ROOT: &str = "MIIDJzCCAg+gAwIBAgIUC3kI/KYpwSCFZIOpQLwZZv3fpIUwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQU0VNQVBSQVggVGVzdCBDQTAeFw0yNjA5MDUxNDU3MTlaFw0zNjA5MDIxNDU3MTlaMBsxGTAXBgNVBAMMEFNFTUFQUkFYIFRlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtxpzwCk3e4aRY3ozKBTi94gfLHe6yKDfDggOHGiwUGotJ9dVH8e4Hh82JamO+jH694HBmjlbGXF+BY7Gxv/Vz8Z7R9VqS1uND7J4V4pJABLL4H//k/c0WPMopTkQRmVyit34hTob14aL+hPq4DFOtH+FxXiUyPaJp6xP0UH7KTJpSBJfBlTAmJoBuMP7Ara05oozrVuLNzSDaUulGGkA5kUuv2GnPvQjTx8PG14GUfJt6okOD64JJSaoQCrraxyHIG8UmZgnHyoIq3UgFY9gj4haVW6ykKe+bkWVbwCOZcMAffzx+NKDodSahn3Qy2z0eDI0ARMtVFDE+ijtxlG/1AgMBAAGjYzBhMB0GA1UdDgQWBBT4Dg/tRse2xlFPUoKfa/7M5c40VjAfBgNVHSMEGDAWgBT4Dg/tRse2xlFPUoKfa/7M5c40VjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAmEWc71S2305pR9Ps29VDVdwOcVoetWsqEnCsAIHg0qfioQz3mznfxE3gOZ4gm03AOslf2sqq8ev02MnEuZWt7Y7xwstrTyo0EA4mWXzBTz0EX7Qp1PgV4MV7Lifp+Dv5ACDx75bgOziKx+u6VVvR0RoE1tUB3m3ihO7aT0HMXOBvElkuY7Ev+fR7lgSFOPGYV2IIBcfaro0dGJlixyBjP/TLGAr8S6buf0ZFCBKtMriXyfiqcQ8IPeLEOtFGxhrWKoNoRpkYwM5kut27vDkoc5UekFmU4EaGPl0cWEpoky5RMXgrA0hAzKEmgPnbIVplKwdoELQjon+MR1HA9txCeg==";
const LEAF: &str = "MIIDSjCCAjKgAwIBAgIUK81c/KylyZTx6OJ/K9lJP7OLzBgwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQU0VNQVBSQVggVGVzdCBDQTAeFw0yNjA5MDUxNDU3MTlaFw0zNjA5MDIxNDU3MTlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6ibgX7OJCn5nsP0DH497ZCdsxQN23ifpv3ZWWNbKScZi4k5R0nZqJb/asrOa/vgc/An5YBYdsHV/9SqE7CVxhgCj+sYo6W2RfyDV8PF3fztxg+1Varrm0RcI4DaZN2N7fqdxZPvpIl//3n3J2G6J2d919ZPZpog0ahqlHjfvmIh1ESeS2XIu1T4dHlBvW1m3AgoFneNZDHDQs9ziuKte6KShv2I6rOzIRSC5vHM4YsDC64NANbheAV0L98rc/51A6jJxziKQtpFDhBHGvAhag3JkOUyLP7fiIPiHBI0Qxmh70EBj2EgUo5OqV1pNytbH4zBrKlyjQj+R2o8ReNpY8CAwEAAaOBjDCBiTAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFD69svZnO8+sMQfesN19Zk40CBU8MB8GA1UdIwQYMBaAFPgOD+1Gx7bGUU9Sgp9r/szlzjRWMA0GCSqGSIb3DQEBCwUAA4IBAQAwcYsnw9zK+9lMrIN6zSxry26FFIjOP/ZRXSeloNPA2Fd2p+16b7RoHL+tcn4P4NMCKsz2Y+faX6lzSzIi0lydRsM8rH3xY4/Y8UDoLyC6zDQXpZNbEyWQALgKoZjV8l4XEbtmhLx++h2wArD/eEneBW3aCL8QzNgTU6gyobp1y6AqxQPnl+2SpBlFtpnoz0W3CCOGc0UiaobxBNTYydtY37vGQPLs32drQ2E0o9RfD+4/MTTkS380fXI4pEW4XOm/AofuMwVz1zkWXY/CzYp+1czf7/sOLDTsuwt0/QJFhK3IGSBL1wH3lU8BUHC6LMysilY3Eujo+Ya7dHAyM0lb";
const LEAF_KEY: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOom4F+ziQp+Z7D9Ax+Pe2QnbMUDdt4n6b92VljWyknGYuJOUdJ2aiW/2rKzmv74HPwJ+WAWHbB1f/UqhOwlcYYAo/rGKOltkX8g1fDxd387cYPtVWq65tEXCOA2mTdje36ncWT76SJf/959ydhuidnfdfWT2aaINGoapR4375iIdREnktlyLtU+HR5Qb1tZtwIKBZ3jWQxw0LPc4rirXuikob9iOqzsyEUgubxzOGLAwuuDQDW4XgFdC/fK3P+dQOoycc4ikLaRQ4QRxrwIWoNyZDlMiz+34iD4hwSNEMZoe9BAY9hIFKOTqldaTcrWx+Mwaypco0I/kdqPEXjaWPAgMBAAECggEAS9lKyq5HOq4vB8Aru5Q4lXH7Oo89cXwA3o5m7WqG1TvFtC193oA+h919lW3F/KNNgq2hxsXWHjipYAL+3f4vSzbBvFKyUMXlhYknyFt5UWIoNOGnnOtjGQ0cRDzTbbooxL1vnkSCXxJMz+5iyH4jd+vqyFixKLMxcOVZ6Do6OyzuFK2hq1dp2R+fk0TVyQAFTtqSVC5DR/dxzX+mIkkzJWJvfsTnlBZ19j9q8ft0XnOfEpHDSfxzoOXx1SdF+CvA15kjmWVUQbHTMgcPni90NhomPgdlhqXfHx+N+ar3GJO9+GJ8QGhwPXGRGpa81lkQZMTb0Q+rsbqws3Xvl1Nz4QKBgQDtKB7jWevWtakv6k8i6HVe4iGxBwYAHUKe8IrMZt5HQ0gs4iBU6kwZtgW9c02VeHYHnSf/oEF/2OnXpxyQjiHR5LkcZ87lnuivX0bZo8Ijt1dXfczQFZA/zCfpuoTHSQKD8Mw5MbrQ1XrRZaYZMlZ6f0OBPMN8P1657nVwCg3RIQKBgQDfDXj8HqC2blafwwb2dUvKQSH7J4biz7QFl/ZTCJyEu8SSLNJRnKyrIC5mewdJFM3CT9eqIklNkrxbIqd0URy0i512cVIjQmGTtaD0c3S361N9MStlKwsrCtj7Oy4qBdlq/lG03pMubWntRdXnm6e+l+KG6fZ+h+W5y6MEXLWwrwKBgHsfISoXPQEzPqrJklwlIwonjCZD5zGX/0ZUyzpjDXMh0w66Nt7e5LNUdJZujhDTgTNiu6lSoa6mBoEXGRVTNOurOw8sNZWwckzZwgarpda1EHszrGk7SLBWZUJKuzRbCxtEoEHxN3PD4QdlJl5ea9ccywcFbNfMbnlI+183WQUBAoGAVyqBrC0f6wsFiRuC/g9qldiMOgUBXmOC22i+V0aXO/vQ3rrrWf9bLui9mUjc2P9rRVNEWXVaphkAyLCrNfZ4vEmPOHkieyr2zO1+v+japQEuuE7dwYRnseNkVhGTgdKVW42VSpRseglCCvpulDss+3uJh+WocVwUN15QD2VXj3sCgYAyP2FCNPdfg1r2LcNMn06gwnLz+NHn4HK1PNjrRTQgrKYG9xf8gvM0HgoSdR1mfDjdPqgPMdLFG23jmpOG23waokgIsBl88SGdaCVJ/+Ti4WFHhKkhRwgmNX/4se+JsD5nSGaBwkrZ6uyLs+W39hFa0MQzDdRCQjsuuRWFsn7YpA==";

fn decode64(input: &str) -> Vec<u8> {
    fn digit(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("test fixture is base64"),
        }
    }
    let mut output = Vec::new();
    let mut bits = 0u32;
    let mut count = 0u8;
    for byte in input.bytes().filter(|byte| *byte != b'=') {
        bits = (bits << 6) | u32::from(digit(byte));
        count += 6;
        if count >= 8 {
            count -= 8;
            output.push((bits >> count) as u8);
            bits &= (1u32 << count) - 1;
        }
    }
    output
}

fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn trusted_configs() -> (rustls::ClientConfig, rustls::ServerConfig) {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(decode64(ROOT)))
        .expect("test root is a certificate");
    let client = rustls::ClientConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()
        .expect("ring has safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()
        .expect("ring has safe protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(decode64(LEAF))],
            rustls::pki_types::PrivatePkcs8KeyDer::from(decode64(LEAF_KEY)).into(),
        )
        .expect("test key matches test certificate");
    (client, server)
}

fn empty_root_client() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()
        .expect("ring has safe protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
}

/// Retain the certificate's `localhost` identity while pinning this test's
/// only resolution to its held loopback listener.
fn loopback_adapter(tls: rustls::ClientConfig, port: u16) -> NativeHttpsAdapter {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(2)
        .resolve("localhost", SocketAddr::from(([127, 0, 0, 1], port)))
        .build()
        .expect("explicit loopback transport config");
    NativeHttpsAdapter { client }
}

struct ExpectedRequest {
    route: &'static str,
    content_type: &'static str,
    delivery_header: &'static str,
    body_marker: &'static [u8],
    signature: Option<String>,
}

fn read_request(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
) -> (Vec<u8>, Vec<u8>) {
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("bounded request headers");
        headers.push(byte[0]);
        assert!(headers.len() <= 16_384, "request headers are bounded");
    }
    let text = std::str::from_utf8(&headers).expect("request headers are ASCII");
    let length = text
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("request has content length")
        .parse::<usize>()
        .expect("content length is decimal");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).expect("request body");
    (headers, body)
}

fn serve_once(
    config: rustls::ServerConfig,
    expected: impl FnOnce(u16) -> ExpectedRequest + Send + 'static,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
    let port = listener.local_addr().expect("listener address").port();
    let expected = expected(port);
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("one TLS client");
        socket
            .set_read_timeout(Some(Duration::from_millis(2_250)))
            .expect("read timeout");
        let connection = rustls::ServerConnection::new(Arc::new(config)).expect("TLS server");
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let (headers, body) = read_request(&mut stream);
        let text = std::str::from_utf8(&headers).expect("headers are ASCII");
        assert!(
            text.starts_with(&format!("POST {} HTTP/1.1\r\n", expected.route)),
            "typed delivery owns its exact request target"
        );
        assert!(
            text.lines()
                .any(|line| line == format!("content-type: {}", expected.content_type)),
            "typed delivery owns its media type"
        );
        assert!(
            text.lines().any(|line| line == expected.delivery_header),
            "boundary-owned delivery identity reaches the peer"
        );
        assert!(
            text.lines()
                .any(|line| line.starts_with("idempotency-key: ")),
            "boundary-owned idempotency identity reaches the peer"
        );
        if let Some(expected_signature) = expected.signature.as_deref() {
            let signature = text
                .lines()
                .find_map(|line| line.strip_prefix("x-semaprax-signature-v2: "))
                .expect("host-owned webhook signature reaches the peer");
            assert_eq!(
                signature, expected_signature,
                "the exact signed bytes reach TLS"
            );
        } else {
            for forbidden in [
                "authorization:",
                "proxy-authorization:",
                "cookie:",
                "x-api-key:",
                "api-key:",
                "x-provider-token:",
                "provider-token:",
                "x-provider-api-key:",
                "provider-api-key:",
                "x-access-token:",
                "access-token:",
                "bearer-token:",
                "smtp-credential:",
            ] {
                assert!(
                    !text.lines().any(|line| line.starts_with(forbidden)),
                    "provider credentials stay outside the email request: {forbidden}"
                );
            }
        }
        assert!(
            body.windows(expected.body_marker.len())
                .any(|window| window == expected.body_marker),
            "typed body reaches the private TLS peer"
        );
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("bounded response write");
        stream.flush().expect("response flush");
    });
    (port, worker)
}

fn serve_rejected_handshake(config: rustls::ServerConfig) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
    let port = listener.local_addr().expect("listener address").port();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("one TLS client");
        socket
            .set_read_timeout(Some(Duration::from_millis(2_250)))
            .expect("read timeout");
        let connection = rustls::ServerConnection::new(Arc::new(config)).expect("TLS server");
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut byte = [0u8; 1];
        let _ = stream.read(&mut byte);
    });
    (port, worker)
}

fn policy(port: u16, policy_id: &str, max_response_bytes: usize) -> OutboundPolicy {
    OutboundPolicy::new(
        policy_id,
        [format!("https://localhost:{port}")],
        4_096,
        max_response_bytes,
        2_000,
        8,
        8,
    )
    .expect("explicit loopback policy")
}

fn capability(port: u16, policy_id: &str, max_response_bytes: usize) -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host(
        "sha256:native-delivery-loopback",
        "native-delivery-invocation-1",
        policy(port, policy_id, max_response_bytes),
    )
    .expect("trusted host grant")
}

fn webhook(endpoint: String, body: &[u8]) -> WebhookRequest {
    WebhookRequest {
        endpoint,
        delivery_id: "native-webhook-1".into(),
        idempotency_key: "native:webhook:1".into(),
        content_type: "application/json".into(),
        body: body.to_vec(),
        deadline_ms: 2_000,
    }
}

/// Independently render the fixed v2 MAC input. This intentionally does not
/// call the production signing helper: a framing regression must fail at the
/// real TLS peer rather than be repeated by the expectation.
fn expected_webhook_signature(secret: [u8; 32], port: u16, body: &[u8]) -> String {
    fn part(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
        mac.update(&(bytes.len() as u64).to_le_bytes());
        mac.update(bytes);
    }
    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut rendered = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            rendered.push(HEX[(byte >> 4) as usize] as char);
            rendered.push(HEX[(byte & 0x0f) as usize] as char);
        }
        rendered
    }

    let origin = format!("https://localhost:{port}");
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("fixed HMAC key");
    mac.update(b"semaprax.outbound.webhook-signature.v2\0");
    for value in [
        b"POST".as_slice(),
        b"sha256:native-delivery-loopback".as_slice(),
        origin.as_bytes(),
        b"/v1/webhook".as_slice(),
        b"native-webhook-1".as_slice(),
        b"native:webhook:1".as_slice(),
        b"application/json".as_slice(),
        body,
    ] {
        part(&mut mac, value);
    }
    format!("hmac-sha256={}", lower_hex(&mac.finalize().into_bytes()))
}

fn email(endpoint: String, body: &[u8]) -> EmailRequest {
    EmailRequest {
        endpoint,
        delivery_id: "native-email-1".into(),
        idempotency_key: "native:email:1".into(),
        sender: "sender@example.test".into(),
        recipients: vec!["recipient@example.test".into()],
        reply_to: Some("reply@example.test".into()),
        subject: "Private loopback delivery".into(),
        body: body.to_vec(),
        attachments: vec![EmailAttachment {
            name: "receipt.txt".into(),
            media_type: "text/plain".into(),
            body: b"attachment".to_vec(),
        }],
        deadline_ms: 2_000,
    }
}

#[derive(Default)]
struct WebhookStore {
    checkpoints: Vec<WebhookDeliverySessionCheckpoint>,
}

impl WebhookDeliverySessionCheckpointStore for WebhookStore {
    fn commit(&mut self, checkpoint: &WebhookDeliverySessionCheckpoint) -> CheckpointCommit {
        self.checkpoints.push(checkpoint.clone());
        CheckpointCommit::Committed
    }
}

#[derive(Default)]
struct EmailStore {
    checkpoints: Vec<EmailDeliverySessionCheckpoint>,
}

impl EmailDeliverySessionCheckpointStore for EmailStore {
    fn commit(&mut self, checkpoint: &EmailDeliverySessionCheckpoint) -> CheckpointCommit {
        self.checkpoints.push(checkpoint.clone());
        CheckpointCommit::Committed
    }
}

fn rebind_without_connection(port: u16) -> TcpListener {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("rebind loopback port");
    listener
        .set_nonblocking(true)
        .expect("nonblocking replay listener");
    listener
}

fn assert_no_connection(listener: &TcpListener, message: &str) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "{message}"
    );
}

#[test]
fn webhook_session_dispatches_once_over_private_tls_and_restores_without_redispatch() {
    let body = br#"{"event":"completed"}"#;
    let (client, server) = trusted_configs();
    let (port, worker) = serve_once(server, move |port| ExpectedRequest {
        route: "/v1/webhook",
        content_type: "application/json",
        delivery_header: "x-semaprax-delivery-id: native-webhook-1",
        body_marker: b"\"completed\"",
        signature: Some(expected_webhook_signature([31; 32], port, body)),
    });
    let endpoint = format!("https://localhost:{port}/v1/webhook");
    assert_ne!(
        expected_webhook_signature([31; 32], port, body),
        expected_webhook_signature([31; 32], port, br#"{"event":"changed"}"#),
        "the exact body participates in the independently calculated MAC"
    );
    assert_ne!(
        expected_webhook_signature([31; 32], port, body),
        expected_webhook_signature([32; 32], port, body),
        "a distinct host signing secret changes the independently calculated MAC"
    );
    let mut session = WebhookDeliverySession::new(2).expect("bounded typed session");
    let mut store = WebhookStore::default();
    let mut adapter = loopback_adapter(client, port);
    let first = session
        .reconcile_durable(
            prepare_webhook_delivery(
                capability(port, "native.webhook.v1", 64),
                WebhookSigningSecret::from_trusted_host_bytes([31; 32]),
                webhook(endpoint.clone(), body),
            )
            .expect("matching explicit host policy admits webhook"),
            &mut store,
            &mut adapter,
        )
        .expect("webhook settles over private TLS");
    assert!(matches!(
        first,
        DurableWebhookDeliveryOutcome::Dispatched(_)
    ));
    assert_eq!(
        store.checkpoints.len(),
        2,
        "intent and terminal states commit"
    );
    worker.join().expect("one webhook TLS request");

    let checkpoint = store.checkpoints.last().expect("terminal checkpoint");
    let wire = checkpoint.render();
    let digest = checkpoint.digest();
    let capacity = checkpoint.capacity();
    let mut tampered = wire.clone();
    tampered.push(' ');
    assert!(matches!(
        WebhookDeliverySession::restore_authenticated(
            tampered.as_bytes(),
            WebhookDeliverySessionRestoreCapability::grant_for_trusted_host(&digest, capacity)
                .expect("trusted store binds expected checkpoint"),
        ),
        Err(WebhookDeliverySessionRestoreRefusal::Checkpoint(
            DeliverySessionCheckpointRefusal::BindingMismatch
        ))
    ));
    let mut restored = WebhookDeliverySession::restore_authenticated(
        wire.as_bytes(),
        WebhookDeliverySessionRestoreCapability::grant_for_trusted_host(digest, capacity)
            .expect("trusted store binds exact checkpoint"),
    )
    .expect("exact webhook checkpoint restores");

    let listener = rebind_without_connection(port);
    let (client, _) = trusted_configs();
    let mut replay_adapter = loopback_adapter(client, port);
    let replay = restored
        .reconcile(
            prepare_webhook_delivery(
                capability(port, "native.webhook.v1", 64),
                WebhookSigningSecret::from_trusted_host_bytes([31; 32]),
                webhook(endpoint.clone(), body),
            )
            .expect("exact replay remains admitted"),
            &mut replay_adapter,
        )
        .expect("exact webhook replay is retained");
    assert!(replay.was_replayed());
    assert_no_connection(&listener, "exact restored webhook replay must not open TLS");

    assert_eq!(
        restored.reconcile(
            prepare_webhook_delivery(
                capability(port, "native.webhook.v1", 64),
                WebhookSigningSecret::from_trusted_host_bytes([31; 32]),
                webhook(endpoint.clone(), br#"{"event":"changed"}"#),
            )
            .expect("changed webhook remains individually valid"),
            &mut replay_adapter,
        ),
        Err(WebhookLedgerRefusal::Ledger(
            LedgerRefusal::ConflictingRequest
        ))
    );
    assert_no_connection(&listener, "webhook request drift must refuse before TLS");
    assert_eq!(
        restored.reconcile(
            prepare_webhook_delivery(
                capability(port, "native.webhook.v1", 64),
                WebhookSigningSecret::from_trusted_host_bytes([32; 32]),
                webhook(endpoint.clone(), body),
            )
            .expect("a changed host secret still produces an individually valid request"),
            &mut replay_adapter,
        ),
        Err(WebhookLedgerRefusal::Ledger(
            LedgerRefusal::ConflictingRequest
        ))
    );
    assert_no_connection(
        &listener,
        "webhook signing-secret drift must refuse before TLS",
    );
    assert_eq!(
        restored.reconcile(
            prepare_webhook_delivery(
                capability(port, "native.webhook.v1", 63),
                WebhookSigningSecret::from_trusted_host_bytes([31; 32]),
                webhook(endpoint.clone(), body),
            )
            .expect("policy-drifted webhook remains individually valid"),
            &mut replay_adapter,
        ),
        Err(WebhookLedgerRefusal::PolicyChanged)
    );
    assert_no_connection(&listener, "webhook policy drift must refuse before TLS");

    let (_, server) = trusted_configs();
    let (untrusted_port, worker) = serve_rejected_handshake(server);
    let mut uncertain = WebhookDeliverySession::new(1).expect("bounded session");
    let receipt = uncertain
        .reconcile(
            prepare_webhook_delivery(
                capability(untrusted_port, "native.webhook.untrusted.v1", 64),
                WebhookSigningSecret::from_trusted_host_bytes([31; 32]),
                webhook(
                    format!("https://localhost:{untrusted_port}/v1/webhook"),
                    body,
                ),
            )
            .expect("untrusted route remains policy-admitted before TLS"),
            &mut loopback_adapter(empty_root_client(), untrusted_port),
        )
        .expect("post-start TLS failure settles as a typed receipt");
    assert!(matches!(
        receipt.evidence().disposition(),
        DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport
        }
    ));
    worker.join().expect("untrusted webhook TLS peer");
}

#[test]
fn email_session_dispatches_once_over_private_tls_and_restores_without_redispatch() {
    let body = b"private message";
    let (client, server) = trusted_configs();
    let (port, worker) = serve_once(server, |_| ExpectedRequest {
        route: "/v1/email",
        content_type: "application/vnd.semaprax.email.v1+json",
        delivery_header: "x-semaprax-delivery-id: native-email-1",
        body_marker: b"70726976617465206d657373616765",
        signature: None,
    });
    let endpoint = format!("https://localhost:{port}/v1/email");
    let mut session = EmailDeliverySession::new(2).expect("bounded typed session");
    let mut store = EmailStore::default();
    let mut adapter = loopback_adapter(client, port);
    let first = session
        .reconcile_durable(
            prepare_email_delivery(
                capability(port, "native.email.v1", 64),
                email(endpoint.clone(), body),
            )
            .expect("matching explicit host policy admits email"),
            &mut store,
            &mut adapter,
        )
        .expect("email settles over private TLS");
    assert!(matches!(first, DurableEmailDeliveryOutcome::Dispatched(_)));
    assert_eq!(
        store.checkpoints.len(),
        2,
        "intent and terminal states commit"
    );
    worker.join().expect("one email TLS request");

    let checkpoint = store.checkpoints.last().expect("terminal checkpoint");
    let wire = checkpoint.render();
    let digest = checkpoint.digest();
    let capacity = checkpoint.capacity();
    let mut tampered = wire.clone();
    tampered.push(' ');
    assert!(matches!(
        EmailDeliverySession::restore_authenticated(
            tampered.as_bytes(),
            EmailDeliverySessionRestoreCapability::grant_for_trusted_host(&digest, capacity)
                .expect("trusted store binds expected checkpoint"),
        ),
        Err(EmailDeliverySessionRestoreRefusal::Checkpoint(
            DeliverySessionCheckpointRefusal::BindingMismatch
        ))
    ));
    let mut restored = EmailDeliverySession::restore_authenticated(
        wire.as_bytes(),
        EmailDeliverySessionRestoreCapability::grant_for_trusted_host(digest, capacity)
            .expect("trusted store binds exact checkpoint"),
    )
    .expect("exact email checkpoint restores");

    let listener = rebind_without_connection(port);
    let (client, _) = trusted_configs();
    let mut replay_adapter = loopback_adapter(client, port);
    let replay = restored
        .reconcile(
            prepare_email_delivery(
                capability(port, "native.email.v1", 64),
                email(endpoint.clone(), body),
            )
            .expect("exact replay remains admitted"),
            &mut replay_adapter,
        )
        .expect("exact email replay is retained");
    assert!(replay.was_replayed());
    assert_no_connection(&listener, "exact restored email replay must not open TLS");

    assert_eq!(
        restored.reconcile(
            prepare_email_delivery(
                capability(port, "native.email.v1", 64),
                email(endpoint.clone(), b"changed message"),
            )
            .expect("changed email remains individually valid"),
            &mut replay_adapter,
        ),
        Err(EmailLedgerRefusal::Ledger(
            LedgerRefusal::ConflictingRequest
        ))
    );
    assert_no_connection(&listener, "email request drift must refuse before TLS");
    assert_eq!(
        restored.reconcile(
            prepare_email_delivery(
                capability(port, "native.email.v1", 63),
                email(endpoint.clone(), body),
            )
            .expect("policy-drifted email remains individually valid"),
            &mut replay_adapter,
        ),
        Err(EmailLedgerRefusal::PolicyChanged)
    );
    assert_no_connection(&listener, "email policy drift must refuse before TLS");

    let (_, server) = trusted_configs();
    let (untrusted_port, worker) = serve_rejected_handshake(server);
    let mut uncertain = EmailDeliverySession::new(1).expect("bounded session");
    let receipt = uncertain
        .reconcile(
            prepare_email_delivery(
                capability(untrusted_port, "native.email.untrusted.v1", 64),
                email(format!("https://localhost:{untrusted_port}/v1/email"), body),
            )
            .expect("untrusted route remains policy-admitted before TLS"),
            &mut loopback_adapter(empty_root_client(), untrusted_port),
        )
        .expect("post-start TLS failure settles as a typed receipt");
    assert!(matches!(
        receipt.evidence().disposition(),
        DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport
        }
    ));
    worker.join().expect("untrusted email TLS peer");
}
