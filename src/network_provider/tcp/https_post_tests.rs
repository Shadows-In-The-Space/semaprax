//! Loopback HTTPS POST evidence for the explicit host authority boundary.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use super::super::{HttpFailure, NetworkProvider as _};
use super::tls_rejection_tests::trusted_loopback_tls_configs;
use super::TcpNetworkProvider;

fn read_post(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
) -> (Vec<u8>, Vec<u8>) {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("request headers");
        request.push(byte[0]);
        assert!(request.len() < 16_384, "bounded request headers");
    }
    let headers = std::str::from_utf8(&request).expect("HTTP headers are ASCII");
    assert!(
        headers
            .lines()
            .any(|line| { line.eq_ignore_ascii_case("content-type: application/octet-stream") }),
        "POST uses the fixed binary content type"
    );
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("POST has content length")
        .parse::<usize>()
        .expect("content length is decimal");
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body).expect("POST body");
    (request, body)
}

fn serve_post(
    config: rustls::ServerConfig,
    expected_path: &'static [u8],
    expected_body: &'static [u8],
    response: &'static [u8],
    observe_redirect: bool,
) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
    let port = listener.local_addr().expect("local address").port();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("one TLS client");
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("read timeout");
        let connection = rustls::ServerConnection::new(Arc::new(config)).expect("TLS server");
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let (request, body) = read_post(&mut stream);
        let mut request_prefix = b"POST ".to_vec();
        request_prefix.extend_from_slice(expected_path);
        request_prefix.extend_from_slice(b" HTTP/1.1\r\n");
        assert!(
            request.starts_with(&request_prefix),
            "the requested path reaches the TLS peer"
        );
        assert_eq!(body, expected_body, "request body crosses TLS intact");
        stream.write_all(response).expect("write bounded response");
        stream.flush().expect("flush response");
        if observe_redirect {
            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {}
                Ok(_) => panic!("POST redirect caused another request"),
                Err(error) => panic!("unexpected TLS read after redirect: {error}"),
            }
        }
    });
    (port, worker)
}

#[test]
fn loopback_tls_post_preserves_body_and_never_follows_redirects() {
    let (client_config, server_config) = trusted_loopback_tls_configs();
    let (body_port, body_server) = serve_post(
        server_config,
        b"/body",
        b"request-body",
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        false,
    );
    let body_origin = format!("https://localhost:{body_port}");
    let mut provider = TcpNetworkProvider::with_tls_config(Arc::new(client_config));
    provider
        .set_https_post_origins(&[&body_origin])
        .expect("host grants the loopback origin");
    let body_response = provider
        .https_post(&format!("{body_origin}/body"), b"request-body", 1_024)
        .expect("authorized TLS POST");
    assert!(body_response.starts_with(b"HTTP/1.1 201 semaprax\r\n"));
    assert!(body_response.ends_with(b"\r\n\r\nok"));
    body_server.join().expect("body server");

    let (_, empty_server_config) = trusted_loopback_tls_configs();
    let (empty_port, empty_server) = serve_post(
        empty_server_config,
        b"/empty",
        b"",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        false,
    );
    let empty_origin = format!("https://localhost:{empty_port}");
    provider
        .set_https_post_origins(&[&empty_origin])
        .expect("host replaces the loopback origin");
    let empty_response = provider
        .https_post(&format!("{empty_origin}/empty"), b"", 1_024)
        .expect("empty request bodies are valid");
    assert!(empty_response.starts_with(b"HTTP/1.1 204 semaprax\r\n"));
    empty_server.join().expect("empty-body server");

    let (_, redirect_server_config) = trusted_loopback_tls_configs();
    let (redirect_port, redirect_server) = serve_post(
        redirect_server_config,
        b"/redirect",
        b"request-body",
        b"HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: 0\r\n\r\n",
        true,
    );
    let redirect_origin = format!("https://localhost:{redirect_port}");
    provider
        .set_https_post_origins(&[&redirect_origin])
        .expect("host replaces the loopback origin");
    let redirect_response = provider
        .https_post(
            &format!("{redirect_origin}/redirect"),
            b"request-body",
            1_024,
        )
        .expect("redirect is a completed POST response, not a follow-up request");
    assert!(redirect_response.starts_with(b"HTTP/1.1 302 semaprax\r\n"));
    redirect_server.join().expect("redirect server");
}

#[test]
fn post_authority_and_capacity_refusals_happen_before_dispatch() {
    let (client_config, _) = trusted_loopback_tls_configs();
    let mut provider = TcpNetworkProvider::with_tls_config(Arc::new(client_config));
    provider
        .set_https_post_origins(&["https://localhost:443"])
        .expect("host grants one canonical origin");

    assert_eq!(
        provider.https_post("https://user@localhost:443/", b"", 1),
        Err(HttpFailure::InvalidUrl)
    );
    assert_eq!(
        provider.https_post("https://@localhost:443/", b"", 1),
        Err(HttpFailure::InvalidUrl)
    );
    assert_eq!(
        provider.https_post("https://localhost:443/#fragment", b"", 1),
        Err(HttpFailure::InvalidUrl)
    );
    assert_eq!(
        provider.https_post("https://localhost:443/\0", b"", 1),
        Err(HttpFailure::InvalidUrl)
    );
    assert_eq!(
        provider.https_post("https://localhost:444/", b"", 1),
        Err(HttpFailure::AuthorityDenied)
    );
    let oversized_body = vec![0; 65_537];
    assert_eq!(
        provider.https_post("https://localhost:443/", &oversized_body, 1),
        Err(HttpFailure::ResponseTooLarge)
    );
    assert_eq!(
        provider.https_post("https://localhost:443/", b"", 65_537),
        Err(HttpFailure::ResponseTooLarge)
    );
    let overlong = format!("https://localhost:443/{}", "a".repeat(2_048));
    assert_eq!(
        provider.https_post(&overlong, b"", 1),
        Err(HttpFailure::InvalidUrl)
    );
}
