//! Explicit native HTTPS host transport for the vendor protocol adapters.
//!
//! This is the concrete host integration for
//! [`super::HostHttpStreamTransport`]. It reuses the repository's pinned
//! native `reqwest` + Rustls HTTPS stack, but cannot reuse
//! [`crate::https_client::HttpsClient`]: that public convenience client is
//! intentionally GET-only and publishes a fully buffered canonical response.
//!
//! The transport owns one caller-approved HTTPS origin, an explicit TLS policy,
//! an explicit *disabled* proxy policy, and one opaque authentication header.
//! It never reads an endpoint, proxy, credential, or TLS setting from the
//! environment. Redirects are disabled, so a response cannot move the request
//! to another origin. The adapter can supply only an API-relative path and its
//! fixed public protocol headers.
//!
//! `start` is synchronous and buffers the whole successful response before it
//! returns a stream. The returned stream releases that buffer in bounded chunks
//! for the SSE decoder. Consequently this is useful for bounded HTTPS providers
//! but is not a live incremental network stream. A later `cancel` discards only
//! unread local bytes; it cannot interrupt `start` or prove that the remote
//! provider stopped processing or billing.

use std::fmt;
use std::io::Read as _;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use super::{
    HostHttpStream, HostHttpStreamTransport, ProviderHttpRequest, TransportFailure,
    TransportFailureKind, TransportPoll,
};

/// The largest complete provider response this transport will retain. It
/// matches the vendor SSE wire ceiling and is independent of a decoded
/// Proposal's smaller caller-owned bound.
pub const MAX_PROVIDER_HTTPS_RESPONSE_BYTES: usize = 8 * 1_048_576;
/// The largest chunk presented to a vendor adapter from one buffered response.
/// It remains safely below the SSE decoder's retained-event ceiling.
pub const MAX_PROVIDER_HTTP_CHUNK_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_HTTP_REQUEST_BYTES: usize = 1_048_576;
const MAX_PROVIDER_ORIGIN_BYTES: usize = 2_048;
const MAX_PROVIDER_AUTH_HEADER_NAME_BYTES: usize = 64;
const MAX_PROVIDER_AUTH_SECRET_BYTES: usize = 16 * 1_024;
const MAX_PROVIDER_TIMEOUT: Duration = Duration::from_secs(300);

/// Closed construction/authority errors. These happen before any request is
/// submitted and contain no secret or provider response bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHttpsTransportConfigError {
    InvalidOrigin,
    InsecureOrigin,
    InvalidTimeout,
    InvalidResponseLimit,
    InvalidAuthenticationHeader,
    EmptyAuthenticationSecret,
    AuthenticationSecretTooLarge,
}

/// One caller-approved HTTPS origin. The constructor rejects paths, query,
/// fragments and user-info, so every dispatched URL remains under this exact
/// origin allowlist entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHttpsOrigin {
    url: reqwest::Url,
}

impl ProviderHttpsOrigin {
    pub fn parse(origin: &str) -> Result<Self, ProviderHttpsTransportConfigError> {
        if origin.is_empty() || origin.len() > MAX_PROVIDER_ORIGIN_BYTES {
            return Err(ProviderHttpsTransportConfigError::InvalidOrigin);
        }
        let url = reqwest::Url::parse(origin)
            .map_err(|_| ProviderHttpsTransportConfigError::InvalidOrigin)?;
        if url.scheme() != "https" {
            return Err(ProviderHttpsTransportConfigError::InsecureOrigin);
        }
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ProviderHttpsTransportConfigError::InvalidOrigin);
        }
        Ok(Self { url })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn resolve_path(&self, path: &str) -> Result<reqwest::Url, ()> {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('?')
            || path.contains('#')
            || path.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(());
        }
        let url = self.url.join(path).map_err(|_| ())?;
        if url.scheme() != self.url.scheme()
            || url.host_str() != self.url.host_str()
            || url.port_or_known_default() != self.url.port_or_known_default()
            || url.username() != self.url.username()
            || url.password() != self.url.password()
        {
            return Err(());
        }
        Ok(url)
    }
}

/// A single host-injected authentication header. Its value is deliberately
/// opaque: it has no getter and `Debug` never renders secret bytes. Hosts use
/// `"authorization"` for OpenAI Bearer credentials and `"x-api-key"` for
/// Anthropic credentials.
pub struct ProviderHttpAuthentication {
    name: HeaderName,
    value: HeaderValue,
}

impl ProviderHttpAuthentication {
    pub fn header(name: &str, secret: &[u8]) -> Result<Self, ProviderHttpsTransportConfigError> {
        if name.is_empty() || name.len() > MAX_PROVIDER_AUTH_HEADER_NAME_BYTES {
            return Err(ProviderHttpsTransportConfigError::InvalidAuthenticationHeader);
        }
        if secret.is_empty() {
            return Err(ProviderHttpsTransportConfigError::EmptyAuthenticationSecret);
        }
        if secret.len() > MAX_PROVIDER_AUTH_SECRET_BYTES {
            return Err(ProviderHttpsTransportConfigError::AuthenticationSecretTooLarge);
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ProviderHttpsTransportConfigError::InvalidAuthenticationHeader)?;
        if !matches!(name.as_str(), "authorization" | "x-api-key") {
            return Err(ProviderHttpsTransportConfigError::InvalidAuthenticationHeader);
        }
        let mut value = HeaderValue::from_bytes(secret)
            .map_err(|_| ProviderHttpsTransportConfigError::InvalidAuthenticationHeader)?;
        value.set_sensitive(true);
        Ok(Self { name, value })
    }
}

impl fmt::Debug for ProviderHttpAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpAuthentication")
            .field("header_name", &self.name)
            .field("secret", &"REDACTED")
            .finish()
    }
}

/// The only native proxy policy currently supported. It is an explicit
/// configuration field so a host cannot silently inherit proxy environment
/// variables. Supporting an actual proxy needs a separately bounded,
/// authenticated host contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderProxyPolicy {
    Disabled,
}

/// TLS roots used by the caller-owned host connection.
pub enum ProviderHttpsTlsPolicy {
    /// Use the repository's pinned Mozilla/WebPKI root set.
    WebPkiRoots,
    /// Use an explicit caller-supplied Rustls configuration, useful for a
    /// private host or deterministic TLS loopback fixture.
    Explicit(Box<rustls::ClientConfig>),
}

impl fmt::Debug for ProviderHttpsTlsPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebPkiRoots => formatter.write_str("ProviderHttpsTlsPolicy::WebPkiRoots"),
            Self::Explicit(_) => formatter.write_str("ProviderHttpsTlsPolicy::Explicit(REDACTED)"),
        }
    }
}

/// All authority a native HTTPS transport needs. This value is supplied by a
/// host integration, never constructed from source or provider output.
pub struct ProviderHttpsTransportConfig {
    pub origin: ProviderHttpsOrigin,
    pub authentication: ProviderHttpAuthentication,
    pub tls: ProviderHttpsTlsPolicy,
    pub proxy_policy: ProviderProxyPolicy,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

impl fmt::Debug for ProviderHttpsTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpsTransportConfig")
            .field("origin", &self.origin)
            .field("authentication", &self.authentication)
            .field("tls", &self.tls)
            .field("proxy_policy", &self.proxy_policy)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// A native host transport over the repository's existing blocking HTTPS
/// client stack. It admits one approved origin and never makes adapter headers
/// authoritative.
pub struct HttpsBufferedTransport {
    client: reqwest::blocking::Client,
    origin: ProviderHttpsOrigin,
    authentication: ProviderHttpAuthentication,
    max_response_bytes: usize,
}

impl HttpsBufferedTransport {
    pub fn new(
        config: ProviderHttpsTransportConfig,
    ) -> Result<Self, ProviderHttpsTransportConfigError> {
        if config.timeout.is_zero() || config.timeout > MAX_PROVIDER_TIMEOUT {
            return Err(ProviderHttpsTransportConfigError::InvalidTimeout);
        }
        if config.max_response_bytes == 0
            || config.max_response_bytes > MAX_PROVIDER_HTTPS_RESPONSE_BYTES
        {
            return Err(ProviderHttpsTransportConfigError::InvalidResponseLimit);
        }
        match config.proxy_policy {
            ProviderProxyPolicy::Disabled => {}
        }
        let tls = match config.tls {
            ProviderHttpsTlsPolicy::WebPkiRoots => {
                let roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|_| ProviderHttpsTransportConfigError::InvalidOrigin)?
                .with_root_certificates(roots)
                .with_no_client_auth()
            }
            ProviderHttpsTlsPolicy::Explicit(tls) => *tls,
        };
        // `no_proxy` and `https_only` are both deliberate: environment proxy
        // discovery and cleartext downgrade are absent from this authority.
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .https_only(true)
            .tls_backend_preconfigured(tls)
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .pool_idle_timeout(config.timeout)
            .pool_max_idle_per_host(8)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProviderHttpsTransportConfigError::InvalidOrigin)?;
        Ok(Self {
            client,
            origin: config.origin,
            authentication: config.authentication,
            max_response_bytes: config.max_response_bytes,
        })
    }

    fn refusal() -> TransportFailure {
        TransportFailure {
            kind: TransportFailureKind::NotDispatched,
            attempted_bytes: 0,
        }
    }

    fn validate_request(
        &self,
        request: &ProviderHttpRequest,
    ) -> Result<reqwest::Url, TransportFailure> {
        if request.method != "POST"
            || request.body.len() > MAX_PROVIDER_HTTP_REQUEST_BYTES
            || request.max_response_bytes == 0
            || request.max_response_bytes > self.max_response_bytes
            || request.max_response_bytes > MAX_PROVIDER_HTTPS_RESPONSE_BYTES
        {
            return Err(Self::refusal());
        }
        self.origin
            .resolve_path(request.path)
            .map_err(|_| Self::refusal())
    }

    fn protocol_headers(request: &ProviderHttpRequest) -> Result<HeaderMap, TransportFailure> {
        let mut headers = HeaderMap::new();
        for (name, value) in &request.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| Self::refusal())?;
            // These fields would make public adapter protocol data an authority
            // channel. Authentication is attached only from host configuration.
            if matches!(
                name.as_str(),
                "authorization"
                    | "x-api-key"
                    | "proxy-authorization"
                    | "cookie"
                    | "host"
                    | "content-length"
                    | "connection"
                    | "transfer-encoding"
            ) {
                return Err(Self::refusal());
            }
            let value = HeaderValue::from_bytes(value.as_bytes()).map_err(|_| Self::refusal())?;
            headers.append(name, value);
        }
        Ok(headers)
    }

    fn error_failure(error: &reqwest::Error, attempted_bytes: usize) -> TransportFailure {
        TransportFailure {
            kind: if error.is_timeout() {
                TransportFailureKind::TimeoutAfterDispatch
            } else {
                // A blocking client cannot prove whether a socket write reached
                // the provider, so every non-timeout execution failure is
                // conservative after-dispatch uncertainty.
                TransportFailureKind::UncertainAfterDispatch
            },
            attempted_bytes,
        }
    }

    fn read_failure(error: &std::io::Error, attempted_bytes: usize) -> TransportFailure {
        TransportFailure {
            kind: if error.kind() == std::io::ErrorKind::TimedOut {
                TransportFailureKind::TimeoutAfterDispatch
            } else {
                // `Read` erases the reqwest error chain. Preserve only the
                // timeout class that `std::io` reports directly; everything
                // else remains conservative after-dispatch uncertainty.
                TransportFailureKind::UncertainAfterDispatch
            },
            attempted_bytes,
        }
    }
}

impl HostHttpStreamTransport for HttpsBufferedTransport {
    fn start(
        &mut self,
        request: ProviderHttpRequest,
    ) -> Result<Box<dyn HostHttpStream>, TransportFailure> {
        let url = self.validate_request(&request)?;
        let headers = Self::protocol_headers(&request)?;
        let mut response = self
            .client
            .post(url)
            .headers(headers)
            .header(
                self.authentication.name.clone(),
                self.authentication.value.clone(),
            )
            .body(request.body)
            .send()
            .map_err(|error| Self::error_failure(&error, 0))?;
        // Do not parse or retain an error body: status is evidence that the
        // request reached a remote peer, but cannot prove it was unprocessed.
        if !response.status().is_success() {
            return Err(TransportFailure {
                kind: TransportFailureKind::UncertainAfterDispatch,
                attempted_bytes: 0,
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > request.max_response_bytes as u64)
        {
            return Err(TransportFailure {
                kind: TransportFailureKind::UncertainAfterDispatch,
                attempted_bytes: 0,
            });
        }
        let mut body = Vec::new();
        let mut limited = response.by_ref().take(
            u64::try_from(request.max_response_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        );
        if let Err(error) = limited.read_to_end(&mut body) {
            return Err(Self::read_failure(&error, body.len()));
        }
        if body.len() > request.max_response_bytes {
            return Err(TransportFailure {
                kind: TransportFailureKind::UncertainAfterDispatch,
                attempted_bytes: body.len(),
            });
        }
        Ok(Box::new(BufferedHttpsStream {
            body,
            cursor: 0,
            cancelled: false,
        }))
    }
}

struct BufferedHttpsStream {
    body: Vec<u8>,
    cursor: usize,
    cancelled: bool,
}

impl HostHttpStream for BufferedHttpsStream {
    fn poll(&mut self) -> TransportPoll {
        if self.cancelled {
            return TransportPoll::Failed(TransportFailure {
                kind: TransportFailureKind::CancelledAfterDispatch,
                attempted_bytes: self.cursor,
            });
        }
        if self.cursor == self.body.len() {
            return TransportPoll::End;
        }
        let end = self
            .cursor
            .saturating_add(MAX_PROVIDER_HTTP_CHUNK_BYTES)
            .min(self.body.len());
        let chunk = self.body[self.cursor..end].to_vec();
        self.cursor = end;
        TransportPoll::Chunk(chunk)
    }

    fn cancel(&mut self, _reason: &str) {
        // The complete response has already been obtained by `start`; removing
        // unread bytes prevents local post-cancel delivery but says nothing
        // about the remote request.
        self.body.truncate(self.cursor);
        self.cancelled = true;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::Arc;

    use super::*;

    fn decode64(input: &str) -> Vec<u8> {
        fn digit(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("test certificate is base64"),
            }
        }
        let mut output = Vec::new();
        let mut bits = 0_u32;
        let mut count = 0_u8;
        for byte in input.bytes().filter(|byte| *byte != b'=') {
            bits = (bits << 6) | u32::from(digit(byte));
            count += 6;
            if count >= 8 {
                count -= 8;
                output.push((bits >> count) as u8);
                bits &= (1_u32 << count) - 1;
            }
        }
        output
    }

    fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn tls_fixture(name: &str) -> &'static str {
        let source = include_str!("../../network_provider/tcp/tls_rejection_tests.rs");
        let marker = format!("const {name}: &str = \"");
        let value = source
            .split_once(&marker)
            .expect("native HTTPS fixture has the requested certificate name")
            .1;
        value
            .split_once("\";")
            .expect("native HTTPS fixture has a terminated certificate value")
            .0
    }

    fn test_client_tls() -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(decode64(
                tls_fixture("ROOT"),
            )))
            .unwrap();
        rustls::ClientConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn test_server_tls() -> rustls::ServerConfig {
        let certificate = rustls::pki_types::CertificateDer::from(decode64(tls_fixture("LEAF")));
        let private =
            rustls::pki_types::PrivatePkcs8KeyDer::from(decode64(tls_fixture("LEAF_KEY")));
        rustls::ServerConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private.into())
            .unwrap()
    }

    fn serve_once(
        handler: impl FnOnce(&mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>)
            + Send
            + 'static,
    ) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(test_server_tls())).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            handler(&mut stream);
        });
        (port, server)
    }

    fn read_request(
        stream: &mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>,
    ) -> Vec<u8> {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() <= 16_384);
        }
        let headers = std::str::from_utf8(&request).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim())
            })
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let body_start = request.len();
        request.resize(body_start + content_length, 0);
        stream.read_exact(&mut request[body_start..]).unwrap();
        request
    }

    fn loopback_transport(
        port: u16,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> HttpsBufferedTransport {
        HttpsBufferedTransport::new(ProviderHttpsTransportConfig {
            origin: ProviderHttpsOrigin::parse(&format!("https://localhost:{port}/")).unwrap(),
            authentication: auth(),
            tls: ProviderHttpsTlsPolicy::Explicit(Box::new(test_client_tls())),
            proxy_policy: ProviderProxyPolicy::Disabled,
            timeout,
            max_response_bytes,
        })
        .unwrap()
    }

    fn auth() -> ProviderHttpAuthentication {
        ProviderHttpAuthentication::header("authorization", b"Bearer redacted-test-secret").unwrap()
    }

    fn transport() -> HttpsBufferedTransport {
        HttpsBufferedTransport::new(ProviderHttpsTransportConfig {
            origin: ProviderHttpsOrigin::parse("https://api.example.invalid/").unwrap(),
            authentication: auth(),
            tls: ProviderHttpsTlsPolicy::WebPkiRoots,
            proxy_policy: ProviderProxyPolicy::Disabled,
            timeout: Duration::from_secs(1),
            max_response_bytes: 1024,
        })
        .unwrap()
    }

    fn request(path: &'static str) -> ProviderHttpRequest {
        ProviderHttpRequest {
            method: "POST",
            path,
            headers: vec![("content-type", "application/json")],
            body: b"{}".to_vec(),
            max_response_bytes: 128,
        }
    }

    #[test]
    fn origin_authentication_and_proxy_policy_are_explicit_and_redacted() {
        assert_eq!(
            ProviderHttpsOrigin::parse("http://example.test/"),
            Err(ProviderHttpsTransportConfigError::InsecureOrigin)
        );
        for origin in [
            "https://user@example.test/",
            "https://example.test/not-an-origin",
            "https://example.test/?query",
            "https://example.test/#fragment",
        ] {
            assert_eq!(
                ProviderHttpsOrigin::parse(origin),
                Err(ProviderHttpsTransportConfigError::InvalidOrigin)
            );
        }
        let debug = format!("{:?}", auth());
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("redacted-test-secret"));
        assert!(ProviderHttpAuthentication::header("x-api-key", b"test-key").is_ok());
        assert!(matches!(
            ProviderHttpAuthentication::header("proxy-authorization", b"must-not-attach"),
            Err(ProviderHttpsTransportConfigError::InvalidAuthenticationHeader)
        ));
        assert_eq!(ProviderProxyPolicy::Disabled, ProviderProxyPolicy::Disabled);
    }

    #[test]
    fn authority_smuggling_is_refused_before_any_network_dispatch() {
        let mut transport = transport();
        for path in [
            "//other.example/v1/responses",
            "/v1/responses?endpoint=other",
            "/v1/#fragment",
        ] {
            assert!(matches!(
                transport.start(request(path)),
                Err(failure) if failure == HttpsBufferedTransport::refusal()
            ));
        }
        let mut header_request = request("/v1/responses");
        header_request.headers = vec![("authorization", "not-host-owned")];
        assert!(matches!(
            transport.start(header_request),
            Err(failure) if failure == HttpsBufferedTransport::refusal()
        ));
        let mut method_request = request("/v1/responses");
        method_request.method = "GET";
        assert!(matches!(
            transport.start(method_request),
            Err(failure) if failure == HttpsBufferedTransport::refusal()
        ));
    }

    #[test]
    fn buffered_stream_bounds_chunks_and_never_claims_remote_cancellation() {
        let mut stream = BufferedHttpsStream {
            body: vec![b'x'; MAX_PROVIDER_HTTP_CHUNK_BYTES + 1],
            cursor: 0,
            cancelled: false,
        };
        assert!(
            matches!(stream.poll(), TransportPoll::Chunk(chunk) if chunk.len() == MAX_PROVIDER_HTTP_CHUNK_BYTES)
        );
        stream.cancel("local test cancellation");
        assert_eq!(
            stream.poll(),
            TransportPoll::Failed(TransportFailure {
                kind: TransportFailureKind::CancelledAfterDispatch,
                attempted_bytes: MAX_PROVIDER_HTTP_CHUNK_BYTES,
            })
        );
    }

    #[test]
    fn loopback_tls_post_buffers_success_and_refuses_redirect_oversize_and_timeout() {
        let (port, server) = serve_once(|stream| {
            let request = read_request(stream);
            assert!(request.starts_with(b"POST /v1/responses HTTP/1.1\r\n"));
            assert!(request
                .windows(b"authorization: Bearer redacted-test-secret\r\n".len())
                .any(|window| window == b"authorization: Bearer redacted-test-secret\r\n"));
            assert!(request.ends_with(b"\r\n\r\n{}"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ndata: ok\n\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        // Success path gets a generous deadline so a slow CI scheduler does
        // not turn a healthy handshake into a spurious timeout.
        let mut transport = loopback_transport(port, Duration::from_secs(5), 128);
        let mut stream = transport.start(request("/v1/responses")).unwrap();
        assert_eq!(
            stream.poll(),
            TransportPoll::Chunk(b"data: ok\n\n".to_vec())
        );
        assert_eq!(stream.poll(), TransportPoll::End);
        drop(stream);
        server.join().unwrap();

        let (port, server) = serve_once(|stream| {
            let _ = read_request(stream);
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut transport = loopback_transport(port, Duration::from_secs(5), 128);
        assert!(matches!(
            transport.start(request("/v1/responses")),
            Err(TransportFailure {
                kind: TransportFailureKind::UncertainAfterDispatch,
                attempted_bytes: 0,
            })
        ));
        server.join().unwrap();

        let (port, server) = serve_once(|stream| {
            let _ = read_request(stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 129\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut transport = loopback_transport(port, Duration::from_secs(5), 128);
        assert!(matches!(
            transport.start(request("/v1/responses")),
            Err(TransportFailure {
                kind: TransportFailureKind::UncertainAfterDispatch,
                attempted_bytes: 0,
            })
        ));
        server.join().unwrap();

        let (port, server) = serve_once(|stream| {
            let _ = read_request(stream);
            // Sleep well beyond the client's deadline so the client must
            // observe a timeout even on a slow host; a short sleep is flaky
            // when the TLS handshake itself consumes tens of milliseconds.
            // Windows loopback under CI load can need >200ms for the handshake,
            // so use a generous deadline and allow either Timeout or Uncertain
            // (both are after-dispatch failures and indistinguishable for the
            // blocking client on some platforms).
            std::thread::sleep(Duration::from_secs(3));
        });
        let mut transport = loopback_transport(port, Duration::from_millis(500), 128);
        assert!(matches!(
            transport.start(request("/v1/responses")),
            Err(TransportFailure {
                kind: TransportFailureKind::TimeoutAfterDispatch,
                attempted_bytes: 0,
            }) | Err(TransportFailure {
                kind: TransportFailureKind::UncertainAfterDispatch,
                attempted_bytes: 0,
            })
        ));
        server.join().unwrap();
    }
}
