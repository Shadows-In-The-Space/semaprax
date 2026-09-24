//! Explicit, bounded native HTTPS acquisition for already-named immutable
//! registry bytes. This module is deliberately below signed admission: it
//! downloads bytes but does not install roots, verify metadata, write a held
//! store, populate a resolver cache, or execute an artifact.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Read as _;
use std::time::Duration;

use sha2::{Digest as _, Sha256};

pub const MAX_MIRROR_ORIGIN_BYTES: usize = 2_048;
pub const MAX_MIRROR_PATH_BYTES: usize = 2_048;
pub const MAX_MIRROR_OBJECTS: usize = 64;
pub const MAX_MIRROR_METADATA_BYTES: usize = 1_048_576;
pub const MAX_MIRROR_ARTIFACT_BYTES: usize = 16 * 1_048_576;
/// Complete batches retain every accepted object until all digest checks pass,
/// so their declared bounds must fit the held-generation ceiling too.
pub const MAX_MIRROR_TOTAL_BYTES: usize = 64 * 1_048_576;
pub const MAX_MIRROR_TIMEOUT: Duration = Duration::from_secs(60);

/// Closed object classes. The class only fixes a byte ceiling; signed
/// Registry-v3 admission still decides what the returned bytes mean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MirrorObjectKind {
    Metadata,
    Artifact,
}

/// One caller-selected immutable object. `path` is an origin-relative,
/// canonical byte path and `digest` is the expected raw SHA-256 binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MirrorObject<'a> {
    pub kind: MirrorObjectKind,
    pub path: &'a str,
    pub digest: &'a str,
    pub max_bytes: usize,
}

/// A bounded batch whose returned order is exactly its caller-supplied order.
pub struct MirrorRequest<'a> {
    pub objects: &'a [MirrorObject<'a>],
}

/// A verified immutable response. It is byte evidence only, not a trust-store
/// receipt or a reusable network capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorBytes {
    pub kind: MirrorObjectKind,
    pub path: String,
    pub digest: String,
    bytes: Vec<u8>,
}

impl MirrorBytes {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Configuration failures and transport refusals intentionally carry no
/// response body, credential, proxy, or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MirrorError {
    InvalidOrigin,
    InvalidTimeout,
    InvalidRequest,
    NotFoundOrNonSuccess,
    ResponseTooLarge,
    RedirectOrOriginChanged,
    DigestMismatch,
    TransportFailed,
}

/// One exact HTTPS origin, constructed by a host integration. User-info,
/// base paths, queries and fragments are refused so object paths cannot leave
/// the selected origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorOrigin {
    url: reqwest::Url,
}

impl MirrorOrigin {
    pub fn parse(value: &str) -> Result<Self, MirrorError> {
        if value.is_empty() || value.len() > MAX_MIRROR_ORIGIN_BYTES {
            return Err(MirrorError::InvalidOrigin);
        }
        let url = reqwest::Url::parse(value).map_err(|_| MirrorError::InvalidOrigin)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(MirrorError::InvalidOrigin);
        }
        Ok(Self { url })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn object_url(&self, path: &str) -> Result<reqwest::Url, MirrorError> {
        validate_path(path)?;
        let url = self
            .url
            .join(path)
            .map_err(|_| MirrorError::InvalidRequest)?;
        if url.scheme() != self.url.scheme()
            || url.host_str() != self.url.host_str()
            || url.port_or_known_default() != self.url.port_or_known_default()
            || url.username() != self.url.username()
            || url.password() != self.url.password()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(MirrorError::InvalidRequest);
        }
        Ok(url)
    }
}

/// An explicit host-granted network authority. It is consumed by no source,
/// metadata, cache, or store value; callers retain it while dispatching each
/// bounded batch. There is no proxy, credential, redirect or ambient-origin
/// selection field.
pub struct MirrorNetworkAuthority {
    origin: MirrorOrigin,
    timeout: Duration,
}

impl MirrorNetworkAuthority {
    pub fn new(origin: MirrorOrigin, timeout: Duration) -> Result<Self, MirrorError> {
        if timeout.is_zero() || timeout > MAX_MIRROR_TIMEOUT {
            return Err(MirrorError::InvalidTimeout);
        }
        Ok(Self { origin, timeout })
    }

    #[must_use]
    pub fn origin(&self) -> &MirrorOrigin {
        &self.origin
    }

    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Fetches all bytes before publishing any result. The caller must pass
    /// the resulting exact bytes into the separate Registry-v3 signed proof
    /// and held-host APIs; this method cannot compose decoded data into them.
    pub fn acquire<T: MirrorTransport>(
        &self,
        transport: &mut T,
        request: &MirrorRequest<'_>,
    ) -> Result<Vec<MirrorBytes>, MirrorError> {
        if request.objects.is_empty() || request.objects.len() > MAX_MIRROR_OBJECTS {
            return Err(MirrorError::InvalidRequest);
        }
        let mut paths = BTreeSet::new();
        let mut planned = Vec::with_capacity(request.objects.len());
        let mut total_bytes = 0_usize;
        // Validate the complete batch before the first effect. In particular,
        // a later duplicate cannot turn a rejected request into a published
        // prefix of network observations.
        for object in request.objects {
            let max_bytes = validate_object(*object)?;
            total_bytes = total_bytes
                .checked_add(max_bytes)
                .filter(|total| *total <= MAX_MIRROR_TOTAL_BYTES)
                .ok_or(MirrorError::InvalidRequest)?;
            if !paths.insert(object.path) {
                return Err(MirrorError::InvalidRequest);
            }
            planned.push((*object, max_bytes, self.origin.object_url(object.path)?));
        }
        let mut fetched = Vec::with_capacity(request.objects.len());
        for (object, max_bytes, url) in planned {
            let response = transport.get(MirrorGet {
                url: url.as_str(),
                timeout: self.timeout,
                max_bytes,
            })?;
            if response.status < 200 || response.status >= 300 {
                return Err(MirrorError::NotFoundOrNonSuccess);
            }
            if response.final_url != url.as_str() {
                return Err(MirrorError::RedirectOrOriginChanged);
            }
            if response.body.len() > max_bytes {
                return Err(MirrorError::ResponseTooLarge);
            }
            if sha256(&response.body) != object.digest {
                return Err(MirrorError::DigestMismatch);
            }
            fetched.push(MirrorBytes {
                kind: object.kind,
                path: object.path.to_owned(),
                digest: object.digest.to_owned(),
                bytes: response.body,
            });
        }
        Ok(fetched)
    }
}

/// The one permitted operation of a transport capability. Implementations
/// receive no caller-supplied headers, credentials, redirect policy or proxy.
pub trait MirrorTransport {
    fn get(&mut self, request: MirrorGet<'_>) -> Result<MirrorResponse, MirrorError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MirrorGet<'a> {
    url: &'a str,
    timeout: Duration,
    max_bytes: usize,
}

impl MirrorGet<'_> {
    #[must_use]
    pub fn url(&self) -> &str {
        self.url
    }

    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

pub struct MirrorResponse {
    pub status: u16,
    pub final_url: String,
    pub body: Vec<u8>,
}

/// Concrete native HTTPS implementation. Construction uses only the supplied
/// authority's origin/timeout, the pinned WebPKI roots and an explicitly
/// disabled proxy policy. Redirects and retries are both disabled.
pub struct NativeHttpsMirrorTransport {
    client: reqwest::blocking::Client,
    origin: MirrorOrigin,
    timeout: Duration,
}

impl NativeHttpsMirrorTransport {
    pub fn new(authority: &MirrorNetworkAuthority) -> Result<Self, MirrorError> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| MirrorError::TransportFailed)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .https_only(true)
            .tls_backend_preconfigured(tls)
            .timeout(authority.timeout)
            .connect_timeout(authority.timeout)
            .pool_idle_timeout(authority.timeout)
            .pool_max_idle_per_host(8)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| MirrorError::TransportFailed)?;
        Ok(Self {
            client,
            origin: authority.origin.clone(),
            timeout: authority.timeout,
        })
    }

    fn validate_get(&self, request: MirrorGet<'_>) -> Result<(), MirrorError> {
        if request.timeout != self.timeout || request.max_bytes == 0 {
            return Err(MirrorError::InvalidRequest);
        }
        let url = reqwest::Url::parse(request.url).map_err(|_| MirrorError::InvalidRequest)?;
        let expected = self.origin.object_url(url.path())?;
        if url.as_str() != expected.as_str() {
            return Err(MirrorError::InvalidRequest);
        }
        Ok(())
    }
}

impl MirrorTransport for NativeHttpsMirrorTransport {
    fn get(&mut self, request: MirrorGet<'_>) -> Result<MirrorResponse, MirrorError> {
        self.validate_get(request)?;
        let mut response = self
            .client
            .get(request.url)
            .send()
            .map_err(|_| MirrorError::TransportFailed)?;
        if response
            .content_length()
            .is_some_and(|length| length > request.max_bytes as u64)
        {
            return Err(MirrorError::ResponseTooLarge);
        }
        let mut body = Vec::new();
        response
            .by_ref()
            .take(request.max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| MirrorError::TransportFailed)?;
        if body.len() > request.max_bytes {
            return Err(MirrorError::ResponseTooLarge);
        }
        Ok(MirrorResponse {
            status: response.status().as_u16(),
            final_url: response.url().as_str().to_owned(),
            body,
        })
    }
}

fn validate_object(object: MirrorObject<'_>) -> Result<usize, MirrorError> {
    let ceiling = match object.kind {
        MirrorObjectKind::Metadata => MAX_MIRROR_METADATA_BYTES,
        MirrorObjectKind::Artifact => MAX_MIRROR_ARTIFACT_BYTES,
    };
    if object.max_bytes == 0 || object.max_bytes > ceiling || !valid_digest(object.digest) {
        return Err(MirrorError::InvalidRequest);
    }
    Ok(object.max_bytes)
}

fn validate_path(path: &str) -> Result<(), MirrorError> {
    if path.len() < 2
        || path.len() > MAX_MIRROR_PATH_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(MirrorError::InvalidRequest);
    }
    for segment in path[1..].split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(MirrorError::InvalidRequest);
        }
    }
    Ok(())
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 71
        && digest.starts_with("sha256:")
        && digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(71);
    rendered.push_str("sha256:");
    for byte in digest.as_slice() {
        write!(&mut rendered, "{byte:02x}").expect("writing to String cannot fail");
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptedTransport {
        expected: VecDeque<(String, MirrorResponse)>,
    }
    impl MirrorTransport for ScriptedTransport {
        fn get(&mut self, request: MirrorGet<'_>) -> Result<MirrorResponse, MirrorError> {
            assert!(request.timeout() <= MAX_MIRROR_TIMEOUT);
            let (url, response) = self.expected.pop_front().expect("unexpected request");
            assert_eq!(request.url(), url);
            Ok(response)
        }
    }

    fn authority() -> MirrorNetworkAuthority {
        MirrorNetworkAuthority::new(
            MirrorOrigin::parse("https://mirror.example.test/").unwrap(),
            Duration::from_secs(5),
        )
        .unwrap()
    }
    fn object<'a>(kind: MirrorObjectKind, path: &'a str, bytes: &[u8]) -> MirrorObject<'a> {
        MirrorObject {
            kind,
            path,
            digest: Box::leak(sha256(bytes).into_boxed_str()),
            max_bytes: bytes.len().max(1),
        }
    }
    fn response(url: &str, bytes: &[u8]) -> MirrorResponse {
        MirrorResponse {
            status: 200,
            final_url: url.into(),
            body: bytes.into(),
        }
    }

    #[test]
    fn exact_metadata_and_artifact_paths_are_fetched_in_caller_order() {
        let metadata = b"signed metadata";
        let artifact = b"wasm artifact";
        let objects = [
            object(
                MirrorObjectKind::Metadata,
                "/metadata/timestamp.json",
                metadata,
            ),
            object(MirrorObjectKind::Artifact, "/artifacts/app.wasm", artifact),
        ];
        let mut transport = ScriptedTransport {
            expected: VecDeque::from([
                (
                    "https://mirror.example.test/metadata/timestamp.json".into(),
                    response(
                        "https://mirror.example.test/metadata/timestamp.json",
                        metadata,
                    ),
                ),
                (
                    "https://mirror.example.test/artifacts/app.wasm".into(),
                    response("https://mirror.example.test/artifacts/app.wasm", artifact),
                ),
            ]),
        };
        let found = authority()
            .acquire(&mut transport, &MirrorRequest { objects: &objects })
            .unwrap();
        assert_eq!(
            found
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
            ["/metadata/timestamp.json", "/artifacts/app.wasm"]
        );
        assert_eq!(found[0].bytes(), metadata);
        assert_eq!(found[1].bytes(), artifact);
        assert!(transport.expected.is_empty());
    }

    #[test]
    fn malformed_origin_path_duplicate_and_bound_refuse_before_dispatch() {
        for origin in [
            "http://mirror.example.test/",
            "https://user@mirror.example.test/",
            "https://mirror.example.test/base",
        ] {
            assert_eq!(MirrorOrigin::parse(origin), Err(MirrorError::InvalidOrigin));
        }
        let bytes = b"x";
        for path in [
            "metadata/x",
            "//metadata/x",
            "/metadata/../x",
            "/metadata/x?query",
            "/metadata/%2f",
        ] {
            let objects = [object(MirrorObjectKind::Metadata, path, bytes)];
            let mut transport = ScriptedTransport {
                expected: VecDeque::new(),
            };
            assert_eq!(
                authority().acquire(&mut transport, &MirrorRequest { objects: &objects }),
                Err(MirrorError::InvalidRequest)
            );
        }
        let one = object(MirrorObjectKind::Metadata, "/metadata/x", bytes);
        let mut transport = ScriptedTransport {
            expected: VecDeque::new(),
        };
        assert_eq!(
            authority().acquire(
                &mut transport,
                &MirrorRequest {
                    objects: &[one, one]
                }
            ),
            Err(MirrorError::InvalidRequest)
        );
        assert!(matches!(
            MirrorNetworkAuthority::new(
                MirrorOrigin::parse("https://mirror.example.test/").unwrap(),
                Duration::ZERO
            ),
            Err(MirrorError::InvalidTimeout)
        ));
        let digest = sha256(bytes);
        let oversized = [
            MirrorObject {
                kind: MirrorObjectKind::Artifact,
                path: "/artifacts/a",
                digest: &digest,
                max_bytes: MAX_MIRROR_ARTIFACT_BYTES,
            },
            MirrorObject {
                kind: MirrorObjectKind::Artifact,
                path: "/artifacts/b",
                digest: &digest,
                max_bytes: MAX_MIRROR_ARTIFACT_BYTES,
            },
            MirrorObject {
                kind: MirrorObjectKind::Artifact,
                path: "/artifacts/c",
                digest: &digest,
                max_bytes: MAX_MIRROR_ARTIFACT_BYTES,
            },
            MirrorObject {
                kind: MirrorObjectKind::Artifact,
                path: "/artifacts/d",
                digest: &digest,
                max_bytes: MAX_MIRROR_ARTIFACT_BYTES,
            },
            MirrorObject {
                kind: MirrorObjectKind::Artifact,
                path: "/artifacts/e",
                digest: &digest,
                max_bytes: MAX_MIRROR_ARTIFACT_BYTES,
            },
        ];
        let mut transport = ScriptedTransport {
            expected: VecDeque::new(),
        };
        assert_eq!(
            authority().acquire(
                &mut transport,
                &MirrorRequest {
                    objects: &oversized
                }
            ),
            Err(MirrorError::InvalidRequest)
        );
    }

    #[test]
    fn response_redirect_status_oversize_and_digest_drift_are_refused() {
        let object = object(MirrorObjectKind::Metadata, "/metadata/x", b"ok");
        let url = "https://mirror.example.test/metadata/x";
        for response in [
            MirrorResponse {
                status: 302,
                final_url: url.into(),
                body: Vec::new(),
            },
            response("https://other.example.test/metadata/x", b"ok"),
            response(url, b"no"),
            response(url, b"too"),
        ] {
            let mut transport = ScriptedTransport {
                expected: VecDeque::from([(url.into(), response)]),
            };
            let expected = if transport.expected[0].1.status == 302 {
                MirrorError::NotFoundOrNonSuccess
            } else if transport.expected[0].1.final_url != url {
                MirrorError::RedirectOrOriginChanged
            } else if transport.expected[0].1.body.len() > object.max_bytes {
                MirrorError::ResponseTooLarge
            } else {
                MirrorError::DigestMismatch
            };
            assert_eq!(
                authority().acquire(&mut transport, &MirrorRequest { objects: &[object] }),
                Err(expected)
            );
        }
    }

    #[test]
    fn concrete_native_transport_has_no_proxy_redirect_or_credential_input_surface() {
        let authority = authority();
        let _transport = NativeHttpsMirrorTransport::new(&authority).unwrap();
        assert_eq!(
            std::mem::size_of::<MirrorGet<'_>>(),
            std::mem::size_of::<(&str, Duration, usize)>()
        );
    }

    #[test]
    fn native_transport_refuses_cross_authority_origin_or_timeout_reuse_before_dispatch() {
        let mut transport = NativeHttpsMirrorTransport::new(&authority()).unwrap();
        let object = object(MirrorObjectKind::Metadata, "/metadata/x", b"ok");
        let other_origin = MirrorNetworkAuthority::new(
            MirrorOrigin::parse("https://other.example.test/").unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            other_origin.acquire(&mut transport, &MirrorRequest { objects: &[object] }),
            Err(MirrorError::InvalidRequest)
        );
        let other_timeout = MirrorNetworkAuthority::new(
            MirrorOrigin::parse("https://mirror.example.test/").unwrap(),
            Duration::from_millis(1),
        )
        .unwrap();
        assert_eq!(
            other_timeout.acquire(&mut transport, &MirrorRequest { objects: &[object] }),
            Err(MirrorError::InvalidRequest)
        );
    }
}
