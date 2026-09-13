# HTTPS Client I/O v2

Status: bounded implementation for application outbound HTTP (#193); local
focused evidence does not extend historical hosted or platform support claims.

The additive compiler-owned operation is:

```semaprax
https_post(url: borrow Slice<u8>, body: borrow Slice<u8>, max: usize) -> own Bytes
```

Its persistent identity is `core.host.https-post`. It requires `network.http`
on the function and module. Arguments evaluate left to right and remain borrowed;
only a complete response becomes an owned result. Capacity and cleanup admission
use the same conservative 65,536-byte owned-result site as `https_get`.
The existing `https-command-io.v1` profile admits the additive operation; its GET
behavior remains governed by [v1](HTTPS-CLIENT-IO-V1.md).

URL input is nonempty UTF-8, at most 2048 bytes, with no NUL. POST accepts HTTPS
only and refuses userinfo and fragments. Request body is at most 65,536 bytes;
`max` is positive and at most 65,536, including the complete canonical response
headers and body. Empty bodies are valid. Concrete hosts send the fixed
`Content-Type: application/octet-stream`; source does not supply headers. Response projection reuses v1's
HTTP/1.1-shaped canonical bytes, independently of negotiated transport version.
Outbound request bytes count against the interpreter's cumulative network budget
before dispatch and are not refunded after failure.

## Authority and failures

Declaring the effect alone does not authorize any POST destination. The provider
must receive an explicit host-selected HTTPS origin policy (at most eight origins). No source-selected
authentication header, source credential, ambient proxy, or environment-derived
origin grants authority. The concrete Rust and native hosts do not follow redirects for
POST and perform no automatic retries. The host retains TLS trust configuration.
Origin authorization is not IP pinning or a guarantee about DNS rebinding; hosts
requiring network-range restrictions must enforce them at their network boundary.

The existing `semaprax.http.v1` status domain remains closed: 1 invalid URL,
2 insecure scheme, 3 transport failure, 4 capacity overflow, 5 unsupported HTTP
version, 6 authority denied. For POST, capacity includes request as well as
response bounds. A status after dispatch does not prove that an external effect
failed: even timeout, response overflow or response loss may follow successful
remote processing. Source failure aborts the invocation and publishes no partial
response; this operation does not return a checked delivery-outcome value.
Evidence and errors do not authorize a retry. Webhook delivery reconciliation,
checked uncertain-result APIs, signing and email remain separate work.

## Explicit host configuration

Rust hosts use `TcpNetworkProvider::with_https_post_origins` or
`set_https_post_origins` with at most eight canonical HTTPS origins. TLS policy
remains injected through the existing provider constructors. An origin matches
scheme, host and effective port; there are no wildcard authorizations.

Generated native commands consume leading
`--spx-https-post-origin=https://host[:port]` host options before exposing the
remaining arguments to source. Embedders supply an explicit
`spx_https_post_allowlist_v1` to
`spx_https_command_run_with_post_allowlist_v1`. The ordinary runner grants no
POST origin. Host option errors refuse before executing the source command.

## Fixture v4 and Wasm

`semaprax.network-fixture.v4` keeps v3's connections/listeners and HTTPS GET
fields and requires an additional ordered `https_post` array. Both `https` and
`https_post` are required arrays of at most eight entries each. A POST entry has
exactly `url`, `body`, and `response`, each a JSON string. Body and response use
UTF-8 bytes and are capped at 65,536 bytes; URL uses the source bound. This fixture
profile represents UTF-8 payloads, while the actual source operation accepts
arbitrary body bytes. The existing whole-document fixture limit still applies.

A replay requires exact URL and body bytes and sufficient response capacity.
Mismatch or insufficient capacity preserves the entry. Earlier fixture versions
remain accepted for their original operations and deny POST authority. Fixtures
are replay data and never grant actual network authority.

Core Wasm adds `spx_https_post_v1(url_root, url_len, body_root, body_len, max,
out_owned) -> status`, with six i32 parameters and the existing owned-result
validation/publication contract. The generated npm adapter executes this import
against the explicit fixture only, with no browser fetch or Node socket fallback.
