# HTTPS Client Runtime v1

Status: implemented native-host Rust runtime, source operation and Project-v13
native-C11 client; **HOSTED GREEN** under the
[v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md).
Broader generated-target adapters remain open.

Audience: compiler embedders, runtime contributors, and reviewers.

`semaprax::https_client::HttpsClient` is an explicitly constructed reusable
client for bounded HTTPS GET requests. It accepts only `https` URLs, disables
ambient system-proxy discovery, authenticates TLS through Reqwest's Rustls
backend, negotiates HTTP/1.1 or HTTP/2, follows at most ten redirects, retains
at most eight idle connections per origin, and publishes a response only when
the complete body fits the caller's positive bound of at most 1 MiB.

The response contains the status, negotiated protocol, final URL, headers, and
body bytes. Headers are sorted deterministically by lowercase name. The sort
is stable: duplicate names retain receipt order, so ordered `Content-Encoding`
codings and repeated `Set-Cookie` values stay separate and in received order.

Construction and execution share one closed error vocabulary. Transport error
text and platform errors do not cross the API. Reusing a client reuses its
keep-alive pool. There is no global client, and no compiler path creates one
implicitly.

Server-side TLS is a separate native socket-provider route. The host must
construct `TcpNetworkProvider::with_tls_configs` with both client and server
Rustls policies, then call `accept_tls`. Accepted streams use the same send,
receive, close, and settlement paths as client streams. Without a server policy,
the provider fails with `AuthorityDenied` before accepting TLS.

Focused evidence covers redirect resolution, keep-alive reuse, declared
and streamed body overflow, insecure URL rejection, authenticated client and
server TLS over loopback, and settlement:

```sh
cargo test --locked -p semaprax --lib https_client::tests::
cargo test --locked -p semaprax --lib network_provider::tcp::tests::
```

The ignored `public_https_endpoint_negotiates_and_returns_a_bounded_response`
case is an opt-in live public-PKI smoke. It is intentionally outside the
deterministic default gate because DNS, routing, and the remote service are not
repository-owned inputs. The hosted-green baseline applies to the admitted
release corpus; it does not silently select this external-service smoke or
relabel a historical loopback observation as public-internet execution.

The additive [HTTPS Client I/O v1](HTTPS-CLIENT-IO-V1.md) profile exposes this
runtime as the source-level `https_get` operation and returns a canonical byte
projection accepted by the existing `std.http` parsers. Its separate native-C11
adapter uses libcurl with compiler-owned Mozilla roots and the same bounded
canonical response contract. HTTP/3, server request parsing, live browser Fetch
authority, structured async integration, observability, cross-platform libcurl
provisioning, and broad target conformance remain open.

[HTTPS Client I/O v2](HTTPS-CLIENT-IO-V2.md) adds bounded POST with explicit
destination authorization and fixture v4; it does not change the GET contract
or promote its local evidence to hosted support.
