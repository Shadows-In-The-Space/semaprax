# Package registry mirror transport v1

Status: additive bounded native HTTPS byte acquisition. This is neither a
hosted registry nor a trust, store, resolver, cache, installation, publication,
credential, proxy, or execution route.

## Authority and request boundary

`package_registry::mirror_transport` accepts one host-constructed
`MirrorNetworkAuthority`. It contains one exact HTTPS origin and a timeout in
the closed interval `(0, 60 seconds]`. The origin has a host, no user-info,
path other than `/`, query, or fragment. A caller supplies one through 64 exact
origin-relative object paths, each with a lower-case `sha256:<hex>` binding and
its own byte bound. Paths are canonical ASCII segments (`A-Z`, `a-z`, `0-9`,
`-`, `_`, `.`) separated by a single `/`; empty, dot, query, fragment,
percent-escaped and control-character paths fail before dispatch.

`Metadata` is limited to 1 MiB and `Artifact` to 16 MiB. Duplicate paths,
empty batches, wrong digest syntax and bounds fail before the transport is
called. The checked sum of all declared object bounds is at most 64 MiB, so the
all-or-nothing returned batch cannot reserve a larger accepted payload than the
held-generation ceiling. Returned objects preserve caller request order, but no partial result
is returned: every requested response must be successful, remain at the exact
requested URL, fit its bound and match its raw SHA-256. The module sends no
caller-controlled headers, credentials, cookies, proxy selection or redirect
policy.

The native `NativeHttpsMirrorTransport` uses the pinned WebPKI roots,
HTTPS-only reqwest client, explicit `no_proxy`, the authority timeout for
connect/read/pool idle bounds, redirect policy `none`, and retry policy `never`.
It buffers at most the requested bound plus one byte. A redirect/non-success,
URL change, oversized result, digest drift or transport failure returns a
closed `MirrorError` without retaining response bytes or OS error text.

## Composition and nonclaims

Acquisition returns `MirrorBytes`: exact digest-bound byte evidence only. It
cannot install a root, produce a `RegistryUpdateCandidate`, mutate
`HeldTrustStore`, populate the resolver cache, grant filesystem access, or
authorize artifact execution. An embedding host must separately supply the
returned metadata and artifacts to the existing Registry Trust v2 verifier and
Registry Host v2 `Update` flow; their sealed registry, independent root pin,
fixed trusted time, Lock-v3 replay, manifest bindings and durable `ACTIVE`
checks remain mandatory. A mirror digest does not replace any signature or lock
check.

No remote discovery, mutable version selection, availability, credential,
proxy, hosted, physical-device or production support is claimed. The local
tests use an in-process scripted `MirrorTransport`; they prove the dispatch
contract but do not establish a real TLS peer, DNS, certificate, Internet, or
hosted-registry end-to-end result.

## Focused evidence

`package_registry::mirror_transport::tests` owns four local cases: ordered
metadata/artifact exact URL acquisition; invalid origin/path/duplicate/timeout
or aggregate bound pre-dispatch refusal; redirect, status, URL, size and digest
hostile responses; and construction of the concrete native transport. The latter inspects no
network and makes no availability claim.
