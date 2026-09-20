# Outbound Host Adapter v1

Status: implementation slice for issue #193; deterministic fixture evidence
only. No hosted or public-network support claim follows from this module.

Audience: runtime integrators and reviewers of outbound application effects.

`src/outbound_host_adapter/` joins the existing pure `std` policy packages and
bounded HTTPS POST runtime at one injected host boundary. It covers structured
operational export, signed webhook delivery, and a provider-neutral email
envelope. The policy layer reads no environment and creates no threads or
timers. `NativeHttpsAdapter` is the explicit physical HTTPS implementation: its
host supplies TLS policy, while it disables ambient proxies, redirects, and
retries. Tests use a deterministic recording fixture and perform no network
I/O.

## Authority and admission

An `OutboundCapability` names the deployment binding, invocation, exact HTTPS
origins, and hard request, response, deadline, field, and label limits. It is
move-only and is consumed by one call, preventing this API from reusing a grant
for automatic retry. Its public Rust constructor is a **trusted embedder seam**,
not an unforgeable token against arbitrary Rust code: calling it asserts that
deployment policy already authorized the operation. SEMAPRAX source cannot call
that constructor. The capability is ordinary host configuration, not proof that
an endpoint was reached. Evidence cannot be converted back into it.

Endpoint syntax, exact origin membership, deadline, request size, content type,
delivery identity, idempotency key, export cardinality, and protected-field
shape are checked before `OutboundAdapter::send`. Origins have no wildcard;
userinfo, fragments, insecure schemes, controls, and noncanonical policy origins
are refused. Redirects and retries are absent from the adapter contract. A
trusted custom transport implementation is required to issue the one prepared
request exactly once, but arbitrary Rust implementations can violate that
contract. Only `NativeHttpsAdapter` mechanically configures no proxy, no
redirect, and no retry.
Exact origin admission is not IP pinning or DNS-rebinding prevention; a host
that requires network-range policy must enforce it in its resolver or network
boundary.

Webhook headers are boundary-owned. Callers cannot inject authorization or
signature headers. `WebhookSigningSecret` is explicit, move-only, and redacted
from `Debug`; its owned Rust array is zeroized on drop, with no claim about
caller, allocator, transport, process-dump, or operating-system copies.
HMAC-SHA-256 v2 binds a domain separator, `POST`, deployment binding, canonical
origin, canonical request target, exact delivery ID, idempotency key, content
type, and body. The delivery ID and idempotency key are also included in
evidence; neither authorizes replay.

Idempotency is receiver-enforced: this adapter sends the key but keeps no durable
deduplication ledger and cannot prove the receiver honored it. A restart loses
all local fixture/adapter memory. Uncertain settlement therefore remains
uncertain and never authorizes an automatic retry, even when a key was sent.

## Email envelope

`deliver_email` accepts one explicit `EmailRequest` and consumes the same
single-use capability before handing an `application/vnd.semaprax.email.v1+json`
request to the injected adapter. The body is a canonical, bounded envelope with
the sender, authored-order recipient and attachment vectors, optional Reply-To,
subject, and body bytes. Duplicate recipients and attachment names are refused;
the boundary never reorders caller-authored vectors because their order can be
meaningful to a provider. Raw body and attachment bytes use lowercase hex in
that envelope, so the host adapter receives an exact byte sequence without a
text-decoding ambiguity. They are omitted from request debug output and from
delivery evidence, which retains only the prepared-request digest.

Admission tightens the pure `std.email` policy boundary at the host seam:
sender, recipients, and Reply-To require an ASCII mailbox with exactly one `@`,
safe local atoms with no leading/trailing/consecutive dots, and dotted domain
labels of ASCII alphanumeric/hyphen bytes (1 through 63 bytes, no edge hyphen).
Recipients are 1 through 64. Subject is required, refuses every ASCII control,
and is at most 256 bytes. Bodies are at most 8 KiB; there may be at most four
attachments, each with a closed safe file name, a one-slash media type, and at
most 2 KiB of bytes. The JSON writer is capped by the deployment's existing
request limit as well, so escaping/encoding cannot turn admitted members into an
unbounded wire body.

`verify_email_envelope` is the authority-free replay side: it bounds input
before allocating member vectors, requires the closed schema/key/type shape,
lowercase-even hex, admitted mailbox and attachment members, and byte-exact
canonical JSON re-rendering. It then requires the decoded bytes to be the exact
body of a prepared email request with the boundary-owned content type and
delivery headers. Unknown, duplicate, reordered, malformed-hex, and
over-bound encodings refuse. This verifies one request representation only; it
does not recover a capability, prove provider receipt, or authorize a retry.

This is **not SMTP** and it neither resolves MX records nor manages an SMTP or
provider credential. A deployment selects a provider endpoint and trusted
adapter implementation; that adapter may apply deployment-owned authentication
outside the caller-controlled request. The request value and evidence never
grant that authority. Email content is intentionally delivered to the selected
provider adapter, so callers must apply the pure `std.email`/redaction policy to
their source data before constructing an email request; this Rust host boundary
does not infer secret classification from arbitrary bytes.

## Settlement and evidence

A response is `Accepted` only for 2xx. Other complete responses are `Rejected`.
A fixture or physical adapter may report `NotDispatched` only when it knows the
transport was never started. Deadline, response overflow, and every failure
after start are `Uncertain`, because the remote service may have acted before
the local observation failed. The boundary performs no automatic retry in any
case.

`DeliveryEvidence` binds the schema, deployment, invocation, policy, canonical
origin, complete prepared-request digest, delivery ID, idempotency key, and
settlement. Its bounded canonical decoder re-derives the origin and delivery
identities from the exact prepared request and checks the caller-retained
settlement. This is diagnostic evidence only: it is not a capability, delivery
receipt from the remote party, or permission to retry.

Operational exports encode sorted, duplicate-free labels and fields with fixed
cardinality and value limits. A protected field has no plaintext variant at the
boundary: it renders `[REDACTED]` plus an optional SHA-256 commitment. The
`export_after_primary` result keeps the primary application outcome separate
from export settlement, so exporter failure cannot replace it.

## Focused evidence

Once the module is wired from `src/lib.rs`, the focused selector is:

```sh
cargo test --locked -p semaprax --lib outbound_host_adapter::tests::
```

The corpus covers exact signing and replay binding, pre-dispatch refusal,
origin/userinfo/fragment checks, deadline/body maximum-plus-one, header and
identity injection, response maximum-plus-one, sticky uncertainty, redaction,
cardinality and duplicate-name refusal, and preservation of primary failure.
The email cases add canonical replay, header and address injection, recipient
and attachment cardinality, member maximum-plus-one, exact boundary admission,
noncanonical/unknown/duplicate/malformed-hex envelope hostility, and
after-start uncertainty. It performs no live network operation.
