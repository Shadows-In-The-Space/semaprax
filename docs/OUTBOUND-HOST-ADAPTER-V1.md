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

## Host-owned reconciliation ledger

`HostDeliveryLedger` is an optional, process-local reconciliation primitive for
host code that owns a prepared-request dispatch boundary. It is deliberately
separate from `OutboundCapability` and `DeliveryEvidence`: a trusted host
chooses to invoke `reconcile` *before* its one-shot adapter action, supplying
its bounded deployment/invocation/idempotency identity and the exact
`PreparedRequest`.
The ledger independently derives the existing canonical request digest and
requires its idempotency component to be the one exact boundary-owned
`idempotency-key` header. It records only the digest plus the closed local
disposition.

The existing `deliver_*` convenience calls remain stateless, one-shot helpers;
there is no production caller of this optional primitive yet. A host adopting
it selects `reconcile` at its own prepared-request dispatch boundary. The
primitive remembers a disposition only, not a `DeliveryResult` or response
body, so it does not offer response replay. Adding it does not silently change
legacy helper behavior or invent a cross-process recovery route.

For an exact identity and request digest, a later `reconcile` call returns the
remembered disposition and never enters its dispatch closure. A different
digest under the same identity refuses before dispatch. `Accepted`, `Rejected`,
and every `Uncertain` observation are sticky; uncertainty is specifically never
auto-retried. `NotDispatched` is also retained for the same exact-pair
non-redispatch rule, so an explicit new host attempt must use a distinct
invocation identity rather than quietly reuse the first attempt. The ledger
reserves a conservative `Uncertain { Transport }` disposition immediately
before it invokes the host closure; if that closure unwinds after a physical
start, normal Rust unwinding leaves the reservation intact and a caught caller
still cannot retry through the ledger.

The ledger has a fixed maximum of 256 entries, rejects a full ledger before
dispatch, stores no request body, endpoint, headers, response body, or raw
identity components, and renders a deterministic diagnostic snapshot using
only SHA-256 identity and request commitments. Those hashes are not
confidential redaction: low-entropy inputs can be guessed and tested offline.
It has no restore API and intentionally
forgets all knowledge when dropped or after a process restart. Consequently it
is neither durable delivery state nor an exactly-once protocol; it cannot prove
remote receipt, turn evidence into a capability, or authorize a retry.

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
after-start uncertainty. The reconciliation cases add bounded-capacity refusal,
duplicate exact replay without redispatch, changed-payload conflict refusal,
idempotency/header mismatch refusal, sticky uncertainty after an unwinding
dispatch closure, and deterministic commitment state. It performs no live
network operation.
