# Outbound Host Adapter v1

Status: implementation slice for issue #193; deterministic fixture evidence
only. No hosted or public-network support claim follows from this module.

Audience: runtime integrators and reviewers of outbound application effects.

`src/outbound_host_adapter/` joins the existing pure `std` policy packages and
bounded HTTPS runtime at one injected host boundary. It covers typed
GET/POST/PUT/PATCH/DELETE requests, structured operational export, signed
webhook delivery, and a provider-neutral email envelope. The policy layer reads no environment and creates no threads or
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
Legacy POST requests retain the v1 digest domain and byte layout. Non-POST
requests use the v2 domain and bind the selected method before the remaining
request fields, so extending the adapter does not silently rewrite existing
email, webhook, export, or POST evidence commitments.

The existing `deliver_*` convenience calls remain stateless, one-shot helpers.
The additive `prepare_email_delivery` plus `EmailDeliverySession::reconcile`
route is the first in-tree family integration: it validates and constructs the
exact request before entering the ledger, then lets only a fresh exact identity
enter the injected adapter closure. A matching request gets a newly derived
authority-free receipt and never calls `send`; a changed request conflicts
before dispatch. Fresh physical work still requires the injected capability
inside `PreparedEmailDelivery`.

This email session deliberately settles **disposition-only**. It discards even
a bounded nonempty accepted provider response before it writes replay state and
its receipt type exposes no response bytes. Therefore exact replay needs the
canonical request, identity/idempotency, policy commitment, and closed
disposition only; it neither pretends to replay provider payloads nor retains
them in process memory. A panic after adapter entry leaves both the pre-dispatch
policy commitment and the ledger's pre-reserved `Uncertain { Transport }`
terminal record sticky, so an exact replay can reconstruct the uncertainty
without adapter entry. A normal ledger refusal rolls back a newly staged policy
commitment. The policy commitment domain-separates the policy ID, sorted
allowed origins, and every request/response/deadline/export limit, so a host
cannot silently replay through a changed policy with the same policy ID.
Policy commitments and session identities are SHA-256 values;
no request, raw identity, credential, or response bytes are stored. This does
not silently change legacy helper behavior or invent a cross-process recovery
route.

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

### Read-only disposition checkpoints

`HostDeliveryLedger::checkpoint` and the corresponding method on the HTTP,
email, webhook, and structured-export sessions produce an immutable
`LedgerCheckpoint`. Its additive
`semaprax.outbound.delivery-ledger-checkpoint.v1` JSON wire contains exactly
`schema`, `capacity`, and `entries`. Each entry contains exactly an identity
commitment, a request commitment, and the closed local disposition, ordered by
identity commitment. The older one-way diagnostic `render` format is unchanged.
Neither format contains endpoint, headers, signing keys, raw identity parts,
request/response bytes, or provider errors. SHA-256 commitments can still expose
guessable low-entropy inputs to offline comparison.

The checkpoint digest domain is
`semaprax.outbound.delivery-ledger-checkpoint.v1\0`; SHA-256 covers that domain,
the canonical wire byte length as little-endian u64, and the exact wire bytes.
`decode(bytes, expected_digest)` bounds input to 98,304 bytes before hashing or
JSON parsing, requires the independently retained digest, and validates the
closed schema, 1–256 capacity, entry count no greater than capacity, lowercase
SHA-256 values, unique identities, closed dispositions, and byte-exact canonical
re-rendering. Accepted statuses must be 2xx; rejected statuses are the remaining
100–599 values. Duplicate fields/entries, reordered entries, alternate JSON
spellings, unknown members, and invalid status/reason combinations refuse.
The maximum 256-entry checkpoint fits below the wire limit.

An imported checkpoint offers read-only `lookup` by exact identity and prepared
request. Unknown identities remain unknown; changed request bytes conflict.
`verify_against` compares its complete state and capacity against a still-live
ledger; each family session exposes `verify_checkpoint` for the same comparison.
`merge` computes a bounded union of compatible observations without modifying
either input. Capacity must match, and any request or disposition disagreement
refuses, including replacing an uncertainty with acceptance. A panic-reserved
uncertainty is preserved when exported and imported.

This is offline observation transport, **not live-session restoration**. The
checkpoint does not include session policy/event commitments, cannot construct
a capability or delivery receipt, and has no dispatch method or conversion into
a live ledger/session. It does not create a journal, fsync, authenticate its own
provenance, establish freshness, or prevent external rollback. A digest supplied
alongside attacker-controlled bytes authenticates nothing; trusted hosts must
retain/authenticate the expected commitment independently. Missing or stale
observations never authorize a retry through this API. Exporting a snapshot
after settlement cannot close the crash window before that export, so durable
delivery recovery and exactly-once claims remain out of scope.

## High-level HTTPS requests

`deliver_http` and `prepare_http_delivery` admit an explicit `HttpMethod`,
canonical HTTPS endpoint, stable request and idempotency identities, optional
content type, bounded public headers, body, and deadline. The physical adapter
receives the selected method; the canonical request digest binds that method
in addition to endpoint, ordered headers, body, deadline, redirect limit, and
response limit. GET bodies are refused. Redirects and transport retries remain
fixed at zero for every method.

Header admission is deliberately narrow. Names must be canonical lowercase,
values are bounded and control-free, duplicates refuse, and callers cannot
supply the boundary-owned `content-type` or `idempotency-key` names.
Credential-shaped names (`authorization`, `proxy-authorization`, `cookie`,
`set-cookie`, and `x-api-key`) are refused from the caller-controlled value.
A trusted provider adapter may apply deployment-owned credentials outside the
request value; this module does not read a secret store or expose credentials
to source, debug output, checkpoints, or evidence.

`HttpDeliverySession` gives the same bounded process-local disposition replay
as email/webhook/export sessions. An exact identity and complete request,
including method, replays without entering the adapter; changing only the
method conflicts before dispatch. Accepted response bytes are intentionally
dropped by the session, while the one-shot `deliver_http` result may return a
bounded accepted body. Panic, deadline, transport, and response-overflow
uncertainty stay sticky. This does not claim durable or remote exactly-once
delivery, DNS pinning, provider authentication, or public-network support.

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
boundary also normalizes ASCII case and `-`/`_` spelling for the closed
credential-name inventory shared with `std.log.redact`; a protected name cannot
carry a public field or label value. Matching is exact, not substring-based, so
an ordinary name such as `password_hash` is not silently classified. This is a
bounded name policy, not content-based secret discovery. The
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
after-start uncertainty. The integrated email session cases add a nonempty
accepted provider response that is intentionally not retained, exact replay
with zero adapter calls, changed-request and policy-commitment refusal before
dispatch, and an unwinding adapter attempt whose reserved uncertainty cannot be
retried. The reconciliation cases add bounded-capacity refusal,
duplicate exact replay without redispatch, changed-payload conflict refusal,
idempotency/header mismatch refusal, sticky uncertainty after an unwinding
dispatch closure, and deterministic commitment state. It performs no live
network operation.

The HTTP cases execute all five typed methods through the injected adapter,
cover endpoint/body/header/content-type maxima and credential-name refusal,
redacted debug surfaces, exact no-redispatch reconciliation, method-only
conflict, bounded response settlement, sticky panic uncertainty, and read-only
checkpoint verification. They exercise fixtures only, not a public endpoint.

The checkpoint selector is
`outbound_host_adapter::ledger::checkpoint::tests::`. Its seven cases cover
deterministic all-disposition round trips, the empty-state known-answer digest,
commitment/live-state drift, exact lookup, monotonic union/conflict refusal,
panic-reserved uncertainty, full-capacity admission and byte/inventory limits,
hostile schemas/digests/statuses/noncanonical wires, and exports/imports from
the adapter sessions without extra adapter calls.
