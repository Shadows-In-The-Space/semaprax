# Provider Adapter SDK v1

Status: **LOCAL** bounded SDK, fixture/recording evidence, two real provider
*protocol normalizers*, and an explicitly configured native HTTPS host
transport. No live credential, endpoint, or network call was used to produce
the local evidence cited here.

Audience: implementers of issue #181 ("Create a provider adapter SDK and
deterministic model-provider conformance suite") and reviewers of the
adapter/conformance boundary this document adds around
[Live Invocation Contract v1](LIVE-INVOCATION-CONTRACT-V1.md),
[Model Budget Policy v1](MODEL-BUDGET-POLICY-V1.md), and
[Model Call Receipt v1](MODEL-CALL-RECEIPT-V1.md).

This document assumes the reader already knows Live Invocation Contract v1's
`model.invoke` effect boundary (`src/live_invocation/model_invoke.rs`):
`ModelHandler`, `ProposalDecoder`, `AuthorizationGate`, `InvocationBudgetHook`,
and the closed `ModelFailure` failure domain. Everything below is additive to
that contract, never a restatement or a second copy of it.

## What already existed at the audit baseline (2026-09-11, `ae25c6a4`)

- `live_invocation::model_invoke` already defines the provider-independent
  `model.invoke` request/response shape and the injected `ModelHandler`
  trait a real deployment binds to one concrete transport. It is a single
  blocking call: one request in, one `ModelInvocationOutcome` out.
  `live_invocation::fixture` ships only deterministic, scripted
  implementations of every seam.
- `model_budget_policy::classification::AttemptOutcomeClass` and
  `retry_is_permitted` already define the closed, transport-agnostic
  retry-safety vocabulary; `model_budget_policy::provider_policy` already
  owns the exact ordered, confidentiality-checked failover sequence a
  deployment may switch across.
- `model_call_receipt` already owns the canonical, redaction-aware,
  replayable record of one settled attempt, and `agent_interaction_schema`
  (with its `streaming_proposal_decode` extension) already owns the one
  real, compiler-derived Proposal grammar and its incremental, chunk-order-
  agnostic decoder.
- No public, stable, capability-declaring **adapter** interface existed: a
  real provider integration had nowhere to declare what it supports before
  being dispatched against, and no shared corpus existed to check that
  declaration, or a candidate implementation's behavior under hostile
  input, before describing it as conforming.

## What this module adds

`src/provider_adapter_sdk/` is new. It sits *behind*
`live_invocation::model_invoke::ModelHandler`, never replacing it: a real
deployment still binds exactly one `ModelHandler` per deployment, and
adapting one `ProviderAdapter` into that seam is downstream integration
work, out of this module's scope. What this module adds is the richer,
capability-declaring, event-streaming shape a third-party provider
integration implements once, plus the shared suite that checks it.

### The ABI (`adapter.rs`, `capability.rs`)

- `AdapterCapabilities`: the adapter's self-report — identity/version,
  provider profile, supported structured-output modes, whether it streams,
  where its usage/cost numbers come from, its cancellation semantics, which
  `AttemptOutcomeClass` values it promises are safe to retry, its endpoint
  policy, and its byte/token ceilings. Declared once, before any dispatch.
- `AdapterInvocationCapability`: the explicit, non-ambient grant required to
  construct and drive an adapter, mirroring
  `ModelInvokeCapability::grant` exactly.
- `ProviderAdapter`: `capabilities`, `start`, `poll`, `cancel`. `poll`
  returns one `AdapterEvent` (`Delta`/`Usage`/`Completed`), `Pending`, a
  terminal `Settled`, or a terminal `Failed { failure: ModelFailure, .. }` —
  reusing `live_invocation::model_invoke::ModelFailure` as the one closed
  error-normalization vocabulary, not a second one.
- `negotiate(caps, required)`: the *only* function that decides whether a
  declared adapter may be dispatched against. It refuses, unconditionally
  and before any call to `start`: an adapter that declares
  `EndpointPolicy::AdapterDeclaredAmbient` (an ambient endpoint/proxy/
  credential lookup instead of `HostInjected`), or one that declares a
  retry-unsafe `AttemptOutcomeClass` as retryable. It additionally refuses,
  against a caller's stated `RequiredCapabilities`: an unsupported streaming
  or structured-output-mode requirement, or a byte budget larger than the
  adapter's declared maximum.

### The driver (`conformance.rs`)

`drive_to_settlement` is the one place this SDK concatenates `Delta` events
and enforces the rules a conforming adapter must never violate:

| Rule | Violation code |
| --- | --- |
| A streaming or eventful attempt has exactly one `Completed` before settlement | `ADAPTER-DUPLICATE-COMPLETION` / `ADAPTER-SETTLED-WITHOUT-COMPLETION` |
| No event after `cancel()` was called | `ADAPTER-LATE-AFTER-CANCEL` |
| Usage never regresses across snapshots or from a snapshot to settlement | `ADAPTER-CONTRADICTORY-USAGE` |
| Delta and terminal batch response stay within the request bound | `ADAPTER-OVERSIZED-RESPONSE` |
| Terminal bytes exactly equal ordered Deltas whenever any Delta was emitted | `ADAPTER-SETTLEMENT-MISMATCH` |
| No `Delta`/`Usage` after `Completed` | `ADAPTER-EVENT-AFTER-COMPLETION` |
| A terminal outcome is reached within a bounded poll budget | `ADAPTER-POLL-BUDGET-EXCEEDED` |

An eventless non-streaming batch settlement remains admitted, but its terminal
bytes are still bounded. `run_conformance_suite` separately verifies concrete
request bytes and response allowance against the declared adapter maxima before
it calls `start`; `drive_to_settlement` is the lower event normalizer and assumes
that admission already happened. A mid-stream disconnect (the adapter itself
returns `Failed`) is not a violation of any of these: the driver surfaces it
unchanged, matching `ModelFailure`'s existing closed vocabulary.

### The report (`report.rs`)

`ConformanceReport` binds adapter identity/version, provider profile, the
named test corpus (`TEST_CORPUS_ID`), one canonical rendering of the
adapter's observed capabilities, an ordered list of named case results, and
a fixed set of nonclaims. `render`/`digest` are canonical and deterministic,
mirroring `ModelCallReceipt`'s own "commitments, not authority" discipline: a
fully passing report is local evidence that the suite ran and observed no
violation, never itself a support or publication decision
(`NONCLAIM_NOT_A_SUPPORT_DECISION`).

### The fixtures (`fixture_adapters.rs`, `hostile.rs`)

Two materially different conforming adapters — `ScriptedBatchAdapter`
(single-shot, non-streaming) and `ScriptedStreamingAdapter` (multi-event
streaming) — both pass the same corpus, demonstrating the ABI is not shaped
around either transport style. `RecordedReplayAdapter` replays a fixed
recording verbatim; there is no field in it capable of an outbound call, so
"replay reproduces the recording without dispatch" is a structural property
of the type, not a runtime check. `hostile.rs` ships one adapter (or
capability declaration) per named violation above, plus an ambient-endpoint
declaration, an unsafe-retryable-class declaration, and a credential-holding
adapter used only to prove nothing it holds ever appears in a report.

### Concrete provider protocols (`vendor/`)

`vendor::OpenAiResponsesAdapter` and `vendor::AnthropicMessagesAdapter` are
separate implementations over one deliberately narrow host-injected HTTP/SSE
seam. The seam receives only a fixed relative path, public protocol headers and
a bounded request body. It owns the absolute endpoint, proxy/TLS policy and
credential attachment, so neither adapter has a URL, secret, environment
lookup, or socket implementation. No new HTTP dependency is introduced.

The OpenAI adapter sends `POST /v1/responses` with `stream: true`, maps
`response.output_text.delta` to raw `Delta`, receives final usage from
`response.completed`, and waits for host stream end before settlement. The
Anthropic adapter sends `POST /v1/messages` with `stream: true`, maps
`content_block_delta` `text_delta` events, observes `message_start` and
cumulative `message_delta` usage, and likewise requires `message_stop` plus
host end. Arbitrary transport chunks are framed as bounded SSE before JSON is
decoded; truncated, overlarge, malformed, or post-completion data fails closed.

Provider-native OpenAI function/MCP calls and Anthropic client/server tool-use
events are refused and request best-effort stream cancellation. They never
become an `AdapterEvent::Delta`, cannot execute a host tool, and still pass the
unchanged compiler-derived proposal decoder only as ordinary raw text.

The wire shapes were checked against the current primary documentation:
[OpenAI Responses streaming](https://platform.openai.com/docs/api-reference/responses-streaming)
and [Anthropic streaming Messages](https://platform.claude.com/docs/en/build-with-claude/streaming)
(accessed 2026-09-13). These are protocol implementations and hostile raw-wire
fixtures, not proof of live-provider support, billing, or hosted conformance.

The protocol adapters cap total HTTP/SSE wire input at 8 MiB, including ignored
comments, with at most 1 MiB retained undecoded bytes and 4,096 frames per poll.
Decoded Proposal bytes retain the caller's separate response bound. Framing
uses one scan and one buffer compaction per poll. Model labels must contain
1–256 bytes and configured output limits must be 1–1,048,576 tokens before
host access; these are local admission bounds, not vendor support guarantees.

### Native HTTPS host transport (`vendor::HttpsBufferedTransport`)

The native-only `HttpsBufferedTransport` is an actual
`HostHttpStreamTransport` for a host that intentionally grants a provider
connection. It uses the repository's existing pinned `reqwest`/Rustls HTTPS
stack rather than adding a provider SDK or a dependency. The existing public
`HttpsClient` cannot be used directly because it deliberately exposes only a
buffered `GET`; this transport needs a bounded `POST` with host-attached
authentication.

A host constructs `ProviderHttpsTransportConfig` with all of the following:

- exactly one `ProviderHttpsOrigin`, parsed as a bare `https` origin with no
  user-info, path, query, or fragment. The adapter's path must remain a plain
  API-relative path under that origin; redirects are disabled.
- `ProviderHttpAuthentication::header(...)`, an opaque host-only header. It
  admits both `authorization: Bearer …` for OpenAI and `x-api-key: …` for
  Anthropic, has no secret getter, and redacts its value in debug output.
- a TLS policy: pinned WebPKI roots or an explicit caller-supplied Rustls
  configuration, plus the explicit `ProviderProxyPolicy::Disabled` policy.
  The native client uses `no_proxy`, so neither proxy environment variables nor
  implicit proxy discovery can alter the connection.
- one timeout from 1 ns through 300 s and one wire-response ceiling no larger
  than 8 MiB. Origins are capped at 2,048 bytes; authentication header names
  at 64 bytes and secret values at 16 KiB before client construction. Request
  protocol headers cannot supply authentication, host, framing, cookies, or
  proxy credentials.

This initial transport is deliberately **synchronous and buffered**. `start`
performs the HTTPS request and retains a successful response within the exact
wire bound; `poll` then yields at most 64 KiB at a time to preserve the SSE
decoder's bounded framing. A timeout, non-success response, truncated read, or
oversize response is conservatively reported after dispatch, so it is never an
automatic retry claim. Calling `cancel` removes unread local bytes and reports
local cancellation after dispatch; it cannot interrupt a blocked `start`, call
a provider cancellation endpoint, or establish that remote work or billing
stopped. The local authority tests cover origin/path/header smuggling,
credential redaction, chunk bounds, and cancellation wording without calling a
real provider.

## Nonclaims

`StreamingModelHandler` is the optional generic-kernel bridge for an adapter
and one `CompiledInteractionSchema`. It negotiates streaming raw-text support
before `start`, incrementally validates `Delta` bytes, requests cancellation
on an early refusal, and returns canonical schema bytes only after both a
`Completed` event and matching settlement. It does not implement a live
provider transport, generated clients, or Direct Runtime wiring.

- **No live call, key, endpoint, or support claim.** The concrete adapters
  normalize real vendor protocols and may use an explicitly configured native
  host transport; the local tests do not contact a vendor. Endpoint selection
  and authentication remain host authority, outside source semantics and this
  SDK.
- **Cancellation is a request, not proof.** `CancellationSemantics` has no
  `Guaranteed` variant. `AdapterPoll::Failed { failure: ModelFailure::Cancelled, .. }`
  proves only that this process observed cancellation, never that a
  provider stopped processing or billing.
- **Usage/cost is adapter-reported, not independently verified.** This
  suite checks internal consistency (usage never regresses), never
  agreement with real provider billing.
- **A passing report is not a support decision.** Generating a report, even
  a fully passing one, is not itself a decision to describe an adapter as
  supported — that remains a separate, human, out-of-band decision.
- **Protocol normalization is not hosted evidence.** The two vendor modules
  prove that two materially different documented protocols fit the neutral
  seam. A passing local wire fixture does not establish live-provider support.

## Live-kernel streaming bridge

`StreamingModelHandler` implements the generic kernel's `ModelHandler` using an
explicitly supplied adapter and adapter invocation capability. It checks the
request's grammar identity, projects task and observation bytes losslessly as
`task_hex`/`observation_hex` with the unchanged compiler-derived provider schema,
and negotiates the bounded prompt and response sizes before adapter start.
Task plus observation are limited to 65,536 bytes; provider-schema output is
limited to 262,144 bytes. Response capacity is capped at the existing streaming
decoder's 65,536-byte limit, including before copying a hostile delta.

Every delta is fed to `ProposalStreamDecoder` before another poll. A malformed
prefix cancels the adapter and stops reading. Completed must occur exactly once,
with no subsequent deltas or usage; settlement bytes must match the entire
stream. Negative/regressing usage refuses. Only a completed, compiler-admitted
canonical document is returned. `CompiledProposalDecoder` then applies that
same checked schema at the generic kernel's separate decode boundary, before
any authorization grant can be minted. No provider-native tool events execute.

`with_cancellation_and_deadline` binds an explicit cancellation signal, clock
and original absolute deadline. It checks before adapter start and every poll,
including Pending; controls cannot interrupt a host adapter blocked inside its
own poll. Without explicit controls, the hard 10,000-poll bound still applies.
A cancel request is best-effort and does not prove the provider stopped work.
The bridge rechecks cancellation and deadline after a settlement poll returns
and before publishing response bytes; it retains the adapter's attempted-byte
measurement on that refusal. The corresponding source bridge applies the same
post-settlement control check before proposal publication.
The SDK contract gives each adapter instance one start; hosts must provide a
fresh adapter for a new attempt. This bridge does not select providers, retry,
or provide a network transport.

The focused bridge tests include the actual live kernel with streaming compiled
decode, model-policy reservation and journal receipt projection together;
malformed first-chunk refusal with no further reads or authorization; and
pre-dispatch/pending deadline, cancellation, schema and hostile byte-cap cases.
These are offline injected adapters, not evidence for two live vendors.

## Ordinary source proposal streaming bridge

`source_bridge::StreamingSourceProposalAdapter` implements the existing source
`ProposalSource` trait using a fresh, explicitly injected `SourceAdapterFactory`
for each attempt. It uses the source `CompiledAgentProposalSchema`, distinct
from the generic interaction schema, and refuses source revision or schema
drift before adapter creation. The source driver retains authorization and
retry decisions. This bridge advertises no checkpoint policy: it does not
invent durable provider attempt identities or journal intents.

The generated `semaprax.source-adapter-prompt.v1` JSON carries exact task bytes
as hex, task budget, source revision, turn, attempt, remaining iterations,
canonical lifecycle state/observation, prior effect bytes as hex or null, prior
rejection or null, and the compiler proposal schema. Retained carriers are
checked before rendering with a conservative 65,536-byte upper bound and depth
64; prior effect/rejection and complete prompt are bounded at 65,536 bytes.
These bounds do not alter the lifecycle's canonical retained-value encoding.

An optional host cancellation token and absolute `InvocationClock` deadline
are checked before factory creation, before start, and before each poll.
The bridge allows at most 10,000 polls; blocking host callbacks remain
cooperative. It checks each chunk before the next poll, cancels on early
refusal, and requires one Completed event followed by settlement containing
exactly the streamed bytes. Duplicate completion, post-completion deltas/usage,
negative or regressing known usage, malformed framing, and semantic decoder
refusal cannot produce a proposal. Missing usage remains unknown.

Local fixture tests cover real compiled-schema admission, iterative context,
fresh attempts, early stream refusal/cancellation, predispatch cancellation,
deadline, identity and capacity refusals, and settlement/usage contradictions.
This is an in-process adapter seam, not evidence of a network provider or a
durable source checkpoint implementation.

### Durable generic policy model identity

The additive generic policy v2 route requires `ProviderAdapter::model_identity`
to return an `AdapterModelIdentity` matching the retained deployment's exact
provider, model, and ordered capabilities. The default returns no identity;
that route refuses such an adapter before `start`. Existing adapter routes
retain their current behavior. This is a host declaration checked against
retained policy, not proof of a remote endpoint's identity or billing.
