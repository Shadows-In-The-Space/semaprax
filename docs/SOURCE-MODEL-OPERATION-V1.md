# Source Model Operation v1

Status: **IMPLEMENTED BOUNDED DIRECT-RUNTIME ROUTE; LOCAL EXECUTABLE EVIDENCE**.

Audience: Direct Runtime v2, source-Agent, and provider-adapter maintainers.

This contract binds a source Agent's existing `propose` role to one explicit,
provider-neutral streaming adapter in Direct Runtime v2. It adds to the ordinary
caller-owned `ProposalSource` route without new source syntax: checked Agent
declarations already require `propose` to have kind `model`.

## Bound operation

`AgentRuntimeV2::source_model_binding` derives `SourceModelBinding v1` only
from an already retained and checked Direct Runtime producer. Its canonical,
domain-separated digest binds:

- the runtime's DeploymentRoot and InstanceRoot, admitted deployment and
  bound-deployment digests;
- exact source revision and compiler-derived Proposal schema digest;
- deployment capability grants, the source's declared model-capability
  requirements, and one provider/model pair whose parsed capability row
  satisfies those requirements;
- host-selected adapter identity, version and opaque profile label; and
- the deployment's effective provider request and response byte limits.

The caller gives the resulting binding and its opaque
`SourceModelInvocationCapability` to
`StreamingSourceProposalAdapter::new_bound`, together with the existing
explicit `AdapterInvocationCapability`. The binding capability ties the adapter to this checked runtime, but grants
no network authority. Permission to call one adapter comes from the separately
injected, non-ambient adapter capability.

Before calling an adapter factory, the bound source checks the compiler
Proposal schema digest, source revision and binding capability. After factory
construction, but before `ProviderAdapter::start`, it checks exact adapter
identity/version/profile equality and runs the existing streaming capability
negotiation. It never derives a provider, model, endpoint,
credential, environment value or filesystem path from source/model bytes.

`AgentRuntimeV2::run_live_bound_model` refuses a frozen proposal inventory, a
reused source that already contains observations, or a source binding whose
DeploymentRoot, InstanceRoot, source revision or Proposal schema does not equal
the retained runtime. It then invokes the existing checked live
lifecycle: observe, proposal decode, authorize, typed effect and reduce remain
the same lifecycle stages. A malformed stream, schema refusal, cancellation or
settlement disagreement therefore cannot reach typed-effect dispatch.

## Redacted attempt evidence

The bound route keeps `SourceModelEvidence v1` as an in-memory typed value.
Each bounded attempt commits
only request digest/length, optional response digest/length, a closed terminal
tag, and optional provider usage observations. It never retains prompt bytes,
response text, credentials, endpoints or raw provider errors. At most 4,096
attempt records are retained. If the next attempt cannot be retained, the
source refuses before adapter factory construction or start; it does not
execute an unrecorded model attempt. The evidence digest, not a new serialized
evidence document, is joined into the ExecutionRoot evidence.

The additive success and failure products both expose this evidence. A failure
returns `AgentRuntimeV2ModelFailure` rather than dropping the accumulated
attempt observations. Its EvidenceRoot v4 binds the existing ExecutionRevision
and InstanceRoot, the exact validated source-model binding digest, a closed
completion or refusal status, the source-model evidence digest, and (on
success) the typed effect evidence digest. A rejected preflight does not
attribute a reused source's earlier observations to the current invocation.
Existing EvidenceRoot v3 bytes and the ordinary
`run_live` API are unchanged.

## Effective model policy

`source_model_policy_binding` intersects the retained source ceilings, the
validated deployment limits, and one caller-supplied invocation ceiling using
the existing `ModelPolicyLedger` limit type. The selected model's declared
context limit narrows the result. `new_bound_with_policy` requires a
host-injected `SourceModelAttemptQuoter` that returns the existing
request-digest-bound `ModelAttemptQuote`; it rejects a mismatched digest,
negative cost or token overflow, then reserves a fresh attempt before adapter
factory construction. Reservations are nonrefundable and appear as redacted
reservation facts in attempt evidence.

The current deployment document has no ordered, confidentiality-cleared
fallback list. This route therefore binds exactly its selected primary provider
and an effective `max_providers == 0`: the primary remains available, while
every provider switch is refused. It does not invent a provider order from
model rows. The iterative source lifecycle also has no automatic retry
transition, so retries and failovers remain refused until a checked lifecycle
transition and deployment policy admit them.

`new_bound_checkpointed_with_policy` is the additive V6 durable form. Its
request-bound quote is checked without reserving; the journal constructs the
exact policy intent and the adapter reserves only that intent before its store
acknowledgement and provider start. The durable deadline is the earlier of the
source journal's absolute deadline and `initial_millis + max_latency_millis`;
checked overflow refuses. The runtime requires the adapter ledger to use that
exact resulting instant, and recovery reuses the acknowledged instant instead
of starting a fresh latency window.

## Security and nonclaims

- A model response remains untrusted Proposal text. Compiler decode precedes
  authorization, and authorization precedes every effect dispatch.
- Provider/model selection comes from the bound deployment; adapter labels are
  exact checked host commitments, not core-language provider names.
- Cancellation asks the adapter to stop but does not claim remote cancellation,
  no provider processing, or no billing.
- The opt-in bound-policy route admits one selected primary through the
  source/deployment/invocation token and cost ceilings. It has no checked
  lifecycle retry transition, ordered failover provider list, or durable
  reservation state; retries, provider switches, and recovery remain refused.
- `new_bound_checkpointed` admits the unpriced bound route to
  `run_live_bound_model_durable`. It derives the canonical request identity,
  receives the Source Live Journal v2 intent ACK before factory construction or
  adapter start, then records the exact bounded raw settlement bytes or a
  closed attempted-byte failure. Recovery never redispatches an unresolved
  intent. The journal binding also commits the typed registry and effective
  effect ceilings through its derived program-root profile.
- The `new_bound_with_policy` route remains nondurable: its in-memory,
  nonrefundable `ModelPolicyLedger` has no durable reservation carry, so the
  durable entry refuses it before adapter construction. Use the combined V6
  constructor for durable policy state. Retries and provider switches remain
  unavailable.
- The V6 checkpointed policy route folds acknowledged quote reservations before
  recovery can continue. Reported usage may exceed a quote: it is retained as
  observed exposure and can only exhaust later admission; it never refunds a
  token or cost reservation. Missing or malformed settlement usage is
  explicitly unknown.
- It creates no target ABI. Native C11 and Core Wasm Agent-stage execution
  retains a separate additive local parity protocol under
  `agent_lifecycle::iterative::model`. That protocol consumes the same checked
  lifecycle `ProposalRequest`, bounds the injected model host before Proposal
  decode, and independently replays canonical request/evidence pairs across
  interpreter, native C11 and Core Wasm stage execution. It deliberately does
  not claim that the Direct Runtime provider adapter itself runs inside a
  generated target or that a physical provider is available there.
- Local fixtures are local evidence. This document makes no hosted-provider,
  production-support, billing, credential, network, or public-ABI claim.

## Focused coverage

`tests/agent_runtime_v1/execution_revision/typed/live_streaming.rs` drives a
source-native retained Agent through `source_model_binding`, a scripted
streaming adapter, `run_live_bound_model`, compiler-derived Proposal decode,
authorization and typed effects. It asserts the selected adapter path records
one admitted redacted model observation for each live proposal while the
existing malformed, cancellation and settlement-refusal cases retain their
no-effect-dispatch guarantees.
