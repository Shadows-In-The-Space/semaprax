# Source Model Operation v1

Status: **IMPLEMENTED BOUNDED DIRECT-RUNTIME ROUTE; LOCAL EXECUTABLE EVIDENCE**.

Audience: Direct Runtime v2, source-Agent, and provider-adapter maintainers.

This contract binds the existing source Agent `propose` role to one explicit,
provider-neutral streaming adapter in Direct Runtime v2. It is additive to the
ordinary caller-owned `ProposalSource` route. It creates no source syntax: the
existing checked Agent declaration already requires the `propose` role to have
kind `model`.

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
explicit `AdapterInvocationCapability`. The binding capability commits an
adapter to this checked runtime; it is not network authority. The adapter
capability remains the separately injected, non-ambient host authority to call
one adapter.

Before construction can reach an adapter factory, the bound source checks the
compiler Proposal schema digest, source revision and binding capability. After
factory construction but before `ProviderAdapter::start`, it requires exact
adapter identity/version/profile equality and performs the existing streaming
capability negotiation. It never derives a provider, model, endpoint,
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

## Security and nonclaims

- A model response remains untrusted Proposal text. Compiler decode precedes
  authorization, and authorization precedes every effect dispatch.
- Provider/model selection comes from the bound deployment; adapter labels are
  exact checked host commitments, not core-language provider names.
- Cancellation asks the adapter to stop but does not claim remote cancellation,
  no provider processing, or no billing.
- This v1 route has no retry/failover/token-policy composition. The existing
  #179 policy types remain separate until their source/deployment/invocation
  policy wire is explicitly bound.
- This v1 route is nondurable. `Source Live Journal v2` and checkpointed host
  sources keep their own contract; this change does not claim a Direct Runtime
  v2 durable model path.
- It creates no target ABI. Native C11 and Core Wasm Agent-stage execution
  must consume this same checked request/evidence contract in their own parity
  profile.
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
