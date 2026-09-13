# Model Call Adapter Evidence v1

Status: local implementation for #178/#180; no hosted or remote-provider claim.
Audience: compiler contributors and provider adapter integrators.

`provider_adapter_sdk/observation` owns the canonical
`semaprax.provider-adapter-attempt-observation.v1` transcript (the exported
`ATTEMPT_OBSERVATION_SCHEMA` is authoritative). A one-start `RecordingAdapter` wraps
an explicitly injected adapter, borrowed or factory-owned. It records request
commitment/length, declared capability identity/profile/accounting source,
ordered Delta commitments and lengths (including empty chunks), Usage snapshots,
Completed, settlement or failure, start refusal, cancellation commitment/count,
and optional caller-clock observations. Raw payloads stay outside the rendered
evidence. Hashes are commitments, not encryption or low-entropy privacy.

Capture has a fixed event ceiling and bounded metadata. Overflow is explicit
and fails replay. Replay assembly never exceeds 65,536 bytes or the original
request response ceiling. Replay checks the exact retained request, event
sequence, cancellation, terminal facts and grammar digest; successful settlement
requires exactly one Completed and the concatenated deltas as the response.
A terminal-free capture can describe a cancelled or unresolved attempt. It is
not evidence of successful remote settlement. Clock values and capability
claims are host observations, not provider attestations.

`model_call_receipt/adapter_projection` owns the additive
`semaprax.model-call-adapter-evidence.v1` document. For a settled generic-kernel
attempt, it independently validates the journal and invocation seed, matches
the exact logical request, budget and observation commitment, reconstructs the
transport request through the live bridge's shared projection, replays the
adapter transcript, and decodes the retained settlement with the independently
supplied compiled schema. The decoded canonical response must equal the actual
journal response. A recorded admitted Proposal must have the same commitment.
Provider profile must occur in the seed's explicitly approved provider list.

The canonical JSON object (sorted keys, terminal LF, at most 4096 bytes) binds
schema, journal receipt digest, adapter observation digest, invocation id,
turn, attempt, program root, deployment policy, proposal grammar digest, logical
request digest, transport request/response lengths, and decoded response digest.
`replay_settled_adapter_call` regenerates and compares the exact submitted bytes;
there is no provider, factory, authorization gate, or tool callback parameter.
The seed is capped at 262,144 bytes/1024 providers, logical task plus observation
at 65,536 bytes, and provider schema at 262,144 bytes before request expansion.

This projection covers observed, successfully decoded generic settlements.
Existing journal projections retain failures and unresolved attempts. It does
not fabricate Agent/DeploymentRoot/InstanceRoot associations, timing, invoice
identity, cost estimates, or missing token counts to fill the older rich receipt.
Source bridge conformance captures and replays the same adapter observations
and independently reproduces the typed source Proposal; source-checkpoint joins
remain separate work. Neither evidence object grants execution authority.

The focused SDK tests exercise real generic/source bridge paths, cancellation
before another poll, reordered chunks, altered settlement/request/schema/seed,
and exact-byte mutation rejection. Tests use local in-memory provider fixtures.
