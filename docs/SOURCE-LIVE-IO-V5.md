# Source Live I/O v5

Status: additive I/O profile for durable source journal; local evidence, no provider billing claim.
Audience: source-live integrators and private CLI operators.

Source Live I/O v5 adds cumulative provider request and response reservations
to the durable source journal for an existing v2, v3, or priced v4 execution
binding. It does not change the canonical binding,
entry, decoder, chain, or receipt bytes of a binding that has no I/O limits.
The source journal remains the accounting authority; a CLI receipt is an
authority-free view of a recovered terminal checkpoint.

## Bound policy and counters

`SourceIoLimits` has exactly these checked fields:

| Field | Meaning |
| --- | --- |
| `max_request_bytes` | Maximum exact canonical provider prompt bytes for one attempt, from `0` through `65536`. |
| `max_total_request_bytes` | Cumulative request reservation ceiling as a `u64`. |
| `max_total_response_bytes` | Cumulative response reservation ceiling as a `u64`. |

The journal calculates `SourceIoTotals` with exactly these fields:

| Field | Meaning |
| --- | --- |
| `reserved_request_bytes` | Sum of every acknowledged intent's exact canonical prompt bytes. |
| `reserved_response_bytes` | Sum of every acknowledged intent's bound per-attempt response limit. |
| `observed_response_bytes` | Exact raw bytes in acknowledged settled responses. |
| `unknown_response_reservation_bytes` | Response reservation still attributable to an unobserved provider result. |

Before dispatch, the source prepares the canonical prompt and records its exact
length in the attempt identity. When admitting the attempt intent, v5 reserves
that length and the full `response_limit` against cumulative limits. Checked
arithmetic rejects attempts that cannot fit either ceiling, without
acknowledging the intent or calling the provider. Earlier initialization stages
and the selected terminal failure may still have acknowledged checkpoints.

Reservations are never refunded. Malformed responses, provider failures,
cancellation or deadline after acknowledgement, recovery, and migration do not
reduce either reserved total. A settled response adds
its actual raw byte count to `observed_response_bytes`; it does not credit
unused response reservation. A failed or uncertain provider result leaves its
response reservation unknown. In particular, a local transport's
`attempted_bytes == 0` is not proof that the provider used zero response
bytes.

V5 composes with V4 pricing when the caller supplies `SourceLivePricing`.
The same acknowledged attempt then carries the ordinary work reservation, the
V4 integer money reservation, the exact request reservation, and the maximum
response reservation. It may also be used on an unpriced execution binding;
I/O policy is independent from currency accounting.

## Binding, replay, and compatibility

The host selects V5 through
`SourceLivePolicy::binding_with_io_limits` or
`CompiledIterativeLifecycle::run_live_durable_with_io_limits`. The profile
derives a V5 invocation and chain domain only when `SourceIoLimits` is present.
For a priced binding, the internal priced identity is rebound to that final
V5 invocation, so its attempt digests cannot collide with the corresponding
non-I/O V4 invocation.

Recovery supplies the independently derived binding again. It rejects a
different I/O limit, profile, invocation, chain, attempt identity, prompt
length, response bound, counter overflow, or causal order. Existing V1--V4
documents are not decoded as V5 and V5 documents are not accepted by their
older profile bindings.

The implementation uses the existing `AttemptIntent`, `AttemptSettled`, and
`AttemptFailed` rows. Those rows already bind canonical request bytes and the
per-attempt response limit. V5 folds those authenticated rows after ordinary
execution validation; it does not introduce optional fields into legacy rows
or a parallel provider journal.

## Migration

V5 migration uses the existing checked source migration evaluator and an
authenticated recovered predecessor. It carries the predecessor I/O totals
and binds them into the destination V5 identity. The destination limits may
narrow, but each destination cumulative ceiling must still admit the carried
reservations. Historical reservations that exhaust a narrowed ceiling remain
visible and permit no later admission; they are not erased or treated as a
credit.

Profile conversion is refused. A V4 predecessor cannot be migrated to V5, and
a V5 predecessor cannot be migrated to V1--V4, because either conversion
would invent or discard cumulative I/O history. The private CLI supports its
same one-predecessor-to-one-destination handoff only when both configurations
select the same I/O profile. Its checked embedding APIs retain their separate
topology and ownership rules.

## Private CLI v3

CLI configuration v3 has schema
`semaprax.source-live-cli.config.v3`. It retains every exact v2 key and
requires both the v2 `pricing` object and this exact `io_limits` object:

```json
{"max_request_bytes":65536,"max_total_request_bytes":131072,"max_total_response_bytes":8192}
```

Unknown, missing, negative, non-integer, noncanonical, or over-limit keys are
refused before a checkpoint or provider call. `max_request_bytes` may be zero;
the total limits are nonnegative `u64` values. V1 and V2 do not accept the
`io_limits` key and retain their existing unpriced or priced behavior.

A terminal v3 run returns `semaprax.source-live-cli.receipt.v3`. It has the
v2 top-level and `money` fields plus an `io` object containing exactly
`reserved_request_bytes`, `reserved_response_bytes`,
`observed_response_bytes`, and `unknown_response_reservation_bytes`. Failure
diagnostics retain these acknowledged I/O counters when a checkpoint exists.
The output is neither provider reconciliation nor a billing or publication
authority.

See [Source Live Journal v2](SOURCE-LIVE-JOURNAL-V2.md) for the common causal
journal and [Source live CLI v1](SOURCE-LIVE-CLI-V1.md) for host/store and
command semantics.
