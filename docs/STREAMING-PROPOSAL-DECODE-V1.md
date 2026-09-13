# Streaming Proposal Decode v1

Status: **LOCAL** bounded implementation with an executable reference and
focused regression corpus, implemented in `src/streaming_proposal_decode.rs`.
This is issue #178 ("Derive streaming structured-output decoding from the
checked Proposal type"). No hosted evidence exists for this document; the
focused unit claims are local tests against fixture schemas in
`src/streaming_proposal_decode/tests.rs`.

Audience: implementers wiring a provider transport's chunked response bytes
into a decoded Proposal, and reviewers of the streaming grammar and safety
layer around the existing whole-document decoder. Generated-client streaming
consistency was exercised locally through the existing TypeScript, Python,
and Rust execution harness, including one-byte delivery of exact integers,
UTF-8, escapes and mutated object keys.

## Why a new module instead of extending `agent_interaction_schema`

`src/agent_interaction_schema/` derives `CompiledInteractionSchema` from one
checked source record or variant and decodes one complete `&[u8]` response
through `CompiledInteractionSchema::decode`. Its own module documentation is
explicit that this is deliberate: "Whole-value, not streaming... A streaming
transport can buffer provider output into one complete response before
calling this same boundary — this module needs nothing from a streaming
extension to exist." That module (and `src/live_invocation/`, which defines
the `ProposalDecoder` seam a real deployment binds a whole-document decoder
to) is leased to other issues' ownership for this round and is read-only
here regardless.

This document does not change either module's admitted source language or
canonical wire format. The streaming module uses the schema's compiled
stream grammar: it incrementally checks the closed envelope and the admitted
inside-`value` field and case order, scalar forms and scalar bounds, while a
bounded structural scanner checks bytes, UTF-8, depth, strings, and framing.
The grammar exposes read-only `ExpectedNext` categories and `grammar_work()`;
`STREAM-GRAMMAR` is the closed refusal for a grammar mismatch or work limit.
It retains the explicit incomplete/accepted/refused state a chunked transport
needs. Existing SDK bridges use it before model invocation or Direct Runtime
can authorize a proposal.

## Compiled grammar and final admission

Both incremental grammars lower from the same opaque compiled schema objects
that own the whole decoder and provider/client projections. The interaction
schema retains a DAG of record/variant types; the source schema currently
admits scalar record/variant fields. Lowering preserves stable identities,
declaration order, exact integer representations and schema-owned text/byte
bounds. No nested types are expanded recursively at construction.

The incremental machine rejects mismatches early and final acceptance still
requires the owning whole-document decoder on the exact buffered bytes. Thus
an incremental parser defect cannot authorize a value the whole decoder would
reject. Valid-stream conformance is exercised by the deterministic corpus,
adversarial chunking and generated-client executions; final delegation alone
would not prove absence of false early refusals.

The incremental scanner and grammar are intended to
refuse malformed documents before completion. Transport and work bounds are
explicit; the final decoder independently checks semantic legality:


| Streaming rule | Whole-document rule it is a subset of |
|---|---|
| Buffered bytes ≤ `MAX_STREAM_BYTES` (65536) | `source.len() > MAX_DOCUMENT_BYTES` (65536) is already refused |
| First byte must be `{` | A non-object top level already fails `value.as_object()` |
| Exact compiled envelope and incremental inside-`value` field/case order, scalar forms, and scalar bounds | The compiled stream grammar is derived from the checked schema; unknown, duplicate, reordered, or mismatched identities cannot replay canonically |
| No raw whitespace/control byte outside a string, other than the single terminal `\n` | Canonical rendering never emits whitespace; any inserted whitespace already fails the exact byte-for-byte canonical-replay check |
| Exactly one trailing `\n`, nothing after | `text.strip_suffix('\n')` plus "no other `\n`/`\r`" is already required |
| UTF-8 validity | Uses `std::str::from_utf8` — the identical stdlib check the whole decoder itself runs |
| String/escape/`\u`-hex well-formedness | Already required for the JSON parse to succeed |
| Container nesting ≤ `MAX_STREAM_DEPTH` (64) and grammar stack ≤ `MAX_STREAM_DEPTH * 4` | Both structural and schema-driven work are bounded before completion |
| String-literal token count ≤ `MAX_STREAM_STRING_TOKENS` (8192) | Token work is bounded independently of byte and grammar work |
| Grammar work ≤ `MAX_GRAMMAR_WORK` (`MAX_STREAM_BYTES * 64`) | Each incremental grammar transition is charged against a fixed work cap |

This table is the "prove they agree, don't assert it" evidence: every early
refusal is provably conservative, and the accept path is the same function
call. `src/streaming_proposal_decode/tests.rs`'s
`streaming_outcome_agrees_with_the_whole_document_decoder_for_every_case`
exercises this directly — for a corpus of one valid document and eight
distinct hostile mutations (unknown field, missing field, duplicate field,
wrong scalar type, out-of-range integer, oversized text field, trailing
data, unknown variant tag), it decodes each with
`CompiledInteractionSchema::decode` directly and separately drives the same
bytes through `ProposalStreamDecoder` three ways (one chunk, one byte at a
time, split at the midpoint), asserting the streaming outcome always agrees
— `Accepted` only with the identical decoded value, `Refused` whenever and
only whenever the whole decoder itself refuses.

## The three-way outcome: incomplete, accepted, refused

`PushOutcome` has three variants, and a prefix can never be mistaken for a
complete value:

- **`Incomplete`** — valid so far, more bytes are required. Carries no code
  or message at all, so it cannot be confused with any refusal by
  inspecting its text (there is no text to inspect).
- **`Accepted(DecodedInteractionValue)`** — the buffered document decoded
  successfully. Only [`ProposalStreamDecoder::finish`] produces this, never
  `push` alone: reaching the document's terminal newline only stops `push`
  from refusing more input under this document, it does not yet authorize
  anything, because a later chunk could still turn out to carry trailing
  data after that newline. Only the caller's explicit "no more bytes are
  coming" signal (`finish`) can turn a syntactically-complete-so-far prefix
  into a genuine acceptance.
- **`Refused(StreamRefusal)`** — a closed, stable `code` plus caller-facing
  `message` and a best-effort `at_byte` offset. `push` can refuse a document
  before it ever completes (a structural violation, or a bound driven past
  its limit); `finish` can additionally refuse a document that reached the
  terminal newline but that the compiled decoder itself rejects
  (`STREAM-SEMANTIC`), or one that never reached the terminal newline at
  all (`STREAM-TRUNCATED`).

`src/streaming_proposal_decode/tests.rs`'s
`every_strict_prefix_is_incomplete_only_the_complete_document_is_accepted`
feeds every strict prefix of a valid document and asserts each is
`Incomplete`, with only the complete byte sequence (after `finish`) reaching
`Accepted`.

## The closed refusal vocabulary

| Code | Meaning |
|---|---|
| `STREAM-START` | The document did not open with `{`. |
| `STREAM-WHITESPACE` | A raw whitespace or control byte appeared outside a string, other than the single terminal newline. |
| `STREAM-STRING` | An unescaped control byte, unknown escape character, or invalid `\u` hex digit inside a string literal. |
| `STREAM-BRACKET` | A closing `}`/`]` had no matching open, or did not match the innermost open container's kind. |
| `STREAM-UTF8` | The buffered bytes are not valid UTF-8 (via `std::str::from_utf8`, the same check the whole decoder uses). |
| `STREAM-DEPTH` | Container nesting exceeded `MAX_STREAM_DEPTH`. |
| `STREAM-TOKENS` | String-literal token count exceeded `MAX_STREAM_STRING_TOKENS`. |
| `STREAM-BYTES` | Buffered byte count exceeded `MAX_STREAM_BYTES`. |
| `STREAM-GRAMMAR` | The compiled stream grammar rejected an envelope, field/case order, scalar form/bound, or exceeded its grammar work/stack bound. |
| `STREAM-TRAILING` | A byte arrived after the document's terminal newline, or the top-level value closed without one immediately following. |
| `STREAM-TRUNCATED` | `finish` was called before the document reached its terminal newline. |
| `STREAM-CANCELLED` | The caller explicitly cancelled the stream via `cancel`. |
| `STREAM-SEMANTIC` | The complete, syntactically well-formed document was rejected by `CompiledInteractionSchema::decode` itself; the message carries that diagnostic's own stable code and text (mirroring `live_bridge::SourceInteractionProposalDecoder`'s own refusal-reason convention), so a caller sees exactly which admission rule failed. |

Every code is distinct from every other, and none overlaps the vocabulary
`Incomplete` would need if it carried one (it does not carry a message at
all) — `incomplete_and_refused_are_never_textually_confusable` asserts both
the pairwise distinctness and the absence of "incomplete" text in any code.

## Bounded buffering and work

No unbounded buffering: each bound below is checked as bytes arrive, not
only once a document completes, and the scanner's byte, depth, and token
limits have focused unit checks at their declared boundaries. Grammar
transitions and binary case-table comparisons charge `MAX_GRAMMAR_WORK` and
cap the parser stack at
`MAX_STREAM_DEPTH * 4`; these are separate from the structural scanner's
bounds. `byte_bound_is_enforced_at_its_exact_limit`,
`depth_bound_is_enforced_at_its_exact_limit`, and
`string_token_bound_is_enforced_at_its_exact_limit` each construct a stream
that reaches the bound exactly and then supplies one more unit (refused with
the bound's own code). The byte test uses an actual checked large record;
the depth/token tests address the structural scanner directly, since typed
shape validation can reject their deliberately untyped payloads earlier. The byte bound is the
primary "no unbounded buffering" guarantee — the buffer literally never
grows past `MAX_STREAM_BYTES`, the bound is checked before appending a
chunk, not after — and it structurally caps the streaming scanner's total
work, since every scanner step is a single O(1) transition over at most
`MAX_STREAM_BYTES` bytes.

## Determinism across chunk boundaries

`SourceProposalStreamDecoder` applies this same bounded framing to the
source-live route's distinct `CompiledAgentProposalSchema` grammar. Its
incremental grammar is limited to the source schema's existing flat envelope
and scalar forms; it adds no new source-language admission. It does not
translate that grammar into the interaction-value wire: after a terminal LF
it calls the source schema's own `decode` and returns `DecodedProposal`.

The single most valuable property this document proves: the same total
byte sequence produces the identical final outcome no matter how it is
split into chunks. `ProposalStreamDecoder` has no chunk-boundary-dependent
logic anywhere — every scanner and grammar transition (UTF-8 confirmation,
container depth, string/escape state, byte/token counters, expected
field/case/scalar state) is carried across `push` calls, never re-derived from
where a chunk happened to end.
`identical_bytes_produce_identical_outcomes_regardless_of_chunk_boundaries`
drives one valid document, one document with a multi-byte-UTF-8 text value
(covering split UTF-8 continuation bytes), one document with an unknown
field (a semantic refusal), and one document with a corrupted UTF-8 byte
(a structural refusal) through every single-split-point chunking plus fully
one-byte-at-a-time chunking, asserting every chunking of a given byte
sequence produces the same outcome as feeding it in one piece.

## Cancellation and premature end of stream

`cancel(reason)` closes the stream early with `STREAM-CANCELLED`, but cannot
retroactively un-authorize an already-`Accepted` value — a stream that
already finished successfully returns that same `Accepted` value unchanged
if `cancel` is called afterward, matching this codebase's sticky
failure-selection discipline elsewhere
(`cancel_after_acceptance_cannot_retroactively_unauthorize_the_decoded_value`).
`finish` called before the document reaches its terminal newline refuses as
`STREAM-TRUNCATED` rather than leaving the caller waiting forever
(`finish_refuses_a_stream_that_never_reached_its_terminal_newline`). Once
any terminal outcome is reached (`Accepted` or any `Refused`), the decoder
is closed: further `push`/`cancel`/`finish` calls return that same stored
outcome (`a_refusal_is_sticky_across_further_pushes`).

## What this document does not claim

The checked-schema bridge now exists: `CompiledProposalDecoder` supplies the
ordinary `ProposalDecoder` seam, while
`provider_adapter_sdk::StreamingModelHandler` feeds adapter `Delta` events
through this decoder before the generic kernel can authorize a proposal.
The bridge waits for `Completed` and the matching adapter settlement before
calling `finish`; an early streaming refusal requests adapter cancellation and
does not poll again. The source-native counterpart,
`StreamingSourceProposalAdapter`, feeds `SourceProposalStreamDecoder` through
the ordinary `ProposalSource` seam. `bind_agent_runtime_v2_live` binds an empty
frozen proposal inventory and `AgentRuntimeV2::run_live` refuses any runtime
that was bound with submitted proposal bytes. It reuses the checked typed
effect dispatcher, so malformed streamed bytes fail before authorization or
effect dispatch. Adapter integration uses offline injected fixtures. Generated
client bytes are additionally checked against whole and streaming decoders.

- **The scanner is not the typed grammar.** The structural scanner validates
  container nesting, string-literal well-formedness, disallowed raw bytes,
  UTF-8, byte/token bounds, and framing. The compiled `GrammarState` validates
  the closed envelope plus inside-`value` field and case order, scalar lexical
  forms, and scalar bounds incrementally, returning `ExpectedNext` categories
  for read-only inspection. Neither layer is final authority: only the
  complete buffered bytes passed to `CompiledInteractionSchema::decode` can
  produce the accepted typed value and final semantic decision.
- **No provider prompt/schema projection change.** `provider_json_schema`
  is unchanged, untouched, and out of this module's scope.
- **No hosted evidence.** The focused unit corpus and scanner bounds are local
  evidence. Generated-client consistency also passed locally with provisioned
  TypeScript 5.8.3, Node 24.3, Python 3.14 and offline Rust dependencies.

## Executable reference

`src/streaming_proposal_decode.rs` (`ProposalStreamDecoder`, `PushOutcome`,
`StreamRefusal`, the `STREAM-*` closed vocabulary, and the `MAX_STREAM_*`
bounds), its generic tests, and the additive `source` decoder and source tests
form the reference implementation. The source decoder delegates final
admission to `CompiledAgentProposalSchema` and preserves the existing source
Proposal wire format. Focused gate:

```sh
cargo test --locked -p semaprax --lib streaming_proposal_decode
```

## Ordered transport evidence

[Model Call Adapter Evidence v1](MODEL-CALL-ADAPTER-EVIDENCE-V1.md) records
ordered chunk/result commitments and grammar identity from an actual adapter
behind either runtime bridge. Independent replay uses retained transport bytes;
the generic journal join additionally reconstructs the exact dispatched request
and reproduces the compiled Proposal without a provider callback. These are
local fixture-backed checks, not claims about a remote provider's internals.
