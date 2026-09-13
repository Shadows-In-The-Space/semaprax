# Compact Semantic Projection v1

[Model-text v2](COMPACT-SEMANTIC-PROJECTION-V2.md) adds a separately versioned
selective-dictionary encoding; this document retains the frozen v1 contract.

Status: versioned bounded reference; the completion matrix owns product status.

Audience: agent and tool authors who paste or transport a selected semantic
view repeatedly (model prompts, caches, wire transport), plus compiler
contributors working on issue #201 ("Add a compact lossless semantic
projection optimized for model context and transport").

Compact Semantic Projection v1 (`../src/compact_semantic_projection.rs`)
re-encodes an already-selected semantic view -- the whole resolved program
graph (`crate::graph::to_json`) or a byte/node-bounded call closure
(`crate::graph::agent_context_v2_json`) -- into a smaller wire form, and
decodes it back to the exact same bytes. It never selects, filters, or
budgets anything itself; it calls those two existing engines unchanged and
only re-encodes their output.

## What already existed before this module

- `crate::graph::to_json`: the whole resolved program graph, deterministic
  and revision-bound.
- `crate::graph::agent_context_v2_json`: a byte/node-bounded, depth- and
  direction-limited call closure around one seed declaration, with
  per-omission reasons and a resumable frontier (issue's "Agent Context v2").
- `crate::semantic_task_context` (issue #197): a goal-aware, token-budgeted
  bundle composed from many calls to the engine above.

All three already own their selection, closure, and budget rules. This
module duplicates none of that logic; every byte it encodes is bytes those
functions already produced.

## What this module adds

1. **A stable-ID/string dictionary ordered by canonical (raw) byte order.**
   [`encode_bytes`] scans the selected view's JSON text for its string
   literals -- exactly where every repeated stable ID, type name, and
   field-shaped string lives -- and deduplicates them into a
   `BTreeSet`-ordered dictionary. The order is a property of the *set* of
   distinct literals, never of first-appearance order or of what other
   literals happen to share the envelope: the same literal string can sit at
   a different numeric index in two different envelopes and still decode
   correctly in both
   (`tests::dictionary_index_for_the_same_literal_differs_across_envelopes_and_decode_is_unaffected`).
   The index is local compression bookkeeping only, never a persistent
   identity -- `CompactProjection`'s dictionary and body fields are private,
   and its only public operation is "reconstruct the whole selected view,"
   never "resolve this index."
2. **Two independent wire forms over one in-memory structure.**
   `CompactProjection::to_text`/[`decode_text`] is a compact ASCII form
   meant to be pasted into a model prompt: a small length-framed header,
   one dictionary entry per line (a JSON string literal can never contain a
   raw newline byte, so no per-entry length prefix is needed), and a body
   stream that emits raw JSON punctuation verbatim and substitutes each
   dictionary reference inline as `~<index>~` -- no per-token framing at
   all. `CompactProjection::to_binary`/[`decode_binary`] is a fixed-width
   length-framed binary form for transport/cache. Both decoders share one
   validation-and-reconstruction path (`finish_decode`), so a bound or an
   integrity rule can never drift between the two forms.
3. **A source digest re-verified after every decode.** Every
   `CompactProjection` a decoder returns has already had its body
   reconstructed once and its digest recomputed and compared to the
   envelope's own declared digest. A wire value that still parses cleanly
   but was tampered with (one content byte flipped, with every length and
   count left intact) is refused at this step
   (`tests::tampered_wire_content_fails_digest_verification`,
   `tests::tampered_text_body_content_fails_digest_verification`), not
   silently accepted with different content than it started from.
4. **A migration/version refusal.** An unrecognized `format_version` is
   refused outright (`SPX-Z904`); this module never attempts a heuristic
   decode of an unknown wire version.
5. **Every declared bound actually enforced, at its exact edge.** Six
   `MAX_*` constants (`MAX_SOURCE_BYTES`, `MAX_ENCODED_BYTES`,
   `MAX_DICTIONARY_ENTRIES`, `MAX_ENTRY_BYTES`, `MAX_BODY_TOKENS`,
   `MAX_HEADER_FIELD_BYTES`) are each driven to one-under/at/one-over in a
   dedicated test (see "Evidence" below) -- the repository's own
   experience is that a `MAX_*` constant gets declared in one file and
   enforced in none, so each bound here is proved to actually gate
   behaviour, not merely documented.

## Profiles implemented here

`ProjectionSource::FullGraph` wraps `crate::graph::to_json` (root `"*"`,
envelope `profile` field `"full-graph"`); `ProjectionSource::AgentContextV2`
wraps `crate::graph::agent_context_v2_json` for one seed symbol (`profile`
`"agent-context-v2"`, root the seed symbol). The wire format itself does not
restrict `profile` to this list -- a future profile is one more
`ProjectionSource` variant in [`encode_profile`], with no wire-format
change. [`ProjectionSelection`](../src/compact_semantic_projection/selected.rs)
adds authoritative profiles whose replay regenerates their owning kernel before
accepting decoded content: goal-aware `semantic_task_context::compile`, the
explicitly scoped Project v8 owned-data public API descriptor, a candidate's
`semantic_delta_catalog(expected_candidate)`, and one compiled Agent
definition's canonical graph. These profiles bind respectively to the graph
revision, retained Project revision, candidate revision plus expected candidate
digest, and AgentGraph digest; they do not accept a self-rehashed envelope as
replay evidence.

## Negotiation and transport

`compact_semantic_projection::negotiation` selects only existing v1 text or
binary encodings and the six implemented profile names. Both parties provide
at most 16 explicit offers; an unknown version or profile refuses
the exchange rather than falling back. The encoding is a closed Rust enum. Selection is deterministic across
offer ordering: it chooses the lexicographically earliest common profile,
then binary before text. Negotiation changes no codec or wire format.

The CLI and retained semantic service expose these projections through the
existing compiler producers. `compact graph <project>` also wraps the full
retained Project graph with profile `full-graph`, root `*`, and Project revision;
its reconstructed graph schema distinguishes it from a single-source graph.
`semaprax compact ... --replay <wire>` reconstructs only after comparison with
freshly selected content. MCP `workspace__compact_projection` uses the same
`workspace/compact-projection` dispatcher and requires the exact active
workspace revision. Caller source labels select retained Project sources;
they cannot open host paths. See [Unified CLI v1](UNIFIED-CLI-V1.md) and
[Semantic Service Transport v1](PERSISTENT-SEMANTIC-SERVICE-TRANSPORT-V1.md).

The library exposes explicit format/encoding/profile negotiation, and the
host-side `scripts/benchmark_compact_projection.py` measures actual tokenizer
counts using cached, versioned encodings. Measurement evidence and its
limitations are recorded below; byte compaction alone is not a token claim.

## Honesty bar: what "lossless" means here, exactly

[`decode_text`] and [`decode_binary`], given bytes produced by
`CompactProjection::to_text`/`to_binary` from an [`encode_profile`] result,
reconstruct the selected view's JSON text byte-for-byte identical to what
`crate::graph::to_json`/`agent_context_v2_json` returned **directly** --
proved in this module's tests by comparing against a *second,
independently obtained* call to those functions, never against a
round-tripped copy of the encoding itself
(`tests::round_trip_agent_context_v2_binary_matches_the_original_engine_output_exactly`,
`tests::round_trip_full_graph_text_matches_the_original_engine_output_exactly`).
Every byte of the selected view is either a dictionary entry or a raw body
token; reconstruction is their concatenation in original order. Nothing is
dropped, summarized, or approximated.

This module claims a materially smaller wire size **only where measured**
below, not as a universal property, and it does not claim:

- a universal token reduction or provider billing equivalence; the host-side
  measurements below name exact encoding versions and vocabulary fingerprints;
- that every profile or content shape compacts (a selected view with few
  repeated strings could compact only slightly, or -- for the binary
  form specifically -- not at all, see the measurements below);
- version *negotiation* between differing format versions (this module
  only *refuses* an unrecognized version).

## Measured compaction, on this repository's own committed examples

`graph` output is documented elsewhere in this repository as roughly forty
times the source bytes; that is the pre-existing baseline this module
starts from, not a number this module changes. The comparison this module
is actually responsible for is the *selected JSON view* against its own
*compact re-encoding* of the same view, measured directly by
`tests::compact_wire_forms_are_materially_smaller_on_a_committed_example`
and reproduced here for two committed `examples/*.spx` files, encoded under
`ProjectionSource::FullGraph`:

| Example | Source `.spx` bytes | `graph::to_json` bytes | Compact binary | Compact text | Dictionary entries | Body tokens |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `examples/http_app_routing.spx` | 19,396 | 610,864 | 566,677 (92.8%, 1.08x) | 399,030 (65.3%, 1.53x) | 1,574 | 76,679 |
| `examples/banking_ledger.spx` | 3,823 | 139,770 | 139,129 (99.5%, 1.00x) | 88,586 (63.4%, 1.58x) | 584 | 18,953 |

Percentages are the compact size as a fraction of the graph JSON size it
re-encodes; the trailing multiplier is the same ratio inverted (graph JSON
size divided by compact size). Two honest observations follow directly from
these numbers:

- **The binary form's advantage is small and shrinks with less
  repetition.** Its fixed 4-byte length prefix per dictionary entry and per
  raw body span is real overhead; it wins only when enough content repeats
  to amortize that prefix. On `banking_ledger.spx` -- a small file with
  proportionally less repeated identifier text -- the binary form is
  barely smaller than the JSON it replaces (99.5%). A first, naive design
  of the text form's body used the same explicit per-token length framing
  and was *measured, in this same test, to be larger than the original on
  `http_app_routing.spx`* before the marker-substitution design below
  replaced it; that failed measurement is why the text form's body carries
  no per-token framing at all.
- **The text form wins consistently because it drops per-token framing
  entirely.** Raw JSON punctuation between string literals is emitted
  verbatim (no length prefix), and a dictionary reference costs only
  `~<digits>~` -- a handful of bytes regardless of how long the literal it
  stands for is. On real graph JSON, most literals are referenced many
  times (a stable ID appears once as a declaration and again at every call
  site, for example), so this consistently nets a smaller document even on
  a file with modest repetition.

## Evidence

Local, offline unit tests (`cargo test --locked -p semaprax --lib
compact_semantic_projection`, 26 tests) cover:

- **Round-trip against an independently obtained original**, for both
  profiles and both wire forms, with an explicit assertion that the wire
  form is *not* byte-identical to the original (ruling out a disguised
  passthrough) -- see "Honesty bar" above for the two test names.
- **A negative control**: a wire value with one content byte flipped (same
  length, same counts) is refused with the specific digest-mismatch
  diagnostic (`SPX-Z907`), for both the binary and text forms
  (`tampered_wire_content_fails_digest_verification`,
  `tampered_text_body_content_fails_digest_verification`).
- **Determinism**: encoding the same program twice produces byte-identical
  binary and text output (`round_trip_is_deterministic_across_repeated_encodes`).
- **Dictionary indices are not identity**: the same literal string occupies
  different indices in two different envelopes, and both decode correctly
  (`dictionary_index_for_the_same_literal_differs_across_envelopes_and_decode_is_unaffected`).
- **Every `MAX_*` bound driven to one-under/at/one-over**, each isolated so
  only the bound under test fires
  (`max_dictionary_entries_bound_is_enforced_at_its_exact_limit`,
  `max_body_tokens_bound_is_enforced_at_its_exact_limit`,
  `max_entry_bytes_bound_is_enforced_at_its_exact_limit`,
  `max_header_field_bytes_bound_is_enforced_at_its_exact_limit`,
  `max_source_bytes_bound_is_enforced_at_its_exact_limit`,
  `max_encoded_bytes_bound_is_enforced_at_its_exact_limit_ahead_of_structural_parsing`).
- **Hostile length/count/index/duplicate/order/version/root/field-injection
  cases**, each asserting the *specific* diagnostic code, never a generic
  failure: a truncated wire (`SPX-Z903`), trailing bytes after a complete
  wire (`SPX-Z903`), a declared dictionary count far beyond the bound
  backed by almost no bytes -- refused before any per-entry allocation is
  attempted (`SPX-Z901`), an out-of-range body reference (`SPX-Z906`),
  duplicated or out-of-order dictionary entries (`SPX-Z905`), an
  unrecognized format version in both wire forms (`SPX-Z904`), an
  unrecognized body-token tag (`SPX-Z903`), a field-injected `root` that
  parses as a structurally valid but differently-bound envelope --
  accepted by plain `decode_binary`, refused by `decode_binary_and_verify`
  (`SPX-Z908`) -- and an unresolved seed symbol refused at encode time
  (`SPX-Z909`).

No test in this module opens a file outside this repository's own
committed `examples/*.spx` fixtures, spawns a process, or contacts a
network.

## No ambient authority

[`encode_profile`] takes an already-parsed `&Program` and calls only
`crate::graph::to_json`/`agent_context_v2_json`. [`decode_text`] and
[`decode_binary`] take only byte/string slices. Nothing in this module
opens a file, spawns a process, or contacts a network.

## Offline model-token measurements (2026-09-13)

The reproducible helper runs the actual CLI encoder and replay for both wire
forms, compares reconstructed bytes with the ordinary graph command (allowing
its one display newline), then measures UTF-8 text with cached `tiktoken 0.12.0`
encodings. Socket connections are disabled while tokenizer assets load. The
[complete local report](../benchmarks/compact-semantic-projection-v1/local-token-measurements.json)
records exact content hashes and tokenizer vocabulary/pattern fingerprints.
Binary bytes are measured as transport bytes, never decoded as model text.

| Input | Full bytes | Text bytes | Binary bytes | cl100k full → text tokens | o200k full → text tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| `examples/banking_ledger.spx` | 139,770 | 88,586 | 139,129 | 37,846 → 46,781 | 38,779 → 47,124 |
| `examples/http_app_routing.spx` | 610,864 | 399,030 | 566,677 | 161,861 → 220,491 | 165,329 → 221,565 |
| `examples/calculator-project/semaprax.toml` | 9,893 | 7,474 | 11,513 | 2,500 → 3,606 | 2,521 → 3,626 |
| `examples/frame-payload-project/semaprax.toml` | 6,615 | 5,471 | 8,203 | 1,766 → 2,679 | 1,784 → 2,694 |

Text saves bytes on all four examples but **increases model tokens by 21–52%**.
Binary is larger than ordinary JSON on both measured Projects. These results
are a negative control against assuming byte savings imply token savings.
Issue #201 remains open for a measured token-efficient representation; the
current text form is a byte-compaction option, not a recommended model-token
optimization. Neither measurement implies provider billing or model quality.

Reproduce with an already installed `tiktoken` and cached encoding assets:

```sh
python3 scripts/benchmark_compact_projection.py --semaprax target/debug/semaprax --root . --output compact-measurements.json
```

The `task-context` CLI selection additionally accepts prioritized repeated seeds,
explicit byte/lexical accounting and an expected source revision; the exact
selection grammar and bounds are owned by
[Semantic Task Context v1](SEMANTIC-TASK-CONTEXT-V1.md#multi-seed-cli-selection).
This changes selection inputs, not the compact wire encodings or authority.
