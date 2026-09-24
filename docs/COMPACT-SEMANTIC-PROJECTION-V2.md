# Compact semantic projection: model-text v2

Status: additive local implementation. [Version 1](COMPACT-SEMANTIC-PROJECTION-V1.md)
text and binary bytes remain unchanged. Model-text uses format version 2 and
an explicit `model-text` encoding selection; it does not replace full JSON.
Audience: agent and tool authors using model-text encoding and compiler contributors.

## Wire and deterministic selection

The UTF-8 envelope begins `SEMAPRAX-MODEL-TEXT 2\n`, followed by the same four
length-framed metadata fields as v1, in order: `profile`, `root`,
`source_revision`, `source_digest`. Each field is `name byte_length value\n`.
Next comes `dict N\n`, exactly N raw JSON string literals each followed by LF,
and `body\n` followed by the selected JSON bytes with dictionary references.
The digest uses v1’s existing domain-separated SHA-256 over the source length
and exact reconstructed selected bytes.

Documents smaller than 16,384 bytes use an empty dictionary.
Otherwise, only JSON string literals at least 16 bytes long, including quotes
and escape spelling, that occur at least twice enter the dictionary. Entries
are sorted by their exact UTF-8 bytes and numbered from zero. The body replaces
these literals with `@` followed by the canonical unsigned decimal index,
without a closing marker. Quotes delimit remaining inline strings, so `@` and
`~` inside them remain literal content. Short or infrequent strings remain
inline. Selection is a fixed deterministic heuristic; no tokenizer, network,
or model is consulted during encoding.

## Validation and replay

`encode_model_text` consumes an opaque existing `CompactProjection`.
`decode_model_text` parses the envelope independently, expands references with
source bounds checked before appending, verifies the selected-byte digest, and
normalizes through the existing projection encoder. Re-encoding must reproduce
the entire v2 wire exactly, which rejects alternate dictionary order, duplicate
entries, unnecessary references and noncanonical number or header spellings.
`decode_model_text_and_verify` also verifies the expected profile, root and
source revision with the existing binding diagnostic. Integrity is not origin
authentication: the CLI replay route additionally regenerates the selected
producer and requires exact selected-content equality.

Existing limits apply: 16 MiB wire and reconstructed source, 65,536 dictionary
entries, 1 MiB per entry and 4 KiB per metadata field. Decoder errors use the
existing compact diagnostic family; v1 compatibility and error meanings remain
unchanged. Decoded v2 values can be serialized as ordinary v1 projections.

## Interfaces and measurement

All six existing selected profiles admit `--encoding model-text` in the CLI
and `encoding: "model-text"` in `workspace/compact-projection`, including its
MCP forwarding route. The service reports `format_version: 2`. Negotiation
requires the exact version/encoding/profile intersection; v1 `text` or `binary`
cannot negotiate as v2. Existing binary-before-text preference is retained,
with model-text following those encodings when multiple offers are common.

`scripts/benchmark_compact_projection.py` measures full JSON, v1 text and v2
model-text with the same cached cl100k/o200k tokenizers, while independently
replaying all three wire forms including binary. The complete envelope counts
toward measurements. Small inputs can grow because metadata has a fixed cost;
this format does not claim universal savings, exact token budgets, or billing
authority. The benchmark records exact bytes and hashes, tokenizer versions
and vocabulary fingerprints. Results are local, not a hosted/provider result.

## Local measurements

The committed [measurement report](../benchmarks/compact-semantic-projection-v2/local-token-measurements.json)
uses cached tiktoken 0.12.0 with cl100k_base and o200k_base. Every wire replay
matches the selected full bytes; graph cases also match the ordinary graph
producer. Counts include the complete envelope.

| Selected view | Full bytes | Model-text bytes | cl100k full → model-text | o200k full → model-text |
|---|---:|---:|---:|---:|
| examples/banking_ledger.spx | 139,770 | 104,579 | 37,846 → 32,486 | 38,779 → 33,052 |
| Task context: ledger.apply | 6,069 | 6,322 | 1,679 → 1,802 | 1,721 → 1,844 |
| examples/http_app_routing.spx | 610,864 | 440,692 | 161,861 → 134,165 | 165,329 → 135,959 |
| Task context: app.main | 19,793 | 15,974 | 5,602 → 5,010 | 5,718 → 5,080 |
| examples/calculator-project/semaprax.toml | 9,893 | 10,138 | 2,500 → 2,615 | 2,521 → 2,639 |
| examples/frame-payload-project/semaprax.toml | 6,615 | 6,860 | 1,766 → 1,886 | 1,784 → 1,905 |

The two large graphs save 14–18% of measured tokens; the HTTP task context
saves 11%. Small Project graphs and the banking task context grow 5–7%
because the envelope dominates. Consumers should use full JSON for those
small views when token cost is the priority. Version 1’s measured token
regression remains documented; byte savings alone do not imply token savings.
