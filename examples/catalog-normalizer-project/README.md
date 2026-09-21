# Catalog normalizer application (#124)

The frozen acceptance contract is [CATALOG-NORMALIZER-ORACLE-V1](../../docs/CATALOG-NORMALIZER-ORACLE-V1.md). The independent oracle and its cases under `tests/oracle/catalog_normalizer/` are not application source.

The Semaprax project implements the bounded application end to end:

- `src/batch.spx` counts records under CNORM-001, locates line byte ranges, detects empty lines, and exposes the exact whole-body, record-count, and line-length bounds in CNORM-002..004. A lone LF represents zero records; two LFs represent two empty records. The application test suite checks 512/513-byte lines and 256/257-record batches.
- `src/app.spx` decodes JSON string tokens using `std.data.json.dec`, enforces the distinct decoded id (1..64 bytes) and label (at most 256 bytes) bounds, compares ids by decoded value for the duplicate-id rule, and trims only the four ASCII boundary whitespace bytes from labels (CNORM-010..014). Published-oracle boundary and escaped-duplicate cases are reproduced in named tests.
- `src/record.spx` composes `std.data.json.doc`, the decoder, and a compact exact nonnegative-decimal scanner into a bounded per-line parser. It narrows a document to a depth-8 object, requires the exact raw `id`/`label`/`quantity` key set, validates scalar value classes and bounds, and carries the first local failure as a deterministic category-plus-byte-offset scalar. `src/batch.spx` then identifies the first later decoded-equivalent id without an owned map.
- `src/enrichment.spx` is the CNORM-060 fixture-provider seam. Its table is frozen and source-local: no network capability, retry loop, or ambient provider selection exists. An enabled run looks up every already-accepted decoded id and either appends its category, appends `null`, or selects one terminal provider envelope before a response buffer is allocated.

`src/tests.spx` has fourteen named cases. The owning Rust application gate in `tests/useful_data/catalog_normalizer_application.rs` is registered exactly once by the `useful_data` harness and runs that same test closure serially through the authenticated interpreter, C11 at `-O0` and `-O2`, and Core Wasm. Native and Wasm artifacts have disjoint lifetimes, and scratch artifacts are removed even when an assertion unwinds, keeping this capacity-sensitive gate bounded without dropping a lane. It also mutates terminal-LF counting, UTF-8 admission, and checked-total overflow and requires the complete project test closure to reject each otherwise-valid candidate. The Rust gate runs the parser/duplicate literals through the independent oracle to pin their categories and byte positions, and byte-compares success, duplicate, and enrichment canonical response literals to live oracle output.

All admitted parser, first-error, duplicate, checked-total, fixture-enrichment, and canonical success/error projection logic is connected for the source-tested bounded path. The writer validates the complete batch before allocating its response and emits through one scalar byte mapper, so failure cannot publish a successful prefix. Broader malformed-input corpus coverage and an output-capacity proof across every maximal body remain outside this local application tranche. The manifest's public `smoke` export is a contract-free probe, not the application API.

The fourteen-case source suite needs the documented bounded interpreter envelope:

```sh
semaprax test . --max-steps 1000000 --max-bytes 65536
```

Capacity remains a development constraint. The complete source-test projection forecast 46,202,120 builder bytes but exceeded the intermediate 48 MiB ceiling during live construction, motivating the 64 MiB graph ceiling. The fully scalar writer and source suite separately motivated the 32,000,000-unit global cleanup-replay work ceiling. The per-function 65,536-path refusal remains unchanged. The focused application gate is the executable evidence for this capacity-sensitive shape.
