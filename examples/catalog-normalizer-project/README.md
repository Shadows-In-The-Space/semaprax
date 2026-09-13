# Catalog normalizer application (#124)

The frozen acceptance contract is [CATALOG-NORMALIZER-ORACLE-V1](../../docs/CATALOG-NORMALIZER-ORACLE-V1.md). The independent oracle and its cases under `tests/oracle/catalog_normalizer/` are not application source.

The current Semaprax project implements two parts of the application:

- `src/batch.spx` counts records under CNORM-001, locates line byte ranges, detects empty lines, and exposes the exact whole-body, record-count, and line-length bounds in CNORM-002..004. A lone LF represents zero records; two LFs represent two empty records. The application test suite checks 512/513-byte lines and 256/257-record batches.
- `src/app.spx` decodes JSON string tokens using `std.data.json.dec`, enforces the distinct decoded id (1..64 bytes) and label (at most 256 bytes) bounds, compares ids by decoded value for the duplicate-id rule, and trims only the four ASCII boundary whitespace bytes from labels (CNORM-010..014). Published-oracle boundary and escaped-duplicate cases are reproduced in named tests.

`src/tests.spx` has eight named cases. The owning Rust application gate in `tests/useful_data/catalog_normalizer_application.rs` runs that same test closure through the authenticated interpreter, C11 at `-O0` and `-O2`, and Core Wasm. It also mutates terminal-LF counting and requires the test closure to reject that candidate.

This is not yet the full catalog normalizer: record JSON/schema validation, exact error positions, duplicate decoded IDs, checked total, all-or-nothing canonical output, and the typed enrichment provider must be connected before #124 can close. The manifest's public `smoke` export is a contract-free probe, not the application API.

Capacity remains a development constraint. An earlier decoder/trim application probe importing both `std.data.json.doc` and `std.data.json.dec` hit `SPX-G171` even after removing `src/limits.spx`. This is a cumulative semantic-graph bound, not proof that the two packages can never be combined. The application does not bypass the bound by copying standard-library parser logic or raising the cap.
