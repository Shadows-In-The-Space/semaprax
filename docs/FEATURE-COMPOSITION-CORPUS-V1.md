# Feature-composition corpus V1

Status: bounded acceptance inventory for issue #103.

Audience: compiler contributors and release reviewers.

Schema: `semaprax.feature-composition-corpus.v1`.

This bounded acceptance inventory for issue #103 maps each row to its owning
test and the independent facts that test preserves. A rejected source shape
is not execution support. Semantic status, event order, values and live-owner
counts remain part of the comparison.

The checked inventory in
`tests/project/standard_library/composition_inventory.rs` protects every row
below against deletion, duplicate identity, lost module registration, a
missing owner test, or a missing document row.  The inventory links the matrix to executable tests. Its text checks do not
replace those tests' runtime observations.

## Executable rows

| Row identity | Finite selection | Required observations | Owning executable gate |
| --- | --- | --- | --- |
| `scalar.fixed-status-v1` | 15 stable declarations | exact returned values or status domain/code; native O0/O2 and Core Wasm transcript equality | `tests/scalar_status_backend_equivalence.rs::native_o0_o2_and_core_wasm_share_exact_scalar_status_results` |
| `scalar.view-origin-context-v1` | 7: whole/ranged view × `if`/`while`/`match` (6), plus growing range in `while` | exact scalar value for interpreter, native O0/O2, Core Wasm; every selected case returned | `view_ownership_composition::view_ownership_composition_agrees_across_interpreter_native_and_core_wasm` |
| `scalar.view-ownership-route-v1` | 2: borrowed versus `own Bytes` transfer | same value on interpreter and native O0/O2 | `view_ownership_composition::ownership_route_agrees_across_interpreter_and_native` |
| `scalar.view-call-boundary-v1` | 8: whole/ranged × direct/forwarded borrow × `if`/loop | exact value and per-case backend agreement | `view_call_boundary_composition::borrowed_view_call_matrix_agrees_across_interpreter_native_and_core_wasm` |
| `scalar.lazy-checked-failure-v1` | 2: `false && (7 / 0)` and `true || (7 / 0)` | exact successful result; the unneeded checked-failure operand remains unexecuted | `differential::lazy_short_circuit_skips_checked_failure_across_every_available_lane` |
| `scalar.seeded-differential-v1` | 16 fixed PR seeds; 64 frontend/interpreter sweep; 256 explicitly provisioned campaign seeds | canonical source, graph/verification result, exact observations, selected lane command and tool identity; discrepancy report includes seed, source and minimized reproducer | `differential::{fixed_seeds_agree_across_every_available_lane,the_frontend_and_reference_interpreter_agree_on_a_wider_seed_sweep,bounded_campaign_agrees_across_every_available_lane}` |
| `project.imported-offset-view-v1` | 1 imported `std.bytes` offset/range fixture | exact value `328`, nonzero offset and byte oracle, zero retained Core-Wasm owners | `standard_library::imported_view_composition::imported_std_bytes_view_composition_agrees_across_project_backends` |
| `project.owned-cursor-contract-v1` | 1 decode → quote → checked-contract fixture, run twice through entry and test routes | sticky contract status; native O0/O2 failure; Core-Wasm zero owners and exact drops `[3, 2, 1, 6, 5, 4]` | `standard_library::owned_failure_composition::owned_cursor_chain_settles_before_sticky_contract_failure_on_project_backends` |
| `generic.result-allocation-rejection-v1` | 1 result-allocation injection after two input leaves | allocation failure, zero live allocations/handles on all engines; exact input release order `[1, 0]` on interpreter/Core-Wasm | `settlement_corpus::allocation_rejection_order::result_allocation_rejection_preserves_ordered_input_release` |
| `generic.boundary-input-v1` | 7 base carrier shapes plus every nonterminal trace-injection ordinal | zero/one/embedded-NUL/two-leaf/exact-max/over-max-count/over-max-byte input boundaries, sticky status, canonical result bytes, retained trace and live-resource facts | `settlement_corpus::native_o0_and_o2_agree_with_interpreter_and_wasm_across_the_shared_settlement_corpus` |

The source rejection rows are distinct from successful execution rows:
`view_call_boundary_composition::borrowed_view_return_is_rejected_with_stable_diagnostic`
pins `SPX-T264`; `differential::shadowing_is_rejected_rather_than_generated`
pins `SPX-T209`.  Neither is counted as support for the rejected shape.

## Deterministic replay and mutation controls

The seeded row uses fixed values rather than sampling.  A mismatch is rendered
by `differential/report.rs` with the compiler revision/version, tool paths,
commands, source, seed, lane classification, and a structure-preserving
minimized source.  `differential/shrink.rs` has a fixed predicate budget and
the owning test proves that a real divide-by-zero classification survives
reduction.

The corpus has independent negative controls: tampered value/failure/abort
observations go through the real differential comparator; a wrong Core-Wasm
view observation is rejected; the imported Project and owned-cursor Core-Wasm
observers reject a perturbed value/drop sequence; the generic allocation row
rejects forward release order.  The project inventory additionally proves its
own duplicate and missing-row checks fail.  These controls mutate observed
data or test-only expected data, never production compiler code.

## Provisioning and bounds

The required Linux `ci.yml` scalar backend step provisions/arms the fixed
scalar and view matrix.  The dispatch-only
`.github/workflows/feature-composition-corpus.yml` provisions Rust, clang and
Node, asserts those tools exist, sets `SEMAPRAX_DIFFERENTIAL_SEEDS=256`, and
runs the ignored broad campaign with an exact selector and
`SEMAPRAX_DIFFERENTIAL_REQUIRE_ALL=1`.  That opt-in requires the exact three
generated backend lanes (native O0, native O2, Core Wasm) for every seed; a
missing tool or unavailable lane is a failure of that workflow, never parity.

Core-Wasm is deliberately absent from `scalar.view-ownership-route-v1`:
Public Scalar Export Profile V1 rejects non-Value ownership/Bytes transfer in
an entire module.  There is no admitted per-function byte-view dispatch route
to substitute.  The exact corpus source is pinned as `SPX-W115` by
`view_ownership_composition::scalar_export_profile_refuses_ownership_transfer_with_spx_w115`.
Extending that profile is a separate backend/product decision.
The native command-line Project fixtures are Unix-only.  This inventory makes
neither a non-Linux native execution claim nor a hosted-run claim from local
results.
