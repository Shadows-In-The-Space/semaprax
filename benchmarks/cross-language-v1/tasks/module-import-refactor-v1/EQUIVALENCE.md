# Task equivalence: `module-import-refactor-v1`

This task measures a multi-module invoice calculation refactor. The public entry point must import a helper for whole-subtotal tax calculation; hidden execution keeps helper and candidate modules unchanged and overlays only assertions.

## Problem and oracle

`invoice_total(price, quantity, tax_rate, shipping)` computes, in order: `subtotal = price * quantity`; `tax = floor(subtotal * tax_rate / 100)` for nonnegative integer inputs; then `subtotal + tax + shipping`. Tax is calculated once from the whole subtotal, and shipping is added after tax. The candidate imports `tax_for_subtotal` from a separate helper module. This module arrangement is a fixture-level refactor requirement; behavioral tests alone do not prove that an import was used. A candidate that rounds tax per item or includes shipping in the taxable base passes simple public cases but fails hidden fractional-tax/shipping cases.

Public vectors use exact/simple cases. Hidden vectors include fractional whole-subtotal tax with nonzero shipping, distinguishing a helper that rounds per item or taxes shipping. Every vector is within the exact intersection of Rust `i64` and JavaScript safe integers (`0..=9_007_199_254_740_991`); concrete inputs are nonnegative and far below that ceiling.

## Independent hidden overlay

Rust and TypeScript hidden phases overlay only their assertion entry module; copied public helper and candidate modules remain under test. SEMAPRAX hidden overlays only executed `src/app.spx`, preserving copied `src/helper.spx` and `src/candidate.spx`. A wrong imported helper is intended to pass public vectors but fail hidden assertions; that claim requires the runner's actual negative-control execution. Deleting public assertions cannot make hidden acceptance pass because hidden assertions call the same copied modules.

This directory is fixture-only evidence until the existing runner is invoked with registered adapters; no trial or language comparison is claimed here.
