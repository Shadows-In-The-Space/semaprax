# Model Call Invoice Import v1

Status: local implementation for #180, with offline fixture verification. This
is an evidence boundary and grants no network, model, tool, payment or signing
authority. Imported observations are not proof of semantic correctness.
Audience: compiler contributors and invoice import integrators.

`model_call_receipt::invoice_import` accepts raw input through
`RetainedInvoiceBytes` (at most 65,536 bytes) and independently retained
`InvoiceImportExpectation` account, call and adapter identities (each nonempty,
at most 4096 UTF-8 bytes). Constructors bound borrowed input before copying.
`import_invoice_row` checks the verifier identity, invokes the explicitly
supplied `InvoiceImportVerifier` on the exact retained bytes, then independently
checks returned account/call identities, label bounds and nonnegative cost.
Only this path constructs opaque `VerifiedInvoiceImport` values.

The built-in `ExpectedContentDigestVerifier` is a closed offline verifier. It
matches an independently retained domain-separated SHA-256 digest and parses a
canonical normalized JSON row with exactly `account_id`, `cost_micros`,
`provider_call_id`, `tokens_in`, `tokens_out` in that order, no whitespace or
trailing bytes, canonical string encoding and decimal integers. It rejects
unknown/duplicate/missing keys, negative cost, floats, exponents, leading zeros
and numeric overflow. Tokens are unsigned 64-bit and cost is signed 64-bit
micro-units; no currency conversion is inferred. It authenticates equality to
retained bytes, not the provider that produced them. Custom adapters own their
verification policy and may parse their provider-specific captured format.

The import envelope schema is `semaprax.model-call-invoice-import.v1`. Fixed
field order is schema, adapter identity, raw invoice digest, account id, provider
call id, input tokens, output tokens, cost micros. It has no trailing LF; digest
domains distinguish raw bytes and envelope bytes. Raw payloads remain external.
Rendered evidence permits 262,144 bytes because JSON escaping can expand labels
beyond the raw-input cap. Pure `VerifiedInvoiceImport::replay` requires exact
submitted envelope bytes, retained raw bytes, expected identities, and the
closed data-only digest verifier. It takes no arbitrary verifier callback.
`reverify` is a separately named fresh verification operation for custom
verifiers; it is not claimed to be callback-free replay.

`BillingReconciler::reconcile_verified_provider_import` captures a bounded
immutable snapshot of the source call reference, independently optional provider
usage and settlement state, and passes that same snapshot to the existing
reconciler once. The resulting opaque `ReconciliationRecord` commits to source
snapshot and import envelope digests plus the complete closed reconciliation
outcome, including all known discrepancy dimensions. Source and record digests
are domain-separated. Schema is
`semaprax.model-call-invoice-reconciliation-record.v1`; fixed-order JSON has no
trailing LF. Original attempt receipts are not rewritten. A `reconciled` result
is observed billing evidence, not execution or payment authority.

Record replay compares exact submitted bytes, original source snapshot and
import identity, and an independently retained expected outcome. It does not
rerun mutable duplicate detection or consume an invoice again. It validates
that captured evidence remains unchanged; reconstructing historical duplicate
state still requires the caller's original reconciliation history. This is not
an invoice signature or remote-provider attestation.
