# Owned string variants v1

Status: local implementation for owned String variant payloads; no public ABI or network claim.
Audience: compiler contributors and variant ownership integrators.

This profile adds direct owned `string` fields to issue #216's variant payload
admission. Text still requires cleanup; it is not a Copy scalar.

## Admission and authority

An authored monomorphic variant may contain direct `string` and the existing
admitted Copy scalars. This profile does not admit generic string substitutions,
nested owned records, classes, or mixtures with `Bytes`. Existing Copy record
variant payloads and owned byte profiles keep their separate admission rules.
Construction, own/borrow parameters and exhaustive matching use the same
persistent declaration/case/field identities and ordinary ownership checks.
The existing owned-match result restrictions remain in force: a direct
String result from an owned variant match expression is rejected with
`SPX-T216`. No source host operation, ambient capability or public ABI is
introduced. Private backend runtime helpers implement the existing String
intrinsics using their backend's authenticated carrier representation.

## Ownership and cleanup

The compiler primitive lifecycle `core.string.drop` is derived from the
resolved `string` type. Inventory construction and independent cleanup replay
reconstruct it rather than trusting a backend-supplied identifier. Standalone
strings and string payload bindings participate in the same canonical cleanup
plan, so construction, transfer, calls and failure cleanup cannot create a
second independent owner tracker. String literals and owning place reads
initialize temporary storage; owning place reads retain existing cloning
semantics. Transfers poison the source carrier and move liveness exactly once.
Borrowing place reads retain the existing carrier without allocating a clone.
Guarded and multi-arm scalar matches use child cleanup regions: a guard settles
its temporaries before branching, and an arm settles them after transferring
its result and before joining. Nested lexical regions retain their own exits.
A single unguarded catchall lowers its value directly in the enclosing region.

Cleanup follows the authenticated active case and its field paths in declaration
order. Inactive cases have no live owners. Adding the primitive lifecycle does
not change existing plan transition wire shapes. An older compiler must reject
the plan if it cannot reconstruct this lifecycle.

Conformance traces represent an owned `string` result with the new primitive
marker `{"kind":"string"}`. The marker records the result kind, not its text,
allocation, pointer, or handle. The existing `bytes` and nominal `owned`
result encodings do not change.

## Internal representations

Native64 stores the existing owned string allocation pointer in an eight-byte,
eight-aligned field and uses the existing string finalizer. Wasm32 stores the
existing string handle in an eight-byte, eight-aligned field. Both use the
ordinary tagged-union variant layout, publish the tag after field construction,
and settle live owners in canonical cleanup order. These layouts are internal
compiler contracts, not a frozen public aggregate ABI or Component Model type.

The aggregate Core-Wasm profile retains its byte-carrier runtime. Its optional
private `env` imports are `spx_string_concat_v1`, `spx_string_from_char_v1`,
`spx_string_len_chars_v1`, `spx_string_from_i64_v1`,
`spx_string_from_usize_v1`, `spx_string_starts_with_v1` and
`spx_string_contains_v1`. Inputs are authenticated carriers or typed scalars;
the generated web adapter validates UTF-8 and bounds allocations to 65536
bytes. Concatenation leaves committed inputs intact for emitted cleanup.
These carriers are distinct from the standalone internal-string arena ABI.

## Verification

The owning executable regression is registered in the existing cleanup-backend
harness. It covers source admission and stable rejection, canonical formatting
and graph cleanup identity, interpreter execution, native C11 execution and
Core Wasm execution under Node. Real execution results, not authored fixtures,
are required before this profile can be reported as implemented.

The local gate is `cargo test --locked --test cleanup_backends
owned_string_variant -- --test-threads=1`, with Clang and Node available.
Its three tests pass: interpreter and canonical projections, C11 at `-O0` and
`-O2` with balanced allocations, and 32 invocations of one Core-Wasm instance
under a 16-entry allocation limit. The shared program returns 16 and exercises
String payload construction, own/borrow matching, local String relays, guard
and nested arm cleanup, concatenation, UTF-8 lengths and content equality.
This is local evidence; hosted CI was not run for this addition.
