# Kernel-0 Rung-2 Bootstrap Artifact v1

Status: local, private reproducibility evidence for issue #188. This is not a
release artifact, a public ABI, a formatter authority grant, target-execution
evidence, hosted evidence, or a self-hosting-rung promotion.

Audience: compiler contributors and reviewers of Kernel-0 bootstrap evidence.

This document owns `semaprax.kernel-zero-rung-two-bootstrap.v1`, the closed
binary artifact emitted by `src/kernel_zero/rung_two_bootstrap/`. Its purpose
is deliberately narrow: a future reviewer can retain one exact compiler output
for all current pure renderer fragments, decode it independently, and replay
the ordinary compiler routes from the exact retained source instead of trusting
an old in-memory `BoundTranslation` or a self-reported build result.

## Subject and boundary

The artifact's complete, authored component order is fixed. It is not sorted,
discoverable, configurable, or extensible under v1.

| Ordinal | Name | Exact source | Entry |
| --- | --- | --- | --- |
| 0 | `char` | `src/kernel_zero/canonical_char_renderer.spx` | `format.render-byte` |
| 1 | `bool` | `src/kernel_zero/canonical_bool_renderer.spx` | `format.render-byte` |
| 2 | `int` | `src/kernel_zero/canonical_int_renderer.spx` | `format.render-byte` |
| 3 | `operator` | `src/kernel_zero/canonical_operator_renderer.spx` | `format.operator-render-byte` |
| 4 | `string-scalar` | `src/kernel_zero/canonical_string_renderer.spx` | `format.render-byte` |

Each component is a pure, scalar Kernel-0 byte lane. It has no `Bytes` result,
does not construct a formatter-owned buffer, and does not receive a filesystem,
process, network, secret, signing, publication, or target-execution capability.
The artifact producer returns bytes in memory; it does not write a file. A
caller that persists those bytes owns that separate filesystem decision.

The producer uses ordinary `parse`, HIR resolution, `BoundTranslation` exact
source replay, `codegen::emit_hir_c`, and `wasm::emit_module`. The retained C
payload is generated C11 *source* and the retained Wasm payload is a raw Core
Wasm module. Neither carries a public component wrapper or a driver for the
parameterized `render-byte` entry points. Therefore v1 deliberately makes no
claim that either retained target payload was compiled, loaded, or executed.
The existing independent target corpus remains separately owned evidence.

## Declared local build environment

A reproducible v1 comparison means two local derivations from the same checked
Git checkout, the exact tracked `Cargo.lock` digest retained in the wire, and
the closed `c11-source+raw-core-wasm` target profile produce one byte-identical
artifact. It does not mean that a different compiler revision, a different
dependency lock, a hosted runner, a C compiler, Node, a Wasm runtime, or a
physical target has reproduced or run the artifact.

This scope is intentional. The evidence is a deterministic compiler-output
check; it must not fabricate execution evidence merely because an artifact has
bytes that happen to be C or Wasm.

## Canonical wire

All integers are little-endian. `text` is `u16 byte_length` followed by a
nonempty ASCII byte sequence of at most 256 bytes. `blob` is `u32 byte_length`
followed by at most 1 MiB. Digests are raw 32-byte SHA-256 values. The whole
artifact is at most 8 MiB.

```text
body :=
  magic                         # eight bytes: "SPXR2BT\\0"
  text("semaprax.kernel-zero-rung-two-bootstrap.v1")
  text("c11-source+raw-core-wasm")
  sha256(exact tracked Cargo.lock bytes)
  u8(5)
  component[0] component[1] component[2] component[3] component[4]

component :=
  text(name)
  text(source_name)
  blob(exact source bytes)
  sha256(source bytes)
  text(entry stable ID)
  blob(canonical reified Kernel-0 term bytes)
  sha256(term bytes)
  blob(generated C11 source bytes)
  sha256(C11 bytes)
  blob(raw Core-Wasm module bytes)
  sha256(Wasm bytes)

artifact := body sha256(body)
```

`component[0..4]` must be exactly the table above. No optional fields,
unknown fields, duplicate entries, omitted entries, reordered entries, trailing
bytes, alternative text encoding, or omitted digest is canonical v1. A future
format requires a new schema name and decoder; v1 does not negotiate.

The canonical Kernel-0 term bytes are a private, bounded audit payload, not a
new semantic graph or public term ABI. They encode the exact reified functions,
authored parameter order, scalar types, term constructors, identifiers, binary
and unary opcodes, and call-argument order. Their maximum is 512 KiB and their
encoder independently enforces the established 64-function, 8,192-node, and
depth-128 ceilings while serializing.

The consumer does not accept that producer encoding on its word. It owns a
separate strict parser for `SPX-KERNEL-TERM-V1\\0`: exact magic, nonzero
function count at most 64, unique function and parameter IDs, only the two
scalar type tags, only the eight constructor tags, closed unary/binary opcode
ranges, boolean bytes restricted to zero or one, bounded node/depth recursion,
and exact end-of-input. It re-encodes the decoded structure itself and requires
byte identity before separately re-encoding the newly replayed
`BoundTranslation` program. A malformed term tag/count/depth/trailing byte or
a 512 KiB-plus-one term therefore refuses before C/Wasm comparison; producer
and consumer term serializers cannot accept a framing bug merely by agreeing
on the same bytes.

## Decode and replay

The consumer first bounds the entire byte slice before parsing. It then:

1. verifies the body digest, magic, schema, target profile, lock digest, and
   closed component count;
2. reads every counted field with independent length checks, verifies each
   payload digest, and rejects non-ASCII text or trailing bytes;
3. compares name, source file name, exact source bytes, and entry ID against
   the fixed v1 inventory in authored order;
4. independently reparses and resolves each retained source, derives and
   replays a new exact-source `BoundTranslation`, regenerates its canonical
   Kernel-0 term bytes, generated C11 source, and raw Core-Wasm bytes; and
5. accepts only byte-for-byte equality with every retained term and target
   payload.

The decoder never executes a retained payload, writes it to disk, invokes an
external tool, treats a digest as capability, or changes formatter output.
Any malformed or stale input is a refusal, not a fallback to a nearby source,
old translation, different profile, or partial component inventory.

## Required hostile evidence

The focused Rust module owns these local regressions:

- two consecutive derivations are byte-identical and decode/replay to the same
  digest;
- every retained C source, raw Wasm module, and canonical term payload has the
  expected structural magic and is nonempty;
- reordered and duplicate component inventories refuse;
- an internally digest-consistent replacement of a term, C source, or Wasm
  payload refuses after compiler regeneration;
- bad whole-artifact digest, magic, schema, source bytes, source blob length,
  body truncation, body trailing bytes, malformed term tag/count/depth/term
  trailing bytes, and one-byte-over global/term capacity all refuse.

Passing these tests is local compiler-output evidence only. It neither proves
universal source/HIR correspondence, proves either backend correct, replaces
the renderer's broad byte oracle, provides an owned output buffer, nor makes
the Kernel-0 path authoritative.
