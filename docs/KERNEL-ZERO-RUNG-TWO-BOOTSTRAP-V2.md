# Kernel-0 Rung-2 Bootstrap Artifact v2

Status: local, private reproducibility evidence for issue #188. This is not a
release artifact, a public ABI, a formatter authority grant, hosted evidence,
or a self-hosting-rung promotion. Version 2 is a new closed wire: it does not
silently reinterpret or accept v1 artifacts.

This document owns `semaprax.kernel-zero-rung-two-bootstrap.v2`, the closed
binary artifact emitted by `src/kernel_zero/rung_two_bootstrap/`. It retains
one exact compiler output for all five current pure renderer fragments so an
independent consumer can decode it and replay ordinary compiler routes rather
than trust an old in-memory `BoundTranslation` or a self-reported build.

## Subject and boundary

The complete authored component order is fixed: `char`, `bool`, `int`,
`operator`, and `string-scalar`. Each is a pure scalar Kernel-0 byte lane with
no `Bytes` result, formatter-owned buffer, filesystem, process, network,
secret, signing, publication, or target-execution capability. The producer
returns bytes in memory; any persistence is a separate caller decision.

The producer uses ordinary `parse`, HIR resolution, `BoundTranslation` exact
source replay, `codegen::emit_hir_c`, `wasm::emit_module`, and the private
scalar-export Wasm emitter. The retained C payload is C11 source; the first
retained Wasm payload is raw Core-Wasm; and the second retained Wasm payload is
a private scalar-export companion for `render-length` and `render-byte`.
Neither is a public component wrapper or formatter authority. Target execution
is separately owned local evidence, not a property of artifact decoding.

## Declared local build environment

A reproducible v2 comparison means two local derivations from the same checked
Git checkout, exact tracked `Cargo.lock` bytes, and the closed
`c11-source+raw-core-wasm+private-scalar-export-core-wasm` profile produce one
byte-identical artifact. It does not claim reproduction by another compiler
revision, dependency lock, host, C compiler, Node, Wasm runtime, or physical
target.

## Canonical wire

All integers are little-endian. `text` is a nonempty ASCII `u16`-length value
of at most 256 bytes. `blob` is a `u32`-length value of at most 1 MiB. Every
digest is raw 32-byte SHA-256, and the artifact maximum is 8 MiB.

```text
body :=
  magic                         # eight bytes: "SPXR2BT\\0"
  text("semaprax.kernel-zero-rung-two-bootstrap.v2")
  text("c11-source+raw-core-wasm+private-scalar-export-core-wasm")
  sha256(exact tracked Cargo.lock bytes)
  u8(5)
  component[0] component[1] component[2] component[3] component[4]

component :=
  text(name)
  text(source_name)
  blob(exact source bytes) sha256(source bytes)
  text(entry stable ID)
  blob(canonical reified Kernel-0 term bytes) sha256(term bytes)
  blob(generated C11 source bytes) sha256(C11 bytes)
  blob(raw Core-Wasm module bytes) sha256(raw Wasm bytes)
  blob(private scalar-export Core-Wasm companion bytes) sha256(companion bytes)

artifact := body sha256(body)
```

`component[0..4]` must be exactly the fixed inventory in authored order. No
optional or unknown fields, duplicate/omitted/reordered entries, alternate text
encoding, omitted digest, or trailing byte is canonical v2. A real v1 fixture
uses the same magic but its own v1 schema/profile and omits the companion; the
v2 decoder intentionally refuses it at the schema/profile boundary. The
focused regression builds that structurally valid v1 layout from current valid
source, term, C11, and raw-Wasm bytes to pin the non-negotiation decision.

## Decode and replay

The consumer bounds the whole byte slice, verifies the body digest, magic,
schema, profile, lock digest, closed count, field lengths, field digests,
ASCII text, fixed identity inventory, and absence of trailing data. It strictly
decodes and re-encodes the canonical term; structurally validates the retained
private companion; reparses and resolves each exact retained source; then
replays `BoundTranslation` and exact-compares regenerated term, C11, raw Wasm,
and private companion bytes.

Exact regeneration authenticates reproducibility, not target semantics. A
deterministic bad producer can make a self-consistent wrong artifact; the
separate local target oracle catches that only by executing retained targets
and comparing them with authoritative Rust bytes. Decoding never executes a
payload, writes disk, invokes an external tool, treats a digest as capability,
or changes formatter output.

## Required hostile evidence

Focused tests require two local v2 derivations to be byte-identical; validate
all retained C, raw-Wasm, companion, and term payloads; reject reordered and
duplicate inventories; reject digest-consistent payload substitution after
exact regeneration; reject malformed companions, source/companion plus-one
lengths, bad digest/magic/schema, truncation, trailing bytes, and malformed or
oversized terms; and reject the authentic v1 fixture exactly as intentional.

This is local compiler-output evidence only. It does not prove universal
source/HIR correspondence or either backend's correctness, provide an owned
output buffer, make Kernel-0 authoritative, or reach rung 2.
