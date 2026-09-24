# Public Generic Carrier Hostile Corpus v1

In plain terms: these hostile inputs prove that malformed carriers fail closed.

Audience: ABI, carrier, ownership and generated-consumer maintainers, and
reviewers of the fail-closed replay claim.

Status: frozen corpus schema with an independent reference decoder and
**local evidence only**. It is owned by
`src/public_generic_abi/carrier/hostile_corpus.rs`, checked by that module's
own tests and by
`tests/public_generic_native_adapter_v1/carrier_hostile_corpus.rs`. It is
part of issue #173's answer for PG-6. No hosted run, no publication decision,
and no support claim follows from anything in this document.

## Scope

This corpus is the one canonical, versioned manifest of hostile
[Public Generic Carrier v1](PUBLIC-GENERIC-CARRIER-V1.md#canonical-carrier-bytes)
logical carrier documents and native admission envelopes. Each entry names
**exactly one** violated invariant and the single closed public refusal class
every reader must publish for it.

It covers:

- the target-neutral `LogicalCarrierFrame` wire document — framing, frozen
  literals, closed variant tags, UTF-8, every frozen bound at its exact
  maximum and at maximum plus one, declared-versus-actual length agreement,
  leaf-path uniqueness, and the document's own self-digest;
- semantic binding — descriptor identity, endpoint identity, instance
  identity, leaf-inventory identity, leaf sequence, and direction;
- the native pre-dispatch admission envelope — attempt generation, caller
  ownership, and the settlement (cleanup-plan) digest.

It does **not** cover, and does not claim to cover:

- the compact flat-leaf result carrier the four generated calling consumers
  speak. That is a separate corpus,
  `tests/support/public_generic_hostile_corpus.rs`, driven through really
  compiled and executed Rust, C11, C++17 and TypeScript consumers. The two
  corpora are deliberately separate because the generated consumers do not
  speak `LogicalCarrierFrame`; claiming otherwise would be an overclaim;
- any physical provider integration. Admitting a document here allocates
  nothing, mints no handle, transfers no ownership, invokes no endpoint,
  calls no host function and runs no cleanup — and grants no authority to do
  any of those;
- unbounded fuzzing. Bounded, deterministic property coverage lives in
  `src/public_generic_abi/carrier/fuzz.rs` and
  `src/public_generic_abi/descriptor/fuzz.rs`.

## Versioned identity

| Field | Value |
| --- | --- |
| Schema | `semaprax.public-generic-carrier-hostile-corpus.v1` |
| Manifest digest constant | `hostile_corpus::CARRIER_HOSTILE_CORPUS_DIGEST` |
| Case count constant | `hostile_corpus::CARRIER_HOSTILE_CORPUS_CASE_COUNT` |

The manifest digest is SHA-256 over a deterministic rendering of the schema,
the canonical fixture's digest, and one line per case naming its id,
invariant, recorded mutation, remint mode, envelope mutation, expected
refusal code and pinned document digest. A change to any of those must mint a
new corpus version or deliberately update the known answer. Each case is
additionally pinned by the SHA-256 of the exact document its recorded
mutation produces, so a regenerated corpus that drifts fails a known answer
rather than quietly covering less.

## Reproducible generation, not opaque literals

No hostile document is stored as a byte literal. Each is produced by applying
one recorded `CarrierMutation` — and optionally one recorded
`TicketMutation` — to the canonical valid fixture. The fixture is itself
derived from published constants (`FIXTURE_EXPORT_ID`,
`FIXTURE_DESCRIPTOR_DIGEST`, `FIXTURE_INSTANCE_DIGEST`,
`fixture_leaf_paths`, `fixture_payloads`), so the whole corpus regenerates
byte-identically on any host from source alone.

The canonical fixture deliberately carries an empty leaf, a leaf holding an
embedded zero byte and a non-UTF-8 byte, and an ordinary text leaf, so an
encoder that treats payloads as text, or a zero-length payload as an
absence, fails immediately.

## Reminting: the forgery a digest-only reader accepts

A document carries a trailing `carrier_facts_digest` over its own body. A
reader that checks only that digest is self-consistent — and therefore
accepts any forgery whose digest was recomputed after the forgery.

Cases marked `Remint::Recompute` manufacture exactly that document: the body
is mutated, then the trailing digest is recomputed over the mutated body, so
every internal consistency check the document carries succeeds. These
documents are refused only because both readers recompute the **endpoint
identity** from the trusted export identity and the **leaf-inventory
identity** from the trusted canonical path list, rather than accepting the
wire's copies of either. This is the first failure mode issue #173 names:
"a digest-only check may accept a self-consistent forged document if no
trusted root is recomputed."

## Two readers that share no code

Every case is driven through two implementations:

| Reader | Implementation |
| --- | --- |
| Production codec | `carrier::frame::parse_bounded` then `carrier::frame::CarrierFrameBinding::validate_frame`, wrapped by `native::admission::NativeInputAdmission` |
| Independent reference | `carrier::reference_decoder` |

The reference decoder restates, from this specification rather than from the
production source, its own length-framed field reader, its own fixed-width
integer reader, its own copies of the five frozen bounds, and its own
domain-separated preimage assembly for all three derived identities. A defect
that a self-checking corpus would mirror therefore appears as a disagreement
between the two readers rather than as a passing test.

The reference decoder's bound literals are cross-checked against
`public_generic_abi::boundary_profile` by
`reference_bounds_match_boundary_profile`, so a production bound change that
is not mirrored fails loudly instead of silently diverging.

## The closed public refusal class

Both readers normalize to one closed class. Detailed local diagnostics stay
on the production `Diagnostic`; only the class below is compared.

| Class | Stable code | Meaning |
| --- | --- | --- |
| `Malformed` | `SPX-PG801` | Framing, UTF-8, an unknown literal, an unknown variant tag, a duplicate leaf path, a declared/actual length disagreement, or trailing bytes |
| `Capacity` | `SPX-PG802` | A frozen bound was reached before the allocation it governs |
| `ReplayMismatch` | `SPX-PG803` | A recomputed digest, a semantic binding field, the leaf inventory, or the cleanup plan disagreed |
| `IllegalTransition` | `SPX-PG804` | The frame is not caller-owned before the transfer point |
| `GenerationMismatch` | `SPX-PG805` | The submitted attempt identity is not the live one |

`CarrierRefusal::from_code` returns `None` for any code outside this family,
so a reader that refuses for an unrelated reason can never be scored as
agreeing.

## Check order

Both readers apply the checks in this exact order, so a document that
violates more than one invariant still yields one deterministic class:

1. envelope: generation, then ownership, then cleanup-plan digest;
2. wire byte bound, before any field is read;
3. schema literal, direction literal;
4. the four identity fields;
5. declared leaf count bound, then declared total payload bound;
6. per leaf: path framing and UTF-8, path uniqueness, variant tag, declared
   payload bound, then the payload read, then the running total bound;
7. declared total versus the measured sum;
8. the trailing digest field, then exact consumption of the document;
9. independent recomputation of the self-digest;
10. semantic binding: direction, descriptor, endpoint, instance, inventory,
    then the leaf sequence.

Steps 2 through 9 are structural admission; step 10 is semantic binding. The
split is deliberate: a document that merely decodes is never confused with
one that belongs to the expected subject.

## Bound neighbours

Every frozen bound has both an exact-maximum and a maximum-plus-one case, and
the two classify **differently**. At the bound the claim is admissible, so the
document is refused for not satisfying it (`Malformed`) or admitted outright;
one over, the bound itself refuses it (`Capacity`). A reader with an
off-by-one bound swaps the two classes and fails.

| Bound | Exact maximum | Maximum plus one |
| --- | --- | --- |
| Leaf count (256) | `declared_leaf_count_at_exact_bound` | `declared_leaf_count_one_over_bound` |
| Total payload (16 MiB) | `declared_total_payload_at_exact_bound` | `declared_total_payload_one_over_bound` |
| Declared leaf payload (64 KiB) | `declared_leaf_payload_at_exact_bound` | `declared_leaf_payload_one_over_bound` |
| Real leaf payload (64 KiB) | `leaf_payload_at_exact_bound_admitted` (admitted) | `leaf_payload_one_byte_over_bound` |

Each bound additionally has a `u64::MAX` case, so exact-width handling is
exercised rather than a host `usize` narrowing accident.

## Positive controls

Three documents must be **admitted**, and what they expose must be exactly the
trusted inventory in canonical order:

- `canonical_document_admitted`;
- `leaf_payload_at_exact_bound_admitted`;
- `all_empty_payloads_admitted`.

A reader that refuses everything fails this corpus.

## No effect before admission

`tests/public_generic_native_adapter_v1/carrier_hostile_corpus.rs` drives the
corpus through `NativeInputAdmission::admit_then`, the only sequencing point
at which an installer's callback can run, with a five-counter ledger:
allocation, target invocation, ownership commit, host call, and cleanup. Every
hostile case leaves all five at zero; only the canonical control reaches the
callback.

This is callback-local native staging evidence, not physical handoff evidence.
The separate private authenticated native identity profile installs admission
at its C entry point; its bounded generated-caller projection is described below.
Complete physical corpus participation remains open and overlaps issue #229.

### Private generated C11/C++17 handoff projection

The native adapter harness selector
`authenticated_handoff::same_subject::caller_hostility::generated_c_and_cxx_reject_subject_bound_hostile_handoffs`
projects seven frozen recipes onto one checked flat `Pair<Bytes>` identity
subject: stale/future/zero generation, provider ownership before transfer,
substituted cleanup plan, substituted leaf path, and the adjacent unknown leaf
kind tag. It retains their case identities and expected refusal classes, not
the synthetic corpus fixture's different three-leaf bytes or pinned digests.
Metadata substitutions pass through the real generated encoder's digest
recomputation. Generation/ownership refusals retain raw statuses 8/7 and the
existing generated `ExecutionFailed` mapping; path/cleanup refusals use raw 14
and `CarrierRejected`, and the closed kind tag uses raw 5/`CarrierRejected`.

Both literal-contract subjects (`requires true`/`false`), both callers, and
C11 `-O0`/`-O2` produce 80 process runs: 56 hostile cases, eight canonical
controls, eight unchanged flattened-generator refusals, and eight compiled
generation-check-omission controls. Each ordinary hostile attempt must leave
provider preparation allocations, endpoint entries, and live handles unchanged;
caller-owned allocations and provider-open allocation are outside that delta.
Canonical calls assert exact non-palindromic bytes or raw contract failure 11,
one checked endpoint entry per transform, and settled resources. The omission
control must actually allocate and enter the endpoint, then fail the refusal
oracle with its exact sentinel exit. C++ retains move/close/RAII assertions.
This gate changes neither generator output nor ABI and is not full-corpus,
Core-Wasm, hosted, sanitizer, public-support, or broader endpoint-shape evidence.

## Non-claims

- Local, re-runnable evidence only. Nothing here is hosted evidence.
- No wire format, refusal code, or existing profile is reinterpreted. The
  corpus reads the frozen carrier frame; it does not extend it.
- The frozen corpus itself leaves all four generated calling consumers
  unchanged; the separate private C11/C++17 projection above is narrowly scoped.
- A bounded property run is not a proof of absence of defects outside its
  bounds.
