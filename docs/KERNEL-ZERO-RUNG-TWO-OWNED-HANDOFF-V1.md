# Kernel-0 Rung-2 Owned Handoff v1

Audience: compiler and self-hosting contributors.

Status: private implementation for R16 / #294 with the bounded local evidence
recorded below. This is not accepted-head, hosted, full-gate, or self-hosting-rung
evidence. Remaining acceptance gates and the exact accepted revision must be
recorded independently.

## Closed subject and proof boundary

The five scalar renderer sources, Kernel-0 grammar, evaluator, translation,
and Lean theorem are unchanged. Their length/byte computation and Rust host
assembly happen first. Neither is an owned renderer or an ownership theorem.

The production candidate then passes those exact-source authenticated bytes
through `kernel-zero.owned-handoff.move`: an ordinary checked SEMAPRAX
`own Bytes -> Bytes` function with one immutable move binding and that binding
as its result. Normal source/HIR ownership verification and canonical cleanup
replay govern it. No new ownership rule, cleanup authority, or evaluator exists.
Rust remains the only formatter authority: only a fully settled candidate
equal to the Rust reference may be copied into the caller's 20-byte token.

## Synchronous admission and settlement

`interpreter::retained_call::owned_handoff` owns a crate-private sealed product
with immutable checked HIR and its prepared call. Before ordinary verification,
admission caps the inventory at three functions, forbids authored types, generic
templates/instances, contracts, effects and yields, and checks at most 32 nodes
and depth four per body. The selected function has one owned Bytes parameter,
one immutable owned move binding, a plain owned place result, and no callees.
Other admitted nodes exist only for the target-input shim and scalar main.
The unreferenced implicit Option/Result prelude is retained and independently
validated normally; its presence admits no aggregate handoff.

Input length is `0..=20`; fuel is `1..=8`. Violations refuse before owner
staging. Evaluation recursion is just the selected block and plain places,
not the ordinary interpreter's 256-frame profile. No worker or process is
created. The existing general retained-call API keeps its 64 MiB worker stack
and shares the factored staging, call frame, failure mapping, and harvesting.

Staging creates one ordinary interpreter byte owner, even for empty input.
A weak reference first observes its unique live strong owner. Only after
execution and harvesting release the last strong owner can a settlement
receipt exist. Publication also requires exactly the existing
`CopyOutAndSettleBytes` event, the expected length, and unchanged bytes. The
weak reference grants no cleanup authority and cannot drop an owner.
Exhaustion publishes nothing and must release the owner without inventing a
successful result-harvest event. Unwind panics also release staged ownership;
this is not recovery from allocator abort, stack overflow, or fail-stop.

## Exact private binding and target evidence

`kernel_zero::rung_two_owned_handoff` owns the adapter and bounded binding.
Initialization checks the embedded wrapper, entry, five unchanged scalar
sources, each exact entry and canonical core term, 20-byte maximum, descriptor,
native C provider bytes, Core-Wasm bytes, and Cargo.lock. It reuses the existing
canonical term encoder and source/entry inventory without changing bootstrap-v2 bytes. Only
the tiny wrapper target artifacts are emitted during initialization, not the
five scalar targets; no target compilation or execution occurs there.

Descriptor/emitter APIs receive a private standalone-source subject bound to
source, entry and profile digests: not a managed Project generation or release
provenance. The target-only borrowed-input shim copies its input and calls the
same owned handoff. These are wrapper-boundary artifacts, not owned Kernel
theorems. The existing public owned-data ABI keeps its own larger limit; the
private evidence driver admits at most 20 bytes before calling that ABI.

Before owner allocation the adapter checks artifact length, digest, and complete
equality with its held compiler-derived snapshot. This closed expected-byte
verifier does not parse arbitrary artifact members. Reminting a digest cannot
authorize a changed source, entry, source order, core entry, core term,
descriptor, target, or maximum. Bootstrap-v2's separate decoder and hostile
gates are unchanged.

## Recovery and required evidence

One panic-safe thread-local scope covers scalar execution and handoff. Nested
formatting and active bounded-output scopes bypass both. Refusal, binding drift,
exhaustion, missing settlement, mismatch or unwind panic selects the original
Rust fallback; a later ordinary invocation may re-enter. Production formatting
runs no target executable and gains no filesystem, network, process,
persistence, or worker-thread authority.

The `owned_handoff` library selector covers real owner lifetime, async/synchronous
equality, 0/1/20-byte values, capacity-plus-one, exhaustion, missing receipts,
shallow admission, panic, and a two-MiB test stack. A test-only retained strong
alias makes last-owner release fail and prevents result publication; releasing
that fixture alias restores subsequent success. Graph replay pins the owned
parameter/result and live cleanup entry, and rejects a forged borrow mode.
Reminted substitutions must stage zero owners. The normal formatter's five-lane
gate additionally requires one successful settled handoff per candidate traversal,
so Rust-only fallback
cannot satisfy it.

Physical wrapper evidence requires C11 O0/O2 and Node/Core-Wasm with
`SEMAPRAX_REQUIRE_KERNEL_ZERO_RUNG_TWO_TARGETS=1`. Thirteen rows cover all five
lanes, non-palindromic tokens, empty/NUL/non-UTF-8 bytes, and `i64::MIN`'s exact
20-byte output. Allocator/arena observations cover lifetime, copy refusal,
stale/double-drop refusal, settlement and re-entry. The private host arena is a
bounded test witness, not evidence of generated npm or browser execution.
Native free-call observations include one `free(NULL)` for empty Bytes;
non-NULL live allocations are counted separately. Stale drop must add neither
a free call nor a live owner. Thirteen rows passed locally for each of native
O0, native O2 and Core-Wasm, but this does not replace scalar-target gates.

Existing authority, broad renderer, bootstrap reproducibility/hostility,
scalar real-target recovery, differential, and required Lean gates must pass
at the accepted exact revision. Hosted acceptance and any change from rung 1
remain explicit independent review decisions. This profile promotes no rung,
public ABI, support policy, whole-compiler self-hosting or verification claim.

## Local implementation evidence

The following selectors completed against the local implementation before its
review commit, using a worktree-private target directory, one Cargo build job,
disabled incremental compilation/debug information, and one test thread:

- `owned_handoff`: 10 passed, including required physical wrapper targets.
- `kernel_zero::rung_two_authority::`: 8 passed.
- `kernel_zero::rung_two_renderer::`: 14 passed.
- `kernel_zero::rung_two_bootstrap::`: 10 passed with required native/Wasm targets.

The four-test `kernel_zero::differential::` selector is **incomplete**. Its first
two tests passed: the 2,562-comparison C11 O0/O2 and Core-Wasm corpus reported no
disagreements, and the rung-one capacity-classifier target test passed. The run
was terminated at the user's direction while the third test was active; the
fourth test was not reached. These partial observations are not an overall
differential pass. Lean/formal and full quality gates were not run for this
slice. No full-gate or accepted-revision conclusion follows from these local
results, and further broad runs are outside the user's authorized scope.
