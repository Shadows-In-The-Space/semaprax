# Kernel-0 proof mechanization: proof-assistant choice, the no-holes gate, and a verified spike

- Audience: whoever picks up `docs/SEMANTIC-KERNEL-V1.md`'s item 4 (pick a
  proof engine) or issue #186 (export obligations to an external proof
  kernel) — see "Relationship to issue #186" below, which that issue's own
  audit asked this document to answer explicitly.

- Status: research + spike, not a completed mechanization. Answers two
  questions from `docs/SEMANTIC-KERNEL-V1.md`'s own follow-up list ("pick a
  proof engine... and wire a CI gate that fails on any admitted
  axiom/`sorry`/`admit`") with evidence fetched this session, then spikes
  part of Kernel-0 in the recommended assistant (Lean 4) and **ran it**: the
  transcripts below are verbatim, not reconstructed. No CI workflow is added
  by this document; one is proposed in text, priced from measurements taken
  on this exact host.
- Scope: this document and a new `proofs/` directory only. It does not touch
  `docs/SEMANTIC-KERNEL-V1.md`, `src/`, `crates/`, `tests/`, `benchmarks/`,
  `scripts/`, or `.github/`, all of which other agents hold.

## Non-claims

Read this before citing this document elsewhere.

- **This is not a mechanization of Kernel-0.** It mechanizes Kernel-0's full
  term/type syntax, a genuinely partial (`Fault`-outcome) small-step
  semantics, a fully proved Progress trichotomy for the scalar-and-`if`
  fragment, and a fully proved Preservation for the *entire* language
  (`Let` and non-recursive `Call` included) — see "The spike" below for the
  exact inventory. The later ranked-call-graph extension below proves
  call-chain termination and acyclicity under an explicit strict-rank
  certificate; full small-step normalization and connection to the compiler's
  HIR remain open. The existing `kernel0-lean-proof-gate` CI job runs the proof
  gate; a wired job does not establish a hosted verdict for an unrun commit.
- **The recommendation (Lean 4) is evidence-based on this host, not a
  universal ranking.** Coq/Rocq's ecosystem is arguably the better textbook
  fit for exactly this kind of small-calculus metatheory (see "Ecosystem
  evidence" below); Lean is recommended primarily because it was already
  installed and verified working, hermetically, on this exact host, and
  because reusing it costs no additional disk on a machine that is already
  short on some (see "Disk and installation" below).
- **Every comparison-table cell is either cited to a fetched source or
  marked as this session's own first-hand measurement.** None is from
  training-data recall alone; where a claim could not be verified hands-on
  (Coq, Isabelle, Agda were not installed this session — see "Disk and
  installation"), the table says so and cites documentation instead.
- **A scalar-only proof does not validate the real compiler.** See "What
  this does not tell you" — ownership, effects, contracts, and all three
  backends are entirely outside this document's and the spike's scope.

## Background: the two open questions and the finding that motivates them

`docs/SEMANTIC-KERNEL-V1.md` defines **Kernel-0** — literals, `if`, `let`,
arithmetic/comparison/boolean operators, non-recursive calls, no effects, no
ownership, no contracts — with a **paper, not mechanized** progress-and-
preservation proof, and names, as its highest-priority remaining follow-up:
"pick a proof engine... and wire a CI gate that fails on any admitted
axiom/`sorry`/`admit`."

**The finding that makes this more than a checkbox.** A differential test
added in commit `4296615a` (this same document's history) found that
Kernel-0's stated semantics assert a total-looking `n1 op n2 = n`, while real
`i64` arithmetic is partial: a zero divisor, `i64::MIN / -1`, and range
overflow all have no defined result. A term such as `1 / 0` is well-typed
under the document's own typing rules but has **no reduction rule that
fires** — exactly the stuck state Progress claims cannot happen. The real
compiler resolves this with an explicit third `Fault` outcome (checked
arithmetic, `Flow::Failure`), independently converging on the same
resolution a from-scratch reference interpreter needed. **This is the single
most important fact for this document's task**: a mechanized proof would
have had to confront this gap by construction (there is no rule to apply to
`1 / 0`, so a mechanized progress proof simply fails to compile until the
calculus is fixed), where the paper proof stated the false total-arithmetic
premise and moved on. Section "The spike" below mechanizes the *corrected*,
three-outcome version, with the `Fault` case modeled explicitly — not
smoothed away as the source document's `n1 op n2 = n` does.

## Question 1: which proof assistant

### Ranked comparison

| Rank | Assistant | Maturity for *this* task | No-holes check (exact command) | Offline/hermetic story | CI cost | Ecosystem evidence |
|---|---|---|---|---|---|---|
| **1 (recommended)** | **Lean 4** | Good, growing; no canonical STLC-progress-preservation development ships with the language itself, but community developments exist and this session mechanized a comparable fragment from scratch in about two hours of iteration. | `#print axioms <name>` on every headline theorem; a clean result lists only `propext`/`Classical.choice`/`Quot.sound` (or a subset). Programmatic form: run and grep combined stdout for the literal substring `sorryAx`. **Verified this session** — see "The spike." An independent second check exists: `leanchecker`, shipped in the toolchain (`~/.elan/toolchains/.../bin/leanchecker`), is a standalone kernel-only re-checker distinct from the full elaborator, used in CI as `lake env leanchecker replay` in at least one real project (`williamjblair/lean-proofs`, "CI-gated `#print axioms`"; `coproduct-opensource/nucleus` issue #2555, "Lean trust chain: per-theorem axiom audit, second kernel"). | **Verified hermetic this session, first-hand.** `lake build` on the spike project (`packages = []`, zero external Lean dependencies) after `rm -rf .lake/build` completed in **1.2–1.3 seconds wall-clock with no network activity** — consistent with zero I/O, since any real fetch over any network would not complete in that time. The toolchain itself needs network **once**, to download (`elan`, from GitHub releases); this is a one-time install step, not a per-build cost, exactly analogous to `apt install gcc`. A project that pulls in Mathlib (not needed here, and not used by the spike) additionally runs `lake exe cache get`, which **does** fetch gigabytes over network as an ordinary part of its build — avoided entirely by not depending on Mathlib, which Kernel-0's scalar fragment does not need. | Toolchain already installed on this host: **2.7 GB** (`du -sh ~/.elan/toolchains/leanprover--lean4---v4.34.0`), slightly over the session's own "~2 GB" installation guidance — flagged honestly; this session did not perform that install, it was already present, and no new install was made. Incremental rebuild of the whole spike: ~1 second. A from-scratch CI job would pay the one-time ~2.7 GB toolchain fetch (cacheable via `actions/cache` on `.lake` and the elan toolchain directory, per `lean-action`'s own README) plus a build in the low single-digit seconds for a file this size. | No canonical "Software Foundations"-equivalent in the language itself (confirmed by search: "there is no formalization for simply typed lambda calculus in the mathlib," per a Lean Zulip thread); independent community repositories exist doing STLC with progress/preservation/determinism/soundness and "zero axioms or sorry placeholders" (e.g. `mdk-aza/type-sysytems-in-lean`). This session's own spike is first-party evidence that the shape of proof Kernel-0 needs is tractable in Lean 4.34.0 within a bounded session. |
| 2 | **Coq / Rocq** (renamed from Coq; `rocq-prover.org`) | **Best textbook fit for exactly this proof genre.** *Software Foundations*, volume *Programming Language Foundations* (`softwarefoundations.cis.upenn.edu/plf-current/`), formalizes the simply-typed lambda calculus's syntax, small-step semantics, typing, and **proves Progress and Preservation by the same induction structure Kernel-0's paper proof already uses** — this is the field's standard teaching and reference text, actively maintained. | `Print Assumptions <name>.` on each theorem; clean output lists no axioms. Whole-repository sweep: `grep -Ir "Admitted\." .` and `grep -Ir "Axiom" .`, both expected empty — the standard artifact-evaluation check for Coq papers (per Coq-Club mailing list guidance). Independent re-check: `coqchk`, a separate, smaller trusted kernel that re-validates every axiom in the compiled `.vo` files without re-running tactics. | Coq itself needs no network to build a dependency-free project once installed (same one-time-install-vs-per-build split as Lean); `coqchk` is fully offline by construction. **Not verified hands-on this session** — Coq/`coqc`/`coq_makefile` are absent from this host (confirmed directly: `which coqc coq_makefile` returns nothing, matching issue #186's own audit finding on this same host). | Not installed here, so no first-hand size/time measurement. Docker images (`coqorg/coq`) are Debian-11-slim-based with a documented base layer of ~434 MB before adding the ~17 APT packages the full image needs; a real install (OCaml + opam + Coq) is a heavier, longer install than reusing an already-present Lean toolchain on this specific host. | *Software Foundations* PLF is the closest thing to an industry-standard reference for this exact proof (progress/preservation of a small typed calculus), continuously maintained at Penn; POPLmark-lineage work and CompCert both build on the same style. Strongest ecosystem fit of the four for this specific task, at the cost of a fresh install this session did not attempt. |
| 3 | **Isabelle/HOL** | Strong general automation (Sledgehammer) but Isar's structured-proof style is a less direct match for an inductive small-step relation than Coq/Lean/Agda's tactic- or pattern-matching-driven styles. The Archive of Formal Proofs has adjacent entries (`System_F_Normalization`, Berghofer's `HOL-Proofs-Lambda` fundamental lambda-calculus properties shipped in the distribution itself) but no single canonical "STLC progress/preservation" tutorial entry the way Coq/Agda have. | **Notably stricter default than the other three**: `isabelle build`'s default `quick_and_dirty=false` **rejects `sorry` outright at build time** rather than merely warning and continuing — confirmed via the Isabelle NEWS/mailing-list record ("`sorry` is rejected by `isabelle build` as expected, with the default option `quick_and_dirty=false`"). This makes the "no admitted holes" gate close to *automatic*, rather than something a separate script must scan for. | Isabelle's own base distribution is self-contained (no network for a dependency-free theory); AFP entries are fetched separately and are the analogue of Lean's Mathlib-cache-fetch cost. **Not verified hands-on this session** — Isabelle is not installed on this host. | Not installed here. Community Docker CI images run **2.7 GB** (`braewebb/isabelle-action`), the largest of the four measured/cited here; the official distribution bundles a JVM, Poly/ML, and (optionally) a LaTeX toolchain for document generation, which is why the images run large even before any AFP dependency. | Distribution-shipped `HOL-Proofs-Lambda` and AFP's `System_F_Normalization`/case studies on lambda-calculus (Church-Rosser, standardization, HOAS) show the ecosystem has done this class of proof, but scattered across entries rather than one canonical teaching text the way Coq/Agda have. |
| 4 | **Agda** | **Second-best textbook fit.** *Programming Language Foundations in Agda* (PLFA, `plfa.github.io`) is built around exactly this: STLC syntax, small-step semantics, typing, then "the next chapter prov[ing] its main properties, including progress and preservation," and explicitly notes that in a constructive setting "progress and preservation combine trivially to produce ... an evaluator" — the same intrinsic-typing style this document's spike partly borrows (de Bruijn indices to avoid a capture-avoidance lemma). | `--safe` is a single compiler flag, not a post-hoc scan: it **statically disallows** `postulate` (Agda's axiom-declaration form) and unsolved metavariables/incomplete pattern matches *in the same compilation unit*, confirmed against the current Agda manual ("Safe Agda"). This is arguably the cleanest single-flag version of the four — no separate scan step is needed at all. | Agda's core + standard library needs no network for a dependency-free module once installed; same one-time-install split as the other three. **Not verified hands-on this session** — Agda is not installed on this host. | Not installed here; no first-hand size/time measurement obtained this session. | PLFA is the field's other standard teaching reference for this exact proof shape, alongside Coq's *Software Foundations*, and is still actively maintained (2.8.0.2, 13 September 2026, per the Agda release history) with recent releases as of this session's own week. |

### Notes and citations backing the table

- **Lean 4 current release and cadence.** Stable was 4.33.1 (21 Aug 2026);
  the toolchain already installed on this host is 4.34.0 — consistent with
  the documented roughly-monthly cadence (4.30.0 → 4.31.0 → 4.32.0 →
  4.32.1/4.32.2 → 4.33.0/4.33.1, May–Aug 2026) reaching 4.34.0 by mid-September.
  [Release Notes](https://lean-lang.org/doc/reference/latest/releases/),
  [elan CHANGELOG](https://github.com/leanprover/elan/blob/master/CHANGELOG.md).
- **Coq/Rocq.** Renamed from Coq to Rocq; latest Rocq Prover release 9.2.0
  (27 Mar 2026), Rocq Platform 2026.07.0 shipping Rocq 9.1.
  [Rocq Prover releases](https://rocq-prover.org/releases),
  [Rocq Platform 2026.07.0](https://rocq-prover.org/releases/2026.07.0).
- **Isabelle.** Current stable Isabelle2025-2 (Jan 2026); Isabelle2026 is
  scheduled for mid-October 2026, i.e. about a month after this session.
  [Plan for Isabelle2026](https://sketis.net/2025/plan-for-isabelle2026-october-2026),
  [Release Candidates for Isabelle2026](https://sketis.net/2026/release-candidates-for-isabelle2026).
- **Agda.** Latest patch 2.8.0.2 (13 Sep 2026), following 2.8.0.1 (31 Aug
  2026); the 2.9.0 manual is already in progress.
  [Agda User Manual](https://agda.readthedocs.io/_/downloads/en/latest/pdf/).
- **Lean's no-holes mechanism and community CI precedent.**
  [williamjblair/lean-proofs](https://github.com/williamjblair/lean-proofs)
  ("Self-checking index of formal Lean 4 proofs; CI-gated `#print axioms`"),
  [coproduct-opensource/nucleus#2555](https://github.com/coproduct-opensource/nucleus/issues/2555)
  ("Lean trust chain: per-theorem axiom audit, second kernel, lean-action
  migration").
- **Coq's no-holes mechanism.**
  [Coq 8.18 vernacular commands reference](https://rocq-prover.org/doc/V8.18.0/refman/proof-engine/vernacular-commands.html)
  (`Print Assumptions`); Coq-Club mailing list thread on `admit`/`Qed`/
  `Print Assumptions` conventions,
  [difference between `coqchk` and `Print Assumptions`](https://coq-club.inria.narkive.com/rGG4hOfd/difference-between-coqchk-and-print-assumptions).
- **Isabelle's stricter default.** Isabelle2025-2
  [NEWS](https://www.cl.cam.ac.uk/research/hvg/Isabelle/dist/Isabelle2025-2/doc/NEWS.html)
  and mailing-list record of `sorry` rejection under default
  `quick_and_dirty=false`.
- **Agda's `--safe`.**
  [Safe Agda, current manual](https://agda.readthedocs.io/en/latest/language/safe-agda.html).
- **Software Foundations (Coq).**
  [Stlc](https://softwarefoundations.cis.upenn.edu/plf-current/Stlc.html),
  [StlcProp](https://softwarefoundations.cis.upenn.edu/current/plf-current/StlcProp.html).
- **PLFA (Agda).**
  [Lambda](https://plfa.github.io/Lambda/),
  [Properties: Progress and Preservation](https://plfa.github.io/Properties/).
- **Isabelle AFP/distribution evidence.**
  [System_F_Normalization](https://isa-afp.org/entries/System_F_Normalization.html),
  Berghofer's `HOL-Proofs-Lambda`
  [outline](https://isabelle.in.tum.de/library/HOL/HOL-Proofs-Lambda/outline.pdf).
- **Lean's ecosystem gap and community fallback.** Lean Zulip,
  ["Simply Typed Lambda Calculus in mathlib"](https://leanprover-community.github.io/archive/stream/113488-general/topic/Simply.20Typed.20Lambda.20Calculus.20in.20mathlib.html);
  [mdk-aza/type-sysytems-in-lean](https://github.com/mdk-aza/type-sysytems-in-lean).
- **Docker image sizes.**
  [coqorg/coq base layer](https://hub.docker.com/r/coqorg/base) (~434 MB
  base, before packages); Isabelle CI action image
  [braewebb/isabelle-action](https://hub.docker.com/r/braewebb/isabelle-action)
  (2.7 GB).
- **`lean-action`'s own caching guidance** (for the CI-cost estimate above):
  [leanprover/lean-action](https://github.com/leanprover/lean-action) README,
  which documents caching `.lake` via `actions/cache` to avoid re-fetching on
  every run.

### A concrete pitfall the textual half of the gate must avoid

Grepping for the literal word `sorry` is a real, tried instinct — and it is
**wrong on this exact file**: `grep -n sorry proofs/kernel0-lean/Kernel0.lean`
returns **6 hits**, every one of them inside a doc comment discussing the
topic in English prose ("no `sorry`", "for exactly this reason"), and **zero
of them an actual `sorry` tactic invocation** (verified: the file has none).
A textual gate needs to be scoped to real tokens the language's own lexer
would classify as the `sorry` keyword outside a comment/string, or it must
be paired with (and treated as strictly weaker than) the semantic check.
This is exactly why `#print axioms`/`Print Assumptions`/Isabelle's own
build-time rejection/Agda's `--safe` are the *authoritative* checks in the
table above — they operate on elaborated proof terms, not source text, so a
docstring that merely discusses "sorry" cannot fool them.

## Question 2: how the no-admitted-holes gate works, and what it costs

**The gate formulation (Lean 4, the recommended choice), precisely:**

1. Every top-level theorem this session's programme wants to certify has a
   corresponding `#print axioms <fully-qualified name>` command, either in
   the source file itself (as this spike does — see the bottom of
   `proofs/kernel0-lean/Kernel0.lean`) or in a small driver script.
2. Run `lake build` (or `lake env lean --run <file>` for a single file with
   no lakefile). Lean's elaborator both type-checks every proof and, for
   each `#print axioms` command, prints one `info:` line naming the axioms
   that theorem's proof term transitively depends on.
3. **Pass condition**: every printed axiom set is a subset of
   `{propext, Classical.choice, Quot.sound}` (Lean's three standard,
   accepted axioms — this spike needs only the first two, never
   `Classical.choice`, since every proof here is fully constructive) and
   **no line contains `sorryAx`** or any project-specific custom axiom name.
4. **Failure looks like**: a `warning: declaration uses 'sorry'` at
   elaboration time (visible immediately, even before `#print axioms` runs)
   **and** the corresponding `#print axioms` line reading
   `'<name>' depends on axioms: [sorryAx]` (or `[sorryAx, propext, ...]` if
   mixed with otherwise-real dependencies). A CI script's job is simply:
   run the build, capture combined stdout, and `grep -q sorryAx` — a match
   is a hard failure, unconditionally, no matter which theorem it came from.

**Verbatim demonstration of both outcomes, run this session:**

Clean run (the committed spike, from a `rm -rf .lake/build; lake build`,
i.e. a genuine cold rebuild, not an incremental no-op):

```
⚠ [2/3] Built Kernel0 (1.2s)
warning: Kernel0.lean:506:14: `if_pos` has been deprecated: Use `ite_eq_left` instead
warning: Kernel0.lean:511:14: `if_neg` has been deprecated: Use `ite_eq_right` instead
warning: Kernel0.lean:516:16: `dif_pos` has been deprecated: Use `dite_eq_left` instead
warning: Kernel0.lean:523:16: `dif_neg` has been deprecated: Use `dite_eq_right` instead
info: Kernel0.lean:776:0: 'Kernel0.progress_scalarIf' depends on axioms: [propext, Quot.sound]
info: Kernel0.lean:777:0: 'Kernel0.progress_scalarIf_closed' depends on axioms: [propext, Quot.sound]
info: Kernel0.lean:778:0: 'Kernel0.preservation' depends on axioms: [propext, Quot.sound]
info: Kernel0.lean:779:0: 'Kernel0.subst_preserves_type' depends on axioms: [propext, Quot.sound]
info: Kernel0.lean:780:0: 'Kernel0.subst_preserves_type_args' depends on axioms: [propext, Quot.sound]
info: Kernel0.lean:781:0: 'Kernel0.hastype_weaken_right' depends on axioms: [propext]
info: Kernel0.lean:782:0: 'Kernel0.hastype_weaken_right_args' depends on axioms: [propext]
Build completed successfully (3 jobs).
```

(The four `if_pos`/`if_neg`/`dif_pos`/`dif_neg` lines are pre-existing Lean
4.34 deprecation warnings for tactics this proof uses — not errors, not
holes; a later pass could switch to `ite_eq_left`/`ite_eq_right`/
`dite_eq_left`/`dite_eq_right`, left as a cheap, low-priority follow-up
rather than done reflexively mid-spike.)

Failing run, from a **throwaway scratch copy** with one deliberately broken
theorem appended (`theorem deliberately_broken_for_gate_demo : 1 + 1 = 3 := by
sorry`) — never part of the committed file, discarded after this
demonstration:

```
Kernel0.lean:771:8: warning: declaration uses `sorry`
'Kernel0.preservation' depends on axioms: [propext, Quot.sound]
'deliberately_broken_for_gate_demo' depends on axioms: [sorryAx]
```

Both the inline `uses 'sorry'` warning and the `[sorryAx]` axiom line are
present, and the genuinely-proved `Kernel0.preservation` alongside it still
reports clean — proving the gate distinguishes a real hole from a real proof
in the same run, not merely that it can fail somehow.

**Cost, on this host, measured, not estimated:**

- **Wall-clock**: ~1.2–1.3 seconds for a cold `lake build` of the whole
  spike (782 lines) after deleting all build products; incremental reruns
  are faster still. This is small enough that it would not be the long pole
  in any CI job that also runs SEMAPRAX's own Rust test suite.
- **Disk**: 2.7 GB for the Lean 4.34.0 toolchain (already present on this
  host from before this session), plus 4.2 MB for the spike project's own
  source and build artifacts (`du -sh proofs/kernel0-lean`). The toolchain
  figure is the number that matters for a fresh CI runner or Docker image
  layer; it is cacheable (as `lean-action`'s own README documents) so it is
  a one-time-per-runner-image cost, not a per-run one.
- **Network**: zero at build time for this project specifically, confirmed
  by direct measurement (see the offline/hermetic column above) — the 2.7 GB
  is a one-time toolchain-install cost, structurally identical to installing
  any other compiler toolchain, and is exactly the kind of one-time,
  pinned-version setup AGENTS.md's existing Rust toolchain already needs;
  it is not a *build-time* fetch of the kind AGENTS.md's "no build-time
  network access" invariant forbids.

**A CI gate is not added by this document** (per the file lease), but its
shape, if adopted, is: a job stage after the Rust test suite, using a
cached/pinned Lean toolchain image, running `lake build` on `proofs/*/`
(or a future dedicated proofs crate list) and failing on either a non-zero
exit or a `sorryAx`/custom-axiom hit in the combined log — the exact check
demonstrated above, not a new one invented for this document.

### Issue #188 follow-up: seeding real unsoundness, not a dummy theorem

The failing-run demonstration above proves the axiom scan can fail, but its
seed (`theorem deliberately_broken_for_gate_demo : 1 + 1 = 3 := by sorry`)
is a trivial, unrelated theorem appended to the file — it shows the
`sorryAx` check works, not that **Kernel-0's own semantics or typing rules**
can be broken and have the mechanized Progress/Preservation proof itself
reject the break. Issue #188's audit of `scripts/kernel0-lean-gate.py`
called this out by name as the most valuable remaining gap and asked for it
closed. Two genuine unsoundness seeds were injected directly into
`HasType`/`Step`, built with `lake build` (`lake` is on this host via
`~/.elan/bin`, not on the bare `PATH` a plain `which lake` checks), observed
to fail, then reverted — `git diff` confirms the committed file is
byte-identical to before each seed:

1. **Typing-rule unsoundness — `if`'s two branches decoupled to different
   types.** Changed `HasType.ite`'s conclusion from requiring one shared `T`
   for both branches to allowing independent `T1`/`T2`, concluding `T1`
   regardless of `e2`'s real type (a classic if-branch-type-unification bug:
   it lets `if false then 5 else true` type-check as `int`, even though it
   *steps* to `true`). `lake build` failed with a genuine elaboration error,
   not merely a `sorryAx` line, inside `preservation`'s own `iteFalse` case
   — exactly the case this break should hit, and nowhere else that mattered:
   ```
   error: Kernel0.lean:735:46: Type mismatch
     h2
   has type
     HasType P Γ e2✝ T2✝
   but is expected to have type
     HasType P Γ e2✝ T
   ```
   Progress still elaborated (a trichotomy's "steps"/"is a value" outcomes
   never inspect the two branches' types), confirming precisely which
   theorem's proof depends on the broken invariant and which does not.
2. **Operational-semantics unsoundness — an off-by-one `Call`-beta
   substitution base.** Changed `Step.callBeta`'s conclusion from
   `substEnvAt 0 args fd.body` to `substEnvAt 1 args fd.body` (a
   de-Bruijn-index bug of exactly the shape a miscompiled argument-binding
   pass could introduce: parameter 0 is left free instead of substituted,
   and every other parameter binds one index too high). `lake build` failed
   inside `preservation`'s `callBeta` case, the one case that actually
   invokes the substitution lemma at a fixed base:
   ```
   error: Kernel0.lean:764:6: Type mismatch: After simplification, term
     hsub
    has type
     HasType P Γ (substEnvAt 0 args fd'.body) fd'.ret
   but is expected to have type
     HasType P Γ (substEnvAt 1 args fd'.body) fd'.ret
   ```

Both failures are hard `lake build` exit-1 errors at the exact broken proof
case — a stronger catch than the token scan or the `sorryAx` axiom check,
neither of which needed to run to already know the mechanization rejected
these two: `scripts/kernel0-lean-gate.py`'s source-level checks (signature
pin, `sorry`/`admit` scan) stay green through both seeds, since neither
touches a pinned theorem's statement text or introduces a real `sorry`
token — only the build-dependent check catches them, confirming the gate's
own design note that the build/axiom half and the source-level half are
independent, complementary layers, not redundant ones.

For contrast, two lighter seeds confirm the *other* two layers independently,
run both with and without `~/.elan/bin` on `PATH`:

- A real `sorry` swapped in for one `preservation` case's tactic proof
  (`andFalse`) is caught by the token scan alone with no Lean toolchain on
  `PATH` (`real (non-comment, non-string) tactic token(s) found: sorry`,
  gate exit 1), and, with `lake` available, by three independent signals at
  once: the token scan, `sorryAx` in the combined `lake build` output, and
  `Kernel0.preservation`'s own axiom set naming `sorryAx` — the weakest
  seed of the four, correspondingly the easiest to catch.
- Weakening `progress_scalarIf_closed`'s conclusion from a real trichotomy
  to a vacuous `... ∨ True`, proved by `Or.inr (Or.inr (Or.inr True.intro))`,
  **builds cleanly and reports a clean axiom set** (`lake build` OK, 7/7
  axiom-clean) — a bare `lake build` gate would report this as a pass. Only
  the byte-exact signature pin (`PINNED_SIGNATURES` in
  `scripts/kernel0-lean-gate.py`) catches it, exactly the failure mode that
  script's own module doc names as the reason the pin exists.

**A genuine, real (not seeded) fidelity gap surfaced while choosing where to
probe next:** `evalArith`'s `mod` case had no `i64::MIN`/`-1` exclusion,
unlike `div`. The remainder of any integer division is always representable
(`inRange` never rejects it), but the real system faults there anyway
(`i64::MIN % -1` traps on real hardware/Rust the same shared `idiv`
instruction that makes `i64::MIN / -1` trap, confirmed against
`src/kernel_zero/eval.rs`'s `checked_rem` and an already-passing
differential-corpus case). This was not a seeded defect — it was already
in the committed file — so it was fixed rather than reverted: an explicit
`a = i64Min ∧ b = -1` exclusion mirroring `div`'s, requiring **zero** proof
changes, since Progress and Preservation are generic over `evalArith`'s
`Option` shape and never inspect its formula. See `evalArith`'s own doc
comment in `Kernel0.lean` for the full account.

All four seeds above were reverted before commit; only the `mod` fix and
this section are new committed content from this pass.

## Ranked call-graph extension (issue #188)

The same `Kernel0.lean` now derives `CallEdge` from `Program` lookups and a
complete `callTargets` traversal of its existing `Expr`. It counts calls
inside argument lists and all branches, including a syntactically present
branch that execution may never select. A supplied natural rank is a
certificate to check against those edges, never a replacement graph to trust.

Five additional headline theorems are part of the existing gate:

- `call_path_rank_bound`: a length-`n` call path from `f` to `g` obeys
  `n + rank(g) ≤ rank(f)` under `CallGraphRanked`.
- `ranked_call_graph_acyclic`: a path from a function back to itself has
  length zero under that certificate.
- `ranked_call_chain_terminates`: no infinite sequence of call edges exists
  under that certificate.
- `recursive_call_fixture_rejected`: a self-call nested in another call's
  argument cannot have a strict rank, for any proposed rank function.
- `acyclic_call_fixture_ranked`: a concrete ordinary helper call has a
  valid rank, preventing a reject-all definition from satisfying the suite.

`scripts/kernel0-lean-gate.py` keeps its pinned theorem signatures and
no-hole/custom-axiom checks and includes all five names in its axiom audit.
After a successful build it checks the committed
`negative/RecursiveCallGraph.lean`: the fixture tries to certify the recursive
program with constant rank zero, offering `Nat.le_refl 0` at a strict-rank
obligation. The expected kernel rejection is specifically the type mismatch
between `0 ≤ 0` and `0 < 0`; success, a missing import, another error, or an
admitted hole fails this negative control. Its source is pinned (ignoring
comments and surrounding line whitespace). Weakening strict descent to
non-strict descent would admit precisely this forged certificate, while also
breaking the bounded-path proof in the main model.

This extension is **call-chain termination**, not full normalization of
`Step`. It does not yet show that substitution preserves the extracted call
graph or construct a full evaluation decrease measure. It does not emit or
verify a certificate from Rust HIR. The Rust bounded reifier's active-path
cycle refusal is the corresponding implementation discipline, with finite
differential evidence and independent exact-source replay; no theorem connects
the two. The finite scalar Kernel-0 scope, pinned Lean toolchain, zero external
Lean packages, backend non-claims, and self-hosting rung remain unchanged.

An exact-current-worktree local run of
`python3 scripts/kernel0-lean-gate.py --require-kernel` passed all 16 pinned
theorem signatures, the no-hole scan, `lake build`, every theorem's axiom-set
audit, and the forged recursive-certificate rejection control. This is local
proof-build evidence, not a hosted verdict; the older transcripts above remain
historical evidence for their original theorem set.

## Relationship to issue #186

A parallel audit on issue #186 ("Export selected obligations to an external
proof kernel and bind certificates to artifact bytes") found its SMT/Z3
certificate slice complete, but the issue's own required "select one backend
such as Lean, Dafny, Verus, or Coq" acceptance criterion **unmet**, because
none of `lean`, `lean4`, `dafny`, `verus`, `coqc`, `coq_makefile` was
installed on that host when it was checked, and that audit's most recent
comment reclassified the blocker: not "no install authority" (toolchain
installs are approved), but genuinely open questions about **disk headroom**
and whether such a gate can run **hermetically**, per AGENTS.md's ban on
build-time network access. That comment explicitly asked this document to
say whether its recommendation also unblocks #186's backend requirement.

**Direct answer: partially, and specifically.** This document does not
implement any part of #186 (per this task's own instructions) — no HIR
exporter, no `ExternalKernelCapability` implementation, no certificate
parser. What it *does* settle, with first-hand evidence rather than
documentation alone:

- **Lean 4 can be installed on this host and does run fully hermetically
  for a dependency-free project.** This was the open, unanswered half of
  #186's blocker ("bears on whether a proof gate can run hermetically") —
  now answered empirically, not just in principle: see "Offline/hermetic
  story" above.
- **The toolchain is already present** (2.7 GB, pre-existing from before
  this session), so #186's backend work would not need a *second* multi-
  gigabyte install on a host this session's own disk check found had only
  ~10–12 GB free (`df -h /`) — a real, practical argument for Lean over
  installing Coq or Isabelle fresh specifically for #186, independent of
  either language's abstract merits.
- **The "no admitted holes" half of #186's own required tests** ("No-hole/
  no-admit enforcement tests", one of #186's listed required tests) is
  exactly the mechanism demonstrated above, verbatim, in both directions
  (clean and caught).
- **What #186 would still need, on top of this**: a translator from
  SEMAPRAX's HIR (or a `ResolvedFunction`, mirroring `src/kernel_zero.rs`'s
  own admission predicate) to Lean source for the chosen obligation subset;
  a type implementing the existing `ExternalKernelCapability` trait shape
  (the one `Z3SolverCapability` already implements for the SMT slice, per
  #186's own comment history) that shells out to `lake env lean --run` (or
  an equivalent single-file invocation) and parses the combined
  stdout/exit-code exactly as demonstrated above; and the same certificate/
  Assurance-Manifest binding #186 already has working for Z3, reused rather
  than reinvented. None of that is proof-assistant research — it is ordinary
  integration engineering against an interface #186 already has one working
  instance of.
- **What this document does not settle for #186**: whether Lean specifically
  is the right choice *for #186's obligation shape* (pure total scalar/
  record functions with explicit contracts) rather than Kernel-0's shape
  (small-step operational semantics of a whole calculus) — those are
  different proof genres, and #186's own scope (contracts, not
  progress/preservation of an evaluator) may be a better match for an
  auto-active, SMT-backed verifier (Dafny, Verus) than for a general proof
  assistant at all, a question this document's terms of reference (Lean,
  Coq, Isabelle, Agda) did not cover and does not adjudicate.
- Confirmed independently (per that audit's own note, and consistent with
  reading `docs/SEMANTIC-KERNEL-V1.md`'s own text): **Kernel-0 and issue
  #186 are separate efforts.** Kernel-0 is an in-house, non-mechanized paper
  proof plus a differential test against the real interpreter; #186 is
  about exporting obligations to an *external* kernel and binding a
  certificate to artifact bytes. This document's spike mechanizes (part of)
  the former; it does not implement the latter.

## The spike

**Location**: `proofs/kernel0-lean/` — a self-contained Lean 4 project
(`lakefile.toml`, `lean-toolchain` pinned to `leanprover/lean4:v4.34.0`, one
source file `Kernel0.lean`, 782 lines). No external Lean packages
(`packages = []` implicitly, via an empty `[[lean_lib]]`-only manifest), so
it builds and checks with zero network access once the toolchain itself is
present — see "Offline/hermetic story" above.

**What it covers, precisely** (see the file's own module doc comment for the
same inventory in more detail):

- **Full term/type syntax**: `Ty` (`int`/`bool`), the five arithmetic and
  six comparison operators (integer ordering plus equality/inequality on
  either scalar type), and `Expr` with literals, variables (de Bruijn
  indices — chosen so substitution needs no capture-avoidance lemma, the
  same simplification PLFA's intrinsic-style chapter uses), unary/binary
  operators, `if`, `let`, and non-recursive `call` against a fixed function
  table (`FunDef`, `Program`).
- **Partial arithmetic, modeled explicitly** (the corrected form of the
  document's `n1 op n2 = n` gap): `evalArith`/`evalNeg` return `Option Int`,
  `none` exactly at a zero divisor, `i64`-range overflow (including
  `i64::MIN / -1` for `div`, caught by its quotient's own range check with
  no special case needed), or -- since issue #188's seeded-defect audit
  fixed a real, until-then-unnoticed gap here -- the same `i64::MIN`/`-1`
  pair for `mod` too, named explicitly rather than range-derived (the
  mathematical remainder is always representable, so no range check ever
  rejects it, yet the real system faults there anyway: `i64::MIN % -1`
  traps on real hardware/Rust the same shared `idiv` instruction that makes
  `i64::MIN / -1` trap). `Step`'s `arithVal`/`negVal` rules only fire on
  `some` — there is **no rule at all** for the `none` case, mirroring the
  real gap rather than patching around it.
- **`FaultRedex`**: the stuck-but-intended points, closed under the same
  left-to-right congruence contexts `Step` itself uses (a base `Fault`
  nested under an otherwise-steppable form, e.g. `1 + (2 / 0)`, is stuck
  too — this widening was not the first draft; the initial base-case-only
  version was refuted by the Progress proof itself refusing to close on a
  faulting-operand case, which is exactly the kind of thing a paper proof
  has no mechanism to catch).
- **Progress, scalar-and-`if` fragment (`ScalarIf`), fully proved, zero
  `sorry`**: a genuine three-way trichotomy — value, steps, or
  `FaultRedex` — replacing the source document's incomplete two-outcome
  statement.
- **Boolean-comparison alignment, fully proved and headline-gated**:
  `bool == bool` and `bool != bool` each reduce to the expected value on a
  representative pair, while `bool < bool` is impossible to type. This is
  intentionally a boundary suite, not a claim that every comparison operator
  is polymorphic over scalars.
- **Preservation, the *entire* language, fully proved, zero `sorry`**:
  `Let` and non-recursive `Call` included. This needed:
  - `WellFormedProgram`, an invariant this session's own first Lean encoding
    initially omitted the same way the source document's paper `call`
    typing rule does (checking a call's arguments against the callee's
    signature but never requiring the callee's *body* to type-check against
    it) — discovered only because mechanizing `Preservation`'s `Call` case
    left nothing to substitute into without it. Real compilers enforce this
    once, when a `Fn` is resolved; mechanizing is what forced it to be
    named.
  - A substitution lemma (`subst_preserves_type`) generalized over an
    arbitrary context split, since the proof must grow the left part by one
    entry per nested `let`.
  - A context-weakening lemma (`hastype_weaken_right`) and a small fact that
    a *value*'s typing is context-independent (`hastype_value_any_context`)
    — needed because substituting a call's already-typed arguments into a
    callee body typed under a different, larger context is only sound
    because the arguments are values, not arbitrary expressions.
  - Two of these (`subst_preserves_type`/`subst_preserves_type_args`,
    `hastype_weaken_right`/`hastype_weaken_right_args`) are `mutual` pairs,
    not single self-recursive theorems — a real, first-hand-hit boundary of
    Lean 4.34's termination checker, recorded in the file's own comments:
    a single theorem that recurses into a `List Expr` field several
    `induction`/`cases` steps deep inside its own tactic-mode proof reliably
    produced "failed to infer structural recursion," and forcing
    well-founded mode instead left an unprovable `sizeOf` side-goal with no
    membership witness in scope. Splitting the "recurse into this node" and
    "recurse into this node's list of children" halves into a mutually
    recursive pair — mirroring exactly how `substEnvAt` itself was already
    defined via `List.map`, and how Lean's own manual documents this class
    of function — resolved it cleanly, with no `sizeOf`/`decreasing_by`
    machinery needed at all.
- **Added after the original spike**: ranked call-graph path bounds,
  acyclicity, and call-chain termination, as detailed above.
- **Explicitly not covered**: full small-step normalization, any connection
  to the compiler's real HIR (`src/kernel_zero.rs` or otherwise), and the
  native/Wasm backends.

**Verified, not claimed**: every transcript in "Question 2" above was run
this session against the committed file, from a genuine cold rebuild. The
file contains no `sorry`, `admit`, or custom `axiom` — verified both by
`#print axioms` (see above) and by direct inspection (`grep -n sorry`
returns six hits, all inside doc comments discussing the topic in English
prose, zero as an actual tactic — see "A concrete pitfall" above).

## What this does not tell you

A mechanized proof of a nine-construct, effect-free, ownership-free,
non-recursive scalar calculus's type safety is real evidence about exactly
that calculus, and **no more**. Specifically, it does not tell you:

- **Anything about ownership or cleanup.** RFC 0001's exactly-once cleanup
  claim, `CleanupPlan` construction, and its independent replay are
  untouched by this document and this spike. Kernel-0 itself excludes
  ownership by construction (Kernel-1's job, per `docs/SEMANTIC-KERNEL-V1.md`'s
  own gate ladder).
- **Anything about effects or contracts.** `requires`/`ensures`, the `uses`
  effect system, and issue #186's whole subject (exporting contracts to an
  external kernel) are outside Kernel-0's grammar entirely.
- **Anything about the native or Wasm backends**, or the interpreter, for
  that matter. This document mechanizes the *paper calculus* Kernel-0's own
  document states — not a translation from real HIR, and not a claim that
  any backend's generated code matches this calculus's semantics. The
  differential test in `docs/SEMANTIC-KERNEL-V1.md` (interpreter only, one
  seeded corpus) is the only evidence connecting *any* mechanized or
  semi-mechanized artifact to the real compiler, and this document adds
  nothing to that connection.
- **Anything about records, variants, generics, closures, or loops** — all
  excluded from Kernel-0's own grammar, hence from this spike.
- **That the recommended assistant scales to the real language.** Ownership
  linearity, effect rows, and three-backend lowering correctness are each
  substantially harder mechanization problems than a scalar calculus's
  progress/preservation, in every one of the four candidates surveyed
  above — none of this session's evidence bears on that difficulty.

## Cost and risk of going further, honestly

- **This spike**: on the order of a few hours of interactive Lean
  development against a working, already-installed toolchain, most of it
  spent on two Lean-specific mechanics (de-Bruijn substitution bookkeeping,
  and the `mutual`-pair termination fix above) rather than on the
  mathematical content, which is routine once the calculus is fixed.
- **Extending this spike to cover Kernel-0's termination argument** (the
  call-graph acyclicity Progress's proof sketch currently just asserts)
  would need either a well-founded recursion measure over the call graph or
  an explicit finiteness/acyclicity hypothesis threaded through — a
  moderate, bounded addition, not a redesign.
- **Connecting any mechanized calculus to the real compiler** (closing the
  reification *faithfulness* gap `docs/SEMANTIC-KERNEL-V1.md` already names
  as open) is a substantially larger effort: it needs either (a) a verified
  translator from `ResolvedFunction`/HIR into the mechanized syntax, with
  its own correctness proof, or (b) treating the differential test's
  finite-corpus evidence as the bridge and being explicit that it is
  evidence, not proof — which is exactly what `docs/SEMANTIC-KERNEL-V1.md`
  already does and this document does not improve on.
- **Extending to Kernel-1+ (ownership, effects)** is a different order of
  work entirely: mechanizing linear/affine typing and exactly-once cleanup
  in any of the four candidates is a well-studied but genuinely hard
  problem (it is most of what the POPLmark challenge and its many Coq/Agda/
  Lean solutions are about), not an incremental extension of this spike's
  techniques.
- **The honest risk this document itself demonstrates**: even a careful,
  paper-proof-following first encoding attempt silently under-specified an
  invariant (`WellFormedProgram`) that the source document's own paper
  proof also does not state — mechanization caught it only because the
  proof assistant refused to accept an unsubstantiatable claim, exactly the
  property that makes mechanization worth the cost in the first place, and
  exactly the property a "paper, not mechanized" proof cannot offer.
