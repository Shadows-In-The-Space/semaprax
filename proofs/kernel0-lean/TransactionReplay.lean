/-
Private exact-byte replay model for the finite Rust rename/replace-block
witnesses in src/kernel_zero/transaction.rs. No parser, HIR, transaction
semantics, hashing, filesystem, authority, or physical execution is modeled.

The Rust exporter must first run the existing transaction engine against an
immutable admitted Project, then carry both captured and freshly replayed
bytes into this model. The universal results below concern this guard/replay
composition only. Their finite application is not a proof of the exporter,
the engine, old-value classification, or arbitrary compiler transactions.

All byte fields are lists of UInt8, including paths and optional root fields.
Lists retain their exact inventory order. No digest stands in for its bytes.
-/

namespace Kernel0.TransactionReplay

abbrev Bytes := List UInt8

structure SourceBinding where
  projectRevision : Bytes
  workspaceRevision : Bytes
  workspaceManifest : Bytes
  sources : List (Bytes × Bytes)
deriving DecidableEq

structure OutputBinding where
  sources : SourceBinding
  candidate : Bytes
  graph : Bytes
  baseProgramRoot : Bytes
  candidateProgramRoot : Bytes
  baseProgramRootV2 : Option Bytes
  baseProgramRootV3 : Option Bytes
  impact : Bytes
  impactDigest : Bytes
  review : Bytes
  reviewDigest : Bytes
  result : Bytes
  resultDigest : Bytes
  evidence : Bytes
deriving DecidableEq

structure Request where
  base : SourceBinding
  transaction : Bytes
  evidence : Bytes
deriving DecidableEq

structure Witness where
  request : Request
  output : OutputBinding

inductive Verdict where
  | stale | engineRefused | outputDrift | accepted
deriving DecidableEq

/-- This trace bit describes model delegation, not physical evaluation. -/
def delegates (w : Witness) (current : Request) : Bool :=
  decide (current = w.request)

/-- Engine results are opaque observations, never assumed semantically sound. -/
def replay (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding) : Verdict :=
  if current = w.request then
    match engine current with
    | none => .engineRefused
    | some observed => if observed = w.output then .accepted else .outputDrift
  else .stale

theorem delegates_iff (w : Witness) (current : Request) :
    delegates w current = true ↔ current = w.request := by
  simp [delegates]

theorem stale_never_delegates (w : Witness) (current : Request)
    (h : current ≠ w.request) : delegates w current = false := by
  simp [delegates, h]

theorem stale_refused (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding) (h : current ≠ w.request) :
    replay w current engine = .stale := by
  simp [replay, h]

theorem stale_engine_independent (w : Witness) (current : Request)
    (first second : Request → Option OutputBinding) (h : current ≠ w.request) :
    replay w current first = replay w current second := by
  simp [replay, h]

theorem source_drift_refused (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding) (h : current.base ≠ w.request.base) :
    replay w current engine = .stale := by
  apply stale_refused
  intro equal
  exact h (congrArg Request.base equal)

theorem transaction_drift_refused (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding)
    (h : current.transaction ≠ w.request.transaction) :
    replay w current engine = .stale := by
  apply stale_refused
  intro equal
  exact h (congrArg Request.transaction equal)

theorem evidence_drift_refused (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding)
    (h : current.evidence ≠ w.request.evidence) :
    replay w current engine = .stale := by
  apply stale_refused
  intro equal
  exact h (congrArg Request.evidence equal)

theorem replay_accepted_iff (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding) :
    replay w current engine = .accepted ↔
      current = w.request ∧ engine current = some w.output := by
  by_cases inputEqual : current = w.request
  · subst current
    cases observed : engine w.request with
    | none => simp [replay, observed]
    | some output =>
      by_cases outputEqual : output = w.output
      · simp [replay, observed, outputEqual]
      · simp [replay, observed, outputEqual]
  · simp [replay, inputEqual]

theorem reminted_output_refused (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding)
    (h : engine current ≠ some w.output) :
    replay w current engine ≠ .accepted := by
  intro accepted
  exact h ((replay_accepted_iff w current engine).mp accepted).2

theorem accepted_preserves_all_fields (w : Witness) (current : Request)
    (engine : Request → Option OutputBinding)
    (accepted : replay w current engine = .accepted) :
    current.base = w.request.base ∧
    current.transaction = w.request.transaction ∧
    current.evidence = w.request.evidence ∧
    engine current = some w.output := by
  obtain ⟨inputs, output⟩ := (replay_accepted_iff w current engine).mp accepted
  exact ⟨congrArg Request.base inputs, congrArg Request.transaction inputs,
    congrArg Request.evidence inputs, output⟩

end Kernel0.TransactionReplay
