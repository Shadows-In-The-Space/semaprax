import Kernel0

open Kernel0

-- This deliberately forged certificate must fail with a type mismatch:
-- a constant rank cannot strictly descend around the nested self-call.
-- Weakening CallGraphRanked's strict < to ≤ makes this exact proof compile.
theorem forged_recursive_call_rank :
    CallGraphRanked recursiveCallFixture (fun _ => 0) := by
  intro caller callee edge
  exact Nat.le_refl 0
