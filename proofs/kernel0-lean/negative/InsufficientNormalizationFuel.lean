import Kernel0

open Kernel0

-- The two Step witnesses below are genuine.  The forged certificate must
-- nevertheless fail at its exact budget claim: two steps do not fit in one.
theorem forged_one_step_normalization :
    NormalizesWithin acyclicCallFixture (.call 0 []) 1 := by
  refine ⟨.intLit 42, 2, ?_, helper_call_takes_two_steps, Or.inl (.intLit 42)⟩
  exact Nat.le_refl 2
