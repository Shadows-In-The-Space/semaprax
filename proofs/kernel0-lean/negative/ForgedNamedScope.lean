import Kernel0

open Kernel0

/- A reference to the outer identity must cross the intervening binding.
The injected defect maps it to the innermost slot, changing its meaning. -/
theorem forged_named_scope :
    lowerNamed [] [8, 7] (.var 7) = some (.var 0) := by
  change some (Expr.var 1) = some (Expr.var 0)
  exact (rfl : some (Expr.var 1) = some (Expr.var 1))
