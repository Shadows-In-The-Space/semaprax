import Kernel0

open Kernel0

/-
Hostile control: the first helper beta replaces one call node with one call
node. Claiming that raw syntax size decreases would erase the exact case the
ranked-beta branch must handle. The kernel must reject the offered `0 < 1`
witness at the normalized `1 < 1` obligation.
-/
theorem forged_helper_beta_structural_decrease :
    nodeCount (.call 1 []) < nodeCount (.call 0 []) := by
  show 1 < 1
  exact Nat.lt_succ_self 0
