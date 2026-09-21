/-
Private finite model of the stable-declaration portion of
`semaprax.graph.v10` used by `src/kernel_zero/graph_projection.rs`.

The model deliberately represents a selected graph as a finite list of nodes.
`project` is driven by an independently supplied, canonical stable-ID
inventory: it finds every requested node, refuses an absent ID, and emits only
the persistent identity and authored call-occurrence list.  Display names,
module locations, and input node order are outside that projected fact.

The theorems below prove an exact boundary property, not the Rust renderer:
every successful projection has *exactly* the requested identity inventory,
and rewrites that preserve each node's stable ID and calls preserve the whole
projection.  The concrete fixture uses the same `app.main`, `math.adjust`,
and `math.pair` identities as the compiler-derived finite fixture in
`src/kernel_zero/graph_projection/source_tests.rs`; that Rust test supplies
the executable source/graph correspondence.  This file neither parses JSON
nor proves source/HIR/graph correspondence, uniqueness admission, ordering,
hash binding, call acyclicity, cleanup semantics, or a general claim about
arbitrary compiler graphs.  No authority is modeled or granted.
-/

namespace Kernel0.GraphProjection

/-- The graph fields which may change without changing a persistent
declaration identity. `calls` retains syntactic authored occurrence order. -/
structure Node where
  stableId : String
  displayName : String
  moduleName : String
  calls : List String
deriving DecidableEq, Repr

/-- The bounded correspondence checker deliberately retains these facts and
does not promote display metadata or locations into declaration identity. -/
structure StableFact where
  stableId : String
  calls : List String
deriving DecidableEq, Repr

def toFact (node : Node) : StableFact :=
  ⟨node.stableId, node.calls⟩

/-- First matching lookup is intentionally partial. The real decoder refuses
duplicate IDs before this finite model is applied; that duplicate-ID admission
check is outside this theorem. -/
def lookupStable (id : String) : List Node → Option Node
  | [] => none
  | node :: rest => if node.stableId = id then some node else lookupStable id rest

theorem lookupStable_result_has_requested_id {id graph node}
    (found : lookupStable id graph = some node) : node.stableId = id := by
  induction graph generalizing node with
  | nil => simp [lookupStable] at found
  | cons head tail ih =>
      simp only [lookupStable] at found
      split at found
      · rename_i equal
        cases found
        exact equal
      · exact ih found

/-- Project exactly the supplied canonical stable-ID inventory. -/
def project : List String → List Node → Option (List StableFact)
  | [], _ => some []
  | id :: ids, graph => do
      let node ← lookupStable id graph
      let rest ← project ids graph
      return toFact node :: rest

/-- Erasing display/module metadata cannot change a projected stable fact. -/
theorem toFact_metadata_irrelevant (id display module display' module' calls) :
    toFact ⟨id, display, module, calls⟩ =
      toFact ⟨id, display', module', calls⟩ := by
  rfl

/-- A successful projection carries the canonical requested identity at every
position -- no display name or node position can substitute for it. -/
theorem project_preserves_exact_inventory {inventory graph facts}
    (accepted : project inventory graph = some facts) :
    facts.map StableFact.stableId = inventory := by
  induction inventory generalizing facts with
  | nil =>
      simp [project] at accepted
      subst facts
      rfl
  | cons id ids ih =>
      unfold project at accepted
      cases lookup : lookupStable id graph with
      | none => simp [lookup] at accepted
      | some node =>
          cases projected : project ids graph with
          | none => simp [lookup, projected] at accepted
          | some rest =>
              simp [lookup, projected] at accepted
              cases accepted
              simp only [List.map_cons]
              change node.stableId :: rest.map StableFact.stableId = id :: ids
              rw [lookupStable_result_has_requested_id lookup]
              exact congrArg (List.cons id) (ih projected)

/-- Rewriting only display/module metadata preserves the lookup result for
each stable ID. This is a finite structural theorem, independent of node
ordering or the renderer. -/
theorem lookupStable_metadata_rewrite (id : String) :
    ∀ (graph : List Node) (rename : String → String) (relocate : String → String),
      (lookupStable id
          (graph.map fun node =>
            Node.mk node.stableId (rename node.displayName)
              (relocate node.moduleName) node.calls)) =
        (lookupStable id graph).map fun node =>
          Node.mk node.stableId (rename node.displayName)
            (relocate node.moduleName) node.calls := by
  intro graph rename relocate
  induction graph with
  | nil => rfl
  | cons node rest ih =>
      simp only [List.map_cons, lookupStable]
      by_cases matched : node.stableId = id
      · simp [matched]
      · simp [matched, ih]

/-- Therefore an accepted projection is invariant under arbitrary display
rename and module relocation; its stable IDs and exact call occurrences are
unchanged. -/
theorem project_metadata_rewrite (inventory : List String) (graph : List Node)
    (rename relocate : String → String) :
    project inventory
        (graph.map fun node =>
          Node.mk node.stableId (rename node.displayName)
            (relocate node.moduleName) node.calls) =
      project inventory graph := by
  induction inventory with
  | nil => rfl
  | cons id ids ih =>
      simp only [project]
      rw [lookupStable_metadata_rewrite]
      cases lookupStable id graph <;> simp [ih, toFact]

/-- Concrete finite counterpart of the real compiler-derived graph fixture.
The Rust fixture independently derives these stable IDs and call occurrences
from exact source before asking Lean to check this theorem. -/
def compilerFixture : List Node :=
  [ ⟨"app.main", "main", "test.graph",
      ["math.pair", "math.adjust", "math.adjust", "math.pair"]⟩
  , ⟨"math.adjust", "adjust", "test.graph", []⟩
  , ⟨"math.pair", "pair", "test.graph", []⟩
  ]

def compilerFixtureInventory : List String :=
  ["app.main", "math.adjust", "math.pair"]

theorem compiler_fixture_projection_exact :
    project compilerFixtureInventory compilerFixture = some
      [ ⟨"app.main", ["math.pair", "math.adjust", "math.adjust", "math.pair"]⟩
      , ⟨"math.adjust", []⟩
      , ⟨"math.pair", []⟩
      ] := by
  rfl

theorem compiler_fixture_rename_move_preserves_projection :
    project compilerFixtureInventory
        (compilerFixture.map fun node =>
          Node.mk node.stableId ("renamed." ++ node.displayName)
            "relocated.graph" node.calls) =
      project compilerFixtureInventory compilerFixture := by
  exact project_metadata_rewrite compilerFixtureInventory compilerFixture
    (fun name => "renamed." ++ name) (fun _ => "relocated.graph")

/-! ## Hole audit

These commands make direct Lean checks report the theorem dependencies. The
source is also a default Lake target; this is not a claim that the older
Kernel0-only gate-owned audit has been extended to this new module. -/

#print axioms Kernel0.GraphProjection.project_preserves_exact_inventory
#print axioms Kernel0.GraphProjection.lookupStable_metadata_rewrite
#print axioms Kernel0.GraphProjection.project_metadata_rewrite
#print axioms Kernel0.GraphProjection.compiler_fixture_projection_exact
#print axioms Kernel0.GraphProjection.compiler_fixture_rename_move_preserves_projection

end Kernel0.GraphProjection
