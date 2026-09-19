//! Declared resource claims, and the static refusal of a workflow graph
//! whose concurrent branches claim the same thing.
//!
//! # The failure case this exists for
//!
//! Issue #208 names it directly: "parallel branches can race on shared
//! resources or semantic candidates". [`super::engine::ParallelExecutor`]
//! answers the *execution* half of that by refusing to introduce real
//! concurrency at all — branches run one at a time, in ascending
//! [`StepId`] order, on the one calling thread — so two branches of a run
//! genuinely cannot interleave and cannot race.
//!
//! That is a complete answer for this engine and no answer at all for the
//! workflow author. A graph whose two branches both rewrite the same file,
//! or both claim the same semantic candidate, is a broken workflow whether
//! or not *this* executor happens to serialize them: it says the two
//! branches are independent when they are not, its result depends on the
//! order the engine chose, and the day any host runs those branches
//! anywhere but on one thread, the bug is a race. Serializing execution
//! hides that author error rather than reporting it.
//!
//! So conflict is handled the way this repository handles ownership: as a
//! **declarable property refused before anything runs**, per the invariant
//! that ownership errors are compile-time diagnostics and never backend
//! accidents. A branch declares what it claims; a graph whose concurrent
//! branches claim overlapping resources is refused by
//! [`super::graph::WorkflowGraph::validate`] with
//! [`super::graph::GraphError::ConflictingConcurrentClaims`], surfaced to a
//! user as [`CONFLICT_DIAGNOSTIC_CODE`]. Because
//! [`super::engine::run`] validates before executing, such a graph cannot
//! be run at all — a static refusal, not a runtime race detector that only
//! fires on an unlucky schedule.
//!
//! # What this does not claim
//!
//! Claims are *declared*, so this refuses conflicts an author wrote down.
//! It cannot detect a conflict nobody declared, and nothing here grants a
//! claim any authority: a [`ResourceClaim`] is a name in a graph document,
//! never a lock, a lease, a capability, or permission to touch the thing it
//! names. Declaring `Resource("/etc/passwd")` gives a workflow no more
//! access to that path than declaring nothing does.

use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::Diagnostic;

use super::graph::StepId;

/// Stable diagnostic code for "this workflow graph's concurrent branches
/// claim the same thing". Distinct from the CLI front's own
/// `SPX-Z924`, which covers every other way
/// [`super::graph::WorkflowGraph::validate`] can refuse a graph: a claim
/// conflict is an authoring error about *what two branches do*, not about
/// the graph's structure, and tooling should be able to key on it
/// separately.
pub const CONFLICT_DIAGNOSTIC_CODE: &str = "SPX-Z925";

/// Maximum claims one step may declare. Bounds validation cost the same way
/// [`super::graph::MAX_STEPS`] does, and keeps a hostile document from
/// making conflict detection quadratic in an unbounded per-step set.
pub const MAX_CLAIMS_PER_STEP: usize = 16;

/// What kind of thing a claim names.
///
/// Closed, and deliberately small: these are the two the issue itself
/// names. A claim carries no authority over the thing it names (see the
/// module documentation).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ClaimKind {
    /// A named shared resource — a path, a queue, a lock, a workspace
    /// route. An opaque name to this module: never joined to a filesystem
    /// path, never opened, never resolved.
    Resource,
    /// A named semantic candidate, the other half of the issue's own named
    /// failure case.
    SemanticCandidate,
}

impl ClaimKind {
    /// Stable wire/diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ClaimKind::Resource => "resource",
            ClaimKind::SemanticCandidate => "semantic-candidate",
        }
    }
}

/// One declared claim: a kind plus an opaque name.
///
/// `Ord` is derived over `(kind, name)`, which is what makes conflict
/// detection's "first overlapping claim" a deterministic choice rather than
/// whichever one a hash set happened to yield first.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ResourceClaim {
    pub kind: ClaimKind,
    pub name: String,
}

impl ResourceClaim {
    #[must_use]
    pub fn resource(name: impl Into<String>) -> Self {
        ResourceClaim {
            kind: ClaimKind::Resource,
            name: name.into(),
        }
    }

    #[must_use]
    pub fn semantic_candidate(name: impl Into<String>) -> Self {
        ResourceClaim {
            kind: ClaimKind::SemanticCandidate,
            name: name.into(),
        }
    }
}

/// Every claim a graph's steps declare, keyed by step.
///
/// `BTreeMap`/`BTreeSet` throughout: iteration order is the steps' own
/// ascending order and each step's claims' own sorted order, so every
/// conflict report is a pure function of the declared content and never of
/// insertion order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClaimSet {
    by_step: BTreeMap<StepId, BTreeSet<ResourceClaim>>,
}

impl ClaimSet {
    /// A graph that declares nothing. The default for every existing
    /// workflow: declaring no claims changes nothing about how a graph
    /// validates or runs.
    #[must_use]
    pub fn none() -> Self {
        ClaimSet::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_step.is_empty()
    }

    /// Declares `claim` for `step`. Re-declaring the identical claim for
    /// the same step is a no-op, not a self-conflict: a step never races
    /// itself.
    pub fn declare(&mut self, step: StepId, claim: ResourceClaim) {
        self.by_step.entry(step).or_default().insert(claim);
    }

    /// The claims declared for `step`, or an empty set.
    #[must_use]
    pub fn of(&self, step: StepId) -> Option<&BTreeSet<ResourceClaim>> {
        self.by_step.get(&step)
    }

    /// Every step that declares at least one claim, ascending.
    pub fn declaring_steps(&self) -> impl Iterator<Item = StepId> + '_ {
        self.by_step.keys().copied()
    }

    /// The first step whose declared claim count exceeds
    /// [`MAX_CLAIMS_PER_STEP`], ascending.
    #[must_use]
    pub fn first_over_claim_bound(&self) -> Option<StepId> {
        self.by_step
            .iter()
            .find(|(_, claims)| claims.len() > MAX_CLAIMS_PER_STEP)
            .map(|(step, _)| *step)
    }
}

/// One detected conflict: two steps that run concurrently under `parallel`
/// and both claim `claim`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conflict {
    pub parallel: StepId,
    pub left: StepId,
    pub right: StepId,
    pub claim: ResourceClaim,
}

/// The first conflict among a set of steps that run concurrently, or
/// `None`.
///
/// Deterministic by construction: `concurrent` is a `BTreeSet`, so pairs
/// are examined in ascending `(left, right)` order, and each pair's
/// overlapping claims are examined in the claims' own `Ord` order — the
/// same pair and the same claim are reported on every call for the same
/// input.
#[must_use]
pub fn first_conflict_among(
    claims: &ClaimSet,
    parallel: StepId,
    concurrent: &BTreeSet<StepId>,
) -> Option<Conflict> {
    let ordered: Vec<StepId> = concurrent.iter().copied().collect();
    for (index, left) in ordered.iter().enumerate() {
        let Some(left_claims) = claims.of(*left) else {
            continue;
        };
        for right in &ordered[index + 1..] {
            let Some(right_claims) = claims.of(*right) else {
                continue;
            };
            if let Some(claim) = left_claims.intersection(right_claims).next() {
                return Some(Conflict {
                    parallel,
                    left: *left,
                    right: *right,
                    claim: claim.clone(),
                });
            }
        }
    }
    None
}

/// The user-facing refusal for a detected [`Conflict`], under
/// [`CONFLICT_DIAGNOSTIC_CODE`].
///
/// Names both branches, the parallel step they belong to, and the exact
/// claim — an author cannot act on "this graph has a conflict" without
/// knowing which two branches and over what.
#[must_use]
pub fn conflict_diagnostic(conflict: &Conflict) -> Diagnostic {
    Diagnostic::io(
        CONFLICT_DIAGNOSTIC_CODE,
        format!(
            "workflow graph: parallel step {} runs branches {} and {} concurrently, \
             and both claim {} `{}`; concurrent branches must not claim the same thing",
            conflict.parallel.0,
            conflict.left.0,
            conflict.right.0,
            conflict.claim.kind.as_str(),
            conflict.claim.name
        ),
    )
}

#[cfg(test)]
mod tests;
