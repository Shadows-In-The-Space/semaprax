//! Bounded reachability/model-checking over a declared [`ProtocolSpec`]'s
//! whole transition graph (issue #206 step 6: "optionally model-check
//! bounded traces"), independent of any live `SessionTable`/`Endpoint`.
//!
//! [`ProtocolSpec::validate`] is a closed set of *per-transition* structural
//! checks (unknown state, duplicate label, missing escape at one state,
//! ...). It cannot see two whole-graph properties this module checks
//! instead:
//!
//! 1. A declared state no transition, anywhere in the spec, ever names as a
//!    `Next` target -- an orphan the initial state can never actually
//!    reach, even though the orphan's own outgoing transitions (including
//!    its own required escape) are perfectly well-formed in isolation.
//! 2. A nonterminal state whose only paths loop forever among other
//!    nonterminal states without ever reaching a declared terminal state.
//!    `MissingEscape` only requires *a* state to have *some*
//!    `Cancel`/`Timeout`/`Fail`-kind outgoing transition; nothing in that
//!    single-transition check stops that escape's own `next` from pointing
//!    at another nonterminal state whose own escape points right back --
//!    every state on such a cycle individually satisfies `MissingEscape`
//!    while the cycle as a whole never lets an endpoint actually finish.
//!
//! Both are exhaustive breadth-first search over the declared graph, bounded
//! to `bound` edges so the search is guaranteed to terminate even if a
//! caller's protocol graph itself contains cycles.

use std::collections::{BTreeSet, VecDeque};

use super::spec::{Next, ProtocolSpec, StateId};

/// Why a [`ProtocolSpec`] failed bounded model-checking. Distinct from
/// [`super::spec::SpecError`]: these are whole-graph reachability
/// properties, not a defect local to one transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelCheckError {
    /// `state` is declared in [`ProtocolSpec::states`] but no transition,
    /// transitively from `initial`, ever reaches it within `bound` edges.
    UnreachableState { state: StateId },
    /// `state` is reachable, but no path of at most `bound` further
    /// transitions from it reaches any declared terminal state.
    NoBoundedPathToTerminal { state: StateId, bound: usize },
}

fn successors(spec: &ProtocolSpec, state: StateId) -> Vec<StateId> {
    spec.transitions_from(state)
        .flat_map(|t| match &t.next {
            Next::Then(target) => vec![*target],
            Next::Choice(choices) => choices.iter().map(|(_, target)| *target).collect(),
        })
        .collect()
}

/// The set of states reachable from `start` by at most `bound` transitions,
/// `start` itself included.
fn reachable_within(spec: &ProtocolSpec, start: StateId, bound: usize) -> BTreeSet<StateId> {
    let mut visited = BTreeSet::new();
    visited.insert(start);
    let mut frontier: VecDeque<(StateId, usize)> = VecDeque::new();
    frontier.push_back((start, 0));
    while let Some((state, depth)) = frontier.pop_front() {
        if depth >= bound {
            continue;
        }
        for next in successors(spec, state) {
            if visited.insert(next) {
                frontier.push_back((next, depth + 1));
            }
        }
    }
    visited
}

/// Check both bounded whole-graph properties described in this module's
/// doc, up to `bound` transitions, collecting every defect found rather
/// than stopping at the first.
///
/// `bound` should be at least `spec.states.len()`: an ordinary BFS never
/// needs to revisit a state, so a bound that large makes "not reached
/// within `bound`" mean "not reachable at all," not merely an artifact of
/// too shallow a search.
pub fn check_bounded(spec: &ProtocolSpec, bound: usize) -> Result<(), Vec<ModelCheckError>> {
    let mut errors = Vec::new();

    let reachable = reachable_within(spec, spec.initial, bound);
    for state in &spec.states {
        if !reachable.contains(state) {
            errors.push(ModelCheckError::UnreachableState { state: *state });
        }
    }

    for state in &reachable {
        if spec.terminal.contains(state) {
            continue;
        }
        let onward = reachable_within(spec, *state, bound);
        if !onward.iter().any(|s| spec.terminal.contains(s)) {
            errors.push(ModelCheckError::NoBoundedPathToTerminal {
                state: *state,
                bound,
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
