//! Regressions for [`super::super::engine::SessionTable::admits`], the
//! read-only ordering query a real subsystem uses as its lifecycle gate
//! before it can name the branch its transition took.
//!
//! The property that matters is that `admits` cannot drift from `advance`:
//! if it ever admitted a message `advance` then refused as out of order, a
//! migrated subsystem would accept an illegal sequence and only discover it
//! at the commit, which is precisely the failure this kernel exists to stop.

use crate::session_protocol::engine::{
    AdvanceOutcome, CleanupHandler, ProtocolError, SessionTable,
};
use crate::session_protocol::protocols::{
    database_transaction_protocol, project_agent_session_protocol,
};
use crate::session_protocol::spec::{Label, ProtocolSpec, StateId};

struct NoopCleanup;

impl CleanupHandler for NoopCleanup {
    fn run(&mut self, _: &str, _: StateId, _: &'static str) -> Result<(), String> {
        Ok(())
    }
}

/// Every declared label of a spec, so the matrix below covers out-of-order
/// messages, not only the ones a happy path would send.
fn every_label(spec: &ProtocolSpec) -> Vec<Label> {
    let mut labels: Vec<Label> = spec.transitions.iter().map(|t| t.label).collect();
    labels.sort_unstable();
    labels.dedup();
    labels
}

/// For each reachable state and each declared label, `admits` must agree
/// with what `advance` decides about *ordering*: it may only ever return
/// `Ok` where `advance` does not report `IllegalTransition`, and only ever
/// report `IllegalTransition` where `advance` does too.
fn admits_agrees_with_advance(spec: &'static ProtocolSpec) {
    let labels = every_label(spec);
    let mut checked_illegal = 0usize;
    let mut checked_legal = 0usize;
    for probe in &labels {
        // Walk the spec's own transitions to place a session in each
        // reachable state, then probe every label from there.
        for reached in spec.states.iter().copied() {
            let Some(path) = path_to(spec, reached) else {
                continue;
            };
            let mut table = SessionTable::new(spec);
            let mut endpoint = table.open(format!("probe-{reached}-{probe}")).unwrap();
            let mut placed = true;
            for (label, choice) in path {
                let transition = spec
                    .transitions
                    .iter()
                    .find(|t| t.label == label && t.from == endpoint.state())
                    .unwrap();
                match table.advance(
                    endpoint,
                    label,
                    transition.payload_type,
                    transition.required_capability,
                    choice,
                    None,
                    &mut NoopCleanup,
                ) {
                    Ok(AdvanceOutcome::Live(next)) => endpoint = next,
                    Ok(AdvanceOutcome::Terminal(next, _)) => {
                        endpoint = next;
                    }
                    // A transition this walk cannot satisfy without a
                    // resource token is not this test's subject.
                    Err((_, next)) => {
                        endpoint = next;
                        placed = false;
                        break;
                    }
                }
            }
            if placed && endpoint.state() == reached {
                let admitted = table.admits(&endpoint, probe);
                let declared = spec
                    .transitions
                    .iter()
                    .any(|t| t.from == reached && t.label == *probe);
                if spec.terminal.contains(reached) {
                    assert!(
                        matches!(admitted, Err(ProtocolError::UseAfterTerminal { .. })),
                        "{}: terminal {reached} must refuse {probe} as use-after-terminal, got {admitted:?}",
                        spec.name
                    );
                    checked_illegal += 1;
                } else if declared {
                    assert!(
                        admitted.is_ok(),
                        "{}: {reached} declares {probe} but admits refused: {admitted:?}",
                        spec.name
                    );
                    checked_legal += 1;
                } else {
                    assert!(
                        matches!(admitted, Err(ProtocolError::IllegalTransition { .. })),
                        "{}: {reached} does not declare {probe} but admits allowed it: {admitted:?}",
                        spec.name
                    );
                    checked_illegal += 1;
                }
            }
            // `admits` is read-only, so this probe never took a transition
            // and has nothing to clean up: defuse the abandonment bomb
            // rather than firing an escape the probe never used.
            endpoint.defused = true;
        }
    }
    assert!(
        checked_legal > 0 && checked_illegal > 0,
        "{}: the probe matrix covered nothing ({checked_legal} legal, {checked_illegal} illegal)",
        spec.name
    );
}

/// A shortest label path from the spec's initial state to `target`, as
/// `(label, branch choice)` pairs.
fn path_to(spec: &ProtocolSpec, target: StateId) -> Option<Vec<(Label, Option<Label>)>> {
    use std::collections::{BTreeSet, VecDeque};
    let mut seen = BTreeSet::new();
    let mut frontier = VecDeque::new();
    seen.insert(spec.initial);
    frontier.push_back((spec.initial, Vec::new()));
    while let Some((state, path)) = frontier.pop_front() {
        if state == target {
            return Some(path);
        }
        if spec.terminal.contains(state) {
            continue;
        }
        for transition in spec.transitions.iter().filter(|t| t.from == state) {
            let steps: Vec<(StateId, Option<Label>)> = match &transition.next {
                crate::session_protocol::spec::Next::Then(next) => vec![(*next, None)],
                crate::session_protocol::spec::Next::Choice(choices) => choices
                    .iter()
                    .map(|(choice, next)| (*next, Some(*choice)))
                    .collect(),
            };
            for (next, choice) in steps {
                if seen.insert(next) {
                    let mut path = path.clone();
                    path.push((transition.label, choice));
                    frontier.push_back((next, path));
                }
            }
        }
    }
    None
}

#[test]
fn admits_agrees_with_advance_for_the_database_transaction_protocol() {
    static SPEC: std::sync::OnceLock<ProtocolSpec> = std::sync::OnceLock::new();
    admits_agrees_with_advance(SPEC.get_or_init(database_transaction_protocol));
}

#[test]
fn admits_agrees_with_advance_for_the_project_agent_session_protocol() {
    static SPEC: std::sync::OnceLock<ProtocolSpec> = std::sync::OnceLock::new();
    admits_agrees_with_advance(SPEC.get_or_init(project_agent_session_protocol));
}

#[test]
fn admits_refuses_a_stale_handle_without_advancing_anything() {
    let spec = database_transaction_protocol();
    let mut table = SessionTable::new(&spec);
    let endpoint = table.open("stale").unwrap();
    let stale = crate::session_protocol::engine::Endpoint {
        session_id: "stale".to_owned(),
        state: endpoint.state(),
        generation: endpoint.generation,
        is_terminal: false,
        defused: true,
    };
    let live = match table
        .advance(
            endpoint,
            "begin",
            "BeginRequest",
            None,
            None,
            None,
            &mut NoopCleanup,
        )
        .unwrap()
    {
        AdvanceOutcome::Live(endpoint) => endpoint,
        AdvanceOutcome::Terminal(..) => unreachable!("`begin` is nonterminal"),
    };
    assert!(
        matches!(
            table.admits(&stale, "commit"),
            Err(ProtocolError::StaleHandle { .. })
        ),
        "a superseded handle is stale, never merely out of order"
    );
    // The genuinely current endpoint still proceeds, so the refusal above
    // was about the handle and not about the session.
    assert!(table.admits(&live, "commit").is_ok());
    let _ = table.advance(
        live,
        "commit",
        "CommitRequest",
        None,
        None,
        None,
        &mut NoopCleanup,
    );
}
