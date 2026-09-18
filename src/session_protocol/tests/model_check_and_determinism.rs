//! Bounded model-checking and determinism tests for the session-protocol
//! module, split into their own submodule so `tests.rs` stays under this
//! repository's 1500-line-per-file budget (see AGENTS.md, "Repository
//! navigation").
//!
//! A submodule of `tests`, so `use super::*` below brings in everything
//! `tests.rs` already `use`s (the engine/spec/duality/model_check/
//! protocols/capability re-exports) plus its private test helpers
//! (`RecordingCleanup`, `assert_debug_excludes`, ...) -- descendant
//! modules see an ancestor's private items in Rust.

use super::*;

// ---------------------------------------------------------------------
// Bounded model-checking (issue #206 step 6): whole-graph reachability
// properties `ProtocolSpec::validate`'s per-transition checks cannot see.
// ---------------------------------------------------------------------

#[test]
fn both_applied_protocols_model_check_cleanly() {
    let stream = model_stream_protocol();
    let result = check_bounded(&stream, stream.states.len());
    assert_eq!(
        result,
        Ok(()),
        "model_stream_protocol must model-check cleanly"
    );

    let txn = resource_transaction_protocol();
    let result = check_bounded(&txn, txn.states.len());
    assert_eq!(
        result,
        Ok(()),
        "resource_transaction_protocol must model-check cleanly"
    );
}

#[test]
fn an_orphan_state_no_transition_ever_reaches_is_flagged_by_bounded_model_check_but_not_by_static_validate(
) {
    use std::collections::BTreeSet;
    // `Orphan` is, in isolation, a perfectly well-formed nonterminal state:
    // it has an outgoing transition, and that transition is an escape kind,
    // so it satisfies both `DeadEnd` and `MissingEscape` on its own. What it
    // lacks is any transition, anywhere in the spec, that ever names it as
    // a `Next` target -- `ProtocolSpec::validate` has no rule that looks at
    // a state's *inbound* edges at all, so this defect is invisible to it.
    let spec = ProtocolSpec {
        name: "orphan-v1",
        states: BTreeSet::from(["Idle", "Done", "Orphan"]),
        initial: "Idle",
        terminal: BTreeSet::from(["Done"]),
        transitions: vec![
            Transition {
                from: "Idle",
                label: "go",
                kind: Kind::Send,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Done"),
            },
            Transition {
                from: "Idle",
                label: "abort",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Done"),
            },
            Transition {
                from: "Orphan",
                label: "escape",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Done"),
            },
        ],
        cleanup: vec![("Done", vec![])],
    };
    assert_eq!(
        spec.validate(),
        Ok(()),
        "the orphan defect is, by design, invisible to per-transition static validation"
    );

    let errors = check_bounded(&spec, spec.states.len())
        .expect_err("an unreachable declared state must be flagged");
    assert_eq!(
        errors,
        vec![ModelCheckError::UnreachableState { state: "Orphan" }]
    );
}

#[test]
fn an_escape_cycle_that_never_reaches_terminal_is_flagged_by_bounded_model_check() {
    use std::collections::BTreeSet;
    // `A` and `B` each declare a `Cancel`-kind outgoing transition, so each
    // individually satisfies `MissingEscape`. But each escape points at the
    // OTHER nonterminal state instead of at a terminal one, so an endpoint
    // parked in this A/B cycle can "cancel" forever without the session
    // ever actually ending. Only a whole-graph bounded search sees this;
    // `ProtocolSpec::validate` checks one transition's kind in isolation
    // and has no notion of where that transition's own `next` leads.
    let spec = ProtocolSpec {
        name: "escape-cycle-v1",
        states: BTreeSet::from(["Idle", "A", "B", "Done"]),
        initial: "Idle",
        terminal: BTreeSet::from(["Done"]),
        transitions: vec![
            Transition {
                from: "Idle",
                label: "start",
                kind: Kind::Send,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("A"),
            },
            Transition {
                from: "Idle",
                label: "abort",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Done"),
            },
            Transition {
                from: "A",
                label: "to_b",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("B"),
            },
            Transition {
                from: "B",
                label: "to_a",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("A"),
            },
        ],
        cleanup: vec![("Done", vec![])],
    };
    assert_eq!(
        spec.validate(),
        Ok(()),
        "each state's own escape kind satisfies per-transition validation"
    );

    let errors = check_bounded(&spec, spec.states.len())
        .expect_err("a cycle whose only escapes loop among nonterminal states must be flagged");
    assert_eq!(
        errors,
        vec![
            ModelCheckError::NoBoundedPathToTerminal {
                state: "A",
                bound: spec.states.len()
            },
            ModelCheckError::NoBoundedPathToTerminal {
                state: "B",
                bound: spec.states.len()
            },
        ]
    );
}

// ---------------------------------------------------------------------
// Determinism: the identical message/payload/capability sequence against
// two wholly independent `SessionTable`s produces byte-identical results
// at every step -- successful states, a mid-sequence illegal-message
// error, and the final terminal cleanup inventory alike.
// ---------------------------------------------------------------------

#[test]
fn the_same_message_sequence_produces_byte_identical_results_on_independent_runs() {
    fn run_sequence(session_id: &str) -> Vec<String> {
        let spec = resource_transaction_protocol();
        let mut table = SessionTable::new(&spec);
        let mut cleanup = RecordingCleanup::default();
        let mut trace = Vec::new();

        let endpoint = table.open(session_id).unwrap();
        trace.push(format!("{:?}", endpoint.state()));

        let outcome = table
            .advance(
                endpoint,
                "begin",
                "BeginTxn",
                Some("txn.begin"),
                None,
                None,
                &mut cleanup,
            )
            .unwrap();
        let AdvanceOutcome::Live(endpoint) = outcome else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        let outcome = table
            .advance(
                endpoint,
                "read",
                "ReadOp",
                Some("txn.read"),
                None,
                None,
                &mut cleanup,
            )
            .unwrap();
        let AdvanceOutcome::Live(endpoint) = outcome else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        // A deliberately illegal message mid-sequence (commit is not
        // declared from AwaitingRead): its exact rendered error is itself
        // part of the reproduced trace, not only the eventually-successful
        // path.
        let (err, endpoint) = table
            .advance(
                endpoint,
                "commit",
                "Commit",
                Some("txn.commit"),
                None,
                None,
                &mut cleanup,
            )
            .expect_err("commit is illegal while a read call is in flight");
        trace.push(format!("{err:?}"));

        let outcome = table
            .advance(
                endpoint,
                "read_result",
                "ReadResult",
                None,
                None,
                None,
                &mut cleanup,
            )
            .unwrap();
        let AdvanceOutcome::Live(endpoint) = outcome else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        let token = ResourceToken {
            id: format!("{session_id}-token"),
        };
        let outcome = table
            .advance(
                endpoint,
                "commit",
                "Commit",
                Some("txn.commit"),
                None,
                Some(&token),
                &mut cleanup,
            )
            .unwrap();
        let AdvanceOutcome::Terminal(endpoint, terminal) = outcome else {
            panic!("expected terminal")
        };
        drop(endpoint);
        trace.push(format!("{terminal:?}"));
        trace
    }

    let a = run_sequence("determinism-a");
    let b = run_sequence("determinism-b");
    // The two session ids differ deliberately -- `SessionTable::open`
    // refuses a second open of the SAME id (see
    // `duplicate_open_is_refused_distinctly`), so two truly independent
    // runs of an identical sequence necessarily use different ids. Factor
    // that one caller-chosen difference back out before comparing: the
    // property under test is that the rest of the trace -- every state,
    // the illegal-message error, and the terminal cleanup inventory -- is
    // byte-identical once the id itself is normalized away.
    let normalize = |trace: Vec<String>, id: &str| -> Vec<String> {
        trace
            .into_iter()
            .map(|line| line.replace(id, "<session>"))
            .collect()
    };
    assert_eq!(
        normalize(a, "determinism-a"),
        normalize(b, "determinism-b"),
        "the identical message sequence must produce byte-identical results"
    );
}
