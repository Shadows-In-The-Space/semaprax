//! Tests for [`project_agent_session_protocol`], a transcription of the
//! real, already-shipped `Session`/`SessionState` state machine in
//! `src/project_transport/session.rs` rather than a scenario invented for
//! this kernel (see that function's doc comment for the exact file:line
//! correspondence table). A submodule of `tests`, so `use super::*` brings
//! in everything `tests.rs` already imports plus its private helpers
//! (`RecordingCleanup`, ...) -- descendant modules see an ancestor's
//! private items in Rust.
//!
//! This file's own defect class, distinct from every other fixture this
//! module already tests: every previous applied protocol
//! (`model_stream_protocol`, `resource_transaction_protocol`) was written
//! *for* this kernel. Every prior audit of issue #206 named "no existing
//! subsystem has been migrated onto this mechanism" as the one structural
//! gap the reference layer could not close by itself. This protocol is
//! still not a live migration -- `project_transport::session`'s fields and
//! dispatch methods stay private, and it still performs its own hand-rolled
//! checks rather than calling into `SessionTable` -- but it is the first
//! protocol here whose states and topology are *evidence*, cited against
//! real code, rather than *invention*.

use super::*;
use crate::session_protocol::protocols::project_agent_session_protocol;

// ---------------------------------------------------------------------
// Static shape: the transcription itself is well-formed and every state
// is reachable with a bounded path back to a terminal.
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_protocol_validates_and_model_checks_cleanly() {
    let spec = project_agent_session_protocol();
    assert_eq!(spec.validate(), Ok(()));
    assert_eq!(check_bounded(&spec, spec.states.len()), Ok(()));
    // Exactly the real `SessionState` enum's eight variants -- no state
    // invented, none dropped.
    assert_eq!(spec.states.len(), 8);
}

// ---------------------------------------------------------------------
// Happy path: Configured -> Open -> Prepared -> Applying -> Open ->
// Shutdown, exercising `Send`, `Call`, `Return`, and a `Cancel`-kind
// universal escape, with the checkpoint rule enforced across the one
// genuinely pending operation (`apply`).
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_happy_path_commits_and_shuts_down_with_declared_cleanup_in_order() {
    let spec = project_agent_session_protocol();
    let mut table = SessionTable::new(&spec);
    let mut cleanup = RecordingCleanup::default();

    let endpoint = table.open("agent-session-1").unwrap();
    assert_eq!(endpoint.state(), "Configured");

    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "open",
            "OpenRequest",
            Some("project.open"),
            Some("opened"),
            None,
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    assert_eq!(endpoint.state(), "Open");

    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "rename_preview",
            "RenamePreviewRequest",
            Some("project.rename.preview"),
            Some("prepared"),
            None,
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    assert_eq!(endpoint.state(), "Prepared");

    let token = ResourceToken {
        id: "agent-session-1-a0".to_owned(),
    };
    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "apply",
            "ApplyRequest",
            Some("project.apply"),
            None,
            Some(&token),
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    assert_eq!(endpoint.state(), "Applying");
    assert!(!endpoint.is_terminal());

    // The commit boundary the real `apply_with_runtime` straddles
    // (`session/rename.rs:259` sets `Applying` immediately before staging
    // the A0 commit) is exactly the window `checkpoint` must refuse to
    // resume through: whether the physical effect actually completed is
    // uncertain until the matching `Return` is recorded.
    assert_eq!(
        table.checkpoint(&endpoint),
        Err(CheckpointError::InFlightCall { label: "apply" })
    );

    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "apply_resolved",
            "ApplyResult",
            None,
            Some("committed"),
            None,
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    assert_eq!(endpoint.state(), "Open");
    // Settled again: checkpointing now succeeds.
    assert_eq!(
        table.checkpoint(&endpoint),
        Ok(Checkpoint {
            session_id: "agent-session-1".to_owned(),
            state: "Open",
            generation: endpoint.generation,
        })
    );

    let AdvanceOutcome::Terminal(endpoint, terminal) = table
        .advance(endpoint, "shutdown", "Unit", None, None, None, &mut cleanup)
        .unwrap()
    else {
        panic!("expected terminal")
    };
    assert_eq!(terminal.terminal_state, "Shutdown");
    assert_eq!(terminal.terminal_kind, Kind::Cancel);
    // Cleanup ran in exactly the declared, un-sorted order.
    assert_eq!(terminal.cleanup, vec![("finish_authority", Ok(()))]);
    drop(endpoint);
}

// ---------------------------------------------------------------------
// "Correct order but no authority": reaching `Prepared` in the exactly
// right order never by itself grants permission to `apply`.
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_apply_without_capability_is_refused_even_in_correct_order() {
    let spec = project_agent_session_protocol();
    let mut table = SessionTable::new(&spec);
    let mut cleanup = RecordingCleanup::default();
    let endpoint = drive_to_prepared(&mut table, "agent-session-cap", &mut cleanup);

    let token = ResourceToken {
        id: "agent-session-cap-a0".to_owned(),
    };
    let (err, endpoint) = table
        .advance(
            endpoint,
            "apply",
            "ApplyRequest",
            None,
            None,
            Some(&token),
            &mut cleanup,
        )
        .expect_err("apply without the declared capability must be refused");
    assert_eq!(
        err,
        ProtocolError::MissingAuthority {
            session_id: "agent-session-cap".to_owned(),
            label: "apply",
            required: "project.apply",
        }
    );
    assert_eq!(
        endpoint.state(),
        "Prepared",
        "a failed apply never moves the session"
    );

    // The same order, the same payload, the same token, only the missing
    // capability supplied: now it succeeds.
    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "apply",
            "ApplyRequest",
            Some("project.apply"),
            None,
            Some(&token),
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    assert_eq!(endpoint.state(), "Applying");
    endpoint.discard_for_test();
}

// ---------------------------------------------------------------------
// The commit boundary itself: `apply` moves ownership of a caller-
// presented resource, so committing without one is refused exactly the
// way `resource_transaction_protocol`'s own commit is.
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_apply_without_a_resource_token_is_refused() {
    let spec = project_agent_session_protocol();
    let mut table = SessionTable::new(&spec);
    let mut cleanup = RecordingCleanup::default();
    let endpoint = drive_to_prepared(&mut table, "agent-session-token", &mut cleanup);

    let (err, endpoint) = table
        .advance(
            endpoint,
            "apply",
            "ApplyRequest",
            Some("project.apply"),
            None,
            None,
            &mut cleanup,
        )
        .expect_err("apply consumes a resource token and must refuse a missing one");
    assert_eq!(
        err,
        ProtocolError::ResourceTokenRequired {
            session_id: "agent-session-token".to_owned(),
            label: "apply",
        }
    );

    let token = ResourceToken {
        id: "agent-session-token-a0".to_owned(),
    };
    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "apply",
            "ApplyRequest",
            Some("project.apply"),
            None,
            Some(&token),
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    endpoint.discard_for_test();
}

// ---------------------------------------------------------------------
// Invalid order: skipping straight to `apply` from `Open` is illegal
// (the real `apply_with_runtime` gates on `self.state != Prepared`,
// `session/rename.rs:161`) -- rejected before any runtime effect, exactly
// the criterion "invalid order is rejected before runtime" asks for.
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_apply_out_of_order_from_open_is_refused_distinctly() {
    let spec = project_agent_session_protocol();
    let mut table = SessionTable::new(&spec);
    let mut cleanup = RecordingCleanup::default();

    let endpoint = table.open("agent-session-order").unwrap();
    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "open",
            "OpenRequest",
            Some("project.open"),
            Some("opened"),
            None,
            &mut cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    assert_eq!(endpoint.state(), "Open");

    let token = ResourceToken {
        id: "agent-session-order-a0".to_owned(),
    };
    let (err, endpoint) = table
        .advance(
            endpoint,
            "apply",
            "ApplyRequest",
            Some("project.apply"),
            None,
            Some(&token),
            &mut cleanup,
        )
        .expect_err("apply is not declared from Open");
    assert_eq!(
        err,
        ProtocolError::IllegalTransition {
            session_id: "agent-session-order".to_owned(),
            state: "Open",
            label: "apply",
        }
    );
    // Distinct from a capability or token refusal: the message itself is
    // out of order, independent of what was presented alongside it.
    assert!(!matches!(err, ProtocolError::MissingAuthority { .. }));
    endpoint.discard_for_test();
}

// ---------------------------------------------------------------------
// The real session's most distinctive topological feature next to the
// two invented fixtures: `shutdown` is a state-INDEPENDENT escape. Every
// call site in `session.rs`/`dispatch` sets `SessionState::Shutdown`
// unconditionally, with no guard on `self.state` -- confirmed here from
// three different starting states, including the "stuck but not
// terminal" `Invalidated` state.
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_shutdown_is_a_universal_escape_from_every_waiting_state() {
    let spec = project_agent_session_protocol();

    for from in ["Configured", "Open", "Prepared", "Invalidated"] {
        let mut table = SessionTable::new(&spec);
        let mut cleanup = RecordingCleanup::default();
        let session_id = format!("agent-session-shutdown-{from}");
        let endpoint = drive_to_state(&mut table, &session_id, from, &mut cleanup);
        let AdvanceOutcome::Terminal(endpoint, terminal) = table
            .advance(endpoint, "shutdown", "Unit", None, None, None, &mut cleanup)
            .unwrap()
        else {
            panic!("shutdown from {from} must reach a terminal outcome")
        };
        assert_eq!(terminal.terminal_state, "Shutdown");
        drop(endpoint);
    }
}

// ---------------------------------------------------------------------
// Hostile/malformed shape: take the REAL transcribed protocol -- not a
// synthetic toy spec -- and corrupt exactly the one transition this
// module's own doc comment names as unevidenced by real code
// (`apply_timeout`, `Applying`'s only declared escape). The mutated spec
// must be refused with the specific defect, never silently repaired or
// accepted with the escape simply absent.
// ---------------------------------------------------------------------

#[test]
fn removing_applyings_only_escape_from_the_real_transcription_is_refused_not_repaired() {
    let mut spec = project_agent_session_protocol();
    assert_eq!(
        spec.validate(),
        Ok(()),
        "control: the unmodified transcription validates cleanly"
    );

    spec.transitions.retain(|t| t.label != "apply_timeout");
    let errors = spec
        .validate()
        .expect_err("Applying with no Cancel/Timeout/Fail transition must be refused");
    assert_eq!(errors, vec![SpecError::MissingEscape { state: "Applying" }]);
    // Never conflated with the unrelated dead-end check: `Applying` still
    // has its `apply_resolved` `Return`, so it is not also a `DeadEnd`.
    assert!(!errors.contains(&SpecError::DeadEnd { state: "Applying" }));
}

// ---------------------------------------------------------------------
// Determinism: the identical message sequence against two independent
// `SessionTable`s over this real-subsystem transcription produces
// byte-identical traces, exactly the property
// `the_same_message_sequence_produces_byte_identical_results_on_independent_runs`
// already proves for `resource_transaction_protocol` -- this is the same
// property re-asserted for a protocol built from evidence rather than
// invention, not a new mechanism.
// ---------------------------------------------------------------------

#[test]
fn project_agent_session_determinism_across_independent_runs() {
    fn run_sequence(session_id: &str) -> Vec<String> {
        let spec = project_agent_session_protocol();
        let mut table = SessionTable::new(&spec);
        let mut cleanup = RecordingCleanup::default();
        let mut trace = Vec::new();

        let endpoint = table.open(session_id).unwrap();
        trace.push(format!("{:?}", endpoint.state()));

        let AdvanceOutcome::Live(endpoint) = table
            .advance(
                endpoint,
                "open",
                "OpenRequest",
                Some("project.open"),
                Some("opened"),
                None,
                &mut cleanup,
            )
            .unwrap()
        else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        // A deliberately illegal message mid-sequence: `change_preview` is
        // not declared from `Open` (it needs `Derived`). Its exact
        // rendered error is itself part of the reproduced trace.
        let (err, endpoint) = table
            .advance(
                endpoint,
                "change_preview",
                "ChangePreviewRequest",
                Some("project.change.preview"),
                Some("prepared"),
                None,
                &mut cleanup,
            )
            .expect_err("change_preview is illegal directly from Open");
        trace.push(format!("{err:?}"));

        let AdvanceOutcome::Live(endpoint) = table
            .advance(
                endpoint,
                "rename_derive",
                "RenameDeriveRequest",
                Some("project.rename.derive"),
                Some("derived"),
                None,
                &mut cleanup,
            )
            .unwrap()
        else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        let AdvanceOutcome::Live(endpoint) = table
            .advance(
                endpoint,
                "change_preview",
                "ChangePreviewRequest",
                Some("project.change.preview"),
                Some("prepared"),
                None,
                &mut cleanup,
            )
            .unwrap()
        else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        let token = ResourceToken {
            id: format!("{session_id}-a0"),
        };
        let AdvanceOutcome::Live(endpoint) = table
            .advance(
                endpoint,
                "apply",
                "ApplyRequest",
                Some("project.apply"),
                None,
                Some(&token),
                &mut cleanup,
            )
            .unwrap()
        else {
            panic!("expected live")
        };
        trace.push(format!("{:?}", endpoint.state()));

        let AdvanceOutcome::Terminal(endpoint, terminal) = table
            .advance(
                endpoint,
                "apply_resolved",
                "ApplyResult",
                None,
                Some("uncertain"),
                None,
                &mut cleanup,
            )
            .unwrap()
        else {
            panic!("expected terminal")
        };
        drop(endpoint);
        trace.push(format!("{terminal:?}"));
        trace
    }

    let a = run_sequence("determinism-project-a");
    let b = run_sequence("determinism-project-b");
    let normalize = |trace: Vec<String>, id: &str| -> Vec<String> {
        trace
            .into_iter()
            .map(|line| line.replace(id, "<session>"))
            .collect()
    };
    assert_eq!(
        normalize(a, "determinism-project-a"),
        normalize(b, "determinism-project-b"),
        "the identical message sequence must produce byte-identical results"
    );
}

// ---------------------------------------------------------------------
// Shared drivers.
// ---------------------------------------------------------------------

fn drive_to_prepared(
    table: &mut SessionTable<'_>,
    session_id: &str,
    cleanup: &mut RecordingCleanup,
) -> Endpoint {
    drive_to_state(table, session_id, "Prepared", cleanup)
}

/// Open a fresh session and advance it to exactly `target` (one of
/// `"Configured"`, `"Open"`, `"Prepared"`, `"Invalidated"`) using the
/// shortest legal path this protocol declares.
fn drive_to_state(
    table: &mut SessionTable<'_>,
    session_id: &str,
    target: &str,
    cleanup: &mut RecordingCleanup,
) -> Endpoint {
    let endpoint = table.open(session_id).unwrap();
    if target == "Configured" {
        return endpoint;
    }
    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "open",
            "OpenRequest",
            Some("project.open"),
            Some("opened"),
            None,
            cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    if target == "Open" {
        return endpoint;
    }
    if target == "Invalidated" {
        // Selecting the `"invalidated"` branch is itself a legal, declared
        // choice at the engine level -- `SessionTable` checks message order
        // and declared shape, not the caller's business-level meaning of a
        // choice label -- so this succeeds and lands on `Invalidated`,
        // exactly the way the real `open()` lands there on an invalidating
        // diagnostic (`session.rs:406-408`).
        let AdvanceOutcome::Live(endpoint) = table
            .advance(
                endpoint,
                "open",
                "OpenRequest",
                Some("project.open"),
                Some("invalidated"),
                None,
                cleanup,
            )
            .unwrap()
        else {
            panic!("expected live")
        };
        return endpoint;
    }
    let AdvanceOutcome::Live(endpoint) = table
        .advance(
            endpoint,
            "rename_preview",
            "RenamePreviewRequest",
            Some("project.rename.preview"),
            Some("prepared"),
            None,
            cleanup,
        )
        .unwrap()
    else {
        panic!("expected live")
    };
    debug_assert_eq!(target, "Prepared");
    endpoint
}
