//! Continuation duality: the checks that make two roles agree on *where a
//! message leaves them*, not only on the message itself.
//!
//! Before this submodule, `check_duality` compared each matched
//! `(state, label)` pair's kind, payload tag and required capability, and
//! nothing else. Two consequences, both exercised below as refusals:
//!
//! - A pair could be declared compatible while one role may **select a
//!   branch the peer never offers** -- the peer simply has no case for a
//!   continuation the sender can legally choose.
//! - A pair could be declared compatible while the same message lands the
//!   two roles in **different next states**, so the compatibility proof
//!   holds for exactly one message and the roles then read their legal
//!   continuations from disagreeing states.
//!
//! Ownership movement was likewise uncompared, leaving
//! `OwnershipMove::ConsumesResource` on one side alone invisible to a check
//! that already compared payload and capability.
//!
//! A submodule of `tests`, so `use super::*` brings in everything `tests.rs`
//! already imports plus its private helpers (`assert_debug_excludes`).

use super::*;

// ---------------------------------------------------------------------
// Fixtures: a branching client and its dual server. The client *selects*
// (`Send`) and the server *offers* (`Receive`), which is what makes the
// branch-offering rule directional rather than an equality test.
// ---------------------------------------------------------------------

fn branching_client() -> ProtocolSpec {
    use std::collections::BTreeSet;
    ProtocolSpec {
        name: "branching-client-v1",
        states: BTreeSet::from(["Idle", "AwaitingReply", "Done", "Aborted"]),
        initial: "Idle",
        terminal: BTreeSet::from(["Done", "Aborted"]),
        transitions: vec![
            Transition {
                from: "Idle",
                label: "request",
                kind: Kind::Send,
                payload_type: "Req",
                required_capability: Some("svc.request"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![("accepted", "AwaitingReply"), ("rejected", "Aborted")]),
            },
            Transition {
                from: "Idle",
                label: "cancel",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Aborted"),
            },
            Transition {
                from: "AwaitingReply",
                label: "reply",
                kind: Kind::Receive,
                payload_type: "Rep",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Done"),
            },
            Transition {
                from: "AwaitingReply",
                label: "cancel",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Aborted"),
            },
        ],
        cleanup: vec![("Done", vec![]), ("Aborted", vec![])],
    }
}

fn branching_server_dual_of(client: &ProtocolSpec) -> ProtocolSpec {
    let mut server = client.clone();
    server.name = "branching-server-v1";
    for t in &mut server.transitions {
        t.kind = match t.kind {
            Kind::Send => Kind::Receive,
            Kind::Receive => Kind::Send,
            other => other,
        };
    }
    server
}

/// Replace the `next` of the one transition matching `(state, label)`.
fn retarget(spec: &mut ProtocolSpec, state: StateId, label: Label, next: Next) {
    let t = spec
        .transitions
        .iter_mut()
        .find(|t| t.from == state && t.label == label)
        .expect("fixture must contain the transition this test rewrites");
    t.next = next;
}

// ---------------------------------------------------------------------
// The fixtures are themselves well-formed, so no refusal below can be an
// artifact of a malformed declaration.
// ---------------------------------------------------------------------

#[test]
fn the_branching_fixtures_are_well_formed_and_model_check_cleanly() {
    for spec in [
        branching_client(),
        branching_server_dual_of(&branching_client()),
    ] {
        assert_eq!(
            spec.validate(),
            Ok(()),
            "fixture {} must validate",
            spec.name
        );
        assert_eq!(
            check_bounded(&spec, spec.states.len()),
            Ok(()),
            "fixture {} must model-check",
            spec.name
        );
    }
}

#[test]
fn a_dual_branching_pair_is_compatible() {
    let client = branching_client();
    let server = branching_server_dual_of(&client);
    assert_eq!(check_duality(&client, &server), Ok(()));
}

// ---------------------------------------------------------------------
// A branch the peer never offers.
// ---------------------------------------------------------------------

#[test]
fn a_branch_the_peer_never_offers_is_refused_distinctly() {
    let client = branching_client();
    let mut server = branching_server_dual_of(&client);
    // The server still branches two ways from `Idle` on `request` -- it is
    // a perfectly valid spec -- but it has no case for the *selector's*
    // "rejected". Kind-complementarity, payload and capability all still
    // match exactly, so nothing but the new check can catch this.
    retarget(
        &mut server,
        "Idle",
        "request",
        Next::Choice(vec![("accepted", "AwaitingReply"), ("refused", "Aborted")]),
    );
    assert_eq!(
        server.validate(),
        Ok(()),
        "the peer spec must stay well-formed, so the refusal is about duality alone"
    );

    let errors = check_duality(&client, &server).expect_err("an unoffered branch must be flagged");
    assert!(
        errors.iter().any(|e| matches!(
            e,
            DualityError::BranchNotOffered {
                state: "Idle",
                label: "request",
                choice: "rejected",
            }
        )),
        "expected BranchNotOffered for the selector's own choice, got {errors:?}"
    );
    for e in &errors {
        assert_debug_excludes(
            e,
            &[
                "MissingCounterpart",
                "KindNotComplementary",
                "PayloadDivergence",
                "CapabilityDivergence",
                "ContinuationShapeDivergence",
            ],
        );
    }
}

#[test]
fn an_offering_peer_with_extra_branches_stays_compatible() {
    let client = branching_client();
    let mut server = branching_server_dual_of(&client);
    // The receiving role has a case the sender can never select. That is
    // safe, and refusing it would make the rule an equality test rather
    // than the subset rule it is documented to be. Without this test,
    // `a_branch_the_peer_never_offers_is_refused_distinctly` would also
    // pass under a naive "the two choice sets differ" implementation.
    retarget(
        &mut server,
        "Idle",
        "request",
        Next::Choice(vec![
            ("accepted", "AwaitingReply"),
            ("rejected", "Aborted"),
            ("deferred", "Aborted"),
        ]),
    );
    assert_eq!(check_duality(&client, &server), Ok(()));
}

#[test]
fn an_escape_branch_is_required_on_both_sides_because_escapes_are_symmetric() {
    // `Cancel`/`Timeout`/`Fail` are the same kind on both roles: neither is
    // "the receiver", so the subset rule applied in each direction by
    // `check_duality` amounts to set equality. Each side here offers one
    // branch the other does not, and both must be reported.
    let mut client = branching_client();
    retarget(
        &mut client,
        "Idle",
        "cancel",
        Next::Choice(vec![("local", "Aborted"), ("remote", "Done")]),
    );
    let mut server = branching_server_dual_of(&client);
    retarget(
        &mut server,
        "Idle",
        "cancel",
        Next::Choice(vec![("local", "Aborted"), ("peer", "Done")]),
    );

    let errors = check_duality(&client, &server).expect_err("escape branches must agree both ways");
    for missing in ["remote", "peer"] {
        assert!(
            errors.iter().any(|e| matches!(
                e,
                DualityError::BranchNotOffered {
                    state: "Idle",
                    label: "cancel",
                    choice,
                } if *choice == missing
            )),
            "expected BranchNotOffered for {missing:?} in {errors:?}"
        );
    }
}

// ---------------------------------------------------------------------
// Divergent continuations: same message, different landing state.
// ---------------------------------------------------------------------

#[test]
fn a_divergent_then_target_is_refused_distinctly_from_a_missing_counterpart() {
    let client = branching_client();
    let mut server = branching_server_dual_of(&client);
    // The counterpart exists, its kind is complementary, its payload and
    // capability match -- it simply leaves the server somewhere else.
    retarget(&mut server, "AwaitingReply", "reply", Next::Then("Aborted"));

    let errors =
        check_duality(&client, &server).expect_err("a divergent continuation must be flagged");
    assert!(
        errors.iter().any(|e| matches!(
            e,
            DualityError::ContinuationDivergence {
                state: "AwaitingReply",
                label: "reply",
                choice: None,
                a: "Done",
                b: "Aborted",
            }
        )),
        "expected ContinuationDivergence with no choice label, got {errors:?}"
    );
    for e in &errors {
        assert_debug_excludes(
            e,
            &[
                "MissingCounterpart",
                "KindNotComplementary",
                "PayloadDivergence",
                "CapabilityDivergence",
                "BranchNotOffered",
                "ContinuationShapeDivergence",
            ],
        );
    }
}

#[test]
fn a_shared_branch_landing_in_different_states_is_refused_distinctly_from_an_unoffered_branch() {
    let client = branching_client();
    let mut server = branching_server_dual_of(&client);
    // Both sides offer exactly "accepted" and "rejected", so no branch is
    // unoffered; they disagree only on where "accepted" leads.
    retarget(
        &mut server,
        "Idle",
        "request",
        Next::Choice(vec![("accepted", "Done"), ("rejected", "Aborted")]),
    );

    let errors =
        check_duality(&client, &server).expect_err("a divergent branch target must be flagged");
    assert!(
        errors.iter().any(|e| matches!(
            e,
            DualityError::ContinuationDivergence {
                state: "Idle",
                label: "request",
                choice: Some("accepted"),
                a: "AwaitingReply",
                b: "Done",
            }
        )),
        "expected ContinuationDivergence naming the branch, got {errors:?}"
    );
    for e in &errors {
        assert_debug_excludes(e, &["BranchNotOffered", "ContinuationShapeDivergence"]);
    }
}

#[test]
fn a_continuation_shape_mismatch_is_refused_distinctly_from_a_target_divergence() {
    let client = branching_client();
    let mut server = branching_server_dual_of(&client);
    // One role branches where the other continues unconditionally. There is
    // no shared choice label to compare targets on, so conflating this with
    // `ContinuationDivergence` would report nothing at all.
    retarget(&mut server, "Idle", "request", Next::Then("AwaitingReply"));

    let errors = check_duality(&client, &server).expect_err("a shape mismatch must be flagged");
    assert!(
        errors.iter().any(|e| matches!(
            e,
            DualityError::ContinuationShapeDivergence {
                state: "Idle",
                label: "request",
                a: "choice",
                b: "then",
            }
        )),
        "expected the a->b shape divergence, got {errors:?}"
    );
    assert!(
        errors.iter().any(|e| matches!(
            e,
            DualityError::ContinuationShapeDivergence {
                state: "Idle",
                label: "request",
                a: "then",
                b: "choice",
            }
        )),
        "expected the b->a shape divergence too, got {errors:?}"
    );
    for e in &errors {
        assert_debug_excludes(e, &["BranchNotOffered", "ContinuationDivergence { "]);
    }
}

// ---------------------------------------------------------------------
// Ownership divergence: the one per-transition field the check compared
// neither before nor via any other variant.
// ---------------------------------------------------------------------

#[test]
fn ownership_divergence_is_refused_distinctly_from_payload_and_capability_divergence() {
    let client = branching_client();
    let mut server = branching_server_dual_of(&client);
    for t in &mut server.transitions {
        if t.from == "AwaitingReply" && t.label == "reply" {
            t.ownership = OwnershipMove::ConsumesResource;
        }
    }

    let errors = check_duality(&client, &server).expect_err("ownership divergence must be flagged");
    assert!(
        errors.iter().any(|e| matches!(
            e,
            DualityError::OwnershipDivergence {
                state: "AwaitingReply",
                label: "reply",
                a: OwnershipMove::None,
                b: OwnershipMove::ConsumesResource,
            }
        )),
        "expected OwnershipDivergence, got {errors:?}"
    );
    for e in &errors {
        assert_debug_excludes(
            e,
            &[
                "PayloadDivergence",
                "CapabilityDivergence",
                "MissingCounterpart",
                "KindNotComplementary",
            ],
        );
    }
}

// ---------------------------------------------------------------------
// Determinism: the same pair renders the same errors in the same order.
// ---------------------------------------------------------------------

#[test]
fn continuation_duality_errors_are_deterministic_across_runs() {
    let build = || {
        let client = branching_client();
        let mut server = branching_server_dual_of(&client);
        retarget(
            &mut server,
            "Idle",
            "request",
            Next::Choice(vec![("accepted", "Done"), ("refused", "Aborted")]),
        );
        retarget(&mut server, "AwaitingReply", "reply", Next::Then("Aborted"));
        (client, server)
    };

    let (client_a, server_a) = build();
    let (client_b, server_b) = build();
    let first = format!("{:?}", check_duality(&client_a, &server_a));
    let second = format!("{:?}", check_duality(&client_b, &server_b));
    assert_eq!(first, second);
    assert!(
        first.contains("BranchNotOffered") && first.contains("ContinuationDivergence"),
        "the determinism fixture must actually produce both refusals: {first}"
    );
}

// ---------------------------------------------------------------------
// Non-vacuity: every fixture above is invisible to the checks that already
// existed, so each refusal is genuinely carried by the new layer.
// ---------------------------------------------------------------------

/// Re-implements exactly the comparison `check_duality_one_way` performed
/// before continuation and ownership checking existed: counterpart
/// presence, kind complementarity, payload tag, required capability. If a
/// fixture below passes this and is nonetheless refused by `check_duality`,
/// the refusal can only come from the new layer.
fn agrees_under_the_pre_existing_checks_only(a: &ProtocolSpec, b: &ProtocolSpec) -> bool {
    let complementary = |x: Kind, y: Kind| {
        matches!(
            (x, y),
            (Kind::Send, Kind::Receive)
                | (Kind::Receive, Kind::Send)
                | (Kind::Call, Kind::Return)
                | (Kind::Return, Kind::Call)
        ) || (x == y && x.is_escape())
    };
    let one_way = |from: &ProtocolSpec, to: &ProtocolSpec| {
        from.transitions.iter().all(|ta| {
            match to
                .transitions
                .iter()
                .find(|tb| tb.from == ta.from && tb.label == ta.label)
            {
                None => false,
                Some(tb) => {
                    complementary(ta.kind, tb.kind)
                        && ta.payload_type == tb.payload_type
                        && ta.required_capability == tb.required_capability
                }
            }
        })
    };
    one_way(a, b) && one_way(b, a)
}

#[test]
fn every_new_refusal_fixture_is_invisible_to_the_pre_existing_checks() {
    // Each entry is (name, the exact pair one of the tests above refuses).
    let mut pairs: Vec<(&str, ProtocolSpec, ProtocolSpec)> = Vec::new();

    let client = branching_client();
    let mut unoffered_branch = branching_server_dual_of(&client);
    retarget(
        &mut unoffered_branch,
        "Idle",
        "request",
        Next::Choice(vec![("accepted", "AwaitingReply"), ("refused", "Aborted")]),
    );
    pairs.push(("unoffered branch", client.clone(), unoffered_branch));

    let mut divergent_then = branching_server_dual_of(&client);
    retarget(
        &mut divergent_then,
        "AwaitingReply",
        "reply",
        Next::Then("Aborted"),
    );
    pairs.push(("divergent Then target", client.clone(), divergent_then));

    let mut divergent_branch = branching_server_dual_of(&client);
    retarget(
        &mut divergent_branch,
        "Idle",
        "request",
        Next::Choice(vec![("accepted", "Done"), ("rejected", "Aborted")]),
    );
    pairs.push(("divergent branch target", client.clone(), divergent_branch));

    let mut shape_mismatch = branching_server_dual_of(&client);
    retarget(
        &mut shape_mismatch,
        "Idle",
        "request",
        Next::Then("AwaitingReply"),
    );
    pairs.push((
        "continuation shape mismatch",
        client.clone(),
        shape_mismatch,
    ));

    let mut ownership = branching_server_dual_of(&client);
    for t in &mut ownership.transitions {
        if t.from == "AwaitingReply" && t.label == "reply" {
            t.ownership = OwnershipMove::ConsumesResource;
        }
    }
    pairs.push(("ownership divergence", client.clone(), ownership));

    for (name, a, b) in &pairs {
        assert!(
            agrees_under_the_pre_existing_checks_only(a, b),
            "the {name:?} fixture must be accepted by counterpart/kind/payload/capability \
             comparison alone, or the refusal below proves nothing new"
        );
        assert!(
            check_duality(a, b).is_err(),
            "the {name:?} fixture must be refused by the full check"
        );
    }
    assert_eq!(pairs.len(), 5, "every new refusal family must be covered");
}
