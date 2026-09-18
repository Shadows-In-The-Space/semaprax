//! Local duality/compatibility between two protocol roles (e.g. a client
//! spec and a server spec of one interaction). Two-party only: keeping
//! multi-party global protocols out of scope is an explicit instruction in
//! issue #206, not an oversight here.

use std::collections::BTreeMap;

use super::spec::{Kind, Label, Next, OwnershipMove, ProtocolSpec, StateId, Transition};

/// Why two specs failed the duality/compatibility check. Each variant names
/// a distinct, stable defect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DualityError {
    /// A transition on one side has no counterpart transition (same state,
    /// same label) on the other side.
    MissingCounterpart { state: StateId, label: Label },
    /// The two sides' transition kinds for the same (state, label) are not
    /// complementary (e.g. both `Send`, instead of one `Send` and one
    /// `Receive`).
    KindNotComplementary {
        state: StateId,
        label: Label,
        a: Kind,
        b: Kind,
    },
    /// The two sides declared different payload tags for the same message.
    PayloadDivergence {
        state: StateId,
        label: Label,
        a: &'static str,
        b: &'static str,
    },
    /// The two sides require different capabilities for the same message.
    /// This is the specific unsoundness the crate doc's failure-case list
    /// names: duality that ignores capability divergence would let one
    /// role's compatibility proof paper over the other role needing
    /// authority the first never has to present.
    CapabilityDivergence {
        state: StateId,
        label: Label,
        a: Option<&'static str>,
        b: Option<&'static str>,
    },
    /// The two sides declared different ownership movement for the same
    /// message. Completes the per-transition comparison: payload,
    /// capability and ownership are the three things a transition carries
    /// besides its kind, and a pair that agrees on the first two while one
    /// side alone consumes a [`super::engine::ResourceToken`] is not dual --
    /// one role believes a resource was transferred and the other does not.
    OwnershipDivergence {
        state: StateId,
        label: Label,
        a: OwnershipMove,
        b: OwnershipMove,
    },
    /// The selecting side of a branch may choose `choice`, but the peer's
    /// counterpart transition does not offer it. This is the "branch the
    /// peer never offers" defect: every other per-transition field can
    /// agree exactly while one role is able to select a continuation the
    /// other has no case for. Directional by kind, not by argument order --
    /// see [`check_duality_one_way`].
    BranchNotOffered {
        state: StateId,
        label: Label,
        choice: Label,
    },
    /// The two sides' continuations for the same message have different
    /// *shapes*: one declares an unconditional [`Next::Then`] and the other
    /// a branching [`Next::Choice`]. Rendered as the closed tags `"then"`
    /// and `"choice"`, never as a formatted state list, so the refusal is
    /// deterministic.
    ContinuationShapeDivergence {
        state: StateId,
        label: Label,
        a: &'static str,
        b: &'static str,
    },
    /// The two sides agree on this message and (for a branch) on the choice
    /// label, but land in **different next states**. Without this check a
    /// pair can be declared compatible and then desynchronize on the very
    /// next message, because each role's legal continuations are read from
    /// its own idea of the current state. `choice` is `None` for a
    /// [`Next::Then`] continuation and names the branch otherwise.
    ContinuationDivergence {
        state: StateId,
        label: Label,
        choice: Option<Label>,
        a: StateId,
        b: StateId,
    },
}

/// The closed shape tag of a continuation, for
/// [`DualityError::ContinuationShapeDivergence`].
fn shape(next: &Next) -> &'static str {
    match next {
        Next::Then(_) => "then",
        Next::Choice(_) => "choice",
    }
}

/// Whether a transition of this kind *selects* a branch (rather than
/// offering one), which is what makes the branch rule a subset rule in one
/// direction instead of an equality rule in both.
///
/// Only [`Kind::Receive`] is treated as purely offering. That is
/// deliberately conservative and narrower than it could be:
///
/// - `Send`/`Receive` is unambiguous. The sender chooses what to emit; the
///   receiver must have a case for every choice the sender may make, and a
///   receiver offering *extra* branches is safe.
/// - `Call`/`Return` is **not** unambiguous: the caller decides to issue the
///   operation, while the returning side decides its outcome, so which half
///   "selects" a branching continuation depends on what the branch encodes.
///   Rather than assert an answer, both halves are treated as selecting, so
///   [`check_duality`] applies the subset rule in each direction and the
///   effective rule for a `Call`/`Return` pair is set *equality*.
/// - An escape kind (`Cancel`/`Timeout`/`Fail`) is identical on both sides,
///   so the same two-directional application yields set equality -- which is
///   what "both roles agree on the same cancellation branches" means.
///
/// Equality can only refuse more pairs than the subset rule, never fewer, so
/// this conservatism costs precision on `Call`/`Return` branches and never
/// soundness. Narrowing it is a future refinement, not a defect being hidden.
fn selects_branch(kind: Kind) -> bool {
    !matches!(kind, Kind::Receive)
}

fn complementary(a: Kind, b: Kind) -> bool {
    matches!(
        (a, b),
        (Kind::Send, Kind::Receive)
            | (Kind::Receive, Kind::Send)
            | (Kind::Call, Kind::Return)
            | (Kind::Return, Kind::Call)
    ) || (a == b && a.is_escape())
}

/// Compare the continuations of one matched `(state, label)` transition
/// pair, pushing every divergence found in declared order.
///
/// Three distinct defects, never conflated:
///
/// - **Shape.** One side continues unconditionally and the other branches.
/// - **Branch offering.** The side that *selects* a branch (see
///   [`selects_branch`]) may not select a choice label the peer's
///   counterpart has no case for. This is deliberately a subset rule, not
///   an equality rule: a receiving role that offers *extra* branches the
///   sender can never select is safe, and refusing it would reject a
///   legitimately wider peer.
/// - **Target state.** For a shared continuation -- the `Then` target, or a
///   choice label both sides offer -- the two roles must land in the same
///   next state. Both roles index their legal continuations by state name,
///   so disagreeing here means the pair is declared compatible and then
///   desynchronizes on the very next message.
fn check_continuation(ta: &Transition, tb: &Transition, errors: &mut Vec<DualityError>) {
    match (&ta.next, &tb.next) {
        (Next::Then(target_a), Next::Then(target_b)) => {
            if target_a != target_b {
                errors.push(DualityError::ContinuationDivergence {
                    state: ta.from,
                    label: ta.label,
                    choice: None,
                    a: *target_a,
                    b: *target_b,
                });
            }
        }
        (Next::Choice(choices_a), Next::Choice(choices_b)) => {
            if selects_branch(ta.kind) {
                for (choice, _) in choices_a {
                    if !choices_b.iter().any(|(other, _)| other == choice) {
                        errors.push(DualityError::BranchNotOffered {
                            state: ta.from,
                            label: ta.label,
                            choice: *choice,
                        });
                    }
                }
            }
            for (choice, target_a) in choices_a {
                if let Some((_, target_b)) = choices_b.iter().find(|(other, _)| other == choice) {
                    if target_a != target_b {
                        errors.push(DualityError::ContinuationDivergence {
                            state: ta.from,
                            label: ta.label,
                            choice: Some(*choice),
                            a: *target_a,
                            b: *target_b,
                        });
                    }
                }
            }
        }
        (next_a, next_b) => errors.push(DualityError::ContinuationShapeDivergence {
            state: ta.from,
            label: ta.label,
            a: shape(next_a),
            b: shape(next_b),
        }),
    }
}

/// One-directional check: every transition `a` declares has a compatible
/// counterpart on `b`. This alone does not prove duality -- a transition
/// that exists only on `b`'s side is invisible to this direction, and the
/// branch-offering rule is directional by kind (the module's internal
/// `check_continuation`). Use [`check_duality`] for the full two-way
/// guarantee.
pub fn check_duality_one_way(a: &ProtocolSpec, b: &ProtocolSpec) -> Result<(), Vec<DualityError>> {
    let mut errors = Vec::new();
    let index_b: BTreeMap<(StateId, Label), &Transition> = b
        .transitions
        .iter()
        .map(|t| ((t.from, t.label), t))
        .collect();

    for ta in &a.transitions {
        match index_b.get(&(ta.from, ta.label)) {
            None => errors.push(DualityError::MissingCounterpart {
                state: ta.from,
                label: ta.label,
            }),
            Some(tb) => {
                if !complementary(ta.kind, tb.kind) {
                    errors.push(DualityError::KindNotComplementary {
                        state: ta.from,
                        label: ta.label,
                        a: ta.kind,
                        b: tb.kind,
                    });
                }
                if ta.payload_type != tb.payload_type {
                    errors.push(DualityError::PayloadDivergence {
                        state: ta.from,
                        label: ta.label,
                        a: ta.payload_type,
                        b: tb.payload_type,
                    });
                }
                if ta.required_capability != tb.required_capability {
                    errors.push(DualityError::CapabilityDivergence {
                        state: ta.from,
                        label: ta.label,
                        a: ta.required_capability,
                        b: tb.required_capability,
                    });
                }
                if ta.ownership != tb.ownership {
                    errors.push(DualityError::OwnershipDivergence {
                        state: ta.from,
                        label: ta.label,
                        a: ta.ownership,
                        b: tb.ownership,
                    });
                }
                check_continuation(ta, tb, &mut errors);
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// The full two-way duality/compatibility check: `a` is compatible with `b`
/// only if each side's transitions have a complementary counterpart on the
/// other. Errors from both directions are collected so a caller sees every
/// divergence in one pass, never just the first direction checked.
pub fn check_duality(a: &ProtocolSpec, b: &ProtocolSpec) -> Result<(), Vec<DualityError>> {
    let mut errors = Vec::new();
    if let Err(e) = check_duality_one_way(a, b) {
        errors.extend(e);
    }
    if let Err(e) = check_duality_one_way(b, a) {
        errors.extend(e);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
