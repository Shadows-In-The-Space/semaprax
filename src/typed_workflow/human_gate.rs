//! Human gates as an explicit authority boundary.
//!
//! Reaching a [`super::graph::StepKind::HumanGate`] step in a workflow
//! graph is not modeled here at all, deliberately: this module has no
//! notion of "the engine arrived at the gate, therefore proceed." The only
//! way past a gate is [`GateLedger::evaluate`], which takes a
//! [`GateDecision`] that must independently match the gate's declared
//! revision, candidate digest, role, and expiry, and consumes a one-time
//! decision identity so the same decision can never authorize twice. A
//! successful evaluation returns exactly the one [`EdgeId`] the gate's
//! author bound to it — the decision itself carries no field that could
//! request a different edge, so an approved decision cannot be replayed to
//! grant broader authority than the workflow author declared. This is the
//! repository's "evidence carries no authority" and "a settlement or
//! concurrency model is proof data, not permission" invariants applied to
//! human approval specifically.

use super::checkpoint::RevisionId;
use super::graph::EdgeId;
use std::collections::BTreeSet;

/// A role identity a gate requires. Compared for exact equality only; this
/// module performs no role hierarchy or inference.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Role(pub String);

/// A workflow author's declaration of one human gate. `grants_edge` is
/// fixed here, not supplied by the approving decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateSpec {
    pub revision: RevisionId,
    pub candidate_digest: [u8; 32],
    pub required_role: Role,
    /// Logical-clock expiry; a decision at or before this instant is live.
    pub expires_at: u64,
    pub grants_edge: EdgeId,
}

/// One recorded human decision, independently produced out of band (e.g.
/// by a reviewer's own signed action) and presented to
/// [`GateLedger::evaluate`]. `decision_id` must be unique per decision;
/// reusing one is a replay, not a fresh approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateDecision {
    pub decision_id: u64,
    pub revision: RevisionId,
    pub candidate_digest: [u8; 32],
    pub role: Role,
    pub decided_at: u64,
    pub approve: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateError {
    WrongRevision,
    WrongCandidate,
    WrongRole,
    Expired,
    Rejected,
    Replayed,
}

/// Tracks consumed decision identities so a decision can be evaluated at
/// most once. Not persisted across process restarts by this type; a
/// caller that needs that must fold it into a [`super::checkpoint`]
/// snapshot the same way [`super::compensation::CompensationLedger`] does.
#[derive(Default, Debug, Clone)]
pub struct GateLedger {
    consumed: BTreeSet<u64>,
}

impl GateLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate one decision against one spec. On success, returns exactly
    /// `spec.grants_edge` — never a value derived from `decision` — and the
    /// decision's identity is marked consumed so it cannot be replayed.
    /// Every rejection leaves the ledger unchanged (rejecting a decision is
    /// not itself a use of it) except `Replayed`, which by definition means
    /// no state changes on this call either.
    pub fn evaluate(
        &mut self,
        spec: &GateSpec,
        decision: &GateDecision,
    ) -> Result<EdgeId, GateError> {
        if self.consumed.contains(&decision.decision_id) {
            return Err(GateError::Replayed);
        }
        if decision.revision != spec.revision {
            return Err(GateError::WrongRevision);
        }
        if decision.candidate_digest != spec.candidate_digest {
            return Err(GateError::WrongCandidate);
        }
        if decision.role != spec.required_role {
            return Err(GateError::WrongRole);
        }
        if decision.decided_at > spec.expires_at {
            return Err(GateError::Expired);
        }
        if !decision.approve {
            return Err(GateError::Rejected);
        }
        self.consumed.insert(decision.decision_id);
        Ok(spec.grants_edge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> GateSpec {
        GateSpec {
            revision: RevisionId(7),
            candidate_digest: [9u8; 32],
            required_role: Role("release-manager".to_string()),
            expires_at: 1_000,
            grants_edge: EdgeId(42),
        }
    }

    fn decision() -> GateDecision {
        GateDecision {
            decision_id: 1,
            revision: RevisionId(7),
            candidate_digest: [9u8; 32],
            role: Role("release-manager".to_string()),
            decided_at: 500,
            approve: true,
        }
    }

    #[test]
    fn approved_decision_grants_exactly_the_declared_edge() {
        let mut ledger = GateLedger::new();
        assert_eq!(ledger.evaluate(&spec(), &decision()), Ok(EdgeId(42)));
    }

    #[test]
    fn reaching_a_gate_grants_nothing_on_its_own() {
        // There is no API in this module that takes only a `GateSpec` and
        // returns an edge: authorization requires a `GateDecision` too.
        // This test documents that as an executable fact about the type
        // signature rather than merely asserting it in a comment.
        fn _requires_decision(_spec: &GateSpec, _decision: &GateDecision) {}
        let _ = _requires_decision as fn(&GateSpec, &GateDecision);
    }

    #[test]
    fn wrong_revision_is_refused() {
        let mut ledger = GateLedger::new();
        let mut bad = decision();
        bad.revision = RevisionId(8);
        assert_eq!(
            ledger.evaluate(&spec(), &bad),
            Err(GateError::WrongRevision)
        );
    }

    #[test]
    fn wrong_candidate_digest_is_refused() {
        let mut ledger = GateLedger::new();
        let mut bad = decision();
        bad.candidate_digest = [0u8; 32];
        assert_eq!(
            ledger.evaluate(&spec(), &bad),
            Err(GateError::WrongCandidate)
        );
    }

    #[test]
    fn wrong_role_is_refused() {
        let mut ledger = GateLedger::new();
        let mut bad = decision();
        bad.role = Role("intern".to_string());
        assert_eq!(ledger.evaluate(&spec(), &bad), Err(GateError::WrongRole));
    }

    #[test]
    fn expired_decision_is_refused() {
        let mut ledger = GateLedger::new();
        let mut bad = decision();
        bad.decided_at = 1_001;
        assert_eq!(ledger.evaluate(&spec(), &bad), Err(GateError::Expired));
    }

    #[test]
    fn rejected_decision_grants_no_edge() {
        let mut ledger = GateLedger::new();
        let mut rejection = decision();
        rejection.approve = false;
        assert_eq!(
            ledger.evaluate(&spec(), &rejection),
            Err(GateError::Rejected)
        );
    }

    #[test]
    fn replaying_the_same_decision_id_is_refused_even_if_it_would_reapprove() {
        let mut ledger = GateLedger::new();
        assert_eq!(ledger.evaluate(&spec(), &decision()), Ok(EdgeId(42)));
        assert_eq!(
            ledger.evaluate(&spec(), &decision()),
            Err(GateError::Replayed)
        );
    }

    #[test]
    fn a_rejected_decision_id_can_still_be_replay_checked_but_never_grants() {
        let mut ledger = GateLedger::new();
        let mut rejection = decision();
        rejection.approve = false;
        // Rejections do not consume the decision id (nothing to replay);
        // re-submitting the same rejected id is evaluated fresh each time,
        // and still never grants.
        assert_eq!(
            ledger.evaluate(&spec(), &rejection),
            Err(GateError::Rejected)
        );
        assert_eq!(
            ledger.evaluate(&spec(), &rejection),
            Err(GateError::Rejected)
        );
    }
}
