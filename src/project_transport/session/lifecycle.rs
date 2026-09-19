//! The Agent transport session's lifecycle, driven by the general session
//! protocol kernel rather than by a hand-rolled state field.
//!
//! Issue #206 asks for "at least two real interaction lifecycles ... checked
//! by the general protocol type system". This module is one of them: the
//! JSON-RPC session in [`super`] no longer stores a `SessionState` it
//! assigns to directly. It stores a [`ProjectSessionLifecycle`], which owns
//! a [`SessionTable`] over
//! [`crate::session_protocol::protocols::project_agent_session_protocol`]
//! and one live [`Endpoint`]. Every lifecycle gate in the transport asks
//! [`ProjectSessionLifecycle::admits`] whether the declared protocol
//! allows this method from the state the endpoint is actually in, and every
//! state change is a real [`SessionTable::advance`] against that spec.
//! [`ProjectSessionLifecycle::state`] renders the endpoint back into the
//! `SessionState` the wire protocol reports, so the two can never drift:
//! there is only one state machine now, and it is the declared one.
//!
//! Two things the transport genuinely proves, rather than models:
//!
//! - **Order.** A `rename/apply` from `Open`, a `change/preview` from
//!   `Prepared`, or any method after `shutdown` is refused because the
//!   declared spec has no such transition from that state, not because a
//!   hand-written `if` says so. The refusal still renders as the existing
//!   `SPX-J104` lifecycle diagnostic, byte for byte.
//! - **Authority at the commit boundary.** The `apply` transition declares
//!   `required_capability: Some("project.apply")` and
//!   `OwnershipMove::ConsumesResource`. The transport presents the
//!   capability only *after* its own authenticated re-check of the bound
//!   snapshot succeeds, and presents a resource token only *after*
//!   `PreparedProjectRename::acquire_a0` has actually taken the A0 commit
//!   lock -- the token's identity is the retained plan's preview digest. A
//!   session that reached `Prepared` in perfectly legal order therefore
//!   still cannot advance across the commit boundary without both. Reaching
//!   a protocol state is not authority.
//!
//! The kernel carries no authority of its own. It opens nothing, writes
//! nothing, and grants nothing: it is a checker over declared data, and
//! every physical effect (acquiring A0, committing, reloading, finishing
//! the snapshot's authority) still happens in the transport's own code.

use crate::session_protocol::engine::{
    AdvanceOutcome, CleanupHandler, Endpoint, ProtocolError, ResourceToken, SessionTable,
};
use crate::session_protocol::shared;
use crate::session_protocol::spec::{Label, StateId};

use super::SessionState;

/// A cleanup boundary that records which declared cleanup ops ran, in the
/// canonical order the terminal state declares them. The transport's own
/// physical finalization (`finish_authority`, dropping the snapshot,
/// retaining terminal diagnostics) stays in `Session`; this records that the
/// declared inventory was executed and in what order, and never sorts,
/// repairs, or reinterprets it.
#[derive(Default)]
struct RecordingCleanup {
    ran: Vec<&'static str>,
}

impl CleanupHandler for RecordingCleanup {
    fn run(&mut self, _: &str, _: StateId, op: &'static str) -> Result<(), String> {
        self.ran.push(op);
        Ok(())
    }
}

pub(super) struct ProjectSessionLifecycle {
    table: SessionTable<'static>,
    /// Always `Some`. May be terminal (`Shutdown`/`Uncertain`), in which
    /// case every further `admits` refuses.
    endpoint: Option<Endpoint>,
    cleanup_trace: Vec<&'static str>,
}

const SESSION_ID: &str = "project-agent-session";

impl ProjectSessionLifecycle {
    /// A freshly configured session, exactly as `serve` starts one.
    pub(super) fn new() -> Self {
        let mut table = SessionTable::new(shared::project_agent_session());
        let endpoint = table
            .open(SESSION_ID)
            .expect("a fresh table has no session to collide with");
        Self {
            table,
            endpoint: Some(endpoint),
            cleanup_trace: Vec::new(),
        }
    }

    /// A session that has taken the declared `open` transition, i.e. one an
    /// `workspace/open` call has already admitted. Used by tests that need
    /// to start from a legally opened session without replaying a frame.
    #[cfg(test)]
    pub(super) fn opened() -> Self {
        let mut lifecycle = Self::new();
        lifecycle.opened_or_invalidated(true);
        debug_assert_eq!(lifecycle.state(), SessionState::Open);
        lifecycle
    }

    /// The `SessionState` the wire protocol reports, rendered from the live
    /// protocol endpoint. There is no second copy of this value.
    pub(super) fn state(&self) -> SessionState {
        match self.endpoint.as_ref().map(Endpoint::state) {
            Some("Configured") => SessionState::Configured,
            Some("Open") => SessionState::Open,
            Some("Derived") => SessionState::Derived,
            Some("Prepared") => SessionState::Prepared,
            Some("Applying") => SessionState::Applying,
            Some("Invalidated") => SessionState::Invalidated,
            Some("Uncertain") => SessionState::Uncertain,
            Some("Shutdown") => SessionState::Shutdown,
            other => unreachable!("project-agent-session-v1 declares no state {other:?}"),
        }
    }

    /// Whether the declared protocol admits `label` from the state the
    /// endpoint is actually in. This is the transport's every lifecycle
    /// gate: a refusal here is what renders as `SPX-J104`.
    pub(super) fn admits(&self, label: Label) -> bool {
        self.endpoint
            .as_ref()
            .is_some_and(|endpoint| self.table.admits(endpoint, label).is_ok())
    }

    /// The declared cleanup ops that have run, in the canonical order their
    /// terminal state declares them.
    #[cfg(test)]
    pub(super) fn cleanup_trace(&self) -> &[&'static str] {
        &self.cleanup_trace
    }

    pub(super) fn opened_or_invalidated(&mut self, opened: bool) {
        let choice = if opened { "opened" } else { "invalidated" };
        self.advance(
            "open",
            "OpenRequest",
            Some("project.open"),
            Some(choice),
            None,
        );
    }

    pub(super) fn subject_survived(&mut self, survived: bool) {
        let choice = if survived { "succeeded" } else { "invalidated" };
        self.advance(
            "subject_operation",
            "SubjectRequest",
            Some("project.subject"),
            Some(choice),
            None,
        );
    }

    pub(super) fn rename_previewed(&mut self, prepared: bool) {
        let choice = if prepared { "prepared" } else { "invalidated" };
        self.advance(
            "rename_preview",
            "RenamePreviewRequest",
            Some("project.rename.preview"),
            Some(choice),
            None,
        );
    }

    pub(super) fn rename_derived(&mut self, derived: bool) {
        let choice = if derived { "derived" } else { "invalidated" };
        self.advance(
            "rename_derive",
            "RenameDeriveRequest",
            Some("project.rename.derive"),
            Some(choice),
            None,
        );
    }

    pub(super) fn change_previewed(&mut self, prepared: bool) {
        let choice = if prepared { "prepared" } else { "invalidated" };
        self.advance(
            "change_preview",
            "ChangePreviewRequest",
            Some("project.change.preview"),
            Some(choice),
            None,
        );
    }

    pub(super) fn change_artifact_rendered(&mut self, survived: bool) {
        let choice = if survived { "succeeded" } else { "invalidated" };
        self.advance(
            "change_artifact",
            "ChangeArtifactRequest",
            Some("project.change.artifact"),
            Some(choice),
            None,
        );
    }

    /// The `apply` request was refused before it reached its commit
    /// boundary: the bound snapshot's authenticated re-check failed, or the
    /// consuming final recheck did. The declared `apply_refused` escape is
    /// what makes the session `Invalidated`.
    pub(super) fn apply_refused(&mut self) {
        self.advance("apply_refused", "Unit", None, None, None);
    }

    /// Cross the declared commit boundary. `authority` is presented only
    /// once the transport's own authenticated re-check has passed, and
    /// `a0_token` only once `acquire_a0` has actually taken the A0 lock --
    /// the kernel refuses this transition without both.
    pub(super) fn apply_started(&mut self, authority: Option<&'static str>, a0_token: &str) {
        let token = ResourceToken {
            id: a0_token.to_owned(),
        };
        self.advance("apply", "ApplyRequest", authority, None, Some(&token));
    }

    /// Resolve the in-flight `apply` call. `choice` is one of the declared
    /// `committed`/`rolled_back`/`uncertain` outcomes.
    pub(super) fn apply_resolved(&mut self, choice: Label) {
        self.advance("apply_resolved", "ApplyResult", None, Some(choice), None);
    }

    /// The real transport sets `Shutdown` unconditionally for both the
    /// `shutdown` method and the bodyless notification. The declared
    /// `shutdown` escape exists from every nonterminal state the request
    /// loop can actually be waiting in; a session that has already reached
    /// a terminal state never reads another frame, so a refusal here is
    /// discarded rather than forcing a second terminal transition.
    pub(super) fn shutdown(&mut self) {
        if self.admits("shutdown") {
            self.advance("shutdown", "Unit", None, None, None);
        }
    }

    fn advance(
        &mut self,
        label: Label,
        payload_type: &'static str,
        capability: Option<&'static str>,
        choice: Option<Label>,
        token: Option<&ResourceToken>,
    ) {
        let endpoint = self
            .endpoint
            .take()
            .expect("the lifecycle always holds its endpoint between calls");
        let mut cleanup = RecordingCleanup::default();
        match self.table.advance(
            endpoint,
            label,
            payload_type,
            capability,
            choice,
            token,
            &mut cleanup,
        ) {
            Ok(AdvanceOutcome::Live(endpoint)) => self.endpoint = Some(endpoint),
            Ok(AdvanceOutcome::Terminal(endpoint, _)) => {
                self.endpoint = Some(endpoint);
                self.cleanup_trace.append(&mut cleanup.ran);
            }
            Err((error, endpoint)) => {
                self.endpoint = Some(endpoint);
                unexpected(label, error);
            }
        }
    }
}

impl Drop for ProjectSessionLifecycle {
    /// A live nonterminal endpoint may never simply be abandoned -- the
    /// kernel arms a drop bomb for exactly that. A transport session that
    /// ends without a `shutdown` frame (EOF, an I/O error, an oversized
    /// frame) takes the declared escape for whichever state it is in, which
    /// is what `serve`'s own `finish_authority` already models physically.
    fn drop(&mut self) {
        let Some(endpoint) = self.endpoint.take() else {
            return;
        };
        if endpoint.is_terminal() {
            return;
        }
        // `Applying` is the one nonterminal state `shutdown` is not declared
        // from: the real transport never returns to the request loop while
        // applying, so its declared escape is the timeout.
        let label = if endpoint.state() == "Applying" {
            "apply_timeout"
        } else {
            "shutdown"
        };
        let mut cleanup = RecordingCleanup::default();
        let outcome = self
            .table
            .advance(endpoint, label, "Unit", None, None, None, &mut cleanup);
        debug_assert!(
            outcome.is_ok(),
            "every nonterminal state of project-agent-session-v1 declares an escape"
        );
    }
}

fn unexpected(label: Label, error: ProtocolError) -> ! {
    panic!(
        "project_transport: the session lifecycle presented `{label}`, which the declared \
         protocol refused for a reason this transport cannot produce: {error:?}"
    )
}
