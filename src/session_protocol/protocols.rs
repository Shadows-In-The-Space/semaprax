//! Three applied example protocols, satisfying issue #206's "apply it to at
//! least two real interaction lifecycles" outcome at this module's Rust
//! reference-kernel layer (see the crate doc `Status` section for exactly
//! what layer that is).
//!
//! [`model_stream_protocol`] models a model/tool streaming session (the
//! issue's own "model streams... database transactions... Agent-to-tool
//! interaction" examples): open, receive chunks, end by branching into a
//! graceful close or an aborted stream, with cancel/timeout/fail escapes at
//! every nonterminal state. It exercises `Send`, `Receive`, `Branch`,
//! `Cancel`, `Timeout`, and `Fail`.
//!
//! [`resource_transaction_protocol`] models a bounded database transaction:
//! begin, then any number of `read`/`write` calls (each a `Call` that opens
//! a pending in-flight operation only its own `Return` or a `Timeout`
//! resolves), then commit (which consumes a [`super::engine::ResourceToken`])
//! or rollback. It exercises `Call`/`Return` and `OwnershipMove::ConsumesResource`.
//!
//! [`project_agent_session_protocol`] is different in kind from the two
//! above: it is not a scenario invented for this kernel, but a
//! *transcription* of an already-shipped, already-tested subsystem's own
//! state machine -- `SessionState` in `src/project_transport/session.rs`,
//! the Agent-to-tool JSON-RPC transport the issue names as one of its own
//! "Agent-to-tool interaction" examples. Every state name and every
//! transition topology below is cited against the real implementation's
//! exact lines in that function's doc comment; per-transition
//! `payload_type`/`required_capability` tags are this module's own
//! illustrative vocabulary (the real session gates on an authenticated
//! Project snapshot and a digest match, not a [`super::capability::Grant`]),
//! and is documented as such at each site that is a deliberate abstraction
//! rather than a literal correspondence. It is **no longer a transcription
//! only**: `project_transport::session::Session` now stores a
//! `lifecycle::ProjectSessionLifecycle` instead of a `SessionState` field,
//! and every lifecycle gate in that transport asks
//! [`super::engine::SessionTable::admits`] while every state change is a
//! real [`super::engine::SessionTable::advance`] against this spec. The
//! session state the transport reports on the wire is rendered back out of
//! the live endpoint, so there is no second state machine left to drift.
//!
//! [`database_transaction_protocol`] is the same kind of thing for
//! `crate::database_fixture`'s transaction lifecycle. Those two are the
//! "at least two real interaction lifecycles ... checked by the general
//! protocol type system" issue #206's first acceptance criterion asks for.

use std::collections::BTreeSet;

use super::spec::{Kind, Next, OwnershipMove, ProtocolSpec, Transition};

fn states(names: &[&'static str]) -> BTreeSet<&'static str> {
    names.iter().copied().collect()
}

pub fn model_stream_protocol() -> ProtocolSpec {
    ProtocolSpec {
        name: "model-stream-v1",
        states: states(&[
            "Idle",
            "Streaming",
            "Closing",
            "Closed",
            "Cancelled",
            "Uncertain",
            "Failed",
        ]),
        initial: "Idle",
        terminal: states(&["Closed", "Cancelled", "Uncertain", "Failed"]),
        transitions: vec![
            Transition {
                from: "Idle",
                label: "open",
                kind: Kind::Send,
                payload_type: "StreamRequest",
                required_capability: Some("stream.open"),
                ownership: OwnershipMove::None,
                next: Next::Then("Streaming"),
            },
            Transition {
                from: "Idle",
                label: "abandon",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Cancelled"),
            },
            Transition {
                from: "Streaming",
                label: "chunk",
                kind: Kind::Receive,
                payload_type: "StreamChunk",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Streaming"),
            },
            Transition {
                from: "Streaming",
                label: "end",
                kind: Kind::Send,
                payload_type: "StreamEnd",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![("graceful", "Closing"), ("aborted", "Cancelled")]),
            },
            Transition {
                from: "Streaming",
                label: "cancel",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Cancelled"),
            },
            Transition {
                from: "Streaming",
                label: "timeout",
                kind: Kind::Timeout,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Uncertain"),
            },
            Transition {
                from: "Streaming",
                label: "fail",
                kind: Kind::Fail,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Failed"),
            },
            Transition {
                from: "Closing",
                label: "close",
                kind: Kind::Send,
                payload_type: "StreamClose",
                required_capability: Some("stream.close"),
                ownership: OwnershipMove::None,
                next: Next::Then("Closed"),
            },
            Transition {
                from: "Closing",
                label: "timeout",
                kind: Kind::Timeout,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Uncertain"),
            },
        ],
        cleanup: vec![
            ("Closed", vec!["flush_buffers", "release_socket"]),
            ("Cancelled", vec!["release_socket"]),
            ("Uncertain", vec!["mark_uncertain_for_reconciliation"]),
            ("Failed", vec!["release_socket", "emit_failure_report"]),
        ],
    }
}

pub fn resource_transaction_protocol() -> ProtocolSpec {
    ProtocolSpec {
        name: "resource-transaction-v1",
        states: states(&[
            "Idle",
            "Open",
            "AwaitingRead",
            "AwaitingWrite",
            "Committed",
            "RolledBack",
            "Uncertain",
        ]),
        initial: "Idle",
        terminal: states(&["Committed", "RolledBack", "Uncertain"]),
        transitions: vec![
            Transition {
                from: "Idle",
                label: "begin",
                kind: Kind::Send,
                payload_type: "BeginTxn",
                required_capability: Some("txn.begin"),
                ownership: OwnershipMove::None,
                next: Next::Then("Open"),
            },
            Transition {
                from: "Idle",
                label: "abandon",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("RolledBack"),
            },
            Transition {
                from: "Open",
                label: "read",
                kind: Kind::Call,
                payload_type: "ReadOp",
                required_capability: Some("txn.read"),
                ownership: OwnershipMove::None,
                next: Next::Then("AwaitingRead"),
            },
            Transition {
                from: "Open",
                label: "write",
                kind: Kind::Call,
                payload_type: "WriteOp",
                required_capability: Some("txn.write"),
                ownership: OwnershipMove::None,
                next: Next::Then("AwaitingWrite"),
            },
            Transition {
                from: "Open",
                label: "commit",
                kind: Kind::Send,
                payload_type: "Commit",
                required_capability: Some("txn.commit"),
                ownership: OwnershipMove::ConsumesResource,
                next: Next::Then("Committed"),
            },
            Transition {
                from: "Open",
                label: "rollback",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("RolledBack"),
            },
            Transition {
                from: "AwaitingRead",
                label: "read_result",
                kind: Kind::Return,
                payload_type: "ReadResult",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Open"),
            },
            Transition {
                from: "AwaitingRead",
                label: "timeout",
                kind: Kind::Timeout,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Uncertain"),
            },
            Transition {
                from: "AwaitingWrite",
                label: "write_result",
                kind: Kind::Return,
                payload_type: "WriteResult",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Open"),
            },
            Transition {
                from: "AwaitingWrite",
                label: "timeout",
                kind: Kind::Timeout,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Uncertain"),
            },
        ],
        cleanup: vec![
            (
                "Committed",
                vec!["persist_commit_record", "release_connection"],
            ),
            ("RolledBack", vec!["release_connection"]),
            ("Uncertain", vec!["mark_uncertain_for_reconciliation"]),
        ],
    }
}

/// A transcription of `SessionState` and `Session`'s dispatch logic in
/// `src/project_transport/session.rs` (Agent Transport v2-v6), the
/// already-shipped, already-tested JSON-RPC session this issue's own
/// "Agent-to-tool interaction" example names.
///
/// State-for-state correspondence with the real `enum SessionState`
/// (`src/project_transport/session.rs:82-101`, eight variants, `text()`
/// rendering each to the lowercase string this doc cites):
///
/// - `Configured`/`Open`/`Derived`/`Prepared`/`Applying`/`Invalidated`/
///   `Uncertain`/`Shutdown` are exactly the real eight variants -- no state
///   is added, dropped, or renamed.
///
/// Transition-for-transition sources (method -> real code):
///
/// - `open`: `Session::open` (`session.rs:392-411`), legal from `Configured`
///   or `Open`, landing on `Open` on success or `Invalidated` on an
///   invalidating diagnostic. The real function has a third, narrower
///   outcome this transcription does not carry: a non-invalidating failure
///   leaves the state unchanged (a self-loop indistinguishable here from the
///   `"opened"` branch landing back on the same state) -- see the crate doc
///   `Status` section's note that `payload_type` is a lightweight tag, not
///   full fidelity, and the same posture applies to collapsing that one
///   narrow outcome rather than adding a third named branch for it.
/// - `subject_operation` collapses `Session::subject`'s six identically-shaped
///   callers (`check`/`graph`/`context`/`test`/`workspace/snapshot`/
///   `workspace/status`, `session.rs:306-333`): `Open` -> `Open` on success,
///   `Open` -> `Invalidated` on an invalidating diagnostic. All six share
///   this exact two-outcome shape in the real code, so one representative
///   transition stands for the family rather than six near-duplicates.
/// - `rename_preview`: `Session::rename_preview`
///   (`src/project_transport/session/rename.rs:47-101`), `Open` ->
///   `Prepared` (success) or `Invalidated` (failure).
/// - `rename_derive`: `Session::rename_derive`
///   (`src/project_transport/session/workflow.rs:18-73`), `Open` ->
///   `Derived` or `Invalidated`.
/// - `change_preview`: `Session::change_preview`
///   (`session/workflow.rs:81-132`), `Derived` -> `Prepared` or
///   `Invalidated`.
/// - `change_artifact` collapses `impact`/`review`
///   (`Session::change_artifact`, `session/workflow.rs:158-217`): `Prepared`
///   -> `Prepared` (self-loop success) or `Invalidated`.
/// - `apply` collapses `rename/apply` and `change/apply`
///   (`Session::apply_with_runtime`, `session/rename.rs:146-290`):
///   `Prepared` -> `Applying`, modeled as `Kind::Call` because the real
///   function stages the A0 commit only after re-checking authority and
///   acquiring `prepared.acquire_a0()` (`rename.rs:229-259`) -- an owned
///   call that "stages arguments left to right and transfers them together
///   at its declared commit boundary," which is exactly why this transition
///   is the one `OwnershipMove::ConsumesResource` in this protocol: it
///   models `acquire_a0`'s resource capture, not a
///   [`super::engine::ResourceToken`] literally present in the real code.
/// - `apply_refused`: the two pre-commit failure exits of the same
///   `apply_with_runtime` -- the authenticated re-check of the bound
///   snapshot failing (`rename.rs`, `self.state = SessionState::Invalidated`
///   before `before_a0`), and the consuming final recheck
///   (`old_snapshot.finish_session()`) failing after A0 was acquired. Both
///   leave the session `Invalidated` without ever reaching `Applying`. This
///   transition was missing from the first transcription of this state
///   machine and was added when the real transport was actually wired onto
///   this spec: a transcription can omit an edge and stay green, but a
///   subsystem that runs on the spec cannot.
/// - `apply_resolved`: the three-way `match (commit_result, reloaded)`
///   (`rename.rs:260-289`) resolves the pending `apply` call: `"committed"`
///   and `"rolled_back"` both land back on `Open` (`rename.rs:268,273`; the
///   real code already treats a confirmed rollback as no different from a
///   confirmed commit for session lifecycle purposes -- both retain a fresh
///   authenticated snapshot), and `"uncertain"` lands on the terminal
///   `Uncertain` (`rename.rs:288`, alongside `self.terminal_diagnostics =
///   Some(diagnostics)`).
/// - `apply_timeout`: **not evidenced by any real code line** -- the real
///   `apply_with_runtime` resolves synchronously inside one function call
///   and is never observed as a distinct state across a request boundary,
///   so nothing in the real session ever needs to time out of `Applying`.
///   It exists here only because [`super::spec::ProtocolSpec::validate`]
///   requires every nonterminal state to declare a `Cancel`/`Timeout`/
///   `Fail`-kind escape before an endpoint may safely be abandoned there;
///   this is the documented, honest gap between "the real code's only exit
///   from `Applying` is a `Return`" and "the kernel's declared-protocol
///   rule requires an escape to exist." Marking it here rather than
///   silently adding it un-cited is the same discipline the crate doc's
///   `compile_fail` doctests use for what is genuinely proven versus
///   assumed.
/// - `shutdown`: the real `"shutdown"` method and the bodyless
///   `{"method":"shutdown"}` notification (`session.rs:216-224` in
///   `dispatch`; the notification arm in `handle_frame`) set
///   `SessionState::Shutdown` **unconditionally**, regardless of current
///   state -- confirmed by reading every call site: no guard checks
///   `self.state` first. That is transcribed as one `Cancel`-kind
///   transition from every nonterminal state that can actually still be
///   waiting for a next request frame (`Configured`, `Open`, `Derived`,
///   `Prepared`, `Invalidated`) -- `Applying` is excluded because the real
///   code never returns to the request loop while `Applying` (see above),
///   so a client-issued `shutdown` frame can never actually arrive then.
///
/// `Invalidated` is deliberately **not** terminal here, matching the real
/// session exactly: once invalidated, `subject`/`open`/every `Prepared`-
/// gated method reject with a lifecycle error forever (their guards name
/// `Open`, or `Configured | Open`, or `Prepared`, and never `Invalidated`),
/// but the unconditional `shutdown` above still applies, so an `Invalidated`
/// session is “stuck but not done” in exactly the sense
/// `ModelCheckError::NoBoundedPathToTerminal` exists to catch if it *had* no
/// escape.
pub fn project_agent_session_protocol() -> ProtocolSpec {
    ProtocolSpec {
        name: "project-agent-session-v1",
        states: states(&[
            "Configured",
            "Open",
            "Derived",
            "Prepared",
            "Applying",
            "Invalidated",
            "Uncertain",
            "Shutdown",
        ]),
        initial: "Configured",
        terminal: states(&["Uncertain", "Shutdown"]),
        transitions: vec![
            Transition {
                from: "Configured",
                label: "open",
                kind: Kind::Send,
                payload_type: "OpenRequest",
                required_capability: Some("project.open"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![("opened", "Open"), ("invalidated", "Invalidated")]),
            },
            Transition {
                from: "Configured",
                label: "shutdown",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Shutdown"),
            },
            Transition {
                from: "Open",
                label: "open",
                kind: Kind::Send,
                payload_type: "OpenRequest",
                required_capability: Some("project.open"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![("opened", "Open"), ("invalidated", "Invalidated")]),
            },
            Transition {
                from: "Open",
                label: "subject_operation",
                kind: Kind::Send,
                payload_type: "SubjectRequest",
                required_capability: Some("project.subject"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![("succeeded", "Open"), ("invalidated", "Invalidated")]),
            },
            Transition {
                from: "Open",
                label: "rename_preview",
                kind: Kind::Send,
                payload_type: "RenamePreviewRequest",
                required_capability: Some("project.rename.preview"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![
                    ("prepared", "Prepared"),
                    ("invalidated", "Invalidated"),
                ]),
            },
            Transition {
                from: "Open",
                label: "rename_derive",
                kind: Kind::Send,
                payload_type: "RenameDeriveRequest",
                required_capability: Some("project.rename.derive"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![("derived", "Derived"), ("invalidated", "Invalidated")]),
            },
            Transition {
                from: "Open",
                label: "shutdown",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Shutdown"),
            },
            Transition {
                from: "Derived",
                label: "change_preview",
                kind: Kind::Send,
                payload_type: "ChangePreviewRequest",
                required_capability: Some("project.change.preview"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![
                    ("prepared", "Prepared"),
                    ("invalidated", "Invalidated"),
                ]),
            },
            Transition {
                from: "Derived",
                label: "shutdown",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Shutdown"),
            },
            Transition {
                from: "Prepared",
                label: "change_artifact",
                kind: Kind::Send,
                payload_type: "ChangeArtifactRequest",
                required_capability: Some("project.change.artifact"),
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![
                    ("succeeded", "Prepared"),
                    ("invalidated", "Invalidated"),
                ]),
            },
            Transition {
                from: "Prepared",
                label: "apply",
                kind: Kind::Call,
                payload_type: "ApplyRequest",
                required_capability: Some("project.apply"),
                ownership: OwnershipMove::ConsumesResource,
                next: Next::Then("Applying"),
            },
            Transition {
                from: "Prepared",
                label: "apply_refused",
                kind: Kind::Fail,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Invalidated"),
            },
            Transition {
                from: "Prepared",
                label: "shutdown",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Shutdown"),
            },
            Transition {
                from: "Applying",
                label: "apply_resolved",
                kind: Kind::Return,
                payload_type: "ApplyResult",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Choice(vec![
                    ("committed", "Open"),
                    ("rolled_back", "Open"),
                    ("uncertain", "Uncertain"),
                ]),
            },
            Transition {
                from: "Applying",
                label: "apply_timeout",
                kind: Kind::Timeout,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Uncertain"),
            },
            Transition {
                from: "Invalidated",
                label: "shutdown",
                kind: Kind::Cancel,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Shutdown"),
            },
        ],
        cleanup: vec![
            (
                "Uncertain",
                vec!["release_snapshot", "mark_uncertain_for_reconciliation"],
            ),
            ("Shutdown", vec!["finish_authority"]),
        ],
    }
}

/// A transcription of `TransactionState` and `DatabaseFixture`'s
/// `begin`/`commit`/`rollback`/`connection_lost` methods in
/// `src/database_fixture.rs` -- the in-memory relational engine
/// `crate::job_fixture`, `crate::job_runtime`, and `crate::job_evidence`
/// run their ledger writes through, and the "database transactions"
/// lifecycle issue #206's implementation step 7 names.
///
/// Unlike [`model_stream_protocol`] and [`resource_transaction_protocol`],
/// which were written *for* this kernel, this spec is the declaration
/// `DatabaseFixture` itself consults at runtime:
/// `database_fixture::transaction_lifecycle::TransactionLifecycle` owns a
/// [`super::engine::SessionTable`] over it, and every `begin`/`commit`/
/// `rollback`/`connection_lost` call asks the table to advance a real
/// [`super::engine::Endpoint`] before the fixture touches a single row. The
/// connection's reported `TransactionState` is *derived* from that
/// endpoint, not tracked beside it -- there is no second state machine to
/// drift.
///
/// One session per transaction attempt. The real connection is reusable
/// (`begin` succeeds again once a transaction has settled), so a settled
/// session is terminal here and the lifecycle opens a fresh session for the
/// next attempt, which is also what makes "no use after terminal" do real
/// work: a second `commit` cannot reach the already-committed session.
///
/// Transition-for-transition sources (method -> real code):
///
/// - `begin`: `DatabaseFixture::begin` (`database_fixture.rs`), legal only
///   from `Idle`. `TransactionState::next_on_begin` mapped `Open -> Failed`
///   ("a nested begin is refused *and* poisons the connection"); that is
///   the `nested_begin_refused` escape below, reached because the kernel
///   refuses `begin` from `Open` with
///   [`super::engine::ProtocolError::IllegalTransition`] rather than
///   because the fixture re-derives the rule.
/// - `commit`: `DatabaseFixture::commit`, `Open -> Committed`. From any
///   other state the kernel refuses and the fixture takes the `misuse`
///   escape, reproducing `next_on_commit`'s `_ -> Failed` exactly.
/// - `rollback`: `DatabaseFixture::rollback`, `Open -> RolledBack`, with
///   the same `misuse` escape for every other state.
/// - `connection_lost`: `DatabaseFixture::connection_lost`, an explicit
///   `Kind::Fail` escape from `Open`. Observed from a settled state it is a
///   no-op in the real code, which is exactly the kernel refusing it: the
///   lifecycle discards that refusal without changing state.
///
/// `payload_type` tags are this module's own vocabulary (the real methods
/// take no request value), and no transition declares a
/// `required_capability` or an `OwnershipMove::ConsumesResource`, because
/// the real engine requires neither a capability grant nor a resource token
/// at its commit boundary. Declaring one here would be theatre: the
/// connection would still commit exactly as it does today.
///
/// The three terminal cleanup inventories are canonical runtime order and
/// are really executed -- `TransactionLifecycle`'s handler performs the
/// snapshot work named by each op, so `release_snapshot`,
/// `restore_snapshot`, and `discard_uncertain_snapshot` are the code paths
/// that drop, restore, and abandon the clone-on-begin snapshot.
pub fn database_transaction_protocol() -> ProtocolSpec {
    ProtocolSpec {
        name: "database-transaction-v1",
        states: states(&["Idle", "Open", "Committed", "RolledBack", "Failed"]),
        initial: "Idle",
        terminal: states(&["Committed", "RolledBack", "Failed"]),
        transitions: vec![
            Transition {
                from: "Idle",
                label: "begin",
                kind: Kind::Send,
                payload_type: "BeginRequest",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Open"),
            },
            Transition {
                from: "Idle",
                label: "misuse",
                kind: Kind::Fail,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Failed"),
            },
            Transition {
                from: "Open",
                label: "commit",
                kind: Kind::Send,
                payload_type: "CommitRequest",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Committed"),
            },
            Transition {
                from: "Open",
                label: "rollback",
                kind: Kind::Send,
                payload_type: "RollbackRequest",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("RolledBack"),
            },
            Transition {
                from: "Open",
                label: "connection_lost",
                kind: Kind::Fail,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Failed"),
            },
            Transition {
                from: "Open",
                label: "nested_begin_refused",
                kind: Kind::Fail,
                payload_type: "Unit",
                required_capability: None,
                ownership: OwnershipMove::None,
                next: Next::Then("Failed"),
            },
        ],
        cleanup: vec![
            ("Committed", vec!["release_snapshot"]),
            ("RolledBack", vec!["restore_snapshot"]),
            ("Failed", vec!["discard_uncertain_snapshot"]),
        ],
    }
}
