//! The connection's transaction lifecycle, driven by the general session
//! protocol kernel rather than by a hand-rolled state enum.
//!
//! Issue #206 asks for "at least two real interaction lifecycles ... checked
//! by the general protocol type system". This module is one of them:
//! [`TransactionLifecycle`] owns a [`SessionTable`] over
//! [`crate::session_protocol::protocols::database_transaction_protocol`] and
//! a live [`Endpoint`], and `DatabaseFixture::begin`/`commit`/`rollback`/
//! `connection_lost` reach their outcome *only* by asking that table to
//! advance the endpoint. Nothing here re-derives the legality rule the spec
//! already states:
//!
//! - A nested `begin` is refused because the declared `Open` state has no
//!   `begin` transition, so the kernel returns
//!   [`ProtocolError::IllegalTransition`]; the lifecycle then takes the
//!   declared `nested_begin_refused` escape, which is what makes the
//!   connection `Failed`.
//! - `commit`/`rollback` outside `Open` are refused the same way and take
//!   the declared `misuse` escape.
//! - `connection_lost` from a settled connection is refused and discarded,
//!   which is the real method's documented "only while open" behaviour.
//!
//! The connection's reported [`TransactionState`] is *derived* from the
//! endpoint (see [`TransactionLifecycle::state`]) plus the last terminal
//! state reached, so there is no second state machine that could drift from
//! the declared one.
//!
//! One session per transaction attempt: a settled transaction is terminal in
//! the protocol, and a reusable connection opens a fresh session for its
//! next `begin`. That is also what gives "no use after terminal" real work
//! to do here -- a second `commit` can never reach the already-committed
//! session record.
//!
//! This grants no authority of any kind. The kernel is a checker over
//! declared data; it opens nothing, and every physical effect (cloning,
//! restoring, or dropping the in-memory snapshot) still happens in this
//! crate's own code, invoked through the terminal state's canonical,
//! never-sorted cleanup inventory.

use std::collections::BTreeMap;

use super::{Table, TransactionState};
use crate::session_protocol::engine::{
    AdvanceOutcome, CleanupHandler, Endpoint, ProtocolError, SessionTable,
};
use crate::session_protocol::shared;
use crate::session_protocol::spec::StateId;

/// The connection data one terminal cleanup inventory operates on, plus
/// whether *this* particular escape means the transaction's outcome is
/// uncertain (a real connection loss) or merely refused (a misuse that
/// leaves the connection's data exactly where it was).
pub(super) struct ConnectionData<'a> {
    pub(super) tables: &'a mut BTreeMap<String, Table>,
    pub(super) snapshot: &'a mut Option<BTreeMap<String, Table>>,
    pub(super) uncertain_outcome: bool,
}

impl ConnectionData<'_> {
    /// Take the clone-on-begin snapshot a rollback restores from. Called
    /// only after the kernel admits `begin`.
    fn capture_snapshot(&mut self) {
        *self.snapshot = Some(self.tables.clone());
    }
}

impl CleanupHandler for ConnectionData<'_> {
    fn run(
        &mut self,
        _session_id: &str,
        _terminal_state: StateId,
        op: &'static str,
    ) -> Result<(), String> {
        match op {
            // A committed transaction's snapshot is no longer a rollback
            // target; the live tables are authoritative.
            "release_snapshot" => *self.snapshot = None,
            "restore_snapshot" => {
                if let Some(snapshot) = self.snapshot.take() {
                    *self.tables = snapshot;
                }
            }
            // An uncertain outcome is never reported as success: the
            // in-flight writes go back to the pre-transaction snapshot
            // rather than being kept. A refused operation is *not* an
            // uncertain outcome -- it never touched the data, and the
            // still-open transaction it was refused beside keeps its own
            // snapshot.
            "discard_uncertain_snapshot" => {
                if self.uncertain_outcome {
                    if let Some(snapshot) = self.snapshot.take() {
                        *self.tables = snapshot;
                    }
                }
            }
            other => return Err(format!("unknown cleanup op `{other}`")),
        }
        Ok(())
    }
}

/// A cleanup boundary that performs nothing. Used only by
/// [`TransactionLifecycle::drop`], where the connection's data is being
/// dropped with the lifecycle and restoring a snapshot into it would be
/// observable by nobody.
struct DiscardingCleanup;

impl CleanupHandler for DiscardingCleanup {
    fn run(&mut self, _: &str, _: StateId, _: &'static str) -> Result<(), String> {
        Ok(())
    }
}

pub(super) struct TransactionLifecycle {
    table: SessionTable<'static>,
    /// Always `Some` between calls, and never terminal: a settled
    /// transaction is immediately replaced by a fresh `Idle` session so the
    /// connection stays reusable.
    endpoint: Option<Endpoint>,
    /// The last terminal state reached, reported while the current session
    /// is still `Idle`.
    settled: TransactionState,
    next_session: u64,
}

impl Default for TransactionLifecycle {
    fn default() -> Self {
        let mut table = SessionTable::new(shared::database_transaction());
        let endpoint = table
            .open("txn-0")
            .expect("a fresh table has no session to collide with");
        Self {
            table,
            endpoint: Some(endpoint),
            settled: TransactionState::None,
            next_session: 1,
        }
    }
}

impl TransactionLifecycle {
    /// The connection's transaction state, derived from the protocol
    /// endpoint rather than tracked beside it.
    pub(super) fn state(&self) -> TransactionState {
        match self.endpoint.as_ref().map(Endpoint::state) {
            Some("Open") => TransactionState::Open,
            _ => self.settled,
        }
    }

    pub(super) fn begin(
        &mut self,
        data: &mut ConnectionData<'_>,
    ) -> Result<(), super::FixtureError> {
        let endpoint = self.take_endpoint();
        data.uncertain_outcome = false;
        match self
            .table
            .advance(endpoint, "begin", "BeginRequest", None, None, None, data)
        {
            Ok(AdvanceOutcome::Live(endpoint)) => {
                self.endpoint = Some(endpoint);
                data.capture_snapshot();
                Ok(())
            }
            Ok(AdvanceOutcome::Terminal(..)) => {
                unreachable!("`begin` lands on the nonterminal `Open` state")
            }
            Err((ProtocolError::IllegalTransition { .. }, endpoint)) => {
                // The declared protocol has no `begin` from `Open`: a nested
                // begin is refused, and the declared escape is what poisons
                // the connection.
                self.escape(endpoint, "nested_begin_refused", false, data);
                Err(super::FixtureError::TransactionAlreadyOpen)
            }
            Err((error, _)) => unexpected(error),
        }
    }

    pub(super) fn commit(
        &mut self,
        data: &mut ConnectionData<'_>,
    ) -> Result<(), super::FixtureError> {
        self.settle("commit", "CommitRequest", TransactionState::Committed, data)
    }

    pub(super) fn rollback(
        &mut self,
        data: &mut ConnectionData<'_>,
    ) -> Result<(), super::FixtureError> {
        self.settle(
            "rollback",
            "RollbackRequest",
            TransactionState::RolledBack,
            data,
        )
    }

    /// Models an observed connection loss. The declared `connection_lost`
    /// transition exists only from `Open`, so observing one on a settled
    /// connection is refused by the kernel and discarded here -- exactly the
    /// real method's "forces `Failed` only while open" behaviour.
    pub(super) fn connection_lost(&mut self, data: &mut ConnectionData<'_>) {
        let endpoint = self.take_endpoint();
        data.uncertain_outcome = true;
        match self
            .table
            .advance(endpoint, "connection_lost", "Unit", None, None, None, data)
        {
            Ok(AdvanceOutcome::Terminal(_, _)) => self.reopen(TransactionState::Failed),
            Ok(AdvanceOutcome::Live(..)) => {
                unreachable!("`connection_lost` lands on the terminal `Failed` state")
            }
            Err((ProtocolError::IllegalTransition { .. }, endpoint)) => {
                self.endpoint = Some(endpoint);
            }
            Err((error, _)) => unexpected(error),
        }
    }

    fn settle(
        &mut self,
        label: &'static str,
        payload_type: &'static str,
        settled: TransactionState,
        data: &mut ConnectionData<'_>,
    ) -> Result<(), super::FixtureError> {
        let endpoint = self.take_endpoint();
        data.uncertain_outcome = false;
        match self
            .table
            .advance(endpoint, label, payload_type, None, None, None, data)
        {
            Ok(AdvanceOutcome::Terminal(_, _)) => {
                self.reopen(settled);
                Ok(())
            }
            Ok(AdvanceOutcome::Live(..)) => {
                unreachable!("`{label}` lands on a terminal state")
            }
            Err((ProtocolError::IllegalTransition { .. }, endpoint)) => {
                self.escape(endpoint, "misuse", false, data);
                Err(super::FixtureError::NoOpenTransaction)
            }
            Err((error, _)) => unexpected(error),
        }
    }

    /// Take a declared escape transition to a terminal state, then reopen a
    /// fresh session so the connection stays reusable.
    fn escape(
        &mut self,
        endpoint: Endpoint,
        label: &'static str,
        uncertain_outcome: bool,
        data: &mut ConnectionData<'_>,
    ) {
        data.uncertain_outcome = uncertain_outcome;
        match self
            .table
            .advance(endpoint, label, "Unit", None, None, None, data)
        {
            Ok(AdvanceOutcome::Terminal(_, _)) => self.reopen(TransactionState::Failed),
            Ok(AdvanceOutcome::Live(..)) => {
                unreachable!("`{label}` is a declared escape to a terminal state")
            }
            Err((error, _)) => unexpected(error),
        }
    }

    fn take_endpoint(&mut self) -> Endpoint {
        self.endpoint
            .take()
            .expect("the lifecycle always holds a live, nonterminal endpoint between calls")
    }

    fn reopen(&mut self, settled: TransactionState) {
        self.settled = settled;
        let session_id = format!("txn-{}", self.next_session);
        self.next_session += 1;
        self.endpoint = Some(
            self.table
                .open(session_id)
                .expect("each transaction attempt uses a fresh, never-reused session id"),
        );
    }
}

impl Drop for TransactionLifecycle {
    /// A live nonterminal endpoint may never simply be abandoned: the kernel
    /// arms a drop bomb for exactly that. Dropping the connection takes the
    /// declared escape for whichever state it is in -- a dropped connection
    /// with work in flight *is* a connection loss -- so the endpoint reaches
    /// a terminal state the ordinary way.
    fn drop(&mut self) {
        let Some(endpoint) = self.endpoint.take() else {
            return;
        };
        if endpoint.is_terminal() {
            return;
        }
        let label = match endpoint.state() {
            "Open" => "connection_lost",
            _ => "misuse",
        };
        let outcome = self.table.advance(
            endpoint,
            label,
            "Unit",
            None,
            None,
            None,
            &mut DiscardingCleanup,
        );
        debug_assert!(
            outcome.is_ok(),
            "every nonterminal state of database-transaction-v1 declares an escape"
        );
    }
}

fn unexpected(error: ProtocolError) -> ! {
    panic!(
        "database_fixture: the transaction lifecycle presented an operation the \
         declared protocol refused for a reason this connection cannot produce: {error:?}"
    )
}
