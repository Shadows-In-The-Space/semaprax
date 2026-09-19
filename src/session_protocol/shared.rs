//! Process-wide, validated `&'static ProtocolSpec` handles for the
//! protocols a real subsystem runs against at runtime.
//!
//! [`super::engine::SessionTable`] borrows its spec (`SessionTable<'p>`), so
//! a subsystem that wants to *own* a table alongside its own data needs a
//! spec that outlives it. Building one `ProtocolSpec` per connection would
//! also re-run [`super::spec::ProtocolSpec::validate`] on every `begin`,
//! which is the "construct once, validate once, share by reference" posture
//! `spec.rs`'s own module doc describes.
//!
//! Each accessor validates its spec exactly once, on first use, and panics
//! if validation fails. That is deliberate: a malformed declaration here is
//! a defect in this crate's own source, not a hostile input, and the
//! alternative -- handing a subsystem an unvalidated table -- is exactly the
//! "validate before trusting" rule `SessionTable::new`'s doc states.

use std::sync::OnceLock;

use super::protocols;
use super::spec::ProtocolSpec;

static DATABASE_TRANSACTION: OnceLock<ProtocolSpec> = OnceLock::new();
static PROJECT_AGENT_SESSION: OnceLock<ProtocolSpec> = OnceLock::new();

fn validated(spec: ProtocolSpec) -> ProtocolSpec {
    if let Err(errors) = spec.validate() {
        panic!(
            "session_protocol: built-in protocol '{}' failed its own static validation: {errors:?}",
            spec.name
        );
    }
    spec
}

/// The declaration `crate::database_fixture`'s transaction lifecycle runs
/// against. See [`protocols::database_transaction_protocol`].
pub fn database_transaction() -> &'static ProtocolSpec {
    DATABASE_TRANSACTION.get_or_init(|| validated(protocols::database_transaction_protocol()))
}

/// The declaration `crate::project_transport::session` runs against. See
/// [`protocols::project_agent_session_protocol`].
pub fn project_agent_session() -> &'static ProtocolSpec {
    PROJECT_AGENT_SESSION.get_or_init(|| validated(protocols::project_agent_session_protocol()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_protocol::model_check::check_bounded;

    #[test]
    fn every_shared_protocol_validates_and_model_checks() {
        for spec in [database_transaction(), project_agent_session()] {
            assert!(spec.validate().is_ok(), "{} failed validate", spec.name);
            assert!(
                check_bounded(spec, spec.states.len()).is_ok(),
                "{} failed bounded model check",
                spec.name
            );
        }
    }

    #[test]
    fn a_shared_protocol_handle_is_the_same_value_every_call() {
        assert!(std::ptr::eq(database_transaction(), database_transaction()));
        assert!(std::ptr::eq(
            project_agent_session(),
            project_agent_session()
        ));
    }
}
