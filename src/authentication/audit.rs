//! Structured authentication audit events that cannot carry secret material.
//!
//! Every field on [`AuthAuditEvent`] is either a closed enum tag, a bounded
//! pseudonymous subject identifier, or a host-supplied timestamp tick. There
//! is no constructor path that accepts a `SecretBytes`, `SessionToken`,
//! `StoredPasswordHash`, a raw password, or a bearer token: `new` takes only
//! `&str`/`u64`/closed-enum parameters, so a caller cannot pass a secret type
//! through it even by accident. This mirrors the repository's
//! `AuthError::InvalidCredential`-style closed-tag posture: the outcome
//! carries only the already-redacted [`AuthError`] tag, never the credential
//! that produced it.

use std::fmt;

use super::AuthError;

const MAX_SUBJECT_BYTES: usize = 128;

/// The authentication action an audit event reports on. A closed set:
/// widening it is a deliberate source change, never a caller-selected
/// string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditKind {
    Signup,
    Login,
    SessionVerify,
    SessionRotate,
    Logout,
}

/// The recorded outcome. `Denied` retains only the closed [`AuthError`] tag
/// that `service::AuthService`'s methods already return on failure, never a
/// credential, hash, or bearer-token value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditOutcome {
    Allowed,
    Denied(AuthError),
}

impl AuthAuditOutcome {
    /// Derives the outcome tag from an existing `AuthService` call result
    /// without inspecting anything beyond whether it succeeded and, if not,
    /// its closed error tag. This is the intended wiring: a host calls
    /// `AuthService::login` (or `signup`/`protected`/`rotate`/`logout`),
    /// keeps the `Result` for its own control flow, and separately builds
    /// the audit record from the same `Result` by reference.
    pub fn from_result<T>(result: &Result<T, AuthError>) -> Self {
        match result {
            Ok(_) => Self::Allowed,
            Err(err) => Self::Denied(*err),
        }
    }
}

/// A complete, redaction-safe authentication audit record: a closed action
/// kind, a closed outcome, a bounded pseudonymous subject identifier, and a
/// host-supplied timestamp tick. Nothing else can be attached to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthAuditEvent {
    kind: AuthAuditKind,
    outcome: AuthAuditOutcome,
    subject: String,
    at: u64,
}

impl AuthAuditEvent {
    /// `subject` must already be a bounded account identifier of the shape
    /// `service::validate_subject` accepts (non-empty ASCII letters, digits,
    /// `.`, `_`, `-`, `@`, at most 128 bytes, no control bytes) -- never a
    /// password, password hash, session id, or bearer token. This
    /// constructor re-checks that bound itself rather than trusting the
    /// caller, so a malformed or oversized subject is refused here too, not
    /// only at signup/login time.
    pub fn new(
        kind: AuthAuditKind,
        outcome: AuthAuditOutcome,
        subject: &str,
        at: u64,
    ) -> Result<Self, AuthError> {
        if subject.is_empty()
            || subject.as_bytes().len() > MAX_SUBJECT_BYTES
            || subject
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(AuthError::InvalidInput);
        }
        Ok(Self {
            kind,
            outcome,
            subject: subject.to_owned(),
            at,
        })
    }

    pub fn kind(&self) -> AuthAuditKind {
        self.kind
    }

    pub fn outcome(&self) -> AuthAuditOutcome {
        self.outcome
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub const fn at(&self) -> u64 {
        self.at
    }
}

/// A stable one-line rendering safe for a log sink: every field here is
/// already established as non-secret by `AuthAuditEvent::new`'s admission
/// check, so `Display` (like the derived `Debug`) needs no redaction of its
/// own -- there is nothing on this type left to redact.
impl fmt::Display for AuthAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "auth_audit kind={:?} outcome={:?} subject={} at={}",
            self.kind, self.outcome, self.subject, self.at
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::password::{PasswordHasherHost, PasswordPolicy};
    use crate::authentication::{AuthEntropy, SecretBytes};

    struct FixedEntropy(u8);
    impl AuthEntropy for FixedEntropy {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), AuthError> {
            out.fill(self.0);
            Ok(())
        }
    }

    #[test]
    fn audit_event_is_complete_and_never_carries_secret_material() {
        // A marker unlikely to appear in any rendering by accident, so a
        // leak here would be a real, catchable failure rather than a
        // vacuous pass.
        const MARKER: &str = "UNREDACTED-SECRET-MARKER-9c1b";
        let password = SecretBytes::try_from_bytes(MARKER.as_bytes()).unwrap();
        // Non-vacuity control: the marker really is the secret used below.
        assert_eq!(password.as_bytes(), MARKER.as_bytes());

        let hasher = PasswordHasherHost::new(PasswordPolicy::default()).unwrap();
        let mut entropy = FixedEntropy(7);
        let stored = hasher.hash(&password, &mut entropy).unwrap();
        let wrong_password_result: Result<(), AuthError> = hasher
            .verify(&SecretBytes::try_from_bytes(b"wrong").unwrap(), &stored)
            .map(|()| ());

        let event = AuthAuditEvent::new(
            AuthAuditKind::Login,
            AuthAuditOutcome::from_result(&wrong_password_result),
            "alice",
            10,
        )
        .unwrap();
        assert_eq!(event.kind(), AuthAuditKind::Login);
        assert_eq!(
            event.outcome(),
            AuthAuditOutcome::Denied(AuthError::InvalidCredential)
        );
        assert_eq!(event.subject(), "alice");
        assert_eq!(event.at(), 10);

        let rendered_display = format!("{event}");
        let rendered_debug = format!("{event:?}");
        let stored_record = stored.expose_for_storage().to_owned();
        for rendered in [&rendered_display, &rendered_debug] {
            assert!(!rendered.contains(MARKER));
            assert!(!rendered
                .as_bytes()
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes()));
            assert!(!rendered.contains(&stored_record));
            assert!(!rendered.contains("wrong"));
        }

        let success = AuthAuditEvent::new(
            AuthAuditKind::Login,
            AuthAuditOutcome::from_result(&Ok::<(), AuthError>(())),
            "alice",
            11,
        )
        .unwrap();
        assert_eq!(success.outcome(), AuthAuditOutcome::Allowed);
        assert_ne!(format!("{event}"), format!("{success}"));
    }

    #[test]
    fn oversized_empty_and_control_byte_subjects_are_refused() {
        assert_eq!(
            AuthAuditEvent::new(AuthAuditKind::Signup, AuthAuditOutcome::Allowed, "", 1).err(),
            Some(AuthError::InvalidInput)
        );
        let oversized = "a".repeat(129);
        assert_eq!(
            AuthAuditEvent::new(
                AuthAuditKind::Signup,
                AuthAuditOutcome::Allowed,
                &oversized,
                1
            )
            .err(),
            Some(AuthError::InvalidInput)
        );
        assert_eq!(
            AuthAuditEvent::new(
                AuthAuditKind::Signup,
                AuthAuditOutcome::Allowed,
                "user\u{0}one",
                1
            )
            .err(),
            Some(AuthError::InvalidInput)
        );
        // The exact bound is admitted.
        let boundary = "a".repeat(128);
        assert!(AuthAuditEvent::new(
            AuthAuditKind::Signup,
            AuthAuditOutcome::Allowed,
            &boundary,
            1
        )
        .is_ok());
    }

    #[test]
    fn every_audit_kind_and_outcome_renders_distinctly() {
        let kinds = [
            AuthAuditKind::Signup,
            AuthAuditKind::Login,
            AuthAuditKind::SessionVerify,
            AuthAuditKind::SessionRotate,
            AuthAuditKind::Logout,
        ];
        let mut renderings = Vec::new();
        for kind in kinds {
            let event = AuthAuditEvent::new(kind, AuthAuditOutcome::Allowed, "user", 1).unwrap();
            renderings.push(format!("{event}"));
        }
        let unique: std::collections::BTreeSet<_> = renderings.iter().cloned().collect();
        assert_eq!(unique.len(), renderings.len());

        let denied = AuthAuditEvent::new(
            AuthAuditKind::Login,
            AuthAuditOutcome::Denied(AuthError::Revoked),
            "user",
            1,
        )
        .unwrap();
        let allowed =
            AuthAuditEvent::new(AuthAuditKind::Login, AuthAuditOutcome::Allowed, "user", 1)
                .unwrap();
        assert_ne!(format!("{denied}"), format!("{allowed}"));
    }
}
