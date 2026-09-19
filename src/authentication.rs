//! Explicit-capability authentication for Rust hosts. No source-language authority is added.
use zeroize::Zeroizing;

pub mod audit;
pub mod password;
pub mod service;
pub mod session;

/// Hostile compile-time proof for `std.auth.secret.Secret<T>`
/// (declared in `std/auth/src/auth.spx`) — the `.spx`-visible half of issue
/// #191's non-leaking secret type. See that module's own doc comment for
/// what it does and does not claim.
#[cfg(test)]
mod secret_source_tests;

/// Hostile compile-time proof that `std.auth.identity.Identity` and
/// `std.auth.authorization.Authorization` (declared in
/// `std/auth/src/auth.spx`) are distinct nominal types the compiler
/// enforces — issue #191's "authentication and authorization remain
/// separate typed concepts" acceptance criterion. See that module's own doc
/// comment for what it does and does not claim.
#[cfg(test)]
mod identity_authorization_source_tests;

/// Closed failures never contain credentials or bearer tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    InvalidInput,
    InvalidPolicy,
    InvalidCredential,
    Capacity,
    Entropy,
    Storage,
    Expired,
    Revoked,
    Conflict,
}

/// Owned secret bytes, erased on drop; caller-owned input copies remain caller responsibility.
pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(AuthError::InvalidInput);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Entropy authority is supplied by the embedding host, never acquired by a source program.
pub trait AuthEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), AuthError>;
}

/// Explicit opt-in native OS entropy capability for authentication hosts.
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub struct OsAuthEntropy;
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
impl AuthEntropy for OsAuthEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), AuthError> {
        getrandom::fill(out).map_err(|_| AuthError::Entropy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A marker unlikely to appear in any redacted rendering by accident,
    /// used to prove the negative (content absent) rather than merely the
    /// positive (some fixed literal string present).
    const MARKER: &[u8] = b"UNREDACTED-SECRET-MARKER-7f3a";

    #[test]
    fn secret_bytes_debug_never_prints_its_content() {
        let secret = SecretBytes::try_from_bytes(MARKER).expect("bounded secret");
        // Non-vacuity control: the marker really is inside the owned bytes,
        // so a debug leak is a real possible failure this test would catch.
        assert_eq!(secret.as_bytes(), MARKER);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes([REDACTED])");
        assert!(!rendered
            .as_bytes()
            .windows(MARKER.len())
            .any(|window| window == MARKER));
    }

    #[test]
    fn secret_bytes_rejects_empty_and_oversized_input() {
        assert_eq!(
            SecretBytes::try_from_bytes(&[]).err(),
            Some(AuthError::InvalidInput)
        );
        let oversized = vec![1_u8; 4097];
        assert_eq!(
            SecretBytes::try_from_bytes(&oversized).err(),
            Some(AuthError::InvalidInput)
        );
        // The exact bound is admitted.
        let boundary = vec![1_u8; 4096];
        assert!(SecretBytes::try_from_bytes(&boundary).is_ok());
    }
}
