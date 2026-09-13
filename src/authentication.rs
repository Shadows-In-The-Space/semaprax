//! Explicit-capability authentication for Rust hosts. No source-language authority is added.
use zeroize::Zeroizing;

pub mod password;
pub mod service;
pub mod session;

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
