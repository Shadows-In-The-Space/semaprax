//! Explicit held generation-v2 commit/recovery. Receipts are evidence only;
//! decoded disk data never becomes producer admission or a fetch capability.
use super::{generation_name, hash, refused, string, uncertain, Result};
pub use super::{Artifact, CommitReceipt};
use crate::package_registry::trust::registry_v3 as proof;
use std::path::Path;

pub struct Update<'registry, 'input> {
    pub metadata: proof::UpdateInputs<'registry, 'input>,
    pub rotation: Option<&'input str>,
    pub lock: &'input str,
    pub subjects: &'input [String],
    pub artifacts: &'input [Artifact<'input>],
    pub trusted_time: u64,
}

mod generation;
mod read;
pub use read::{ArtifactRead, VerifiedArtifact};

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod store;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub use store::HeldTrustStore;

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
pub struct HeldTrustStore;
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
impl HeldTrustStore {
    pub fn open(_path: &Path, _independent_pin: &str) -> Result<Self> {
        Err(refused(
            "durable Registry-v3 store is unsupported on this host",
        ))
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
mod tests;
