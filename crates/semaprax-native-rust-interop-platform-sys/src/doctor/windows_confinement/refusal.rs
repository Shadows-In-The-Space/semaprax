//! Host-independent, order-enforcing admission classifier for the Windows
//! confinement primitive. No Win32 call is made anywhere in this file.
//!
//! [`DOCTOR-PRODUCTION-PROVISIONER-V1`][doc] requires that "other hosts
//! reject before interpreting capsule contents or changing namespace/cgroup
//! state." [`admit`] is that ordering as code, not prose: it runs each
//! admission stage in a fixed sequence and never invokes a later stage's
//! closure once an earlier one refuses, so a caller cannot accidentally
//! interpret capsule bytes, restrict a token, tighten a job object, or touch
//! the filesystem before an unsupported-host refusal fires. The hostile-input
//! tests below prove that ordering by making a later closure panic if it is
//! ever called after an earlier refusal.
//!
//! [doc]: https://github.com/wavect/semaprax/blob/main/docs/DOCTOR-PRODUCTION-PROVISIONER-V1.md

use super::capsule::CapsuleError;

/// The fail-closed refusal classes this contract distinguishes. Each names
/// the stage that refused, not the underlying OS error, so a caller can
/// report *why* admission stopped without leaking raw `GetLastError` values
/// into a diagnostic that outlives the process that produced them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Not a supported native Windows host for this contract. Mirrors the
    /// Linux provisioner's "other hosts reject before interpreting capsule
    /// contents": this is checked, and can refuse, before the capsule stage
    /// ever runs.
    UnsupportedHost,
    /// The sealed capsule failed trust-anchor or signed-wire validation; see
    /// [`super::capsule::CapsuleError`] for which check.
    Capsule(CapsuleError),
    /// Building or applying the restricted token failed.
    TokenRestriction,
    /// Creating the job object or tightening its limits failed.
    JobObjectLimits,
    /// Creating or ACL'ing the per-invocation scratch root failed.
    FilesystemConfinement,
    /// An operand outside the five admission stages was malformed --
    /// commonly, a path or argument that cannot be represented as a
    /// NUL-free UTF-16 Windows string. This never comes out of [`admit`]
    /// itself; [`super::primitive`] selects it directly for encoding
    /// failures that happen after admission succeeds but before spawning.
    Invalid,
    /// `CreateProcessAsUserW`, `AssignProcessToJobObject`, or `ResumeThread`
    /// itself failed, distinct from [`Refusal::JobObjectLimits`] (which is
    /// the job object's own limit configuration failing before any spawn is
    /// attempted). Selected directly by [`super::primitive`], never by
    /// [`admit`].
    Spawn,
}

/// Run each admission stage in the fixed order this contract requires --
/// host support, then capsule structure, then the three confinement
/// primitives in the order [`super::primitive`] applies them -- stopping at
/// the first refusal. A later stage's closure is never invoked once an
/// earlier stage refuses.
///
/// Each closure's `Err` payload only needs to be enough to select a
/// [`Refusal`] variant; the capsule stage is the only one whose failure
/// detail this contract distinguishes further, because it is the only stage
/// with more than one host-independent failure class today.
pub fn admit<H, C, T, J, F>(
    host: impl FnOnce() -> Result<H, ()>,
    capsule: impl FnOnce() -> Result<C, CapsuleError>,
    token: impl FnOnce() -> Result<T, ()>,
    job: impl FnOnce() -> Result<J, ()>,
    filesystem: impl FnOnce() -> Result<F, ()>,
) -> Result<(H, C, T, J, F), Refusal> {
    let host = host().map_err(|()| Refusal::UnsupportedHost)?;
    let capsule = capsule().map_err(Refusal::Capsule)?;
    let token = token().map_err(|()| Refusal::TokenRestriction)?;
    let job = job().map_err(|()| Refusal::JobObjectLimits)?;
    let filesystem = filesystem().map_err(|()| Refusal::FilesystemConfinement)?;
    Ok((host, capsule, token, job, filesystem))
}

#[cfg(test)]
mod tests;
