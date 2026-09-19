//! Read-only queries over a built [`RegistrySnapshot`] (issue #195's CLI
//! surface): what a snapshot contains, one entry's exact published bytes,
//! and which published version satisfies a range.
//!
//! These exist so `crate::cli::registry`'s `search`, `fetch` and `add` verbs
//! ask the owning module rather than re-deriving registry facts at the CLI
//! boundary. Every function here reads an already-built snapshot, so
//! everything it reports has already passed [`super::build_snapshot`]'s
//! checks -- a listed entry's `content_digest` is known to bind its
//! `subject_bytes` (`SPX-PKR603`) because no snapshot exists otherwise.
//!
//! Nothing here performs, or enables, any I/O, network access, or
//! publication: they are pure functions from a snapshot to data about it.
//! Version *selection* is deliberately the only decision made here, it
//! reuses [`crate::package_range`]'s frozen range grammar rather than a
//! second one, and it never invents an implicit "latest" for a caller who
//! did not supply a range.

use super::{
    canonical_version_text, shape_error, PublicationStatus, PublishedEntry, RegistrySnapshot,
    YankPolicy,
};
use crate::diagnostic::Diagnostic;
use crate::package_range;
use crate::package_range::Version;

#[cfg(test)]
#[path = "catalog/tests.rs"]
mod tests;

/// One entry's public registry facts, without its (potentially multi-megabyte)
/// `subject_bytes` payload. Use [`RegistrySnapshot::subject_bytes`] for that.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntrySummary {
    pub package: String,
    pub version: String,
    pub content_digest: String,
    pub api_digest: String,
    pub license: String,
    /// The entry's *claimed*, never cryptographically verified, publisher
    /// identity -- see the module docstring's nonclaims.
    pub publisher: String,
    /// `active` or `yanked`.
    pub status: &'static str,
    /// The yank reason, when `status` is `yanked`.
    pub yank_reason: Option<String>,
}

impl RegistrySnapshot {
    /// Every entry, in the snapshot's canonical `(package, version)` order --
    /// the same order its digested bytes use, so a listing and the evidence
    /// can never present two different orders for one snapshot.
    #[must_use]
    pub fn listing(&self) -> Vec<EntrySummary> {
        self.entries
            .iter()
            .map(|((package, version), entry)| summary_of(package, *version, entry))
            .collect()
    }

    /// The exact published Subject-v3 bytes for one coordinate, or `None`.
    /// `version` is matched against the canonical `major.minor.patch`
    /// rendering, so `1.0` and `01.0.0` do not silently match `1.0.0`.
    #[must_use]
    pub fn subject_bytes(&self, package: &str, version: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|((entry_package, entry_version), _)| {
                entry_package == package && canonical_version_text(*entry_version) == version
            })
            .map(|(_, entry)| entry.subject_bytes.as_str())
    }
}

/// The highest published version of `package` that satisfies `range` under
/// `policy`, or a `SPX-PKR601` refusal naming why none does.
///
/// There is no implicit "latest": a caller must always supply a range, and
/// the answer is a fact about the supplied snapshot alone -- never a network
/// lookup and never a fallback to an unpinned newest. Under
/// [`YankPolicy::ExcludeYanked`] a yanked version is not a candidate; under
/// [`YankPolicy::RefuseIfYanked`] and [`YankPolicy::AllowYankedWithWarning`]
/// it is, matching [`super::project_subjects`]'s treatment of the same
/// entries so a selected version cannot then vanish from the catalog it is
/// resolved against.
pub fn select_version(
    snapshot: &RegistrySnapshot,
    package: &str,
    range: &str,
    policy: YankPolicy,
) -> Result<EntrySummary, Diagnostic> {
    let parsed = package_range::parse_range(range, shape_error)?;
    let mut published = 0usize;
    let mut best: Option<EntrySummary> = None;
    // `entries` is a `BTreeMap` keyed by `(package, Version)`, so this walk
    // reaches each package's versions in ascending order and the last
    // admitted match is the highest satisfying one.
    for ((entry_package, version), entry) in &snapshot.entries {
        if entry_package != package {
            continue;
        }
        published += 1;
        if matches!(entry.status, PublicationStatus::Yanked { .. })
            && policy == YankPolicy::ExcludeYanked
        {
            continue;
        }
        if parsed.contains(*version) {
            best = Some(summary_of(entry_package, *version, entry));
        }
    }
    best.ok_or_else(|| {
        shape_error(if published == 0 {
            format!("no version of `{package}` is published in this registry snapshot")
        } else {
            format!(
                "no published version of `{package}` satisfies `{range}` under the active \
                 yank policy ({published} version(s) published)"
            )
        })
    })
}

/// The one place an [`EntrySummary`] is built, shared by
/// [`RegistrySnapshot::listing`] and [`select_version`] so a searched entry
/// and a selected one can never report the same facts differently.
fn summary_of(package: &str, version: Version, entry: &PublishedEntry) -> EntrySummary {
    EntrySummary {
        package: package.to_owned(),
        version: canonical_version_text(version),
        content_digest: entry.content_digest.clone(),
        api_digest: entry.api_digest.clone(),
        license: entry.license.clone(),
        publisher: entry.signature.identity.clone(),
        status: match entry.status {
            PublicationStatus::Active => "active",
            PublicationStatus::Yanked { .. } => "yanked",
        },
        yank_reason: match &entry.status {
            PublicationStatus::Active => None,
            PublicationStatus::Yanked { reason } => Some(reason.clone()),
        },
    }
}
