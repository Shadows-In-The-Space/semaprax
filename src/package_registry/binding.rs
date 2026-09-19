//! Registry-Bound Resolution v1 (issue #195): binds one
//! [`crate::package_resolver_v2`] resolution evidence string to the exact
//! registry snapshot digest and yank policy that produced its catalog.
//!
//! ## The gap this closes
//!
//! [`super::project_subjects`] (and
//! [`super::federation::project_federated_subjects`]) already project a
//! snapshot into the raw `subjects: Vec<String>` catalog
//! [`crate::package_resolver_v2`] consumes, and the resulting resolver
//! evidence -- the lockfile -- is proven byte-identical for identical
//! inputs (`super::tests::projected_subjects_resolve_deterministically_through_package_resolver_v2`
//! and its federation sibling). But that evidence embeds only a digest of
//! the raw subject *bytes* it was handed -- it carries no reference to
//! *which registry snapshot, at which digest, under which yank policy*
//! produced those bytes. Two different snapshots can project the identical
//! subject list for the packages a given resolution actually selects: for
//! example, one snapshot with an extra `Yanked` entry excluded by policy,
//! and one without that entry at all, resolve to byte-identical resolver
//! evidence even though the snapshots -- and therefore the registry's full
//! published history -- genuinely differ. Held on its own, resolver-v2
//! evidence cannot distinguish those two cases; it does not, by itself,
//! "bind exact package digests, registry snapshot/metadata" the way issue
//! #195's implementation sequence requires of a lockfile. This module
//! closes exactly that: [`bind_to_snapshot`] renders one canonical envelope
//! embedding the snapshot's own digest, the yank policy applied, and the
//! resolver-v2 evidence together, so independently re-verifying it
//! ([`verify_bound_resolution`]) requires reproducing *both* the exact
//! registry entries and the exact resolution template -- a substituted,
//! reordered, or otherwise altered snapshot is refused even when it would
//! have resolved to the same package versions.
//!
//! ## No new authority, no new cryptography, no new diagnostic
//!
//! This is composition, not new solving or signing logic:
//! [`bind_to_snapshot`] calls [`super::project_subjects`] and
//! [`crate::package_resolver_v2::generate`] exactly as `super::tests`
//! already does by hand, and [`verify_bound_resolution`] rebuilds the
//! registry snapshot from caller-owned entries
//! ([`super::build_snapshot`]) and the resolution from a caller-owned
//! template, byte-comparing both against the supplied evidence -- the same
//! replay discipline [`super::verify_snapshot`] and
//! [`crate::package_resolver_v2::verify`] already use. It reuses
//! `SPX-PKR608` for a byte-for-byte replay failure and mints no new
//! diagnostic code: a substituted snapshot, an added or removed entry, a
//! changed yank policy, or a retargeted requirement is exactly the same
//! "evidence does not exactly replay its claimed inputs" failure those two
//! functions already name. This module still performs no cryptographic
//! signature or transparency-log verification anywhere -- every nonclaim in
//! the parent module's docstring holds here verbatim.
//!
//! ## Determinism
//!
//! [`bind_to_snapshot`] and [`verify_bound_resolution`] perform no I/O
//! beyond memory: no clock, no environment, no filesystem, and no
//! `HashMap`/`HashSet` anywhere on this file's own source (see
//! `tests::determinism_argument_is_structural_not_just_repeated_runs`).

use sha2::{Digest as _, Sha256};

use super::{
    build_snapshot, limit_error, project_subjects, replay_error, PublishedEntry, RegistrySnapshot,
    YankPolicy, MAX_OUTPUT_BYTES, MAX_RENDER_BYTES,
};
use crate::bounded_output;
use crate::diagnostic::{quote_json, Diagnostic};
use crate::package_lock_v3;
use crate::package_resolver_v2;

#[cfg(test)]
mod tests;

pub const SCHEMA: &str = "semaprax.registry-bound-resolution.v1";
const DIGEST_DOMAIN: &[u8] = b"semaprax.registry-bound-resolution.v1\0";

/// Everything [`crate::package_resolver_v2::ResolutionInput`] needs beyond
/// the `subjects` catalog, which a snapshot projection always supplies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionTemplate {
    pub requirements: Vec<package_resolver_v2::Requirement>,
    pub target: String,
    pub allowed_capabilities: Vec<String>,
}

/// One canonical, content-addressed envelope binding a registry snapshot
/// digest, a yank policy, and the resolver-v2 evidence it produced.
#[derive(Clone, Debug)]
pub struct BoundResolution {
    envelope: String,
    digest: String,
    pub warnings: Vec<Diagnostic>,
}

impl BoundResolution {
    #[must_use]
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedBoundResolution {
    pub packages: Vec<package_lock_v3::Coordinate>,
    pub snapshot_digest: String,
    pub digest: String,
    pub warnings: Vec<Diagnostic>,
}

/// Binds `snapshot` -- projected under `policy` -- to one resolver-v2
/// resolution over `template`. Pure function of its arguments: calling this
/// twice with the same snapshot, policy, template and options always
/// yields byte-identical evidence (see
/// `tests::same_inputs_produce_byte_identical_bound_evidence_every_time`).
pub fn bind_to_snapshot(
    snapshot: &RegistrySnapshot,
    policy: YankPolicy,
    template: &ResolutionTemplate,
    options: &package_resolver_v2::ResolutionOptions,
) -> Result<BoundResolution, Diagnostic> {
    let (result, overflowed) = bounded_output::with_limit(MAX_RENDER_BYTES, || {
        assemble(snapshot, policy, template, options)
    });
    if overflowed {
        return Err(limit_error(
            "registry-bound resolution cumulative String budget exceeded",
        ));
    }
    let assembled = result?;
    Ok(BoundResolution {
        envelope: assembled.envelope,
        digest: assembled.digest,
        warnings: assembled.warnings,
    })
}

/// Independently rebuilds a registry snapshot from `entries` and a
/// resolution from `template`, then checks the result replays `evidence`
/// byte for byte before independently replaying the embedded resolver-v2
/// evidence. There is no cache: a substituted snapshot entry, a reordered
/// entry list, a changed yank policy, or a retargeted requirement is
/// refused rather than accepted because a prior call looked similar. On
/// success, `snapshot_digest` in the result is the *independently rebuilt*
/// digest, never a value merely copied out of `evidence`.
pub fn verify_bound_resolution(
    evidence: &str,
    entries: &[PublishedEntry],
    policy: YankPolicy,
    template: &ResolutionTemplate,
    options: &package_resolver_v2::ResolutionOptions,
) -> Result<VerifiedBoundResolution, Diagnostic> {
    if evidence.len() > MAX_OUTPUT_BYTES {
        return Err(limit_error(
            "registry-bound resolution evidence exceeds output bound",
        ));
    }
    let snapshot = build_snapshot(entries)?;
    let (result, overflowed) = bounded_output::with_limit(MAX_RENDER_BYTES, || {
        let assembled = assemble(&snapshot, policy, template, options)?;
        if assembled.envelope != evidence {
            return Err(replay_error(
                "registry-bound resolution evidence does not exactly replay the supplied \
                 registry entries and resolution template",
            ));
        }
        let verified =
            package_resolver_v2::verify(&assembled.resolver_evidence, &assembled.input, options)
                .map_err(|_| {
                    replay_error(
                        "registry-bound resolution evidence's embedded resolver-v2 evidence \
                         failed independent replay",
                    )
                })?;
        Ok(VerifiedBoundResolution {
            packages: verified.packages,
            snapshot_digest: snapshot.digest().to_owned(),
            digest: assembled.digest.clone(),
            warnings: assembled.warnings.clone(),
        })
    });
    if overflowed {
        return Err(limit_error(
            "registry-bound resolution cumulative String budget exceeded",
        ));
    }
    result
}

struct Assembled {
    input: package_resolver_v2::ResolutionInput,
    resolver_evidence: String,
    warnings: Vec<Diagnostic>,
    envelope: String,
    digest: String,
}

fn assemble(
    snapshot: &RegistrySnapshot,
    policy: YankPolicy,
    template: &ResolutionTemplate,
    options: &package_resolver_v2::ResolutionOptions,
) -> Result<Assembled, Diagnostic> {
    let projected = project_subjects(snapshot, policy)?;
    let input = package_resolver_v2::ResolutionInput {
        requirements: template.requirements.clone(),
        subjects: projected.subjects,
        target: template.target.clone(),
        allowed_capabilities: template.allowed_capabilities.clone(),
    };
    let resolver_evidence = package_resolver_v2::generate(&input, options).map_err(|errors| {
        errors.into_iter().next().unwrap_or_else(|| {
            replay_error("package resolution failed with no diagnostic to report")
        })
    })?;
    let payload = render_payload(snapshot.digest(), policy, &resolver_evidence);
    let envelope = render_wrapper(&payload);
    if envelope.len() > MAX_OUTPUT_BYTES {
        return Err(limit_error(
            "registry-bound resolution evidence exceeds output bound",
        ));
    }
    let digest = envelope_digest(&payload);
    Ok(Assembled {
        input,
        resolver_evidence,
        warnings: projected.warnings,
        envelope,
        digest,
    })
}

fn yank_policy_tag(policy: YankPolicy) -> &'static str {
    match policy {
        YankPolicy::ExcludeYanked => "exclude_yanked",
        YankPolicy::RefuseIfYanked => "refuse_if_yanked",
        YankPolicy::AllowYankedWithWarning => "allow_yanked_with_warning",
    }
}

fn render_payload(snapshot_digest: &str, policy: YankPolicy, resolver_evidence: &str) -> String {
    bounded_output::budgeted_format(format_args!(
        "{{\"schema\":{},\"snapshot_digest\":{},\"yank_policy\":{},\"resolution\":{resolver_evidence}}}",
        quote_json(SCHEMA),
        quote_json(snapshot_digest),
        quote_json(yank_policy_tag(policy)),
    ))
}

fn envelope_digest(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload.as_bytes());
    bounded_output::budgeted_format(format_args!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    ))
}

fn render_wrapper(payload: &str) -> String {
    bounded_output::budgeted_format(format_args!(
        "{{\"schema\":{},\"digest\":{},\"bytes\":{},\"payload\":{payload}}}",
        quote_json(SCHEMA),
        quote_json(&envelope_digest(payload)),
        payload.len(),
    ))
}
