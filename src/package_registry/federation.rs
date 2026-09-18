//! Package Registry Federation v1 (issue #195): the multi-registry
//! dependency-confusion refusal that [`super`]'s single-registry snapshot
//! model deliberately left open.
//!
//! ## What this closes, and what it does not
//!
//! [`super::build_snapshot`] models exactly **one** registry. Its
//! ownership-continuity check therefore protects a package name only
//! *within* that one snapshot: two registries could each serve
//! `examples.meaning@1.0.0`, under different publishers and different
//! content, and nothing in the snapshot layer would notice. That is the
//! classic dependency-confusion attack, and issue #195 names it as a
//! required case. This module is the layer that refuses it.
//!
//! It adds **no** cryptography and **no** authority. Every nonclaim in
//! [`super`]'s docstring still holds here verbatim: signatures stay opaque
//! and are never verified, `provenance_digest` stays an unverified
//! reference, and nothing in this file touches the network, the clock, the
//! environment, or the filesystem. A federation is proof data about a
//! caller-supplied set of snapshots, never permission to fetch one.
//!
//! ## The model
//!
//! A [`Federation`] binds two things together in one canonical,
//! content-addressed `semaprax.package-registry-federation.v1` envelope:
//!
//! 1. a closed, caller-owned set of [`FederatedRegistry`] values, each a
//!    `registry_id` bound to an already-built [`super::RegistrySnapshot`]
//!    by that snapshot's own digest; and
//! 2. a closed [`NamespaceClaim`] table assigning each package namespace --
//!    a dotted prefix, from one segment to a whole package name -- to
//!    exactly one `registry_id`.
//!
//! There is no ambient registry list, no default registry, no ordered
//! search path, and no fallback: a package name that the namespace table
//! does not explicitly authorize is refused, never resolved from whichever
//! registry happens to answer first. Search-path precedence *is* the
//! dependency-confusion bug, so this format has no search path.
//!
//! ## The two refusals
//!
//! - **`SPX-PKR611` — cross-registry dependency confusion.** The same
//!   `package` name is served by more than one registry. This is the
//!   whole cross-registry publisher-identity question too, and the reason
//!   there is no separate identity check here: one package name resolves
//!   to exactly one registry, so a second registry cannot introduce a
//!   competing publisher claim for it at all, and `verify_ownership_continuity`
//!   already refuses a divergent identity *within* that one registry.
//! - **`SPX-PKR612` — namespace authority.** A served package is covered by
//!   no claim, by a claim naming a *different* registry than the one serving
//!   it, or by *more than one* claim; or the table repeats a namespace or
//!   names a `registry_id` that is not in this federation. There is no
//!   longest-match precedence: overlapping claims are refused, not ranked.
//!
//! Registry-set well-formedness reuses [`super`]'s existing codes rather
//! than minting more: a `registry_id` that repeats with a *different*
//! snapshot digest is `SPX-PKR604` (the same "an established binding
//! cannot be silently replaced" refusal as a conflicting republish), a
//! `registry_id` that repeats with the *same* digest is `SPX-PKR605`
//! (duplicate, not idempotent), id/namespace grammar violations are
//! `SPX-PKR601`, and count bounds are `SPX-PKR606`.
//!
//! ## Determinism, structurally
//!
//! Registries are keyed through `BTreeMap<String, _>`, namespace claims
//! through `BTreeMap<String, String>`, and the merged package set through
//! `BTreeMap<(String, Version), _>` -- never a `HashMap`/`HashSet`. Two
//! separate claims follow, and they are deliberately not the same claim:
//!
//! - **Accepted bytes are order-independent, always.** Rendering reads only
//!   the canonical maps, so the same registries and claims in any argument
//!   order produce byte-identical evidence. See
//!   `tests::registry_and_claim_order_do_not_affect_canonical_bytes`.
//! - **Refusal *selection* is content-determined for the two cross-registry
//!   rules only.** `merge_packages` (`SPX-PKR611`) and
//!   `authorize_namespaces` (`SPX-PKR612`) walk the canonical maps, so which
//!   conflict is reported is a pure function of content -- see
//!   `tests::dependency_confusion_is_refused_regardless_of_registry_order`.
//!   The input-table well-formedness checks (`SPX-PKR601`/`604`/`605`) must
//!   iterate the caller's list to build those maps in the first place, so
//!   they report the first offending element *of that list*. This is stated
//!   rather than papered over: a caller that needs a stable choice among
//!   several malformed entries must sort its own input.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use super::{
    apply_yank_policy, canonical_version_text, capacity_error, dependency_confusion_error,
    duplicate_publish_error, immutable_conflict_error, limit_error, namespace_authority_error,
    replay_error, validate_identity, ProjectedCatalog, PublishedEntry, RegistrySnapshot,
    YankPolicy, MAX_OUTPUT_BYTES, MAX_RENDER_BYTES,
};
use crate::bounded_output;
use crate::diagnostic::{quote_json, Diagnostic};
use crate::package_range::Version;

pub const FEDERATION_SCHEMA: &str = "semaprax.package-registry-federation.v1";
pub const MAX_REGISTRIES: usize = 16;
pub const MAX_NAMESPACE_CLAIMS: usize = 256;
pub const MAX_FEDERATED_PACKAGES: usize = 1024;
const DIGEST_DOMAIN: &[u8] = b"semaprax.package-registry-federation.v1\0";

/// One registry in a federation: an identity bound to an already-built,
/// already-digest-bound snapshot. The snapshot must be built by
/// [`super::build_snapshot`], so every per-entry check that layer performs
/// has already run before this layer sees the entry.
#[derive(Clone, Debug)]
pub struct FederatedRegistry {
    pub registry_id: String,
    pub snapshot: RegistrySnapshot,
}

/// An assignment of one package namespace -- a dotted prefix, from a single
/// segment (`examples`) to a whole package name (`examples.meaning`) -- to
/// exactly one registry. A package no claim covers is refused, not defaulted,
/// and a package two claims cover is refused rather than ranked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceClaim {
    pub namespace: String,
    pub registry_id: String,
}

/// Where one package version is served from, after cross-registry
/// validation has accepted the federation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedCoordinate {
    pub registry_id: String,
    pub package: String,
    pub version: String,
}

/// One immutable, canonical, content-addressed federation of registries.
#[derive(Clone, Debug)]
pub struct Federation {
    packages: BTreeMap<(String, Version), (String, PublishedEntry)>,
    envelope: String,
    digest: String,
}

impl Federation {
    #[must_use]
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Every served coordinate, in canonical `(package, version)` order --
    /// which is unambiguous precisely because `SPX-PKR611` has already
    /// refused any package name served by two registries.
    #[must_use]
    pub fn coordinates(&self) -> Vec<FederatedCoordinate> {
        self.packages
            .iter()
            .map(
                |((package, version), (registry_id, _))| FederatedCoordinate {
                    registry_id: registry_id.clone(),
                    package: package.clone(),
                    version: canonical_version_text(*version),
                },
            )
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFederation {
    pub coordinates: Vec<FederatedCoordinate>,
    pub digest: String,
}

/// Builds one canonical federation from a complete, caller-owned registry
/// set and namespace table. Pure function of its arguments: no retained
/// state, no I/O, no clock. Fails closed on cross-registry dependency
/// confusion and on any namespace this table does not explicitly authorize.
pub fn build_federation(
    registries: &[FederatedRegistry],
    claims: &[NamespaceClaim],
) -> Result<Federation, Diagnostic> {
    let (result, overflowed) =
        bounded_output::with_limit(MAX_RENDER_BYTES, || build(registries, claims));
    if overflowed {
        return Err(limit_error(
            "registry federation cumulative String budget exceeded",
        ));
    }
    result
}

/// Independently rebuilds a federation from its inputs and checks it
/// replays `evidence` byte for byte. There is no cache: a substituted
/// snapshot, an added registry, a retargeted namespace claim, or a single
/// flipped byte is refused rather than accepted because a prior call looked
/// similar.
pub fn verify_federation(
    evidence: &str,
    registries: &[FederatedRegistry],
    claims: &[NamespaceClaim],
) -> Result<VerifiedFederation, Diagnostic> {
    if evidence.len() > MAX_OUTPUT_BYTES {
        return Err(limit_error(
            "registry federation evidence exceeds output bound",
        ));
    }
    let (result, overflowed) = bounded_output::with_limit(MAX_RENDER_BYTES, || {
        let rebuilt = build(registries, claims)?;
        if rebuilt.envelope != evidence {
            return Err(replay_error(
                "registry federation evidence does not exactly replay the supplied registries",
            ));
        }
        Ok(VerifiedFederation {
            coordinates: rebuilt.coordinates(),
            digest: rebuilt.digest.clone(),
        })
    });
    if overflowed {
        return Err(limit_error(
            "registry federation cumulative String budget exceeded",
        ));
    }
    result
}

/// Projects a whole federation into the single `subjects: Vec<String>`
/// catalog [`crate::package_resolver_v2::ResolutionInput`] consumes, in one
/// global canonical `(package, version)` order rather than registry by
/// registry -- so the catalog handed to the resolver does not depend on
/// which registry was listed first. Yank handling is
/// `apply_yank_policy`, the same decision the single-registry
/// projection makes, not a second copy of it.
pub fn project_federated_subjects(
    federation: &Federation,
    policy: YankPolicy,
) -> Result<ProjectedCatalog, Diagnostic> {
    let mut subjects = Vec::with_capacity(federation.packages.len());
    let mut warnings = Vec::new();
    for ((package, version), (_registry_id, entry)) in &federation.packages {
        apply_yank_policy(
            package,
            *version,
            entry,
            policy,
            &mut subjects,
            &mut warnings,
        )?;
    }
    Ok(ProjectedCatalog { subjects, warnings })
}

fn build(
    registries: &[FederatedRegistry],
    claims: &[NamespaceClaim],
) -> Result<Federation, Diagnostic> {
    let ordered_registries = order_registries(registries)?;
    let ordered_claims = order_claims(claims, &ordered_registries)?;
    let packages = merge_packages(&ordered_registries)?;
    authorize_namespaces(&packages, &ordered_claims)?;
    let payload = render_payload(&ordered_registries, &ordered_claims, &packages);
    let envelope = render_wrapper(&payload);
    if envelope.len() > MAX_OUTPUT_BYTES {
        return Err(limit_error(
            "registry federation evidence exceeds output bound",
        ));
    }
    let digest = envelope_digest(&payload);
    Ok(Federation {
        packages,
        envelope,
        digest,
    })
}

/// Keys the registry set by `registry_id`. A repeated id is refused: with
/// the same snapshot digest as a duplicate (`SPX-PKR605`), with a different
/// one as an immutable conflict (`SPX-PKR604`) -- one registry identity
/// cannot be silently backed by two different snapshots.
fn order_registries(
    registries: &[FederatedRegistry],
) -> Result<BTreeMap<String, &FederatedRegistry>, Diagnostic> {
    if registries.is_empty() || registries.len() > MAX_REGISTRIES {
        return Err(capacity_error(
            "registry federation registry count is outside bounds",
        ));
    }
    let mut ordered: BTreeMap<String, &FederatedRegistry> = BTreeMap::new();
    for registry in registries {
        validate_identity(&registry.registry_id)?;
        if let Some(existing) = ordered.get(registry.registry_id.as_str()) {
            return Err(
                if existing.snapshot.digest() == registry.snapshot.digest() {
                    duplicate_publish_error(format!(
                    "registry `{}` is listed twice with the same snapshot digest; a federation lists each registry once",
                    registry.registry_id
                ))
                } else {
                    immutable_conflict_error(format!(
                    "registry `{}` is bound to two different snapshot digests in one federation and cannot be silently replaced",
                    registry.registry_id
                ))
                },
            );
        }
        ordered.insert(registry.registry_id.clone(), registry);
    }
    Ok(ordered)
}

/// Keys the namespace table by namespace prefix, refusing any claim whose
/// namespace or registry id is malformed, that repeats a namespace, or that
/// names a registry outside this federation.
fn order_claims(
    claims: &[NamespaceClaim],
    registries: &BTreeMap<String, &FederatedRegistry>,
) -> Result<BTreeMap<String, String>, Diagnostic> {
    if claims.len() > MAX_NAMESPACE_CLAIMS {
        return Err(capacity_error(
            "registry federation namespace claim count exceeds bound",
        ));
    }
    let mut ordered: BTreeMap<String, String> = BTreeMap::new();
    for claim in claims {
        validate_identity(&claim.namespace)?;
        validate_identity(&claim.registry_id)?;
        if !registries.contains_key(claim.registry_id.as_str()) {
            return Err(namespace_authority_error(format!(
                "namespace `{}` is claimed for registry `{}`, which is not in this federation",
                claim.namespace, claim.registry_id
            )));
        }
        if ordered.contains_key(claim.namespace.as_str()) {
            return Err(namespace_authority_error(format!(
                "namespace `{}` carries more than one claim; exactly one registry must own it",
                claim.namespace
            )));
        }
        ordered.insert(claim.namespace.clone(), claim.registry_id.clone());
    }
    Ok(ordered)
}

/// Merges every registry's entries into one canonical package set, refusing
/// cross-registry dependency confusion. Iteration is over the canonically
/// keyed registry map and each snapshot's own canonical entry map, so which
/// registry is "first" -- and therefore which conflict is reported -- is a
/// pure function of content, never of the caller's argument order.
fn merge_packages(
    registries: &BTreeMap<String, &FederatedRegistry>,
) -> Result<BTreeMap<(String, Version), (String, PublishedEntry)>, Diagnostic> {
    let mut packages: BTreeMap<(String, Version), (String, PublishedEntry)> = BTreeMap::new();
    // `package name -> the one registry allowed to serve it`.
    let mut servers: BTreeMap<&str, &str> = BTreeMap::new();
    for (registry_id, registry) in registries {
        for ((package, version), entry) in &registry.snapshot.entries {
            match servers.get(package.as_str()) {
                None => {
                    servers.insert(package.as_str(), registry_id.as_str());
                }
                Some(owner) if *owner != registry_id.as_str() => {
                    return Err(dependency_confusion_error(format!(
                        "`{package}` is served by both registry `{owner}` and registry `{registry_id}`; \
                         one package name must be served by exactly one registry"
                    )));
                }
                Some(_) => {}
            }
            if packages.len() >= MAX_FEDERATED_PACKAGES {
                return Err(capacity_error(
                    "registry federation merged package count exceeds bound",
                ));
            }
            packages.insert(
                (package.clone(), *version),
                (registry_id.clone(), entry.clone()),
            );
        }
    }
    Ok(packages)
}

/// Refuses any served package that the claim table does not authorize:
/// unclaimed, claimed for a different registry, or covered by *more than
/// one* claim. A claim is a dotted namespace prefix -- `examples` covers
/// `examples.meaning`, and `examples.meaning` covers exactly that package --
/// matched segment-wise, so `example` never covers `examples.meaning`.
///
/// There is deliberately **no longest-match precedence**. If two claims both
/// cover a package, the federation is refused rather than resolved in favour
/// of the more specific one: precedence is a silent tie-break, and a silent
/// tie-break between two registries' claims over one package name is exactly
/// the ambiguity dependency confusion exploits. Overlapping claims are an
/// authoring mistake, and this says so instead of picking a winner.
fn authorize_namespaces(
    packages: &BTreeMap<(String, Version), (String, PublishedEntry)>,
    claims: &BTreeMap<String, String>,
) -> Result<(), Diagnostic> {
    for ((package, _version), (registry_id, _entry)) in packages {
        let mut matched: Option<(&str, &str)> = None;
        for (namespace, owner) in claims {
            if !covers(namespace, package) {
                continue;
            }
            if let Some((first, _)) = matched {
                return Err(namespace_authority_error(format!(
                    "`{package}` is covered by more than one namespace claim (`{first}` and \
                     `{namespace}`); exactly one claim must cover a package, and this format has \
                     no longest-match precedence"
                )));
            }
            matched = Some((namespace.as_str(), owner.as_str()));
        }
        match matched {
            None => {
                return Err(namespace_authority_error(format!(
                    "no registry is authorized for `{package}` (served by `{registry_id}`); a \
                     federation authorizes namespaces explicitly and has no default"
                )));
            }
            Some((namespace, owner)) if owner != registry_id => {
                return Err(namespace_authority_error(format!(
                    "namespace `{namespace}` is owned by registry `{owner}`, but `{package}` is \
                     served by registry `{registry_id}`"
                )));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Segment-wise prefix containment: `namespace` covers `package` when they
/// are equal or `package` continues after a `.` boundary. Compared on the
/// boundary rather than with a bare `starts_with`, so `example` does not
/// cover `examples.meaning`.
fn covers(namespace: &str, package: &str) -> bool {
    package == namespace
        || (package.len() > namespace.len()
            && package.starts_with(namespace)
            && package.as_bytes()[namespace.len()] == b'.')
}

fn render_payload(
    registries: &BTreeMap<String, &FederatedRegistry>,
    claims: &BTreeMap<String, String>,
    packages: &BTreeMap<(String, Version), (String, PublishedEntry)>,
) -> String {
    let registry_count = registries.len();
    let namespace_count = claims.len();
    let package_count = packages.len();
    let rendered_registries = bounded_output::budgeted_join(
        registries
            .iter()
            .map(|(registry_id, registry)| {
                bounded_output::budgeted_format(format_args!(
                    "{{\"registry_id\":{},\"snapshot_digest\":{}}}",
                    quote_json(registry_id),
                    quote_json(registry.snapshot.digest()),
                ))
            })
            .collect::<Vec<_>>(),
        ",",
    );
    let rendered_claims = bounded_output::budgeted_join(
        claims
            .iter()
            .map(|(namespace, registry_id)| {
                bounded_output::budgeted_format(format_args!(
                    "{{\"namespace\":{},\"registry_id\":{}}}",
                    quote_json(namespace),
                    quote_json(registry_id),
                ))
            })
            .collect::<Vec<_>>(),
        ",",
    );
    let rendered_packages = bounded_output::budgeted_join(
        packages
            .iter()
            .map(|((package, version), (registry_id, entry))| {
                bounded_output::budgeted_format(format_args!(
                    "{{\"package\":{},\"version\":{},\"registry_id\":{},\"content_digest\":{},\"status\":{}}}",
                    quote_json(package),
                    quote_json(&canonical_version_text(*version)),
                    quote_json(registry_id),
                    quote_json(&entry.content_digest),
                    super::render_status(&entry.status),
                ))
            })
            .collect::<Vec<_>>(),
        ",",
    );
    bounded_output::budgeted_format(format_args!(
        "{{\"schema\":{},\"registry_count\":{registry_count},\"namespace_count\":{namespace_count},\"package_count\":{package_count},\"registries\":[{rendered_registries}],\"namespaces\":[{rendered_claims}],\"packages\":[{rendered_packages}]}}",
        quote_json(FEDERATION_SCHEMA),
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
        quote_json(FEDERATION_SCHEMA),
        quote_json(&envelope_digest(payload)),
        payload.len(),
    ))
}

#[cfg(test)]
mod tests;
