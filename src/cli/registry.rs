//! `semaprax registry search|add|lock|fetch|verify|publish`: read-only
//! fronts over `semaprax::package_registry`, issue #195's last in-scope
//! item.
//!
//! `src/package_registry` was complete internally -- deterministic
//! content-addressed snapshots, immutability and duplicate refusal,
//! ownership continuity, yank policy, multi-registry namespace authority,
//! and registry-bound resolution -- but nothing outside the module
//! referenced it: `SPX-PKR601`-`612` had no route outside a Rust unit test,
//! and issue #195's "CLI search/add/lock/fetch/verify/publish" line was the
//! one in-scope item with nothing behind it. This front closes that gap.
//!
//! Every verb here only decodes and reads bytes the caller already has on
//! disk; every rule is owned by `semaprax::package_registry`
//! (`wire::parse_registry_document`, `build_snapshot`, `verify_snapshot`,
//! `catalog::select_version`, `binding::bind_to_snapshot`,
//! `binding::verify_bound_resolution`) and re-derived from the exact bytes
//! under test, matching `cli::audit`'s and `cli::typed_workflow`'s shape
//! exactly. This front re-implements no registry rule, and the codes it
//! prints for a registry refusal are the owning module's own.
//!
//! ## The three authorities this front does not hold, and cannot
//!
//! **It never publishes.** `registry publish` decides *admissibility* and
//! records that decision: it rebuilds the snapshot that would result from
//! adding the candidate entry, so an immutable conflict (`SPX-PKR604`), a
//! duplicate (`SPX-PKR605`), a reserved `std.*` name (`SPX-PKR602`) or a
//! digest that does not bind its subject bytes (`SPX-PKR603`) is refused --
//! and then prints the registry document that *would* hold it. It writes
//! nothing, signs nothing, and contacts nothing; making that document real
//! is a separate, human act with separate authority, which is exactly issue
//! #195's "publication requires separate explicit authority" and this
//! repository's standing rule that tooling gains no ambient publication
//! authority. No signature is verified anywhere in this path either -- see
//! the nonclaim below.
//!
//! **It never reaches the network.** A registry document is the mirror: the
//! caller supplies the complete entry set as bytes, and `search`/`fetch`
//! answer from those bytes alone. There is no registry URL, no default
//! registry, no search path, and no fallback -- a search path *is* the
//! dependency-confusion vulnerability issue #195 names, so the format has
//! none. Nothing here is capable of an outbound connection;
//! `tests::this_front_spawns_no_process_reaches_no_network_and_writes_nothing`
//! is a source scan pinning that.
//!
//! **It never writes.** `lock` and `publish` emit their documents on stdout
//! for the caller to redirect; this front opens no file for writing, creates
//! no directory, and touches no cache. A path operand is read, never joined
//! with request-derived text: a package name or search query from the
//! command line is only ever compared as an opaque string, never used to
//! build a path.
//!
//! ## Nonclaim
//!
//! No cryptography runs in this front or anywhere beneath it. A
//! `signature.identity` is an *unverified claim* and is reported as such;
//! `package_registry`'s `signature_is_opaque_and_never_cryptographically_checked`
//! pins that a forged signature is accepted by the layer below. Issue #168
//! owns the signing key that would change this, and is open.

use std::path::{Path, PathBuf};

use semaprax::diagnostic::Diagnostic;
use semaprax::package_registry::{
    self, binding, catalog,
    wire::{self, TemplateDocument},
    PublishedEntry, RegistrySnapshot,
};

const USAGE: &str = "registry accepts `search <registry.json> <query>`, \
                     `add <registry.json> <package> <range>`, \
                     `lock <registry.json> <template.json> [--raw]`, \
                     `fetch <registry.json> <package> <version> [--raw]`, \
                     `verify <registry.json> <snapshot-evidence.json>`, \
                     `verify <registry.json> <template.json> <lock-evidence.json>`, or \
                     `publish <registry.json> <entry.json>`; see `semaprax help registry`";

/// Largest document this front reads for any one verb. The owning decoders
/// (`wire::parse_registry_document`, `wire::parse_template_document`) enforce
/// their own bounds independently on the same bytes, and `build_snapshot`
/// enforces the registry's per-entry and total bounds after that; this only
/// keeps a hostile file from being read into memory before any of them ever
/// sees it.
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

/// This front's own code for "the requested document could not be read at
/// all" -- never used for a registry decode or rule failure, which always
/// keeps the owning module's own `SPX-PKR6xx` code.
fn document_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z926", message)
}

/// This front's own code for "the registry was read and checked, and does
/// not contain what the request asked for": an unknown coordinate, or a
/// search/selection that matched nothing. Distinct from [`document_error`]
/// (which never got to read anything) and from every `SPX-PKR6xx` code
/// (which is the registry module refusing its own rule).
fn not_found(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z927", message)
}

pub(crate) enum RegistryCommand {
    Search(PathBuf, String),
    Add(PathBuf, String, String),
    Lock(PathBuf, PathBuf, bool),
    Fetch(PathBuf, String, String, bool),
    VerifySnapshot(PathBuf, PathBuf),
    VerifyLock(PathBuf, PathBuf, PathBuf),
    Publish(PathBuf, PathBuf),
}

fn is_flag(argument: &str) -> bool {
    argument.starts_with("--")
}

fn operand(value: &str) -> bool {
    !value.is_empty() && !is_flag(value)
}

/// The closed argument grammar. An unknown subcommand, a missing operand, an
/// extra operand, or an option-shaped positional operand fails closed with
/// the usage line and exit code 2 before any path is opened.
pub(crate) fn parse(args: &[String]) -> Result<RegistryCommand, u8> {
    let rejected = match args {
        [verb, registry, query]
            if verb == "search" && operand(registry) && !query.is_empty() && !is_flag(query) =>
        {
            return Ok(RegistryCommand::Search(
                PathBuf::from(registry),
                query.clone(),
            ));
        }
        [verb, registry, package, range]
            if verb == "add" && operand(registry) && operand(package) && operand(range) =>
        {
            return Ok(RegistryCommand::Add(
                PathBuf::from(registry),
                package.clone(),
                range.clone(),
            ));
        }
        [verb, registry, template] if verb == "lock" && operand(registry) && operand(template) => {
            return Ok(RegistryCommand::Lock(
                PathBuf::from(registry),
                PathBuf::from(template),
                false,
            ));
        }
        [verb, registry, template, raw]
            if verb == "lock" && operand(registry) && operand(template) && raw == "--raw" =>
        {
            return Ok(RegistryCommand::Lock(
                PathBuf::from(registry),
                PathBuf::from(template),
                true,
            ));
        }
        [verb, registry, package, version]
            if verb == "fetch" && operand(registry) && operand(package) && operand(version) =>
        {
            return Ok(RegistryCommand::Fetch(
                PathBuf::from(registry),
                package.clone(),
                version.clone(),
                false,
            ));
        }
        [verb, registry, package, version, raw]
            if verb == "fetch"
                && operand(registry)
                && operand(package)
                && operand(version)
                && raw == "--raw" =>
        {
            return Ok(RegistryCommand::Fetch(
                PathBuf::from(registry),
                package.clone(),
                version.clone(),
                true,
            ));
        }
        [verb, registry, evidence]
            if verb == "verify" && operand(registry) && operand(evidence) =>
        {
            return Ok(RegistryCommand::VerifySnapshot(
                PathBuf::from(registry),
                PathBuf::from(evidence),
            ));
        }
        [verb, registry, template, evidence]
            if verb == "verify" && operand(registry) && operand(template) && operand(evidence) =>
        {
            return Ok(RegistryCommand::VerifyLock(
                PathBuf::from(registry),
                PathBuf::from(template),
                PathBuf::from(evidence),
            ));
        }
        [verb, registry, entry] if verb == "publish" && operand(registry) && operand(entry) => {
            return Ok(RegistryCommand::Publish(
                PathBuf::from(registry),
                PathBuf::from(entry),
            ));
        }
        [verb, ..]
            if !matches!(
                verb.as_str(),
                "search" | "add" | "lock" | "fetch" | "verify" | "publish"
            ) =>
        {
            format!("unknown registry subcommand `{verb}`; {USAGE}")
        }
        _ => USAGE.to_owned(),
    };
    eprintln!("{rejected}");
    Err(2)
}

fn read_bounded(path: &Path, what: &str) -> Result<String, Diagnostic> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        document_error(format!("cannot read {what} {}: {error}", path.display()))
    })?;
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(document_error(format!(
            "{} is {} bytes, over the {MAX_DOCUMENT_BYTES}-byte bound for a {what}",
            path.display(),
            metadata.len()
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        document_error(format!("cannot read {what} {}: {error}", path.display()))
    })?;
    String::from_utf8(bytes)
        .map_err(|_| document_error(format!("{} is not valid UTF-8", path.display())))
}

/// Reads and decodes a registry document into its caller-owned entry list.
/// Decoding is `wire`'s rule and every registry rule is `build_snapshot`'s;
/// this only supplies the bytes.
fn read_entries(path: &Path) -> Result<Vec<PublishedEntry>, Diagnostic> {
    let text = read_bounded(path, "registry document")?;
    wire::parse_registry_document(&text)
}

fn read_snapshot(path: &Path) -> Result<(Vec<PublishedEntry>, RegistrySnapshot), Diagnostic> {
    let entries = read_entries(path)?;
    let snapshot = package_registry::build_snapshot(&entries)?;
    Ok((entries, snapshot))
}

fn read_template(path: &Path) -> Result<TemplateDocument, Diagnostic> {
    let text = read_bounded(path, "resolution template document")?;
    wire::parse_template_document(&text)
}

fn summary_line(summary: &catalog::EntrySummary) -> String {
    let status = match &summary.yank_reason {
        Some(reason) => format!("yanked ({reason})"),
        None => summary.status.to_owned(),
    };
    format!(
        "  {}@{} {} license={} publisher-claim={} {}\n",
        summary.package,
        summary.version,
        status,
        summary.license,
        summary.publisher,
        summary.content_digest,
    )
}

/// `registry search <registry.json> <query>`: every published coordinate
/// whose package name contains `query`, as a plain substring comparison over
/// already-decoded registry data. `query` is never joined into a path, used
/// as a glob, or interpreted as a pattern.
pub(crate) fn run_search(path: &Path, query: &str) -> Result<String, Diagnostic> {
    let (_, snapshot) = read_snapshot(path)?;
    let matched: Vec<catalog::EntrySummary> = snapshot
        .listing()
        .into_iter()
        .filter(|summary| summary.package.contains(query))
        .collect();
    let mut out = format!(
        "registry search: {} for `{query}`\nsnapshot: {}\nmatches: {}\n",
        path.display(),
        snapshot.digest(),
        matched.len()
    );
    for summary in &matched {
        out.push_str(&summary_line(summary));
    }
    out.push_str(
        "status: SEARCHED (this registry document is the whole registry; \
         no network, no default registry, no search path)\n",
    );
    Ok(out)
}

/// `registry add <registry.json> <package> <range>`: the highest published
/// version satisfying `range`, and the exact requirement to record. Decides
/// and reports; it never edits a manifest, which is `semaprax add`'s
/// separate, already-existing job.
pub(crate) fn run_add(path: &Path, package: &str, range: &str) -> Result<String, Diagnostic> {
    let (_, snapshot) = read_snapshot(path)?;
    let selected = catalog::select_version(
        &snapshot,
        package,
        range,
        package_registry::YankPolicy::ExcludeYanked,
    )?;
    Ok(format!(
        "registry add: {}\nsnapshot: {}\nrequirement: {package}:{range}\n\
         selected: {}@{}\ncontent_digest: {}\napi_digest: {}\nlicense: {}\n\
         publisher-claim: {} (UNVERIFIED: no signature is checked anywhere in this path)\n\
         status: SELECTED (nothing was written; record this requirement yourself)\n",
        path.display(),
        snapshot.digest(),
        selected.package,
        selected.version,
        selected.content_digest,
        selected.api_digest,
        selected.license,
        selected.publisher,
    ))
}

/// `registry lock <registry.json> <template.json>`: binds the registry
/// snapshot to one resolver-v2 resolution and prints the canonical
/// Registry-Bound Resolution v1 document inside a human report. `--raw`
/// prints only the canonical document, so redirecting stdout preserves its
/// exact bytes. Both forms only read caller-supplied files.
pub(crate) fn run_lock(registry: &Path, template: &Path) -> Result<String, Diagnostic> {
    let (_, snapshot) = read_snapshot(registry)?;
    let document = read_template(template)?;
    let bound = binding::bind_to_snapshot(
        &snapshot,
        document.policy,
        &document.template,
        &document.options,
    )?;
    let mut out = format!(
        "registry lock: {} against {}\nsnapshot: {}\nlock digest: {}\nwarnings: {}\n",
        template.display(),
        registry.display(),
        snapshot.digest(),
        bound.digest(),
        bound.warnings.len(),
    );
    for warning in &bound.warnings {
        out.push_str(&format!("  {} {}\n", warning.code, warning.message));
    }
    out.push_str(&format!("lock document:\n{}\n", bound.envelope()));
    out.push_str("status: LOCKED (nothing was written; redirect this document yourself)\n");
    Ok(out)
}

/// The exact Registry-Bound Resolution v1 envelope for `registry` and
/// `template`, with no heading, status line, or appended newline. This is the
/// read-only machine form of `registry lock ... --raw`.
fn run_lock_raw(registry: &Path, template: &Path) -> Result<String, Diagnostic> {
    let (_, snapshot) = read_snapshot(registry)?;
    let document = read_template(template)?;
    Ok(binding::bind_to_snapshot(
        &snapshot,
        document.policy,
        &document.template,
        &document.options,
    )?
    .envelope()
    .to_owned())
}

/// `registry fetch <registry.json> <package> <version>`: the exact published
/// Subject-v3 bytes for one coordinate, from the supplied registry document
/// alone. This is the offline mirror path: there is no cache, no network,
/// and no fallback. The bytes are known to match the published
/// `content_digest` because `build_snapshot` refuses (`SPX-PKR603`) any
/// entry where they do not, and the snapshot was rebuilt here. The default is
/// a human report; `--raw` prints only those exact Subject-v3 bytes.
pub(crate) fn run_fetch(path: &Path, package: &str, version: &str) -> Result<String, Diagnostic> {
    let (_, snapshot) = read_snapshot(path)?;
    let Some(subject) = snapshot.subject_bytes(package, version) else {
        return Err(not_found(format!(
            "`{package}@{version}` is not published in {}",
            path.display()
        )));
    };
    let summary = snapshot
        .listing()
        .into_iter()
        .find(|entry| entry.package == package && entry.version == version)
        .ok_or_else(|| not_found(format!("`{package}@{version}` is not published")))?;
    let mut out = format!(
        "registry fetch: {package}@{version} from {}\nsnapshot: {}\ncontent_digest: {}\n\
         status-field: {}\n",
        path.display(),
        snapshot.digest(),
        summary.content_digest,
        summary.status,
    );
    if let Some(reason) = &summary.yank_reason {
        out.push_str(&format!("yank reason: {reason}\n"));
    }
    out.push_str(&format!(
        "subject bytes: {} bytes\n{subject}\n",
        subject.len()
    ));
    out.push_str(
        "status: FETCHED (offline: served from the supplied registry document; \
         digest binding re-derived, signature NOT verified)\n",
    );
    Ok(out)
}

/// The exact Subject-v3 bytes for one published coordinate, with no heading,
/// status line, or appended newline. This is the read-only machine form of
/// `registry fetch ... --raw`.
fn run_fetch_raw(path: &Path, package: &str, version: &str) -> Result<String, Diagnostic> {
    let (_, snapshot) = read_snapshot(path)?;
    snapshot
        .subject_bytes(package, version)
        .map(str::to_owned)
        .ok_or_else(|| {
            not_found(format!(
                "`{package}@{version}` is not published in {}",
                path.display()
            ))
        })
}

/// `registry verify <registry.json> <snapshot-evidence.json>`: independently
/// rebuilds the snapshot from the registry document and checks the evidence
/// replays it byte for byte. Every refusal keeps `package_registry`'s own
/// `SPX-PKR608`.
pub(crate) fn run_verify_snapshot(registry: &Path, evidence: &Path) -> Result<String, Diagnostic> {
    let entries = read_entries(registry)?;
    let evidence_text = read_bounded(evidence, "registry snapshot evidence document")?;
    let verified = package_registry::verify_snapshot(&evidence_text, &entries)?;
    let mut out = format!(
        "registry verify: {} against {}\ndigest: {}\ncoordinates: {}\n",
        evidence.display(),
        registry.display(),
        verified.digest,
        verified.coordinates.len(),
    );
    for (package, version) in &verified.coordinates {
        out.push_str(&format!("  {package}@{version}\n"));
    }
    out.push_str(
        "status: REPLAYED (snapshot evidence rebuilt from the supplied entries and \
         byte-compared; no signature was verified)\n",
    );
    Ok(out)
}

/// `registry verify <registry.json> <template.json> <lock-evidence.json>`:
/// the same fail-closed replay for a lock document, which additionally
/// re-runs the embedded resolver-v2 evidence through its own verifier.
pub(crate) fn run_verify_lock(
    registry: &Path,
    template: &Path,
    evidence: &Path,
) -> Result<String, Diagnostic> {
    let entries = read_entries(registry)?;
    let document = read_template(template)?;
    let evidence_text = read_bounded(evidence, "lock evidence document")?;
    let verified = binding::verify_bound_resolution(
        &evidence_text,
        &entries,
        document.policy,
        &document.template,
        &document.options,
    )?;
    let mut out = format!(
        "registry verify: {} against {} and {}\nlock digest: {}\nsnapshot: {}\npackages: {}\n",
        evidence.display(),
        registry.display(),
        template.display(),
        verified.digest,
        verified.snapshot_digest,
        verified.packages.len(),
    );
    for package in &verified.packages {
        out.push_str(&format!("  {}@{}\n", package.package, package.version));
    }
    out.push_str(&format!("warnings: {}\n", verified.warnings.len()));
    for warning in &verified.warnings {
        out.push_str(&format!("  {} {}\n", warning.code, warning.message));
    }
    out.push_str(
        "status: REPLAYED (lock evidence and its embedded resolution both independently \
         rebuilt and byte-compared; no signature was verified)\n",
    );
    Ok(out)
}

/// `registry publish <registry.json> <entry.json>`: decide-and-record only.
/// See the module docstring: this rebuilds the snapshot the candidate would
/// produce -- so every immutability, duplicate, namespace, ownership and
/// digest-binding rule runs and can refuse under its own `SPX-PKR6xx` code
/// -- and then prints the registry document that would hold it. It publishes
/// nothing, writes nothing, signs nothing, and contacts nothing.
pub(crate) fn run_publish(registry: &Path, entry: &Path) -> Result<String, Diagnostic> {
    let mut entries = read_entries(registry)?;
    let before = package_registry::build_snapshot(&entries)?;
    let candidate_text = read_bounded(entry, "registry entry document")?;
    let candidate = wire::parse_entry_document(&candidate_text)?;
    let package = candidate.package.clone();
    let version = candidate.version.clone();
    entries.push(candidate);
    let after = package_registry::build_snapshot(&entries)?;
    Ok(format!(
        "registry publish: {} into {}\ncandidate: {package}@{version}\n\
         snapshot before: {}\nsnapshot after: {}\nentries: {} -> {}\n\
         updated registry document:\n{}\n\
         status: ADMISSIBLE, NOT PUBLISHED (no signature was verified and no publication \
         authority exists here; writing this document is a separate human act -- see #168)\n",
        entry.display(),
        registry.display(),
        before.digest(),
        after.digest(),
        before.listing().len(),
        after.listing().len(),
        wire::render_registry_document(&entries),
    ))
}

/// Runs one already-parsed [`RegistryCommand`], returning its deterministic
/// report text.
pub(crate) fn run(command: &RegistryCommand) -> Result<String, Diagnostic> {
    match command {
        RegistryCommand::Search(path, query) => run_search(path, query),
        RegistryCommand::Add(path, package, range) => run_add(path, package, range),
        RegistryCommand::Lock(registry, template, raw) => {
            if *raw {
                run_lock_raw(registry, template)
            } else {
                run_lock(registry, template)
            }
        }
        RegistryCommand::Fetch(path, package, version, raw) => {
            if *raw {
                run_fetch_raw(path, package, version)
            } else {
                run_fetch(path, package, version)
            }
        }
        RegistryCommand::VerifySnapshot(registry, evidence) => {
            run_verify_snapshot(registry, evidence)
        }
        RegistryCommand::VerifyLock(registry, template, evidence) => {
            run_verify_lock(registry, template, evidence)
        }
        RegistryCommand::Publish(registry, entry) => run_publish(registry, entry),
    }
}

#[cfg(test)]
#[path = "registry/tests.rs"]
mod tests;
