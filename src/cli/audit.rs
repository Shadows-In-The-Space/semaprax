//! `semaprax audit inspect|verify|diff`: read-only fronts over
//! `semaprax::audit_capsule`, issue #209's `semaprax.audit-capsule.v1`.
//!
//! Every verb here only decodes, structurally checks, or compares bytes the
//! caller already has on disk. None of them signs, publishes, executes, or
//! authorizes anything, and none of them contacts a network. This is a thin
//! CLI adapter, not a second implementation: every rule is owned by
//! `semaprax::audit_capsule` (`parse_capsule`, `verify_capsule`,
//! `diff_capsules`) and re-derived from the exact bytes under test, never
//! trusted from the manifest's own claims about itself.
//!
//! `verify` needs the capsule's retained object bytes supplied separately
//! (a capsule is a manifest of digests, not a bundle of payloads), read one
//! at a time from an `<objects-dir>/<object-id>` file per non-redacted
//! object. Object ids are arbitrary caller-chosen strings with no character
//! restriction (`audit_capsule::parse_capsule` places none), so
//! [`is_safe_object_id`] refuses to join one into a filesystem path unless
//! it is exactly one plain path segment -- otherwise a capsule with a
//! traversal-shaped id such as `../../etc/passwd` could make this front read
//! a file the caller never named.
//!
//! **Nothing here is signed and no transparency log is contacted.**
//! `run_verify`'s success line and every capsule's own required `nonclaims`
//! (`CapsuleVerificationReport::nonclaims`, printed in full) say so
//! explicitly -- see `docs/AUDIT-CAPSULE-V1.md`. `check_signature_policy`
//! and `check_transparency` remain plaintext-policy and internal-consistency
//! checks only, exactly as the owning module documents.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use semaprax::audit_capsule::{self, ParsedCapsule, SignaturePolicyContext, TransparencyContext};
use semaprax::diagnostic::Diagnostic;

const USAGE: &str = "audit accepts `inspect <capsule.json>`, \
                      `verify <capsule.json> <objects-dir> [--require-role <role>]... \
                      [--revoke <identity>]... [--trust-log <log-id>]... \
                      [--min-checkpoint-size <n>] [--now <unix-seconds>]`, or \
                      `diff <capsule-a.json> <capsule-b.json>`; see `semaprax help audit`";

/// Largest capsule manifest file this front reads. `parse_capsule` enforces
/// its own `MAX_MANIFEST_BYTES` bound independently on the same bytes; this
/// only keeps a hostile file from being read into memory first.
const MAX_MANIFEST_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Largest single retained object body this front reads from an objects
/// directory. `check_object_bytes` enforces its own `MAX_OBJECT_BYTES` bound
/// independently on the same bytes.
const MAX_OBJECT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// This front's own code, for "the requested document could not be read at
/// all" -- never used for a decode or verification failure, which always
/// keeps `audit_capsule`'s own code (the module that decided the rule).
fn document_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z920", message)
}

pub(crate) enum AuditCommand {
    Inspect(PathBuf),
    Verify(VerifyOptions),
    Diff(PathBuf, PathBuf),
}

pub(crate) struct VerifyOptions {
    capsule: PathBuf,
    objects_dir: PathBuf,
    required_roles: Vec<String>,
    revoked_identities: Vec<String>,
    trusted_logs: Vec<String>,
    minimum_accepted_checkpoint_size: u64,
    verification_time_unix_seconds: Option<u64>,
}

fn is_flag(argument: &str) -> bool {
    argument.starts_with("--")
}

/// Parses the optional flags following `verify <capsule> <objects-dir>`.
/// Every flag takes exactly one value; an unrecognized flag, a flag missing
/// its value, or a stray positional operand fails closed.
fn parse_verify_flags(
    capsule: PathBuf,
    objects_dir: PathBuf,
    rest: &[String],
) -> Result<VerifyOptions, String> {
    let mut options = VerifyOptions {
        capsule,
        objects_dir,
        required_roles: Vec::new(),
        revoked_identities: Vec::new(),
        trusted_logs: Vec::new(),
        minimum_accepted_checkpoint_size: 0,
        verification_time_unix_seconds: None,
    };
    let mut index = 0;
    while index < rest.len() {
        let flag = rest[index].as_str();
        if !is_flag(flag) {
            return Err(format!(
                "unexpected operand `{flag}` after <objects-dir>; {USAGE}"
            ));
        }
        let Some(value) = rest.get(index + 1) else {
            return Err(format!("flag `{flag}` requires a value; {USAGE}"));
        };
        if is_flag(value) {
            return Err(format!("flag `{flag}` requires a value; {USAGE}"));
        }
        match flag {
            "--require-role" => options.required_roles.push(value.clone()),
            "--revoke" => options.revoked_identities.push(value.clone()),
            "--trust-log" => options.trusted_logs.push(value.clone()),
            "--min-checkpoint-size" => {
                options.minimum_accepted_checkpoint_size = value.parse().map_err(|_| {
                    format!("`--min-checkpoint-size` needs a non-negative integer, got `{value}`")
                })?;
            }
            "--now" => {
                options.verification_time_unix_seconds = Some(value.parse().map_err(|_| {
                    format!("`--now` needs a non-negative integer of unix seconds, got `{value}`")
                })?);
            }
            other => return Err(format!("unknown flag `{other}`; {USAGE}")),
        }
        index += 2;
    }
    Ok(options)
}

/// `inspect <capsule.json>`, `verify <capsule.json> <objects-dir> [flags...]`,
/// or `diff <capsule-a.json> <capsule-b.json>`, and nothing else. An unknown
/// subcommand, a missing operand, or an option-shaped positional operand
/// fails closed with the usage line and exit code 2 before any path is
/// opened.
pub(crate) fn parse(args: &[String]) -> Result<AuditCommand, u8> {
    let rejected = match args {
        [subcommand, capsule]
            if subcommand == "inspect" && !capsule.is_empty() && !is_flag(capsule) =>
        {
            return Ok(AuditCommand::Inspect(PathBuf::from(capsule)));
        }
        [subcommand, capsule, objects_dir, rest @ ..]
            if subcommand == "verify"
                && !capsule.is_empty()
                && !is_flag(capsule)
                && !objects_dir.is_empty()
                && !is_flag(objects_dir) =>
        {
            return match parse_verify_flags(
                PathBuf::from(capsule),
                PathBuf::from(objects_dir),
                rest,
            ) {
                Ok(options) => Ok(AuditCommand::Verify(options)),
                Err(message) => {
                    eprintln!("{message}");
                    Err(2)
                }
            };
        }
        [subcommand, before, after]
            if subcommand == "diff"
                && !before.is_empty()
                && !is_flag(before)
                && !after.is_empty()
                && !is_flag(after) =>
        {
            return Ok(AuditCommand::Diff(
                PathBuf::from(before),
                PathBuf::from(after),
            ));
        }
        [subcommand, ..] if !matches!(subcommand.as_str(), "inspect" | "verify" | "diff") => {
            format!("unknown audit subcommand `{subcommand}`; {USAGE}")
        }
        _ => USAGE.to_owned(),
    };
    eprintln!("{rejected}");
    Err(2)
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, Diagnostic> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| document_error(format!("cannot read {}: {error}", path.display())))?;
    if metadata.len() > max_bytes {
        return Err(document_error(format!(
            "{} is {} bytes, over the {max_bytes}-byte bound for this front",
            path.display(),
            metadata.len()
        )));
    }
    std::fs::read(path)
        .map_err(|error| document_error(format!("cannot read {}: {error}", path.display())))
}

/// True iff `id`, treated as a filesystem path, is exactly one plain
/// (`Component::Normal`) segment -- never empty, `.`, `..`, an absolute
/// root, or (on Windows) a drive prefix, and never more than one segment
/// however it is delimited. A capsule's object ids are arbitrary
/// caller-chosen strings; this is the only thing standing between a
/// hostile id and a path outside `objects_dir`.
fn is_safe_object_id(id: &str) -> bool {
    let mut components = Path::new(id).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

/// Reads exactly the retained-object files a capsule's own object list
/// names, one per non-redacted object, from `objects_dir`. Never lists the
/// directory and never reads a path the capsule did not name.
fn object_bytes_from_directory(
    capsule: &ParsedCapsule,
    objects_dir: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, Diagnostic> {
    let mut object_bytes = BTreeMap::new();
    for candidate in &capsule.objects {
        if candidate.redacted {
            continue;
        }
        if !is_safe_object_id(&candidate.id) {
            return Err(document_error(format!(
                "object id `{}` cannot be read from {}: only a single plain path segment is \
                 admitted, and this id is not one",
                candidate.id,
                objects_dir.display()
            )));
        }
        let path = objects_dir.join(&candidate.id);
        let bytes = read_bounded(&path, MAX_OBJECT_FILE_BYTES)?;
        object_bytes.insert(candidate.id.clone(), bytes);
    }
    Ok(object_bytes)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// The nonclaims banner every successful `verify` and `inspect` prints,
/// independent of the capsule's own `nonclaims` field (which is printed
/// separately, in full, below it). Kept as one constant so no output path
/// can drift into implying more than this front establishes.
const FRONT_NONCLAIMS: &str = "\
This command performs no cryptographic signature verification and contacts \
no transparency log: `check_signature_policy` and `check_transparency` \
check plaintext policy facts and internal consistency only. It writes, \
executes, and publishes nothing.\n";

/// `audit inspect <capsule.json>`: structural decode only, no object bytes
/// required and no verification performed.
pub(crate) fn run_inspect(capsule_path: &Path) -> Result<String, Diagnostic> {
    let manifest_bytes = read_bounded(capsule_path, MAX_MANIFEST_FILE_BYTES)?;
    let capsule = audit_capsule::parse_capsule(&manifest_bytes)?;
    let mut out = format!(
        "audit inspect: {}\nprofile: {}\nsubject:\n",
        capsule_path.display(),
        capsule.profile.as_str(),
    );
    for (key, value) in &capsule.subject {
        out.push_str(&format!("  {key} = {value}\n"));
    }
    out.push_str(&format!("objects: {}\n", capsule.objects.len()));
    for object in &capsule.objects {
        out.push_str(&format!(
            "  {} : {} ({}){}\n",
            object.id,
            object.object_type,
            object.digest,
            if object.redacted { ", redacted" } else { "" }
        ));
    }
    out.push_str(&format!("associations: {}\n", capsule.associations.len()));
    for edge in &capsule.associations {
        out.push_str(&format!(
            "  {} --{}--> {}\n",
            edge.from_id, edge.relation, edge.to_id
        ));
    }
    out.push_str(&format!("signatures: {}\n", capsule.signatures.len()));
    for signature in &capsule.signatures {
        out.push_str(&format!(
            "  role {} : identity {} (opaque; not cryptographically checked)\n",
            signature.role, signature.identity
        ));
    }
    out.push_str(&format!(
        "transparency: {}\n",
        if capsule.transparency.is_some() {
            "present (internal consistency only; no log contacted)"
        } else {
            "absent"
        }
    ));
    out.push_str("nonclaims:\n");
    for nonclaim in &capsule.nonclaims {
        out.push_str(&format!("  {nonclaim}\n"));
    }
    out.push_str("status: INSPECTED (structural decode only; nothing was verified)\n");
    Ok(out)
}

/// `audit verify <capsule.json> <objects-dir> [flags...]`: independent
/// structural verification, reading each non-redacted object's bytes from
/// `objects_dir` by id.
pub(crate) fn run_verify(options: &VerifyOptions) -> Result<String, Diagnostic> {
    let manifest_bytes = read_bounded(&options.capsule, MAX_MANIFEST_FILE_BYTES)?;
    let capsule = audit_capsule::parse_capsule(&manifest_bytes)?;
    let object_bytes = object_bytes_from_directory(&capsule, &options.objects_dir)?;
    let signature_ctx = SignaturePolicyContext {
        verification_time_unix_seconds: options
            .verification_time_unix_seconds
            .unwrap_or_else(now_unix_seconds),
        revoked_identities: options.revoked_identities.iter().cloned().collect(),
        required_roles: options.required_roles.clone(),
    };
    let transparency_ctx = TransparencyContext {
        known_logs: options.trusted_logs.iter().cloned().collect(),
        minimum_accepted_checkpoint_size: options.minimum_accepted_checkpoint_size,
    };
    let report = audit_capsule::verify_capsule(
        &manifest_bytes,
        &object_bytes,
        &signature_ctx,
        &transparency_ctx,
    )?;
    let mut out = format!(
        "audit verify: {}\nprofile: {}\nverified objects: {}\n",
        options.capsule.display(),
        report.profile.as_str(),
        report.verified_object_ids.len(),
    );
    for id in &report.verified_object_ids {
        out.push_str(&format!("  {id}\n"));
    }
    out.push_str(&format!(
        "unavailable claims (redacted): {}\n",
        report.unavailable_claims.len()
    ));
    for (id, object_type, reason) in &report.unavailable_claims {
        out.push_str(&format!("  {id} ({object_type}): {reason}\n"));
    }
    out.push_str("nonclaims:\n");
    for nonclaim in &report.nonclaims {
        out.push_str(&format!("  {nonclaim}\n"));
    }
    out.push_str("status: VERIFIED (structural integrity only)\n");
    out.push_str(FRONT_NONCLAIMS);
    Ok(out)
}

/// `audit diff <capsule-a.json> <capsule-b.json>`: pure structural
/// comparison of two independently parsed capsules. Neither side is
/// verified here -- run `audit verify` on each first for that.
pub(crate) fn run_diff(before_path: &Path, after_path: &Path) -> Result<String, Diagnostic> {
    let before_bytes = read_bounded(before_path, MAX_MANIFEST_FILE_BYTES)?;
    let after_bytes = read_bounded(after_path, MAX_MANIFEST_FILE_BYTES)?;
    let before = audit_capsule::parse_capsule(&before_bytes)?;
    let after = audit_capsule::parse_capsule(&after_bytes)?;
    let diff = audit_capsule::diff_capsules(&before, &after);

    let mut out = format!(
        "audit diff: {} -> {}\n",
        before_path.display(),
        after_path.display()
    );
    if diff.is_empty() {
        out.push_str("no structural difference\n");
        return Ok(out);
    }
    if let Some((before_profile, after_profile)) = diff.profile_changed {
        out.push_str(&format!(
            "profile: {} -> {}\n",
            before_profile.as_str(),
            after_profile.as_str()
        ));
    }
    for (key, (before_value, after_value)) in &diff.subject_changed {
        out.push_str(&format!(
            "subject.{key}: {} -> {}\n",
            before_value.as_deref().unwrap_or("(absent)"),
            after_value.as_deref().unwrap_or("(absent)")
        ));
    }
    for id in &diff.removed_object_ids {
        out.push_str(&format!("- object {id}\n"));
    }
    for id in &diff.added_object_ids {
        out.push_str(&format!("+ object {id}\n"));
    }
    for (id, change) in &diff.changed_objects {
        match change {
            audit_capsule::ObjectChange::Changed {
                before_digest,
                after_digest,
            } => out.push_str(&format!(
                "~ object {id}: {before_digest} -> {after_digest}\n"
            )),
            audit_capsule::ObjectChange::RedactionChanged { digest } => out.push_str(&format!(
                "~ object {id}: redaction state changed ({digest})\n"
            )),
        }
    }
    for edge in &diff.removed_associations {
        out.push_str(&format!(
            "- association {} --{}--> {}\n",
            edge.from_id, edge.relation, edge.to_id
        ));
    }
    for edge in &diff.added_associations {
        out.push_str(&format!(
            "+ association {} --{}--> {}\n",
            edge.from_id, edge.relation, edge.to_id
        ));
    }
    for role in &diff.removed_signature_roles {
        out.push_str(&format!("- signature role {role}\n"));
    }
    for role in &diff.added_signature_roles {
        out.push_str(&format!("+ signature role {role}\n"));
    }
    Ok(out)
}

/// Runs one already-parsed [`AuditCommand`], returning its deterministic
/// report text.
pub(crate) fn run(command: &AuditCommand) -> Result<String, Diagnostic> {
    match command {
        AuditCommand::Inspect(capsule) => run_inspect(capsule),
        AuditCommand::Verify(options) => run_verify(options),
        AuditCommand::Diff(before, after) => run_diff(before, after),
    }
}

#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;
