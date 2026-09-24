//! `semaprax fetch <cache-dir> <subject.json>...`: place explicitly named
//! Semantic Package Subject-v3 envelopes into the content-addressed cache that
//! `resolve --cache` reads. Each subject is independently replayed before it
//! is filed under its own digest; a subject that fails replay, a digest that
//! does not match, or a cache entry with different bytes at the same address
//! rejects the whole run before any write. The command reads only the paths it
//! is given and contacts no registry or network. `--lock` adds a held-artifact
//! boundary: the exact caller-supplied Lock-v3 must replay precisely the named
//! subject bytes before this host writes the caller-selected cache directory.

use std::path::{Path, PathBuf};

use semaprax::diagnostic::{quote_json, Diagnostic};
use semaprax::package_lock_v3::{verify_dependency_subject, VerifiedDependencySubject};
use semaprax::package_resolver_v2::{MAX_SUBJECTS, MAX_SUBJECT_BYTES};

const USAGE: &str = "fetch requires <cache-dir> <subject.json>... or --lock <lock.json> <cache-dir> <subject.json>...";
const CODE: &str = "SPX-J128";

#[cfg(all(
    unix,
    any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )
))]
mod locked;

pub(crate) struct FetchOptions {
    pub(crate) cache: PathBuf,
    pub(crate) subjects: Vec<PathBuf>,
    pub(crate) lock: Option<PathBuf>,
}

pub(crate) fn parse(args: &[String]) -> Result<FetchOptions, u8> {
    let (lock, cache, subjects) = match args {
        [flag, lock, cache, subjects @ ..]
            if flag == "--lock"
                && !lock.is_empty()
                && !cache.is_empty()
                && !lock.starts_with('-')
                && !cache.starts_with('-') =>
        {
            (Some(PathBuf::from(lock)), cache, subjects)
        }
        [cache, subjects @ ..] if !cache.is_empty() && !cache.starts_with('-') => {
            (None, cache, subjects)
        }
        _ => {
            eprintln!("{USAGE}");
            return Err(2);
        }
    };
    if subjects.is_empty()
        || subjects.len() > MAX_SUBJECTS
        || subjects
            .iter()
            .any(|argument| argument.is_empty() || argument.starts_with('-'))
    {
        eprintln!("{USAGE}");
        return Err(2);
    }
    Ok(FetchOptions {
        cache: PathBuf::from(cache),
        subjects: subjects.iter().map(PathBuf::from).collect(),
        lock,
    })
}

struct Filed {
    subject: VerifiedDependencySubject,
    hex: String,
    bytes: String,
    present: bool,
}

fn cache_error(message: String) -> Vec<Diagnostic> {
    vec![Diagnostic::io(CODE, message)]
}

fn read_subject(path: &Path) -> Result<String, Vec<Diagnostic>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| cache_error(format!("cannot read subject {}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.len() > MAX_SUBJECT_BYTES as u64 {
        return Err(cache_error(format!(
            "subject {} must be a plain file of at most {MAX_SUBJECT_BYTES} bytes",
            path.display()
        )));
    }
    std::fs::read_to_string(path)
        .map_err(|error| cache_error(format!("cannot read subject {}: {error}", path.display())))
}

/// Replay every subject, decide each cache address, and only then write the
/// ones that are new. The receipt names every subject in operand order.
pub(crate) fn run(options: &FetchOptions) -> Result<String, Vec<Diagnostic>> {
    if options.lock.is_some() {
        #[cfg(all(
            unix,
            any(
                target_os = "linux",
                target_os = "android",
                target_vendor = "apple",
                target_os = "redox"
            )
        ))]
        return locked::run(options);
        #[cfg(not(all(unix, any(target_os = "linux", target_os = "android", target_vendor = "apple", target_os = "redox"))))]
        return Err(cache_error("lock-bound fetch requires held-directory no-replace publication unavailable on this host".to_owned()));
    }
    let cache = &options.cache;
    if let Ok(metadata) = std::fs::symlink_metadata(cache) {
        if !metadata.is_dir() {
            return Err(cache_error(format!(
                "cache {} exists and is not a directory",
                cache.display()
            )));
        }
    }
    let mut filed: Vec<Filed> = Vec::with_capacity(options.subjects.len());
    for path in &options.subjects {
        let bytes = read_subject(path)?;
        let subject = verify_dependency_subject(&bytes).map_err(|error| vec![error])?;
        let hex = subject
            .subject_digest
            .strip_prefix("sha256:")
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| {
                cache_error(format!(
                    "subject {} carries a non-canonical digest `{}`",
                    path.display(),
                    subject.subject_digest
                ))
            })?
            .to_owned();
        if let Some(previous) = filed.iter().find(|entry| entry.hex == hex) {
            if previous.bytes != bytes {
                return Err(cache_error(format!(
                    "subjects {} and another operand share digest sha256:{hex} with different bytes",
                    path.display()
                )));
            }
        }
        let destination = cache.join(format!("{hex}.json"));
        let present = match std::fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(cache_error(format!(
                        "cache entry {} is not a plain file",
                        destination.display()
                    )));
                }
                let existing = std::fs::read_to_string(&destination).map_err(|error| {
                    cache_error(format!(
                        "cannot read cache entry {}: {error}",
                        destination.display()
                    ))
                })?;
                if existing != bytes {
                    return Err(cache_error(format!(
                        "cache entry {} holds different bytes for the same content address",
                        destination.display()
                    )));
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(cache_error(format!(
                    "cannot inspect cache entry {}: {error}",
                    destination.display()
                )));
            }
        };
        filed.push(Filed {
            subject,
            hex,
            bytes,
            present,
        });
    }
    let existing = match std::fs::read_dir(cache) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
            })
            .count(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            return Err(cache_error(format!(
                "cannot inspect cache {}: {error}",
                cache.display()
            )));
        }
    };
    let mut added = std::collections::BTreeSet::new();
    for entry in &filed {
        if !entry.present {
            added.insert(entry.hex.as_str());
        }
    }
    if existing + added.len() > MAX_SUBJECTS {
        return Err(cache_error(format!(
            "cache {} would hold more than {MAX_SUBJECTS} subjects",
            cache.display()
        )));
    }
    std::fs::create_dir_all(cache).map_err(|error| {
        cache_error(format!("cannot create cache {}: {error}", cache.display()))
    })?;
    for entry in &filed {
        if entry.present {
            continue;
        }
        let destination = cache.join(format!("{}.json", entry.hex));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
        {
            Ok(mut file) => {
                use std::io::Write;
                if let Err(error) = file
                    .write_all(entry.bytes.as_bytes())
                    .and_then(|_| file.sync_all())
                {
                    return Err(cache_error(format!(
                        "cannot write cache entry {}; cache may be partially written: {error}",
                        destination.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = match std::fs::read_to_string(&destination) {
                    Ok(existing) => existing,
                    Err(read_error) => {
                        return Err(cache_error(format!(
                            "cannot read cache entry {} after concurrent creation: {read_error}",
                            destination.display()
                        )));
                    }
                };
                if existing != entry.bytes {
                    return Err(cache_error(format!(
                        "cache entry {} changed to different bytes during filing",
                        destination.display()
                    )));
                }
            }
            Err(error) => {
                return Err(cache_error(format!(
                    "cannot create cache entry {}: {error}",
                    destination.display()
                )));
            }
        }
    }
    let mut receipt = format!(
        "{{\"schema\":\"semaprax.fetch-receipt.v1\",\"cache\":{},\"subjects\":[",
        quote_json(&cache.display().to_string())
    );
    for (index, entry) in filed.iter().enumerate() {
        if index > 0 {
            receipt.push(',');
        }
        receipt.push_str(&format!(
            "{{\"package\":{},\"version\":{},\"digest\":{},\"state\":{}}}",
            quote_json(&entry.subject.coordinate.package),
            quote_json(&entry.subject.coordinate.version),
            quote_json(&entry.subject.subject_digest),
            quote_json(if entry.present { "present" } else { "added" })
        ));
    }
    receipt.push_str("]}\n");
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn fetch_grammar_is_closed() {
        let options = parse(&strings(&["cache", "a.json", "b.json"])).unwrap();
        assert_eq!(options.cache, PathBuf::from("cache"));
        assert_eq!(options.subjects.len(), 2);
        assert!(options.lock.is_none());
        let held = parse(&strings(&["--lock", "held.lock", "cache", "a.json"])).unwrap();
        assert_eq!(held.lock, Some(PathBuf::from("held.lock")));
        let mut too_many = vec!["cache".to_owned()];
        too_many.extend((0..=MAX_SUBJECTS).map(|index| format!("{index}.json")));
        assert!(parse(&too_many).is_err());
        for malformed in [
            &[][..],
            &["cache"][..],
            &["cache", "--json"][..],
            &["", "a.json"][..],
            &["--lock", "held.lock", "cache"][..],
            &["--lock", "", "cache", "a.json"][..],
        ] {
            assert!(parse(&strings(malformed)).is_err(), "{malformed:?}");
        }
    }
}
