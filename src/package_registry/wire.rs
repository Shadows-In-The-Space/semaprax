//! JSON wire formats for [`super`]'s registry entries and for the
//! resolution template [`super::binding`] consumes (issue #195's CLI
//! surface).
//!
//! Until this module existed a registry could only be described by building
//! [`PublishedEntry`] values in Rust, which is why `SPX-PKR601`-`612` had no
//! route outside a unit test. This module owns the one decode rule for a
//! `semaprax.package-registry-document.v1` document and for a
//! `semaprax.registry-resolution-template.v1` document;
//! `crate::cli::registry` (the CLI front) only reads bytes from disk and
//! calls into here, exactly as `cli::typed_workflow` defers every graph rule
//! to `crate::typed_workflow::graph_wire`.
//!
//! This is a decoder, not a second registry: it builds caller-owned values
//! and performs **no** registry checking of its own -- not the reserved
//! namespace, not immutability, not ownership continuity, not the
//! digest/coordinate binding. [`super::build_snapshot`] owns every one of
//! those, and is what the CLI calls on the decoded entries. The decoder's
//! own refusals are shape refusals only, under one code, `SPX-PKR613`.
//!
//! [`render_registry_document`] is the exact inverse: it renders a decoded
//! entry list back to a canonical document, so `registry publish` can emit
//! the document a caller would have to write themselves (this front never
//! writes one). Round-trip is pinned by
//! `tests::render_then_parse_round_trips_every_field`.

use serde_json::{Map, Value};

use super::binding::ResolutionTemplate;
use super::{
    PublicationStatus, PublishedEntry, RegistrySignature, YankPolicy, MAX_ENTRIES, MAX_TOTAL_BYTES,
};
use crate::diagnostic::{quote_json, Diagnostic};
use crate::package_resolver_v2::{
    Requirement, ResolutionOptions, MAX_ALLOWED_CAPABILITIES, MAX_REQUIREMENTS,
};

#[cfg(test)]
#[path = "wire/tests.rs"]
mod tests;

/// Schema identity a registry document must declare.
pub const DOCUMENT_SCHEMA: &str = "semaprax.package-registry-document.v1";
/// Schema identity a resolution-template document must declare.
pub const TEMPLATE_SCHEMA: &str = "semaprax.registry-resolution-template.v1";

/// Largest registry document this decoder accepts, checked before any JSON
/// parsing runs. Matches [`MAX_TOTAL_BYTES`], the bound
/// [`super::build_snapshot`] independently enforces on the same content once
/// decoded; that per-entry and total bound, not this one, is what actually
/// keeps an oversized registry out of a snapshot.
pub const MAX_DOCUMENT_BYTES: usize = MAX_TOTAL_BYTES;

/// Largest resolution-template document this decoder accepts. A template
/// carries at most [`MAX_REQUIREMENTS`] requirements and
/// [`MAX_ALLOWED_CAPABILITIES`] capability strings, none of which is a
/// package payload, so it is bounded far below a registry document.
pub const MAX_TEMPLATE_BYTES: usize = 256 * 1024;

/// One decoded resolution template plus the two policy choices a lock needs
/// that [`ResolutionTemplate`] itself does not carry.
#[derive(Clone, Debug)]
pub struct TemplateDocument {
    pub template: ResolutionTemplate,
    pub policy: YankPolicy,
    pub options: ResolutionOptions,
}

/// Every refusal in this module. A wire-shape refusal is deliberately *not*
/// `SPX-PKR601`: `601` means "a registry entry's own content violates the
/// registry's shape rules", which [`super::build_snapshot`] decides on
/// decoded values; this code means "these bytes are not a document at all",
/// which is a decision taken before any registry rule has run.
fn malformed(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR613", message.into())
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, Diagnostic> {
    value
        .as_object()
        .ok_or_else(|| malformed(format!("`{what}` must be a JSON object")))
}

fn as_array<'a>(value: &'a Value, what: &str) -> Result<&'a Vec<Value>, Diagnostic> {
    value
        .as_array()
        .ok_or_else(|| malformed(format!("`{what}` must be an array")))
}

fn as_str<'a>(value: &'a Value, what: &str) -> Result<&'a str, Diagnostic> {
    value
        .as_str()
        .ok_or_else(|| malformed(format!("`{what}` must be a string")))
}

/// Requires `map` to carry exactly `keys`, no more and no fewer. An unknown
/// field -- a typo, a stray extra field, or a field belonging to a different
/// document -- is refused rather than ignored, the same closed-key
/// discipline `typed_workflow::graph_wire` uses.
fn closed(map: &Map<String, Value>, keys: &[&str], what: &str) -> Result<(), Diagnostic> {
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        let mut present: Vec<&str> = map.keys().map(String::as_str).collect();
        present.sort_unstable();
        return Err(malformed(format!(
            "`{what}` must have exactly the fields {keys:?}, got {present:?}"
        )));
    }
    Ok(())
}

fn field<'a>(map: &'a Map<String, Value>, key: &str, what: &str) -> Result<&'a Value, Diagnostic> {
    map.get(key)
        .ok_or_else(|| malformed(format!("`{what}` is missing `{key}`")))
}

fn document(
    text: &str,
    bound: usize,
    schema: &str,
    what: &str,
) -> Result<Map<String, Value>, Diagnostic> {
    if text.len() > bound {
        return Err(malformed(format!(
            "{what} is {} bytes, over the {bound}-byte bound",
            text.len()
        )));
    }
    let parsed: Value = serde_json::from_str(text)
        .map_err(|error| malformed(format!("{what} is not valid JSON: {error}")))?;
    let Value::Object(map) = parsed else {
        return Err(malformed(format!("`{what}` must be a JSON object")));
    };
    let declared = as_str(field(&map, "schema", what)?, "schema")?;
    if declared != schema {
        return Err(malformed(format!(
            "{what} declares schema `{declared}`, expected `{schema}`"
        )));
    }
    Ok(map)
}

/// Decodes a `semaprax.package-registry-document.v1` document into the
/// caller-owned entry list [`super::build_snapshot`] takes. Performs no
/// registry checking: an entry whose digest does not bind its subject bytes,
/// whose name is reserved, or which conflicts with another decodes fine here
/// and is refused by `build_snapshot` under its own code.
pub fn parse_registry_document(text: &str) -> Result<Vec<PublishedEntry>, Diagnostic> {
    let map = document(
        text,
        MAX_DOCUMENT_BYTES,
        DOCUMENT_SCHEMA,
        "registry document",
    )?;
    closed(&map, &["schema", "entries"], "registry document")?;
    let entries = as_array(field(&map, "entries", "registry document")?, "entries")?;
    if entries.len() > MAX_ENTRIES {
        return Err(malformed(format!(
            "`entries` has {} elements, over the {MAX_ENTRIES}-entry bound",
            entries.len()
        )));
    }
    entries.iter().map(parse_entry_value).collect()
}

/// Decodes a single registry entry object -- the same shape one element of a
/// registry document's `entries` array has, so `registry publish` reads a
/// candidate entry with the same rule the surrounding document uses.
pub fn parse_entry_document(text: &str) -> Result<PublishedEntry, Diagnostic> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(malformed(format!(
            "registry entry document is {} bytes, over the {MAX_DOCUMENT_BYTES}-byte bound",
            text.len()
        )));
    }
    let parsed: Value = serde_json::from_str(text).map_err(|error| {
        malformed(format!(
            "registry entry document is not valid JSON: {error}"
        ))
    })?;
    parse_entry_value(&parsed)
}

const ENTRY_KEYS: [&str; 9] = [
    "package",
    "version",
    "content_digest",
    "api_digest",
    "license",
    "provenance_digest",
    "signature",
    "status",
    "subject_bytes",
];

fn parse_entry_value(value: &Value) -> Result<PublishedEntry, Diagnostic> {
    let map = as_object(value, "entry")?;
    closed(map, &ENTRY_KEYS, "entry")?;
    let text = |key: &str| -> Result<String, Diagnostic> {
        as_str(field(map, key, "entry")?, key).map(str::to_owned)
    };
    let provenance_value = field(map, "provenance_digest", "entry")?;
    let provenance_digest = if provenance_value.is_null() {
        None
    } else {
        Some(as_str(provenance_value, "provenance_digest")?.to_owned())
    };
    Ok(PublishedEntry {
        package: text("package")?,
        version: text("version")?,
        content_digest: text("content_digest")?,
        api_digest: text("api_digest")?,
        license: text("license")?,
        provenance_digest,
        signature: parse_signature(field(map, "signature", "entry")?)?,
        status: parse_status(field(map, "status", "entry")?)?,
        subject_bytes: text("subject_bytes")?,
    })
}

fn parse_signature(value: &Value) -> Result<RegistrySignature, Diagnostic> {
    let map = as_object(value, "signature")?;
    closed(map, &["algorithm", "identity", "signature"], "signature")?;
    Ok(RegistrySignature {
        algorithm: as_str(field(map, "algorithm", "signature")?, "algorithm")?.to_owned(),
        identity: as_str(field(map, "identity", "signature")?, "identity")?.to_owned(),
        signature: as_str(field(map, "signature", "signature")?, "signature")?.to_owned(),
    })
}

fn parse_status(value: &Value) -> Result<PublicationStatus, Diagnostic> {
    let map = as_object(value, "status")?;
    let state = as_str(field(map, "state", "status")?, "state")?;
    match state {
        "active" => {
            closed(map, &["state"], "status")?;
            Ok(PublicationStatus::Active)
        }
        "yanked" => {
            closed(map, &["state", "reason"], "status")?;
            Ok(PublicationStatus::Yanked {
                reason: as_str(field(map, "reason", "status")?, "reason")?.to_owned(),
            })
        }
        other => Err(malformed(format!(
            "`status.state` must be `active` or `yanked`, got `{other}`"
        ))),
    }
}

/// Decodes a `semaprax.registry-resolution-template.v1` document: the
/// requirements, target and capability allow-list
/// [`super::binding::bind_to_snapshot`] needs, plus the yank policy and the
/// resolver output bound. `max_bytes` is validated by
/// [`ResolutionOptions::new`], which owns that range.
pub fn parse_template_document(text: &str) -> Result<TemplateDocument, Diagnostic> {
    let map = document(
        text,
        MAX_TEMPLATE_BYTES,
        TEMPLATE_SCHEMA,
        "resolution template",
    )?;
    closed(
        &map,
        &[
            "schema",
            "requirements",
            "target",
            "allowed_capabilities",
            "yank_policy",
            "max_bytes",
        ],
        "resolution template",
    )?;
    let requirements = as_array(
        field(&map, "requirements", "resolution template")?,
        "requirements",
    )?;
    if requirements.len() > MAX_REQUIREMENTS {
        return Err(malformed(format!(
            "`requirements` has {} elements, over the {MAX_REQUIREMENTS}-requirement bound",
            requirements.len()
        )));
    }
    let requirements = requirements
        .iter()
        .map(parse_requirement)
        .collect::<Result<Vec<_>, _>>()?;
    let capabilities = as_array(
        field(&map, "allowed_capabilities", "resolution template")?,
        "allowed_capabilities",
    )?;
    if capabilities.len() > MAX_ALLOWED_CAPABILITIES {
        return Err(malformed(format!(
            "`allowed_capabilities` has {} elements, over the \
             {MAX_ALLOWED_CAPABILITIES}-capability bound",
            capabilities.len()
        )));
    }
    let allowed_capabilities = capabilities
        .iter()
        .map(|value| as_str(value, "allowed_capabilities").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let max_bytes = field(&map, "max_bytes", "resolution template")?
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| malformed("`max_bytes` must be a non-negative integer"))?;
    Ok(TemplateDocument {
        template: ResolutionTemplate {
            requirements,
            target: as_str(field(&map, "target", "resolution template")?, "target")?.to_owned(),
            allowed_capabilities,
        },
        policy: parse_yank_policy(as_str(
            field(&map, "yank_policy", "resolution template")?,
            "yank_policy",
        )?)?,
        options: ResolutionOptions::new(max_bytes)?,
    })
}

fn parse_requirement(value: &Value) -> Result<Requirement, Diagnostic> {
    let map = as_object(value, "requirement")?;
    closed(map, &["package", "range"], "requirement")?;
    Ok(Requirement {
        package: as_str(field(map, "package", "requirement")?, "package")?.to_owned(),
        range: as_str(field(map, "range", "requirement")?, "range")?.to_owned(),
    })
}

/// The three-way closed [`YankPolicy`] choice, spelled exactly as
/// `super::binding`'s canonical envelope spells it, so a lock document and
/// the template that produced it never disagree about the same policy.
pub fn parse_yank_policy(text: &str) -> Result<YankPolicy, Diagnostic> {
    match text {
        "exclude_yanked" => Ok(YankPolicy::ExcludeYanked),
        "refuse_if_yanked" => Ok(YankPolicy::RefuseIfYanked),
        "allow_yanked_with_warning" => Ok(YankPolicy::AllowYankedWithWarning),
        other => Err(malformed(format!(
            "`yank_policy` must be `exclude_yanked`, `refuse_if_yanked` or \
             `allow_yanked_with_warning`, got `{other}`"
        ))),
    }
}

/// Renders `entries` back to a canonical registry document, the exact
/// inverse of [`parse_registry_document`]. Entry order is the caller's:
/// this is a document, not a snapshot, and `build_snapshot` is what imposes
/// canonical `(package, version)` order on the bytes that get digested.
#[must_use]
pub fn render_registry_document(entries: &[PublishedEntry]) -> String {
    let rendered: Vec<String> = entries.iter().map(render_entry).collect();
    format!(
        "{{\"schema\":{},\"entries\":[{}]}}",
        quote_json(DOCUMENT_SCHEMA),
        rendered.join(",")
    )
}

/// Renders one entry object, the shape [`parse_entry_document`] accepts.
#[must_use]
pub fn render_entry(entry: &PublishedEntry) -> String {
    let provenance = match &entry.provenance_digest {
        Some(digest) => quote_json(digest),
        None => "null".to_owned(),
    };
    let status = match &entry.status {
        PublicationStatus::Active => "{\"state\":\"active\"}".to_owned(),
        PublicationStatus::Yanked { reason } => {
            format!("{{\"state\":\"yanked\",\"reason\":{}}}", quote_json(reason))
        }
    };
    format!(
        "{{\"package\":{},\"version\":{},\"content_digest\":{},\"api_digest\":{},\
         \"license\":{},\"provenance_digest\":{provenance},\
         \"signature\":{{\"algorithm\":{},\"identity\":{},\"signature\":{}}},\
         \"status\":{status},\"subject_bytes\":{}}}",
        quote_json(&entry.package),
        quote_json(&entry.version),
        quote_json(&entry.content_digest),
        quote_json(&entry.api_digest),
        quote_json(&entry.license),
        quote_json(&entry.signature.algorithm),
        quote_json(&entry.signature.identity),
        quote_json(&entry.signature.signature),
        quote_json(&entry.subject_bytes),
    )
}
