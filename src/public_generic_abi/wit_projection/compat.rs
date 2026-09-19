//! Deterministic compatibility / delta reporting between two
//! [`WitTypeProjectionV1`] renderings of the same WIT world.
//!
//! This is the seventh step of issue #176's implementation sequence ("Add
//! compatibility checks for field/case addition, reordering, ownership
//! change, and identifier-preserving display rename"). Like the projection it
//! compares, it is **not** a support or publication decision: public generic
//! ownership remains unsupported and unpublished pending PG-9 of the
//! [Public Generic Ownership milestone](../../../docs/PUBLIC-GENERIC-OWNERSHIP-MILESTONE-V1.md),
//! and no compiled `.wasm` implements the provider ABI (issue #229). Nothing
//! here emits, instantiates, links, or runs a component; it reads two
//! already-produced projections and reports how they differ.
//!
//! ## Why a delta report rather than a digest comparison
//!
//! Comparing two projections' bytes answers only "did anything change". An
//! ABI reviewer needs the *kind* of change, because the kinds are not
//! interchangeable:
//!
//! - A **record added** to the world is additive: no existing declaration's
//!   field list, field order, or ownership moved, so no consumer already
//!   compiled against the baseline can observe it.
//! - A **field added, removed, or reordered** rewrites a Component Model
//!   record's canonical field sequence. A consumer compiled against the
//!   baseline reads the candidate's fields at the wrong positions. Breaking,
//!   in both directions, and never "additive" the way a new declaration is.
//! - A **field ownership change** — a by-value leaf becoming an
//!   `own<`[`OWNED_BYTES_RESOURCE`](super::OWNED_BYTES_RESOURCE)`>` handle, or
//!   the reverse — moves *who runs cleanup* across the boundary. It is
//!   reported as its own delta kind, distinct from an ordinary type change,
//!   because a reviewer scanning for cleanup-responsibility movement must not
//!   have to re-derive it from two type strings.
//! - A **display-only rename** of a record or a field is, by construction,
//!   *no delta at all*: [`super::legal_name`] hexes a persistent identity (a
//!   canonical grammar term, or a stable field declaration id), and neither
//!   carries a display name. Two projections that differ only by display
//!   names are byte-identical, so this module reports them as unchanged
//!   rather than as a rename to be adjudicated. The executable proof of that
//!   is in this module's tests, not in this sentence.
//!
//! ## Fail-closed
//!
//! [`compare`] refuses two projections that do not share one
//! [`WIT_TYPE_PROJECTION_SCHEMA`](super::WIT_TYPE_PROJECTION_SCHEMA)
//! (`SPX-PGWIT121`): a delta across two mapping-table versions would compare
//! renderings whose terms mean different things. It refuses rather than
//! truncates when the delta count exceeds [`MAX_REPORTED_DELTAS`]
//! (`SPX-PGWIT122`), so a report is never a partial list presented as a whole
//! one. [`require_compatible`] turns any breaking delta into `SPX-PGWIT123`
//! for a caller that wants a gate rather than a report.
//!
//! ## Determinism
//!
//! Record lookup goes through a `BTreeMap` keyed by WIT record name; fields
//! are visited in each record's own declaration order, which
//! [`super::project_admitted_subject`] already fixed. No `HashMap`, clock,
//! environment read, or randomness is on this path, so the same pair of
//! projections yields a byte-identical report on every call.

use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::Diagnostic;

use super::{WitRecordV1, WitTypeProjectionV1, OWNED_BYTES_RESOURCE};

/// The versioned compatibility-report schema. A new delta kind is a new
/// schema.
pub const WIT_COMPATIBILITY_SCHEMA: &str =
    "semaprax.public-generic-type-grammar.v1.wit-projection.v1.compatibility.v1";

/// The two projections do not share one projection schema, so no delta
/// between them is meaningful.
pub const SCHEMA_MISMATCH: &str = "SPX-PGWIT121";
/// More deltas than [`MAX_REPORTED_DELTAS`]. Refused, never truncated: a
/// partial delta list presented as a complete one would understate a break.
pub const REPORT_CAPACITY: &str = "SPX-PGWIT122";
/// The candidate carries at least one breaking delta against the baseline.
pub const INCOMPATIBLE_CANDIDATE: &str = "SPX-PGWIT123";

/// The most deltas one report may carry.
pub const MAX_REPORTED_DELTAS: usize = 512;

fn schema_mismatch(baseline: &str, candidate: &str) -> Diagnostic {
    Diagnostic::io(
        SCHEMA_MISMATCH,
        format!(
            "{WIT_COMPATIBILITY_SCHEMA} compares one projection schema only: baseline \
             `{baseline}` against candidate `{candidate}`"
        ),
    )
}

fn report_capacity() -> Diagnostic {
    Diagnostic::io(
        REPORT_CAPACITY,
        format!("{WIT_COMPATIBILITY_SCHEMA} exceeded its {MAX_REPORTED_DELTAS}-delta report limit"),
    )
}

fn incompatible(breaking: &[&WitDeltaV1]) -> Diagnostic {
    let first = breaking
        .first()
        .map(|delta| delta.render())
        .unwrap_or_default();
    Diagnostic::io(
        INCOMPATIBLE_CANDIDATE,
        format!(
            "{WIT_COMPATIBILITY_SCHEMA} refuses the candidate: {} breaking delta(s), first: {first}",
            breaking.len()
        ),
    )
}

/// Whether one delta can be observed by a consumer already compiled against
/// the baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compatibility {
    /// Additive: no existing declaration's shape moved.
    Compatible,
    /// A consumer compiled against the baseline observes this.
    Breaking,
}

/// One difference between a baseline and a candidate projection.
///
/// A closed set. A new WIT mapping row that could differ in a new way needs a
/// new variant here *and* a new [`WIT_COMPATIBILITY_SCHEMA`], rather than
/// being folded into [`WitDeltaV1::FieldTypeChanged`] as an unclassified
/// string difference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitDeltaV1 {
    /// A world-level identity (`package`, `interface`, `world`, `input-type`,
    /// or `result-type`) differs. Never additive: the identity *is* the
    /// contract a consumer binds to.
    WorldIdentityChanged {
        /// Which identity: `package`, `interface`, `world`, `input-type`, or
        /// `result-type`.
        subject: &'static str,
        baseline: String,
        candidate: String,
    },
    /// The candidate declares [`OWNED_BYTES_RESOURCE`] and the baseline did
    /// not.
    OwnedBytesResourceAdded,
    /// The baseline declared [`OWNED_BYTES_RESOURCE`] and the candidate does
    /// not.
    OwnedBytesResourceRemoved,
    /// A record present only in the candidate.
    RecordAdded { name: String, source_term: String },
    /// A record present only in the baseline.
    RecordRemoved { name: String, source_term: String },
    /// A field present only in the candidate's copy of a shared record.
    FieldAdded {
        record: String,
        field: String,
        type_text: String,
    },
    /// A field present only in the baseline's copy of a shared record.
    FieldRemoved {
        record: String,
        field: String,
        type_text: String,
    },
    /// A field present in both, at a different position among the fields the
    /// two records share.
    FieldReordered {
        record: String,
        field: String,
        baseline_index: usize,
        candidate_index: usize,
    },
    /// A shared field changed between a by-value leaf and an owned resource
    /// handle, in either direction. Cleanup responsibility moved.
    FieldOwnershipChanged {
        record: String,
        field: String,
        baseline: String,
        candidate: String,
    },
    /// A shared field's type changed without crossing the ownership
    /// boundary (one by-value type for another).
    FieldTypeChanged {
        record: String,
        field: String,
        baseline: String,
        candidate: String,
    },
}

impl WitDeltaV1 {
    /// A record *declaration* added to the world is the only additive delta:
    /// nothing a baseline consumer already binds to moved. Everything else —
    /// including a field added to an existing record — rewrites a canonical
    /// field sequence or an identity a consumer is already bound to.
    pub fn compatibility(&self) -> Compatibility {
        match self {
            WitDeltaV1::RecordAdded { .. } => Compatibility::Compatible,
            _ => Compatibility::Breaking,
        }
    }

    /// One canonical line. Stable across runs; part of the report rendering
    /// contract.
    pub fn render(&self) -> String {
        match self {
            WitDeltaV1::WorldIdentityChanged {
                subject,
                baseline,
                candidate,
            } => format!("world-identity-changed {subject} {baseline} -> {candidate}"),
            WitDeltaV1::OwnedBytesResourceAdded => {
                format!("owned-bytes-resource-added {OWNED_BYTES_RESOURCE}")
            }
            WitDeltaV1::OwnedBytesResourceRemoved => {
                format!("owned-bytes-resource-removed {OWNED_BYTES_RESOURCE}")
            }
            WitDeltaV1::RecordAdded { name, source_term } => {
                format!("record-added {name} {source_term}")
            }
            WitDeltaV1::RecordRemoved { name, source_term } => {
                format!("record-removed {name} {source_term}")
            }
            WitDeltaV1::FieldAdded {
                record,
                field,
                type_text,
            } => format!("field-added {record} {field} {type_text}"),
            WitDeltaV1::FieldRemoved {
                record,
                field,
                type_text,
            } => format!("field-removed {record} {field} {type_text}"),
            WitDeltaV1::FieldReordered {
                record,
                field,
                baseline_index,
                candidate_index,
            } => format!("field-reordered {record} {field} {baseline_index} -> {candidate_index}"),
            WitDeltaV1::FieldOwnershipChanged {
                record,
                field,
                baseline,
                candidate,
            } => format!("field-ownership-changed {record} {field} {baseline} -> {candidate}"),
            WitDeltaV1::FieldTypeChanged {
                record,
                field,
                baseline,
                candidate,
            } => format!("field-type-changed {record} {field} {baseline} -> {candidate}"),
        }
    }
}

/// The complete deterministic delta between two projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitCompatibilityReportV1 {
    pub schema: &'static str,
    /// The projection schema both sides share.
    pub projection_schema: String,
    /// Every delta, in the fixed order [`compare`] produces them: world
    /// identities first, then the owned-bytes resource declaration, then
    /// records in WIT-name order, and within a record its removed, added,
    /// reordered, and retyped fields.
    pub deltas: Vec<WitDeltaV1>,
}

impl WitCompatibilityReportV1 {
    /// True when no delta is [`Compatibility::Breaking`]. An empty report is
    /// compatible; so is one holding only added record declarations.
    pub fn is_compatible(&self) -> bool {
        self.breaking().next().is_none()
    }

    /// Every breaking delta, in report order.
    pub fn breaking(&self) -> impl Iterator<Item = &WitDeltaV1> {
        self.deltas
            .iter()
            .filter(|delta| delta.compatibility() == Compatibility::Breaking)
    }

    /// The canonical report text. Deterministic; one delta per line.
    pub fn render(&self) -> String {
        let mut out = format!("schema: {}\n", self.schema);
        out.push_str(&format!("projection-schema: {}\n", self.projection_schema));
        out.push_str(&format!(
            "compatible: {}\n",
            if self.is_compatible() { "yes" } else { "no" }
        ));
        out.push_str(&format!("deltas: {}\n", self.deltas.len()));
        for delta in &self.deltas {
            let marker = match delta.compatibility() {
                Compatibility::Compatible => "compatible",
                Compatibility::Breaking => "breaking",
            };
            out.push_str(&format!("{marker}: {}\n", delta.render()));
        }
        out
    }
}

fn is_owned_handle(type_text: &str) -> bool {
    type_text.starts_with("own<")
}

fn identity_delta(
    deltas: &mut Vec<WitDeltaV1>,
    subject: &'static str,
    baseline: &str,
    candidate: &str,
) {
    if baseline != candidate {
        deltas.push(WitDeltaV1::WorldIdentityChanged {
            subject,
            baseline: baseline.to_owned(),
            candidate: candidate.to_owned(),
        });
    }
}

fn compare_record(deltas: &mut Vec<WitDeltaV1>, baseline: &WitRecordV1, candidate: &WitRecordV1) {
    let baseline_names: BTreeSet<&str> = baseline.fields.iter().map(|f| f.name.as_str()).collect();
    let candidate_names: BTreeSet<&str> =
        candidate.fields.iter().map(|f| f.name.as_str()).collect();

    // Removed and added fields follow each side's own declaration order, so
    // the report reads in the order the source declares rather than in hex
    // name order.
    for field in &baseline.fields {
        if !candidate_names.contains(field.name.as_str()) {
            deltas.push(WitDeltaV1::FieldRemoved {
                record: baseline.name.clone(),
                field: field.name.clone(),
                type_text: field.type_text.clone(),
            });
        }
    }
    for field in &candidate.fields {
        if !baseline_names.contains(field.name.as_str()) {
            deltas.push(WitDeltaV1::FieldAdded {
                record: candidate.name.clone(),
                field: field.name.clone(),
                type_text: field.type_text.clone(),
            });
        }
    }

    // Position is compared among the fields the two records share, so a
    // genuine reorder is not masked by an unrelated insertion earlier in the
    // list, and an insertion does not report every later field as reordered.
    let shared_baseline: Vec<&str> = baseline
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .filter(|name| candidate_names.contains(name))
        .collect();
    let shared_candidate: Vec<&str> = candidate
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .filter(|name| baseline_names.contains(name))
        .collect();
    for (baseline_index, name) in shared_baseline.iter().enumerate() {
        let candidate_index = shared_candidate
            .iter()
            .position(|other| other == name)
            .expect("a shared field is present in both shared sequences");
        if candidate_index != baseline_index {
            deltas.push(WitDeltaV1::FieldReordered {
                record: baseline.name.clone(),
                field: (*name).to_owned(),
                baseline_index,
                candidate_index,
            });
        }
    }

    let candidate_types: BTreeMap<&str, &str> = candidate
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.type_text.as_str()))
        .collect();
    for field in &baseline.fields {
        let Some(candidate_type) = candidate_types.get(field.name.as_str()) else {
            continue;
        };
        if *candidate_type == field.type_text {
            continue;
        }
        let crossed_ownership =
            is_owned_handle(&field.type_text) != is_owned_handle(candidate_type);
        if crossed_ownership {
            deltas.push(WitDeltaV1::FieldOwnershipChanged {
                record: baseline.name.clone(),
                field: field.name.clone(),
                baseline: field.type_text.clone(),
                candidate: (*candidate_type).to_owned(),
            });
        } else {
            deltas.push(WitDeltaV1::FieldTypeChanged {
                record: baseline.name.clone(),
                field: field.name.clone(),
                baseline: field.type_text.clone(),
                candidate: (*candidate_type).to_owned(),
            });
        }
    }
}

/// Report every difference between `baseline` and `candidate`.
///
/// Refuses (`SPX-PGWIT121`) when the two do not share one projection schema,
/// and refuses (`SPX-PGWIT122`) rather than truncating when the delta count
/// exceeds [`MAX_REPORTED_DELTAS`].
pub fn compare(
    baseline: &WitTypeProjectionV1,
    candidate: &WitTypeProjectionV1,
) -> Result<WitCompatibilityReportV1, Diagnostic> {
    if baseline.schema != candidate.schema {
        return Err(schema_mismatch(baseline.schema, candidate.schema));
    }
    let mut deltas = Vec::new();
    identity_delta(&mut deltas, "package", baseline.package, candidate.package);
    identity_delta(
        &mut deltas,
        "interface",
        baseline.interface,
        candidate.interface,
    );
    identity_delta(&mut deltas, "world", baseline.world, candidate.world);
    identity_delta(
        &mut deltas,
        "input-type",
        &baseline.input_type,
        &candidate.input_type,
    );
    identity_delta(
        &mut deltas,
        "result-type",
        &baseline.result_type,
        &candidate.result_type,
    );

    match (
        baseline.uses_owned_bytes_resource,
        candidate.uses_owned_bytes_resource,
    ) {
        (false, true) => deltas.push(WitDeltaV1::OwnedBytesResourceAdded),
        (true, false) => deltas.push(WitDeltaV1::OwnedBytesResourceRemoved),
        _ => {}
    }

    let baseline_records: BTreeMap<&str, &WitRecordV1> = baseline
        .records
        .iter()
        .map(|record| (record.name.as_str(), record))
        .collect();
    let candidate_records: BTreeMap<&str, &WitRecordV1> = candidate
        .records
        .iter()
        .map(|record| (record.name.as_str(), record))
        .collect();

    // One pass over the union of both record-name sets, in `BTreeMap` order:
    // fixed across runs and independent of either projection's emission
    // order.
    let names: BTreeSet<&str> = baseline_records
        .keys()
        .chain(candidate_records.keys())
        .copied()
        .collect();
    for name in names {
        match (baseline_records.get(name), candidate_records.get(name)) {
            (Some(baseline_record), Some(candidate_record)) => {
                compare_record(&mut deltas, baseline_record, candidate_record);
            }
            (Some(baseline_record), None) => deltas.push(WitDeltaV1::RecordRemoved {
                name: baseline_record.name.clone(),
                source_term: baseline_record.source_term.clone(),
            }),
            (None, Some(candidate_record)) => deltas.push(WitDeltaV1::RecordAdded {
                name: candidate_record.name.clone(),
                source_term: candidate_record.source_term.clone(),
            }),
            (None, None) => unreachable!("a name in the union is in at least one side"),
        }
    }

    if deltas.len() > MAX_REPORTED_DELTAS {
        return Err(report_capacity());
    }

    Ok(WitCompatibilityReportV1 {
        schema: WIT_COMPATIBILITY_SCHEMA,
        projection_schema: baseline.schema.to_owned(),
        deltas,
    })
}

/// [`compare`], then refuse (`SPX-PGWIT123`) if any delta is breaking.
///
/// For a caller that wants a gate rather than a report. The report is still
/// returned on success, so an additive-only change is visible rather than
/// silently accepted as "no change".
pub fn require_compatible(
    baseline: &WitTypeProjectionV1,
    candidate: &WitTypeProjectionV1,
) -> Result<WitCompatibilityReportV1, Diagnostic> {
    let report = compare(baseline, candidate)?;
    let breaking: Vec<&WitDeltaV1> = report.breaking().collect();
    if !breaking.is_empty() {
        return Err(incompatible(&breaking));
    }
    drop(breaking);
    Ok(report)
}

#[cfg(test)]
mod tests;
