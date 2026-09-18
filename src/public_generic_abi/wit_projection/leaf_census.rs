//! The owned-leaf census agreement check: does the projected WIT type
//! structure still describe *exactly* the owned leaves the descriptor and
//! carrier will actually move?
//!
//! [`super::project_admitted_subject`] renders record and resource text. On
//! its own that text is unchecked against the thing it projects: a projection
//! that dropped a `Bytes` field, reordered two fields, or reached a different
//! record than the classifier did would still render syntactically valid WIT,
//! and a consumer reading that WIT would build a value whose owned-leaf
//! inventory silently disagrees with the carrier's canonical cleanup order.
//! [Public Generic Carrier v1](../../../docs/PUBLIC-GENERIC-CARRIER-V1.md)
//! bounds and settles exactly that inventory, so a disagreement is not a
//! cosmetic difference — it is a boundary the compiler would verify one way
//! and a foreign consumer would build another way.
//!
//! This module recomputes the inventory a second, independent way — by
//! walking the *rendered projection's* records structurally from the input
//! and result roots — and refuses when it is not byte-identical to
//! `InstanceFacts::owned_leaves`, which
//! [`crate::public_generic_type`] derived by walking the *resolved types*
//! instead. The two derivations share no code path: one reads
//! `WitRecordV1`/`WitFieldV1` and canonical grammar terms, the other reads
//! `ResolvedType` and substituted declarations. Agreement between them is
//! therefore evidence, not a tautology.
//!
//! ## Determinism
//!
//! The walk visits a record's `fields` in the already-canonical order the
//! classifier produced and resolves a record reference through a `BTreeMap`
//! keyed by WIT name. Nothing here reads a `HashMap`, the clock, the
//! environment, or randomness, so the census is a pure function of the
//! projection.
//!
//! ## Nonclaims
//!
//! This check emits no bytes, executes nothing, and grants no authority. It
//! does not make a public generic export supported, published, or callable;
//! it only refuses a *type* projection that has stopped agreeing with the
//! descriptor facts it was derived from. The milestone's standing PG-9
//! position is unchanged.

use std::collections::BTreeMap;

use crate::diagnostic::Diagnostic;

use super::super::boundary_profile::{
    MAX_NESTING_DEPTH, MAX_OWNED_LEAVES_PER_INSTANCE, MAX_VISITED_NODES_PER_INSTANCE,
};
use super::super::classifier::AdmittedSubject;
use super::{WitRecordV1, WitTypeProjectionV1, WIT_TYPE_PROJECTION_SCHEMA};

/// The projected WIT structure's owned-leaf inventory is not the descriptor's
/// inventory for the same instance.
pub const LEAF_CENSUS_DISAGREEMENT: &str = "SPX-PGWIT106";
/// The structural census walk exceeded a Public Generic Boundary Profile v1
/// bound. A refusal, never a truncated census.
pub const CENSUS_CAPACITY: &str = "SPX-PGWIT107";
/// The projection names a record type that it never declared.
pub const UNDECLARED_RECORD: &str = "SPX-PGWIT108";

/// The exact field type text `Projector::field_type` renders for an
/// owned `Bytes` leaf. Pinned as a literal rather than formatted so a change
/// to either spelling is a visible edit here; the unit test below asserts the
/// two stay equal.
const OWNED_BYTES_FIELD_TYPE: &str = "own<spx-owned-bytes>";

/// Every WIT identifier this projection emits begins with this prefix, so a
/// field type that is neither a WIT primitive nor a declared record is
/// distinguishable from a primitive by its spelling alone.
const PROJECTED_NAME_PREFIX: &str = "spx-";

fn disagreement(role: &str, expected: &[String], projected: &[String]) -> Diagnostic {
    let detail = expected
        .iter()
        .zip(projected.iter())
        .enumerate()
        .find(|(_, (left, right))| left != right)
        .map_or_else(
            || {
                format!(
                    "descriptor has {} owned leaves, projection has {}",
                    expected.len(),
                    projected.len()
                )
            },
            |(index, (left, right))| {
                format!("leaf {index} is {left} in the descriptor and {right} in the projection")
            },
        );
    Diagnostic::io(
        LEAF_CENSUS_DISAGREEMENT,
        format!(
            "{WIT_TYPE_PROJECTION_SCHEMA} projected a {role} whose owned-leaf inventory is not \
             the descriptor's: {detail}"
        ),
    )
}

fn capacity(subject: &str) -> Diagnostic {
    Diagnostic::io(
        CENSUS_CAPACITY,
        format!("{WIT_TYPE_PROJECTION_SCHEMA} owned-leaf census exceeded its {subject}"),
    )
}

fn undeclared(name: &str) -> Diagnostic {
    Diagnostic::io(
        UNDECLARED_RECORD,
        format!("{WIT_TYPE_PROJECTION_SCHEMA} named an undeclared record type: {name}"),
    )
}

/// Append `@<len>:<identity>` — the identity framing
/// [`crate::public_generic_type`] uses to build an owned-leaf path.
///
/// That function is private to the grammar module, so this is a deliberate
/// second spelling of the same four-line encoding rather than a call. It is
/// not a silent duplicate: [`check_owned_leaf_census`] compares this
/// module's output against the grammar's own, so any drift between the two
/// spellings fails [`LEAF_CENSUS_DISAGREEMENT`] on the very next projection
/// instead of passing unnoticed.
fn push_identity(output: &mut String, identity: &str) {
    output.push('@');
    output.push_str(&identity.len().to_string());
    output.push(':');
    output.push_str(identity);
}

struct Census<'a> {
    records: BTreeMap<&'a str, &'a WitRecordV1>,
    leaves: Vec<String>,
    nodes: usize,
}

impl<'a> Census<'a> {
    fn walk(&mut self, record_name: &str, prefix: &str, depth: usize) -> Result<(), Diagnostic> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_VISITED_NODES_PER_INSTANCE {
            return Err(capacity("visited node bound"));
        }
        if depth > MAX_NESTING_DEPTH {
            return Err(capacity("record nesting depth"));
        }
        let record = self
            .records
            .get(record_name)
            .copied()
            .ok_or_else(|| undeclared(record_name))?;
        for field in &record.fields {
            let mut path = prefix.to_owned();
            if !path.is_empty() {
                path.push('/');
            }
            push_identity(&mut path, &field.source_field_id);
            if field.type_text == OWNED_BYTES_FIELD_TYPE {
                if self.leaves.len() >= MAX_OWNED_LEAVES_PER_INSTANCE {
                    return Err(capacity("transitive owned leaf bound"));
                }
                self.leaves.push(path);
            } else if field.type_text.starts_with(PROJECTED_NAME_PREFIX) {
                // A projected identifier that is not the owned-bytes handle
                // is a record reference. An unknown one is refused by name
                // rather than treated as a leafless opaque type.
                self.walk(&field.type_text, &path, depth + 1)?;
            }
            // Anything else is a WIT primitive and contributes no owned leaf.
        }
        Ok(())
    }
}

/// The owned-leaf identity paths the projected WIT structure implies for the
/// record named `root`, in structural order.
pub fn projected_owned_leaves(
    projection: &WitTypeProjectionV1,
    root: &str,
) -> Result<Vec<String>, Diagnostic> {
    let mut census = Census {
        records: projection
            .records
            .iter()
            .map(|record| (record.name.as_str(), record))
            .collect(),
        leaves: Vec::new(),
        nodes: 0,
    };
    census.walk(root, "", 1)?;
    Ok(census.leaves)
}

/// Refuse unless the projection's input and result records imply exactly the
/// owned-leaf inventories the classifier already computed for the same
/// instances.
pub fn check_owned_leaf_census(
    subject: &AdmittedSubject,
    projection: &WitTypeProjectionV1,
) -> Result<(), Diagnostic> {
    for (role, facts, root) in [
        ("input", subject.input(), projection.input_type.as_str()),
        ("result", subject.result(), projection.result_type.as_str()),
    ] {
        let projected = projected_owned_leaves(projection, root)?;
        if projected != facts.owned_leaves {
            return Err(disagreement(role, &facts.owned_leaves, &projected));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
