//! Shared incremental grammar lowering for the checked source Proposal role.

use std::collections::BTreeMap;

use crate::streaming_proposal_decode::grammar::{Case, Field, Grammar, Scalar, Type, Value};

use super::shape::{FieldRow, Representation, Shape};

/// The source Proposal v1 subset has one record or variant root and no
/// nominal children. Retaining the same shared graph carrier means the stream
/// engine does not hand-copy source field/case rules.
pub(crate) fn lower(shape: &Shape, envelope: String) -> Grammar {
    let root = "value".to_owned();
    let ty = match shape {
        Shape::Record { fields } => Type::Record(fields.iter().map(field).collect()),
        Shape::Variant { cases } => Type::Variant(
            cases
                .iter()
                .map(|case| Case {
                    id: case.stable_id.clone(),
                    fields: case.fields.iter().map(field).collect(),
                })
                .collect(),
        ),
    };
    Grammar {
        envelope,
        root: root.clone(),
        types: BTreeMap::from([(root, ty)]),
    }
}

fn field(field: &FieldRow) -> Field {
    Field {
        id: field.stable_id.clone(),
        value: Value::Scalar(match field.representation {
            Representation::Bool => Scalar::Bool,
            Representation::I32 => Scalar::I32,
            Representation::I64 => Scalar::I64,
            Representation::U8 => Scalar::U8,
            Representation::U64 => Scalar::U64,
            Representation::Text => Scalar::Text(super::MAX_STRING_FIELD_BYTES),
        }),
    }
}
