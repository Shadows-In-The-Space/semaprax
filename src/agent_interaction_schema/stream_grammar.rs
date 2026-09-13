//! Read-only streaming grammar lowered from the checked interaction type DAG.

use std::collections::BTreeMap;

use super::shape::{FieldType, Representation, TypeGraph, TypeShape};

use crate::streaming_proposal_decode::grammar::{Case, Field, Grammar, Scalar, Type, Value};

pub(crate) fn lower(graph: &TypeGraph, envelope: String) -> Grammar {
    let mut types = BTreeMap::new();
    for decl in &graph.types {
        let ty = match &decl.shape {
            TypeShape::Record { fields } => Type::Record(fields.iter().map(field).collect()),
            TypeShape::Variant { cases } => Type::Variant(
                cases
                    .iter()
                    .map(|case| Case {
                        id: case.stable_id.clone(),
                        fields: case.fields.iter().map(field).collect(),
                    })
                    .collect(),
            ),
        };
        types.insert(decl.stable_id.clone(), ty);
    }
    Grammar {
        envelope,
        root: graph.root_type_id.clone(),
        types,
    }
}
fn field(field: &super::shape::FieldRow) -> Field {
    Field {
        id: field.stable_id.clone(),
        value: match &field.ty {
            FieldType::Nested(id) => Value::Type(id.clone()),
            FieldType::Scalar(value) => Value::Scalar(match value {
                Representation::Bool => Scalar::Bool,
                Representation::I32 => Scalar::I32,
                Representation::I64 => Scalar::I64,
                Representation::U8 => Scalar::U8,
                Representation::U64 => Scalar::U64,
                Representation::Text => Scalar::Text(super::MAX_STRING_FIELD_BYTES),
                Representation::Bytes => Scalar::Bytes(super::MAX_BYTES_FIELD_BYTES),
            }),
        },
    }
}
