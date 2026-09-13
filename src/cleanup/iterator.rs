//! Exact conditional iterator ownership; authored variants retain prior admission.
use crate::hir::{DeclarationId, ResolvedType};
pub(crate) fn variant_leaf_lifecycle(
    container: &ResolvedType,
    case: &DeclarationId,
    field: &DeclarationId,
    ty: &ResolvedType,
) -> Option<&'static str> {
    if let Some(lifecycle) = primitive_leaf_lifecycle(ty) {
        return Some(lifecycle);
    }
    (crate::iterator_ops::is_step(container)
        && case.as_str() == crate::iterator_ops::YIELD_ID
        && field.as_str() == crate::iterator_ops::REST_ID
        && crate::iterator_ops::is_iter(ty)
        && crate::iterator_ops::element(container) == crate::iterator_ops::element(ty))
    .then_some(super::ITER_DROP_LIFECYCLE_ID)
}

/// Compiler-owned primitive cleanup identities, independently derived from type.
pub(crate) fn primitive_leaf_lifecycle(ty: &ResolvedType) -> Option<&'static str> {
    match ty {
        ResolvedType::Bytes => Some(super::BYTES_DROP_LIFECYCLE_ID),
        ResolvedType::String => Some(super::STRING_DROP_LIFECYCLE_ID),
        _ => None,
    }
}
