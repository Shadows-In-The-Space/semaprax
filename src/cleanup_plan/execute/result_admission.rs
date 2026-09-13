//! Closed result types accepted by the target-neutral cleanup executor.
use super::*;

pub(super) fn validate_public_result_type(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
) -> Result<(), CleanupExecutionError> {
    let ResolvedType::Nominal { declaration, .. } = &function.return_type else {
        return if matches!(
            function.return_type,
            ResolvedType::I64 | ResolvedType::Bool | ResolvedType::String
        ) {
            Ok(())
        } else {
            Err(CleanupExecutionError::UnsupportedResultType(
                function.return_type.identity_key(),
            ))
        };
    };
    match program
        .types
        .iter()
        .find(|item| item.id == *declaration)
        .map(|item| &item.kind)
    {
        Some(ResolvedTypeDeclarationKind::Resource { .. }) => Ok(()),
        Some(ResolvedTypeDeclarationKind::Variant { .. })
            if expression_has_try(&function.body)
                && program
                    .declarations
                    .type_facts(&function.return_type)
                    .is_some_and(|facts| {
                        facts.copy && facts.sized && !facts.contains_resource && !facts.needs_drop
                    }) =>
        {
            // The executor authenticates staged Copy-result control/state, but
            // the public conformance protocol intentionally has no aggregate
            // value representation. Terminal materialization remains closed.
            Ok(())
        }
        Some(
            ResolvedTypeDeclarationKind::Record { .. }
            | ResolvedTypeDeclarationKind::Class { .. }
            | ResolvedTypeDeclarationKind::Variant { .. },
        )
        | None => Err(CleanupExecutionError::UnsupportedResultType(
            function.return_type.identity_key(),
        )),
    }
}
