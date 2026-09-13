//! Independent source-derived replay of literal/place String allocation.
use super::*;
use crate::hir::ResolvedTypeDeclarationKind;
pub(super) fn owns_clone(expression: &ResolvedExpr) -> bool {
    expression.ty == ResolvedType::String
        && expression.ownership == OwnershipMode::Own
        && matches!(
            expression.kind,
            ResolvedExprKind::String(_) | ResolvedExprKind::Place(_)
        )
}
pub(super) fn paths(
    expression: &ResolvedExpr,
    work: &mut SkeletonWork<'_, '_>,
) -> Result<Vec<ExprSkeletonPath>, Diagnostic> {
    let destination = temporary_place(expression, work)?;
    let mut path = empty_expr_path();
    let at = work.clone_owned(&expression.id, "string allocation identity")?;
    let initialized = work.clone_owned(&destination, "string allocation destination")?;
    work.push_observation(
        &mut path,
        SkeletonObservation::Initialize {
            at,
            destination: initialized,
        },
        "string allocation initialization",
    )?;
    path.owned_source = Some(destination);
    work.singleton_path(path, "string allocation skeleton")
}

pub(super) fn temporary_place(
    expression: &ResolvedExpr,
    work: &mut SkeletonWork<'_, '_>,
) -> Result<CleanupPlace, Diagnostic> {
    Ok(CleanupPlace {
        storage: StorageId::Temporary(
            work.clone_owned(&expression.id, "temporary-place expression clone")?,
        ),
        projections: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn string_lifecycle_is_rebuilt_from_type_and_rejects_forgery() {
        let checked = crate::check(
            r#"
module test.string.cleanup;
@id("text.keep") fn keep(value: string) -> string { value }
@id("app.main") fn main() -> i64 { string_len(keep("hello")) }
"#,
            "string-cleanup.spx",
        )
        .unwrap();
        let program = crate::hir::resolve(&checked).unwrap();
        crate::hir::validate(&program).unwrap();
        let trace = crate::cleanup_plan::execute::execute_for_conformance(
            &program,
            &crate::hir::DeclarationId::new("text.keep"),
            crate::cleanup_plan::execute::CleanupScenario::new(
                "string-result",
                Some(crate::conformance::TraceResult::String),
            ),
        )
        .unwrap();
        assert!(matches!(
            trace.outcome,
            crate::conformance::TraceOutcome::Success {
                result: crate::conformance::TraceResult::String
            }
        ));
        let mut forged = program.clone();
        let function = forged
            .functions
            .iter_mut()
            .find(|f| f.id.as_str() == "text.keep")
            .unwrap();
        let flag = function
            .cleanup
            .flags
            .iter_mut()
            .find(|f| f.lifecycle.as_str() == crate::cleanup::STRING_DROP_LIFECYCLE_ID)
            .unwrap();
        flag.lifecycle = crate::hir::DeclarationId::new(crate::cleanup::BYTES_DROP_LIFECYCLE_ID);
        assert!(crate::hir::validate(&forged).is_err());
    }
}

pub(super) fn needs_complete_case_domain(
    program: &ResolvedProgram,
    variant: &DeclarationId,
) -> bool {
    if variant.as_str() == crate::iterator_ops::STEP_ID {
        return true;
    }
    program.types.iter().any(|item| {
        item.id == *variant
            && match &item.kind {
                ResolvedTypeDeclarationKind::Variant { cases } => cases
                    .iter()
                    .flat_map(|case| &case.fields)
                    .any(|field| field.ty == ResolvedType::String),
                _ => false,
            }
    })
}
