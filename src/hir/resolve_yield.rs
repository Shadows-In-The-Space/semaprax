//! Resumable Effects v1 (issue #204): resolving and admitting a function's
//! `yields Request -> Response` clause and its body's `yield` expression.
//!
//! `parser::yields` already guarantees, purely syntactically, that an
//! admitted function contains at most one `yield`, and only as a direct
//! top-level `let`/assignment value or tail expression of its own body
//! block, never nested. This module adds the type-level half:
//!
//! - The declared request and response types must be admitted Copy
//!   scalars (`hir::nodes::is_scalar_resolved_type`), deferring records,
//!   variants, and any type needing cleanup to future work so a suspend/
//!   resume never has to reason about ownership crossing the suspension.
//! - The whole function -- every parameter and every intermediate value --
//!   must stay within that same scalar profile, so cleanup-plan
//!   construction never needs a genuinely new exit path for `yield`
//!   (`cleanup_plan::build` treats it as an ordinary single-child node).
//! - The function may declare no `uses` effects: this slice's interpreter
//!   resumes by re-executing the function's prefix with the resume value
//!   substituted at the yield site, which would redispatch a host effect
//!   that already ran during the original, suspended call.
//! - The function may declare no generics (deferred: generics over the
//!   effect type). `source_verify::declared_type` already refuses any
//!   generic function whose body reaches a `Yield` node before `hir::resolve`
//!   ever runs its own checks, so this module adds no second, unreachable
//!   check for that case.
//!
//! See `docs/RESUMABLE-EFFECTS-V1.md`.

use crate::ast;
use crate::diagnostic::Diagnostic;

use super::expr_nodes::{
    ResolvedExpr, ResolvedExprKind, ResolvedFieldInitializer, ResolvedMatchArm,
};
use super::nodes::{is_scalar_resolved_type, ResolvedParam, ResolvedType, ResolvedYieldsClause};
use super::Resolver;

/// A `yields`-declaring function's own request or response type is not an
/// admitted Copy scalar.
const NON_SCALAR_SIGNATURE: &str = "SPX-T301";
/// `yield`'s operand does not have the declared request type.
const ILL_TYPED_YIELD: &str = "SPX-T299";
/// A `yields`-declaring function also declares `uses` effects.
const EFFECTFUL_YIELDS: &str = "SPX-T302";
/// A `yields`-declaring function's body -- a parameter or an intermediate
/// value -- leaves the admitted Copy-scalar profile.
const NON_SCALAR_BODY: &str = "SPX-T303";

impl Resolver<'_> {
    /// Resolves `function.yields`, if present, and checks the admission
    /// rules that depend only on the signature: no `uses` effects,
    /// request/response types and every parameter type scalar. A generic
    /// function declaring `yields` is refused before this ever runs:
    /// `parser::yields` guarantees a `yields`-declaring function's body
    /// contains exactly one `yield`, and `source_verify::declared_type`
    /// already refuses any generic function whose body reaches a `Yield`
    /// node (`SPX-T226`, "outside the direct-scalar slice") as part of
    /// `hir::resolve`'s existing source-verification gate -- generic
    /// functions never reach `resolve_function_in_scope`, so a second,
    /// unreachable check here would be dead code.
    pub(super) fn resolve_yields_clause(
        &self,
        function: &ast::Function,
        params: &[ResolvedParam],
    ) -> Result<Option<ResolvedYieldsClause>, Diagnostic> {
        let Some(yields) = &function.yields else {
            return Ok(None);
        };
        if !function.effects.is_empty() {
            return Err(self.error(
                EFFECTFUL_YIELDS,
                format!(
                    "function `{}` declares both `uses` and `yields`; resuming would \
                     redispatch its host effects a second time, which is not yet admitted",
                    function.name
                ),
                yields.span,
            ));
        }
        let request_type = self.resolve_type(&yields.request_type, yields.span)?;
        let response_type = self.resolve_type(&yields.response_type, yields.span)?;
        if !is_scalar_resolved_type(&request_type) || !is_scalar_resolved_type(&response_type) {
            return Err(self.error(
                NON_SCALAR_SIGNATURE,
                format!(
                    "function `{}` declares a `yields` request or response type that is not an \
                     admitted Copy scalar; records, variants, and owned types are not yet \
                     admitted here",
                    function.name
                ),
                yields.span,
            ));
        }
        if let Some(offender) = params
            .iter()
            .find(|param| !is_scalar_resolved_type(&param.ty))
        {
            return Err(self.error(
                NON_SCALAR_BODY,
                format!(
                    "function `{}` declares `yields` but parameter `{}` is not an admitted Copy \
                     scalar",
                    function.name, offender.name
                ),
                offender.span,
            ));
        }
        Ok(Some(ResolvedYieldsClause {
            request_type,
            response_type,
            span: yields.span,
        }))
    }

    /// Locates the function's single top-level `yield` (guaranteed to exist
    /// exactly once by the parser-level check), checks its operand's
    /// resolved type against the declared request type, and rewrites its
    /// placeholder `ty` (the operand's own type, set when `resolve_expr`
    /// first built the node with no signature context available) to the
    /// declared response type. Also verifies every other resolved value in
    /// the body stays within the admitted Copy-scalar profile.
    pub(super) fn finish_yields_admission(
        &self,
        function_name: &str,
        yields: &ResolvedYieldsClause,
        body: &mut ResolvedExpr,
    ) -> Result<(), Diagnostic> {
        let mut found = false;
        scan_expr(self, function_name, yields, body, true, &mut found)?;
        if !found {
            // Unreachable given the parser-level guarantee; kept as a
            // defensive check rather than trusted silently.
            return Err(self.error(
                "SPX-T298",
                format!("function `{function_name}` declares `yields` but its body never yields"),
                yields.span,
            ));
        }
        Ok(())
    }
}

fn check_scalar(
    resolver: &Resolver<'_>,
    function_name: &str,
    expr: &ResolvedExpr,
) -> Result<(), Diagnostic> {
    if is_scalar_resolved_type(&expr.ty) || expr.ty == ResolvedType::Unit {
        Ok(())
    } else {
        Err(resolver.error(
            NON_SCALAR_BODY,
            format!(
                "function `{function_name}` declares `yields` but an intermediate value has a \
                 type that is not an admitted Copy scalar"
            ),
            expr.span,
        ))
    }
}

/// Exhaustive descent over every resolved expression shape. `top_level` is
/// `true` only while walking positions the parser already admitted a
/// direct `yield` in (the function's own top-level statement values and
/// tail); every recursive call into a child passes `false`.
fn scan_expr(
    resolver: &Resolver<'_>,
    function_name: &str,
    yields: &ResolvedYieldsClause,
    expr: &mut ResolvedExpr,
    top_level: bool,
    found: &mut bool,
) -> Result<(), Diagnostic> {
    match &mut expr.kind {
        ResolvedExprKind::Yield { request } => {
            scan_expr(resolver, function_name, yields, request, false, found)?;
            if !top_level {
                // Unreachable: `parser::yields` already refuses a nested
                // `yield` before resolution ever runs. Defensive.
                return Err(resolver.error(
                    "SPX-T297",
                    format!(
                        "function `{function_name}` yields in a position the parser should \
                         already have refused"
                    ),
                    expr.span,
                ));
            }
            if request.ty != yields.request_type {
                return Err(resolver.error(
                    ILL_TYPED_YIELD,
                    format!(
                        "function `{function_name}`'s `yield` operand has type `{:?}` but the \
                         declared request type is `{:?}`",
                        request.ty, yields.request_type
                    ),
                    request.span,
                ));
            }
            expr.ty = yields.response_type.clone();
            *found = true;
        }
        ResolvedExprKind::Closure { captures, body, .. } => {
            for capture in captures.iter_mut() {
                scan_expr(
                    resolver,
                    function_name,
                    yields,
                    &mut capture.value,
                    false,
                    found,
                )?;
            }
            scan_expr(resolver, function_name, yields, body, false, found)?;
        }
        ResolvedExprKind::FunctionReference { .. }
        | ResolvedExprKind::Int(_)
        | ResolvedExprKind::Int32(_)
        | ResolvedExprKind::Char(_)
        | ResolvedExprKind::Uint8(_)
        | ResolvedExprKind::Usize(_)
        | ResolvedExprKind::ArrayU8(_)
        | ResolvedExprKind::RepeatArrayU8 { .. }
        | ResolvedExprKind::Float32(_)
        | ResolvedExprKind::Float64(_)
        | ResolvedExprKind::Bool(_)
        | ResolvedExprKind::String(_)
        | ResolvedExprKind::Place(_)
        | ResolvedExprKind::BorrowPlace { .. } => {}
        ResolvedExprKind::ByteRange {
            source, start, end, ..
        } => {
            scan_expr(resolver, function_name, yields, source, false, found)?;
            scan_expr(resolver, function_name, yields, start, false, found)?;
            scan_expr(resolver, function_name, yields, end, false, found)?;
        }
        ResolvedExprKind::Invoke { callable, args } => {
            scan_expr(resolver, function_name, yields, callable, false, found)?;
            scan_children(resolver, function_name, yields, args, found)?;
        }
        ResolvedExprKind::Call { args, .. } => {
            scan_children(resolver, function_name, yields, args, found)?;
        }
        ResolvedExprKind::NativeRustImportCall(call) => {
            scan_children(resolver, function_name, yields, &mut call.args, found)?;
        }
        ResolvedExprKind::HostCommandCall(call) => {
            scan_children(resolver, function_name, yields, &mut call.args, found)?;
        }
        ResolvedExprKind::Unary { value, .. } => {
            scan_expr(resolver, function_name, yields, value, false, found)?;
        }
        ResolvedExprKind::Binary { left, right, .. } => {
            scan_expr(resolver, function_name, yields, left, false, found)?;
            scan_expr(resolver, function_name, yields, right, false, found)?;
        }
        ResolvedExprKind::Block { statements, tail } => {
            for statement in statements.iter_mut() {
                scan_statement(resolver, function_name, yields, statement, top_level, found)?;
            }
            scan_expr(resolver, function_name, yields, tail, top_level, found)?;
        }
        ResolvedExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            scan_expr(resolver, function_name, yields, condition, false, found)?;
            scan_expr(resolver, function_name, yields, then_branch, false, found)?;
            scan_expr(resolver, function_name, yields, else_branch, false, found)?;
        }
        ResolvedExprKind::ConstructRecord { fields, .. }
        | ResolvedExprKind::ConstructVariant { fields, .. } => {
            scan_fields(resolver, function_name, yields, fields, found)?;
        }
        ResolvedExprKind::Match {
            scrutinee, arms, ..
        } => {
            scan_expr(resolver, function_name, yields, scrutinee, false, found)?;
            for arm in arms.iter_mut() {
                scan_arm(resolver, function_name, yields, arm, found)?;
            }
        }
        ResolvedExprKind::Try { operand, .. } | ResolvedExprKind::TryOption { operand, .. } => {
            scan_expr(resolver, function_name, yields, operand, false, found)?;
        }
        ResolvedExprKind::UpdateRecord { base, fields, .. } => {
            scan_expr(resolver, function_name, yields, base, false, found)?;
            scan_fields(resolver, function_name, yields, fields, found)?;
        }
        ResolvedExprKind::Project { base, .. } | ResolvedExprKind::Upcast { source: base } => {
            scan_expr(resolver, function_name, yields, base, false, found)?;
        }
    }
    check_scalar(resolver, function_name, expr)
}

fn scan_children(
    resolver: &Resolver<'_>,
    function_name: &str,
    yields: &ResolvedYieldsClause,
    children: &mut [ResolvedExpr],
    found: &mut bool,
) -> Result<(), Diagnostic> {
    for child in children.iter_mut() {
        scan_expr(resolver, function_name, yields, child, false, found)?;
    }
    Ok(())
}

fn scan_fields(
    resolver: &Resolver<'_>,
    function_name: &str,
    yields: &ResolvedYieldsClause,
    fields: &mut [ResolvedFieldInitializer],
    found: &mut bool,
) -> Result<(), Diagnostic> {
    for field in fields.iter_mut() {
        scan_expr(
            resolver,
            function_name,
            yields,
            &mut field.value,
            false,
            found,
        )?;
    }
    Ok(())
}

fn scan_arm(
    resolver: &Resolver<'_>,
    function_name: &str,
    yields: &ResolvedYieldsClause,
    arm: &mut ResolvedMatchArm,
    found: &mut bool,
) -> Result<(), Diagnostic> {
    if let Some(guard) = &mut arm.guard {
        scan_expr(resolver, function_name, yields, guard, false, found)?;
    }
    scan_expr(
        resolver,
        function_name,
        yields,
        &mut arm.value,
        false,
        found,
    )
}

fn scan_statement(
    resolver: &Resolver<'_>,
    function_name: &str,
    yields: &ResolvedYieldsClause,
    statement: &mut super::expr_nodes::ResolvedStatement,
    top_level: bool,
    found: &mut bool,
) -> Result<(), Diagnostic> {
    use super::expr_nodes::ResolvedStatement;
    match statement {
        ResolvedStatement::Let { value, .. } | ResolvedStatement::Assign { value, .. } => {
            scan_expr(resolver, function_name, yields, value, top_level, found)
        }
        ResolvedStatement::Unsafe { body, .. } => {
            scan_expr(resolver, function_name, yields, body, false, found)
        }
        ResolvedStatement::While {
            condition, body, ..
        } => {
            scan_expr(resolver, function_name, yields, condition, false, found)?;
            scan_expr(resolver, function_name, yields, body, false, found)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{EFFECTFUL_YIELDS, ILL_TYPED_YIELD, NON_SCALAR_SIGNATURE};
    use crate::hir;

    fn resolve(source: &str) -> Result<hir::ResolvedProgram, crate::diagnostic::Diagnostic> {
        let program = crate::parse(source, Path::new("resolve-yield-fixture.spx")).unwrap();
        hir::resolve(&program).map_err(|mut errors| errors.remove(0))
    }

    #[test]
    fn a_well_typed_scalar_yield_resolves() {
        let source = r#"
module test.resolve_yield_ok;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let answer = yield seed + 1;
    answer * 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let resolved = resolve(source).expect("well-typed scalar yield resolves");
        let ask = resolved
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        let yields = ask.yields.as_ref().expect("declares yields");
        assert_eq!(yields.request_type, hir::ResolvedType::I64);
        assert_eq!(yields.response_type, hir::ResolvedType::I64);
    }

    #[test]
    fn a_yield_operand_of_the_wrong_type_is_refused() {
        let source = r#"
module test.resolve_yield_ill_typed;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    let answer = yield true;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = resolve(source).unwrap_err();
        assert_eq!(error.code, ILL_TYPED_YIELD);
    }

    #[test]
    fn a_generic_function_cannot_declare_yields() {
        let source = r#"
module test.resolve_yield_generic;
@id("app.ask")
fn ask<T>() -> i64
    yields i64 -> i64
{
    let answer = yield 1;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = resolve(source).unwrap_err();
        // `source_verify::declared_type` refuses any generic function whose
        // body reaches a `Yield` node before `hir::resolve` runs its own
        // checks; see the module doc for why this module adds no second,
        // unreachable check for the same case.
        assert_eq!(error.code, "SPX-T226");
    }

    #[test]
    fn a_function_with_uses_effects_cannot_also_declare_yields() {
        let source = r#"
module test.resolve_yield_effectful;
permit { clock.read }
@id("app.ask")
fn ask() -> i64
    uses { clock.read }
    yields i64 -> i64
{
    let answer = yield 1;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = resolve(source).unwrap_err();
        assert_eq!(error.code, EFFECTFUL_YIELDS);
    }

    #[test]
    fn a_non_scalar_yields_signature_is_refused() {
        let source = r#"
module test.resolve_yield_non_scalar;
@id("app.prompt")
record Prompt { @id("app.prompt.seed") seed: i64, }
@id("app.ask")
fn ask() -> i64
    yields Prompt -> i64
{
    let answer = yield Prompt { seed: 1 };
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = resolve(source).unwrap_err();
        assert_eq!(error.code, NON_SCALAR_SIGNATURE);
    }
}
