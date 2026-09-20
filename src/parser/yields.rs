//! Resumable Effects v1 (issue #204): structural admission for `yield`.
//!
//! Checked once a function's AST is fully parsed, before any semantic
//! resolution runs. Everything here is purely syntactic -- whether a
//! `yield` expression sits at the direct top level of its *own* enclosing
//! function's body block (a `let`/assignment value, or the block's tail),
//! and whether that function declared a `yields` clause at all. Type-level
//! checks (the operand's type against the declared request type, and the
//! whole `yield` expression's type against the declared response type) are
//! `hir::resolve_yield`'s job once types exist.
//!
//! Restricting `yield` to a function's own top-level statement/tail
//! positions -- never nested inside a call's arguments, a binary operator,
//! a record/variant construction, an `if`/`match` arm, or a nested block --
//! is a deliberate first-slice scope decision. It statically guarantees, by
//! construction rather than by a separate check, every deferred case
//! `docs/RESUMABLE-EFFECTS-V1.md` names: no loop can contain a `yield`
//! (`while` bodies are always nested blocks), no owned call's argument
//! staging can observe a suspension (call arguments are always nested
//! sub-expressions), and yield sites execute only in authored top-level
//! sequence.
//! See `docs/RESUMABLE-EFFECTS-V1.md`.

use crate::ast::{Expr, ExprKind, FieldInitializer, Function, MatchArm, Statement};
use crate::diagnostic::Diagnostic;

/// `yield` used somewhere a `yields`-declaring function's own top-level
/// body block does not admit it: nested inside another expression, a
/// loop, a conditional branch, or a function with no `yields` clause.
const MISPLACED_YIELD: &str = "SPX-T297";
/// A `yields`-declaring function's body contains no top-level `yield`
/// expression.
const YIELD_ARITY: &str = "SPX-T298";

pub(super) fn check_function_yield_placement(
    function: &Function,
    path: &str,
) -> Result<(), Diagnostic> {
    let mut top_level_yields: Vec<Expr> = Vec::new();
    scan_top_level(&function.body, &mut top_level_yields, path)?;

    match (&function.yields, top_level_yields.len()) {
        (Some(_), 1..) => Ok(()),
        (Some(clause), 0) => Err(Diagnostic::error(
            YIELD_ARITY,
            format!(
                "function `{}` declares `yields` but its body never yields",
                function.name
            ),
            clause.span,
        )
        .at_path(path)),
        (None, 0) => Ok(()),
        (None, _) => Err(Diagnostic::error(
            MISPLACED_YIELD,
            format!(
                "function `{}` uses `yield` but does not declare a `yields` clause",
                function.name
            ),
            top_level_yields[0].span,
        )
        .at_path(path)),
    }
}

/// Scans exactly the function body's own top-level statement values and
/// tail. A directly-`Yield` position is admitted and recorded; everything
/// else -- including that admitted yield's own operand -- is handed to
/// [`forbid_nested_yield`], which never admits `Yield` at all.
fn scan_top_level(body: &Expr, found: &mut Vec<Expr>, path: &str) -> Result<(), Diagnostic> {
    let ExprKind::Block { statements, tail } = &body.kind else {
        // Every admitted function body is a brace block; a differently
        // shaped body has no top-level position to admit at all.
        return forbid_nested_yield(body, path);
    };
    for statement in statements {
        scan_top_level_statement(statement, found, path)?;
    }
    scan_top_level_slot(tail, found, path)
}

fn scan_top_level_statement(
    statement: &Statement,
    found: &mut Vec<Expr>,
    path: &str,
) -> Result<(), Diagnostic> {
    match statement {
        Statement::Let { value, .. } | Statement::Assign { value, .. } => {
            scan_top_level_slot(value, found, path)
        }
        // A loop or unsafe body is a nested block, never the function's own
        // top-level block; any `yield` inside is a misplacement.
        Statement::Unsafe { body, .. } => forbid_nested_yield(body, path),
        Statement::While {
            condition, body, ..
        } => {
            forbid_nested_yield(condition, path)?;
            forbid_nested_yield(body, path)
        }
        Statement::For { values, body, .. } | Statement::ForOwn { values, body, .. } => {
            forbid_nested_yield(values, path)?;
            forbid_nested_yield(body, path)
        }
    }
}

/// One position that admits a direct `Yield`: record it and check its
/// operand does not itself hide another `yield`, or otherwise forbid it.
fn scan_top_level_slot(slot: &Expr, found: &mut Vec<Expr>, path: &str) -> Result<(), Diagnostic> {
    if let ExprKind::Yield { request } = &slot.kind {
        forbid_nested_yield(request, path)?;
        found.push(slot.clone());
        Ok(())
    } else {
        forbid_nested_yield(slot, path)
    }
}

fn misplaced(span: crate::ast::Span, path: &str) -> Diagnostic {
    Diagnostic::error(
        MISPLACED_YIELD,
        "`yield` is only admitted as a function's own top-level `let`/assignment value or tail \
         expression, never nested inside another expression, a loop, or a conditional branch",
        span,
    )
    .at_path(path)
}

/// Exhaustive descent over every expression shape that never admits a
/// nested `Yield`. Every child of every variant is visited so a `yield`
/// buried at any depth -- inside a call argument, a binary operand, a
/// match arm, an `if` branch, a nested block, a closure body, and so on --
/// is reported rather than silently accepted.
fn forbid_nested_yield(expr: &Expr, path: &str) -> Result<(), Diagnostic> {
    match &expr.kind {
        ExprKind::Yield { .. } => Err(misplaced(expr.span, path)),
        ExprKind::Int(_)
        | ExprKind::Int32(_)
        | ExprKind::Char(_)
        | ExprKind::Uint8(_)
        | ExprKind::Usize(_)
        | ExprKind::ArrayU8(_)
        | ExprKind::RepeatArrayU8 { .. }
        | ExprKind::Float32(_)
        | ExprKind::Float64(_)
        | ExprKind::Bool(_)
        | ExprKind::String(_)
        | ExprKind::Var(_) => Ok(()),
        ExprKind::Closure { body, .. } => forbid_nested_yield(body, path),
        ExprKind::Call { args, .. } => args
            .iter()
            .try_for_each(|arg| forbid_nested_yield(arg, path)),
        ExprKind::MethodCall { receiver, args, .. } => {
            forbid_nested_yield(receiver, path)?;
            args.iter()
                .try_for_each(|arg| forbid_nested_yield(arg, path))
        }
        ExprKind::SuperMethod { args, .. } => args
            .iter()
            .try_for_each(|arg| forbid_nested_yield(arg, path)),
        ExprKind::Unary { value, .. } => forbid_nested_yield(value, path),
        ExprKind::Binary { left, right, .. } => {
            forbid_nested_yield(left, path)?;
            forbid_nested_yield(right, path)
        }
        ExprKind::Block { statements, tail } => {
            for statement in statements {
                forbid_nested_yield_statement(statement, path)?;
            }
            forbid_nested_yield(tail, path)
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            forbid_nested_yield(condition, path)?;
            forbid_nested_yield(then_branch, path)?;
            forbid_nested_yield(else_branch, path)
        }
        ExprKind::ConstructRecord { fields, .. } | ExprKind::ConstructVariant { fields, .. } => {
            forbid_nested_yield_fields(fields, path)
        }
        ExprKind::Match {
            scrutinee, arms, ..
        } => {
            forbid_nested_yield(scrutinee, path)?;
            arms.iter()
                .try_for_each(|arm| forbid_nested_yield_arm(arm, path))
        }
        ExprKind::Try { operand } => forbid_nested_yield(operand, path),
        ExprKind::UpdateRecord { base, fields } => {
            forbid_nested_yield(base, path)?;
            forbid_nested_yield_fields(fields, path)
        }
        ExprKind::Project { base, .. } => forbid_nested_yield(base, path),
    }
}

fn forbid_nested_yield_fields(fields: &[FieldInitializer], path: &str) -> Result<(), Diagnostic> {
    fields
        .iter()
        .try_for_each(|field| forbid_nested_yield(&field.value, path))
}

fn forbid_nested_yield_arm(arm: &MatchArm, path: &str) -> Result<(), Diagnostic> {
    if let Some(guard) = &arm.guard {
        forbid_nested_yield(guard, path)?;
    }
    forbid_nested_yield(&arm.value, path)
}

fn forbid_nested_yield_statement(statement: &Statement, path: &str) -> Result<(), Diagnostic> {
    match statement {
        Statement::Let { value, .. } | Statement::Assign { value, .. } => {
            forbid_nested_yield(value, path)
        }
        Statement::Unsafe { body, .. } => forbid_nested_yield(body, path),
        Statement::While {
            condition, body, ..
        } => {
            forbid_nested_yield(condition, path)?;
            forbid_nested_yield(body, path)
        }
        Statement::For { values, body, .. } | Statement::ForOwn { values, body, .. } => {
            forbid_nested_yield(values, path)?;
            forbid_nested_yield(body, path)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Diagnostic, MISPLACED_YIELD, YIELD_ARITY};

    fn parse(source: &str) -> Result<crate::ast::Program, Diagnostic> {
        crate::parse(source, Path::new("yields-fixture.spx"))
    }

    #[test]
    fn a_single_top_level_yield_in_a_declaring_function_parses() {
        let source = r#"
module test.yields_ok;
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
        parse(source).expect("a direct top-level yield is admitted");
    }

    #[test]
    fn yield_as_the_tail_expression_parses() {
        let source = r#"
module test.yields_tail;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    yield 1
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        parse(source).expect("yield as the function's own tail is admitted");
    }

    #[test]
    fn yield_without_a_yields_clause_is_refused() {
        let source = r#"
module test.yields_missing_clause;
@id("app.ask")
fn ask() -> i64 {
    yield 1
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = parse(source).unwrap_err();
        assert_eq!(error.code, MISPLACED_YIELD);
    }

    #[test]
    fn yield_nested_inside_a_binary_operand_is_refused() {
        let source = r#"
module test.yields_nested;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    let answer = 1 + (yield 1);
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = parse(source).unwrap_err();
        assert_eq!(error.code, MISPLACED_YIELD);
    }

    #[test]
    fn yield_inside_a_while_body_is_refused() {
        let source = r#"
module test.yields_in_loop;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    while true {
        let _consumed = yield 1;
        0
    }
    0
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = parse(source).unwrap_err();
        assert_eq!(error.code, MISPLACED_YIELD);
    }

    #[test]
    fn a_yields_declaring_function_that_never_yields_is_refused() {
        let source = r#"
module test.yields_zero;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    0
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = parse(source).unwrap_err();
        assert_eq!(error.code, YIELD_ARITY);
    }

    #[test]
    fn sequential_top_level_yields_in_a_declaring_function_parse() {
        let source = r#"
module test.yields_twice;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    let a = yield 1;
    let b = yield 2;
    a + b
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        parse(source).expect("sequential top-level yields are admitted");
    }

    #[test]
    fn a_class_method_cannot_declare_yields() {
        let source = r#"
module test.yields_method;
@id("app.box")
class Box {
    @id("app.box.ask")
    fn ask(self: Box) -> i64
        yields i64 -> i64
    {
        yield 1
    }
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let error = parse(source).unwrap_err();
        assert_eq!(error.code, "SPX-T304");
    }
}
