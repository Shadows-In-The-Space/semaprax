//! Yield-free closed-program projections for one selected resumable function.

use super::*;
use std::collections::VecDeque;

pub(super) fn start_projection(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
    request: &ResolvedExpr,
    position: ResumableYieldPosition,
) -> Result<ResolvedFunction, Diagnostic> {
    let mut projected = function.clone();
    projected.yields = None;
    projected.return_type = request.ty.clone();
    projected.ensures.clear();
    let ResolvedExprKind::Block { statements, .. } = &function.body.kind else {
        return Err(invalid("resumable start projection requires a block body"));
    };
    let prefix_len = match position {
        ResumableYieldPosition::Statement { index, .. } => index as usize,
        ResumableYieldPosition::Tail => statements.len(),
    };
    let execution = FunctionExecutionId::Monomorphic(function.id.clone());
    let mut relocated_request = request.clone();
    relocate_expression(
        &mut relocated_request,
        &execution,
        "body.tail",
        &BTreeMap::new(),
    )?;
    projected.body = ResolvedExpr {
        id: function.body.id.clone(),
        ty: request.ty.clone(),
        ownership: OwnershipMode::Value,
        kind: ResolvedExprKind::Block {
            statements: statements[..prefix_len].to_vec(),
            tail: Box::new(relocated_request),
        },
        span: function.body.span,
    };
    rebuild_projection_plans(program, projected)
}

pub(super) fn resume_projection(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
    yield_expression: &ResolvedExpr,
    position: ResumableYieldPosition,
) -> Result<ResolvedFunction, Diagnostic> {
    let mut projected = function.clone();
    projected.yields = None;
    // The request/start projection has already replayed the prefix and checked
    // the recorded request. Running requires a second time here would double
    // the authored contract rather than resume from the checked suspension.
    projected.requires.clear();
    let execution = FunctionExecutionId::Monomorphic(function.id.clone());
    let answer_id = ValueId::parameter(&execution, projected.params.len());
    let answer = ResolvedParam {
        id: answer_id.clone(),
        name: "__semaprax_resumable_answer".to_owned(),
        ownership: OwnershipMode::Value,
        ty: yield_expression.ty.clone(),
        span: yield_expression.span,
    };
    projected.params.push(answer.clone());
    let answer_expression = ResolvedExpr {
        // The answer occupies the exact authored yield slot, so the slot's
        // canonical expression identity remains canonical after replacement.
        id: yield_expression.id.clone(),
        ty: yield_expression.ty.clone(),
        ownership: OwnershipMode::Value,
        kind: ResolvedExprKind::Place(Place {
            root: answer_id,
            projections: Vec::new(),
        }),
        span: yield_expression.span,
    };
    replace_direct_yield(&mut projected.body, position, answer_expression)?;
    rebuild_projection_plans(program, projected)
}

fn replace_direct_yield(
    body: &mut ResolvedExpr,
    position: ResumableYieldPosition,
    answer: ResolvedExpr,
) -> Result<(), Diagnostic> {
    let ResolvedExprKind::Block { statements, tail } = &mut body.kind else {
        return Err(invalid("resumable resume projection requires a block body"));
    };
    let slot = match position {
        ResumableYieldPosition::Statement { index, .. } => statements
            .get_mut(index as usize)
            .ok_or_else(|| invalid("resumable yield statement index is out of bounds"))?
            .value_mut(),
        ResumableYieldPosition::Tail => tail.as_mut(),
    };
    if !matches!(slot.kind, ResolvedExprKind::Yield { .. }) {
        return Err(invalid(
            "resumable projection position no longer names a yield expression",
        ));
    }
    *slot = answer;
    Ok(())
}

fn rebuild_projection_plans(
    program: &ResolvedProgram,
    mut function: ResolvedFunction,
) -> Result<ResolvedFunction, Diagnostic> {
    let mut projected = program.clone();
    replace_function(&mut projected, &function)?;
    function.loan_plan = crate::loan_plan::build_plan(&projected, &function)?;
    replace_function(&mut projected, &function)?;
    function.cleanup = crate::cleanup::build_inventory(&projected, &function)?;
    replace_function(&mut projected, &function)?;
    function.cleanup_plan = crate::cleanup_plan::build_plan(&projected, &function)?;
    Ok(function)
}

pub(super) fn projection_program(
    program: &ResolvedProgram,
    function_id: &DeclarationId,
    function: &ResolvedFunction,
) -> Result<ResolvedProgram, Diagnostic> {
    let mut projected = program.clone();
    replace_function(&mut projected, function)?;
    retain_closed_projection(&mut projected, program, function_id)?;
    hir::validate(&projected)?;
    Ok(projected)
}

/// Retain the original selected function's full direct-call closure and the
/// entrypoint closure required by ordinary HIR/target validation. Computing
/// from the checked source HIR, rather than the truncated start/replaced resume
/// body, makes both projections carry one identical closed function set. Source
/// order is preserved by filtering the canonical vectors in place. Generic
/// calls and function values fail closed until the resumable projection has an
/// exact instance/thunk closure builder of its own.
fn retain_closed_projection(
    projected: &mut ResolvedProgram,
    source: &ResolvedProgram,
    selected: &DeclarationId,
) -> Result<(), Diagnostic> {
    reject_non_scalar_program_surface(source)?;
    let mut retained = BTreeSet::new();
    let mut pending = VecDeque::from([source.entrypoint.clone(), selected.clone()]);

    while let Some(id) = pending.pop_front() {
        if !retained.insert(id.clone()) {
            continue;
        }
        let function = source
            .functions
            .iter()
            .find(|function| function.id == id)
            .ok_or_else(|| invalid(format!("retained projection function `{id}` is absent")))?;
        if function.yields.is_some() && function.id != *selected {
            return Err(invalid(format!(
                "retained projection closure reaches yielding function `{id}`"
            )));
        }
        reject_function_references(function)?;
        validate_retained_scalar_function(source, function)?;
        for expression in function
            .requires
            .iter()
            .chain(std::iter::once(&function.body))
            .chain(&function.ensures)
        {
            let mut error = None;
            hir::visit_resolved_calls(expression, &mut |callee, instance, _| {
                if error.is_some() {
                    return;
                }
                if instance.is_some() {
                    error = Some(invalid(format!(
                        "retained projection closure reaches generic call `{callee}`"
                    )));
                } else if callee == selected && function.id != *selected {
                    error = Some(invalid(format!(
                        "resumable function `{selected}` has retained incoming caller `{}`",
                        function.id
                    )));
                } else if source
                    .functions
                    .iter()
                    .any(|candidate| candidate.id == *callee)
                {
                    pending.push_back(callee.clone());
                } else if source
                    .function_templates
                    .iter()
                    .any(|template| template.id == *callee)
                {
                    error = Some(invalid(format!(
                        "retained projection closure reaches generic function `{callee}`"
                    )));
                }
            });
            if let Some(error) = error {
                return Err(error);
            }
        }
    }

    projected
        .functions
        .retain(|function| retained.contains(&function.id));
    projected.function_templates.clear();
    projected.function_instances.clear();
    projected
        .declarations
        .retain_resumable_projection_functions(
            &projected.functions,
            &projected.function_templates,
        )?;
    Ok(())
}

fn validate_retained_scalar_function(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
) -> Result<(), Diagnostic> {
    let declaration = program
        .declarations
        .declaration(&function.id)
        .ok_or_else(|| {
            invalid(format!(
                "retained function `{}` is not indexed",
                function.id
            ))
        })?;
    if declaration.identity_origin != IdentityOrigin::Explicit {
        return Err(invalid(format!(
            "retained scalar function `{}` lacks an explicit persistent identity",
            function.id
        )));
    }
    if !function.effects.is_empty() {
        return Err(invalid(format!(
            "retained scalar function `{}` declares ordinary effects",
            function.id
        )));
    }
    if !hir::is_scalar_resolved_type(&function.return_type)
        || function.params.iter().any(|parameter| {
            parameter.ownership != OwnershipMode::Value
                || !hir::is_scalar_resolved_type(&parameter.ty)
        })
    {
        return Err(invalid(format!(
            "retained function `{}` has a non-value Copy-scalar signature",
            function.id
        )));
    }
    for root in function
        .requires
        .iter()
        .chain(std::iter::once(&function.body))
        .chain(&function.ensures)
    {
        let mut pending = vec![root];
        while let Some(expression) = pending.pop() {
            if expression.ownership != OwnershipMode::Value
                || (expression.ty != ResolvedType::Unit
                    && !hir::is_scalar_resolved_type(&expression.ty))
            {
                return Err(invalid(format!(
                    "retained scalar function `{}` contains an expression outside the value Copy-scalar profile",
                    function.id
                )));
            }
            hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
        }
    }
    if !function.cleanup.slots.is_empty()
        || !function.cleanup.flags.is_empty()
        || !function
            .cleanup
            .entry_state
            .live_owned_parameters
            .is_empty()
        || !function
            .cleanup
            .entry_state
            .conditional_owned_parameters
            .is_empty()
    {
        return Err(invalid(format!(
            "retained scalar function `{}` carries owned cleanup state",
            function.id
        )));
    }
    Ok(())
}

/// Keep this first retained-closure tranche honest about the exact target
/// profile it can isolate. Nominal/resource declarations, interfaces and
/// capability surfaces carry correlated declarations and executable edges
/// beyond free-function calls; pruning those partially would forge a closed
/// program. They fail before any declaration-index mutation until a later
/// closure builder retains their complete dependency graph.
fn reject_non_scalar_program_surface(program: &ResolvedProgram) -> Result<(), Diagnostic> {
    if !program.permits.is_empty() {
        return Err(invalid(
            "retained scalar projection does not admit module permits",
        ));
    }
    if !program.agents.is_empty() {
        return Err(invalid(
            "retained scalar projection does not admit Agent declarations",
        ));
    }
    if program.types.iter().any(|ty| {
        program
            .declarations
            .declaration(&ty.id)
            .is_none_or(|declaration| declaration.identity_origin != IdentityOrigin::CompilerOwned)
    }) {
        return Err(invalid(
            "retained scalar projection does not admit authored nominal or resource declarations",
        ));
    }
    if !program.interfaces.is_empty() {
        return Err(invalid(
            "retained scalar projection does not admit interfaces or imports",
        ));
    }
    Ok(())
}

fn reject_function_references(function: &ResolvedFunction) -> Result<(), Diagnostic> {
    let mut pending = function
        .requires
        .iter()
        .chain(std::iter::once(&function.body))
        .chain(&function.ensures)
        .collect::<Vec<_>>();
    while let Some(expression) = pending.pop() {
        if let ResolvedExprKind::FunctionReference { target } = &expression.kind {
            return Err(invalid(format!(
                "retained projection closure reaches function reference `{target}`"
            )));
        }
        hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
    }
    Ok(())
}

fn replace_function(
    program: &mut ResolvedProgram,
    function: &ResolvedFunction,
) -> Result<(), Diagnostic> {
    let target = program
        .functions
        .iter_mut()
        .find(|candidate| candidate.id == function.id)
        .ok_or_else(|| invalid("projection target is absent while rebuilding plans"))?;
    *target = function.clone();
    Ok(())
}
