//! Deterministic compiler-owned lowering for the admitted `.spx` resumable
//! effect slice.
//!
//! This module deliberately does not widen source admission. It accepts only
//! the already-checked shape owned by `parser::yields` and
//! `hir::resolve_yield`: one direct top-level `yield`, Copy-scalar state, no
//! ordinary effects, and one explicitly identified free function. Because the
//! current projections retain the rest of the resolved program, they also
//! require this to be the program's only `yields`-declaring function. The
//! module then derives one target-neutral three-state plan and two yield-free
//! HIR projections for the interpreter and test-only backend parity lanes.

use crate::diagnostic::Diagnostic;
use crate::hir::{
    self, DeclarationId, ExpressionId, FunctionExecutionId, IdentityOrigin, OwnershipMode, Place,
    ResolvedExpr, ResolvedExprKind, ResolvedFunction, ResolvedParam, ResolvedProgram,
    ResolvedStatement, ResolvedType, ValueId,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const INVALID_RESUMABLE_PLAN: &str = "SPX-H006";
const PLAN_IDENTITY_DOMAIN: &[u8] = b"semaprax.resumable-plan.v1\0";
const SUSPENSION_BINDING_DOMAIN: &[u8] = b"semaprax.resumable-suspension-binding.v1\0";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResumablePlanIdentity([u8; 32]);

impl ResumablePlanIdentity {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResumableSuspensionBinding([u8; 32]);

impl ResumableSuspensionBinding {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact target-neutral scalar bits used to bind one suspension to the
/// invocation arguments that produced it. Floats are bits, not IEEE equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumableScalar {
    I64(i64),
    I32(i32),
    U8(u8),
    Usize(u64),
    Char(u32),
    F32(u32),
    F64(u64),
    Bool(bool),
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResumableStateId(String);

impl ResumableStateId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumableStateKind {
    Entry,
    Suspended,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumableState {
    pub id: ResumableStateId,
    pub kind: ResumableStateKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumableStatementKind {
    Let,
    Assign,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumableYieldPosition {
    Statement {
        index: u32,
        kind: ResumableStatementKind,
    },
    Tail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumableSuspension {
    pub state: ResumableState,
    pub expression: ExpressionId,
    pub request_expression: ExpressionId,
    pub position: ResumableYieldPosition,
    pub request_type: ResolvedType,
    pub response_type: ResolvedType,
}

/// One yield-free compiler projection. The function keeps the authored
/// function identity because each projection lives in its own isolated
/// `ResolvedProgram`; the enclosing [`ResumablePlan`] and its state identities
/// distinguish the entry/request and resume meanings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumableProjection {
    pub function: ResolvedFunction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumablePlan {
    pub function_id: DeclarationId,
    pub identity: ResumablePlanIdentity,
    pub entry: ResumableState,
    pub suspension: ResumableSuspension,
    pub complete: ResumableState,
    pub start: ResumableProjection,
    pub resume: ResumableProjection,
}

impl ResumablePlan {
    /// Bind a pending suspension to this exact checked program/plan, yield
    /// site, and invocation arguments. The digest is proof data only and
    /// grants no authority to answer or resume the suspension.
    pub fn suspension_binding(&self, arguments: &[ResumableScalar]) -> ResumableSuspensionBinding {
        let mut hasher = Sha256::new();
        hasher.update(SUSPENSION_BINDING_DOMAIN);
        frame(&mut hasher, self.identity.as_bytes());
        frame(&mut hasher, self.suspension.state.id.as_str().as_bytes());
        frame(&mut hasher, self.suspension.expression.as_str().as_bytes());
        hasher.update((arguments.len() as u64).to_le_bytes());
        for argument in arguments {
            hash_scalar(&mut hasher, argument);
        }
        ResumableSuspensionBinding(hasher.finalize().into())
    }

    /// Replace the authored resumable function with the yield-free request
    /// projection and validate the resulting HIR before returning it.
    pub fn start_program(&self, program: &ResolvedProgram) -> Result<ResolvedProgram, Diagnostic> {
        self.authenticate_program(program)?;
        projection_program(program, &self.function_id, &self.start.function)
    }

    /// Replace the authored resumable function with the yield-free resume
    /// projection and validate the resulting HIR before returning it.
    pub fn resume_program(&self, program: &ResolvedProgram) -> Result<ResolvedProgram, Diagnostic> {
        self.authenticate_program(program)?;
        projection_program(program, &self.function_id, &self.resume.function)
    }

    fn authenticate_program(&self, program: &ResolvedProgram) -> Result<(), Diagnostic> {
        let function = program
            .functions
            .iter()
            .find(|function| function.id == self.function_id)
            .ok_or_else(|| invalid("projection program lacks the plan's function"))?;
        let observed = plan_identity(program, function, &self.suspension.expression)?;
        if observed != self.identity {
            return Err(invalid(
                "projection program does not match the plan's checked-program identity",
            ));
        }
        let expected = lower(program, function)?;
        if expected != *self {
            return Err(invalid(
                "resumable plan is not the exact deterministic lowering of the checked program",
            ));
        }
        Ok(())
    }
}

/// Lower one already-admitted resumable function into a deterministic plan.
///
/// The checks here intentionally rederive the load-bearing profile from HIR
/// rather than trusting parser/resolver provenance. Forged nested or multiple
/// yields, non-scalar state, cleanup-bearing values, an automatic function
/// identity, or a mismatched request/response type fail closed.
pub fn lower(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
) -> Result<ResumablePlan, Diagnostic> {
    let canonical = program
        .functions
        .iter()
        .find(|candidate| candidate.id == function.id)
        .ok_or_else(|| invalid("resumable function is absent from the resolved program"))?;
    if canonical != function {
        return Err(invalid(
            "resumable function disagrees with the resolved program's canonical function",
        ));
    }
    let declaration = program
        .declarations
        .declaration(&function.id)
        .ok_or_else(|| invalid("resumable function lacks a declaration-index entry"))?;
    if declaration.identity_origin != IdentityOrigin::Explicit {
        return Err(invalid(
            "resumable function does not have an explicit persistent identity",
        ));
    }
    if program.entrypoint == function.id {
        return Err(invalid(
            "resumable projection cannot replace the program entrypoint",
        ));
    }
    let yields = function
        .yields
        .as_ref()
        .ok_or_else(|| invalid("resumable lowering requires a `yields` clause"))?;
    if !function.effects.is_empty() {
        return Err(invalid(
            "resumable lowering does not admit ordinary effects before suspension",
        ));
    }
    if !hir::is_scalar_resolved_type(&yields.request_type)
        || !hir::is_scalar_resolved_type(&yields.response_type)
        || function
            .params
            .iter()
            .any(|parameter| !hir::is_scalar_resolved_type(&parameter.ty))
    {
        return Err(invalid(
            "resumable lowering requires Copy-scalar request, response, and parameter types",
        ));
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
        return Err(invalid(
            "resumable lowering found owned cleanup state in the Copy-scalar profile",
        ));
    }

    reject_yield_in_contracts(function)?;
    let (yield_expression, request, position) = locate_single_direct_yield(function)?;
    if request.ty != yields.request_type
        || yield_expression.ty != yields.response_type
        || request.ownership != OwnershipMode::Value
        || yield_expression.ownership != OwnershipMode::Value
    {
        return Err(invalid(
            "resumable yield request/response types or ownership disagree with its declaration",
        ));
    }
    require_scalar_expression_tree(&function.body)?;
    reject_incoming_calls(program, &function.id)?;
    reject_reachable_resumable_callees(program, function)?;
    reject_other_resumable_functions(program, &function.id)?;

    let identity = plan_identity(program, function, &yield_expression.id)?;

    let entry = state(&function.id, ResumableStateKind::Entry, None);
    let suspended = state(
        &function.id,
        ResumableStateKind::Suspended,
        Some(&yield_expression.id),
    );
    let complete = state(&function.id, ResumableStateKind::Complete, None);
    let start = start_projection(program, function, request, position)?;
    let resume = resume_projection(program, function, yield_expression, position)?;

    Ok(ResumablePlan {
        function_id: function.id.clone(),
        identity,
        entry,
        suspension: ResumableSuspension {
            state: suspended,
            expression: yield_expression.id.clone(),
            request_expression: request.id.clone(),
            position,
            request_type: yields.request_type.clone(),
            response_type: yields.response_type.clone(),
        },
        complete,
        start: ResumableProjection { function: start },
        resume: ResumableProjection { function: resume },
    })
}

/// The projection currently replaces one function inside an otherwise exact
/// program clone. Any second `yields` function would therefore reach the
/// ordinary native/Wasm admission gate even when disconnected from the
/// selected call closure. Refuse that whole-program shape until projection
/// isolation can retain and validate an exact closed declaration index.
fn reject_other_resumable_functions(
    program: &ResolvedProgram,
    selected: &DeclarationId,
) -> Result<(), Diagnostic> {
    if let Some(other) = program
        .functions
        .iter()
        .find(|function| function.id != *selected && function.yields.is_some())
    {
        return Err(invalid(format!(
            "resumable projection requires exactly one yielding function in the whole program; additional function `{}` declares `yields`",
            other.id
        )));
    }
    if let Some(other) = program
        .function_instances
        .iter()
        .find(|instance| instance.function.yields.is_some())
    {
        return Err(invalid(format!(
            "resumable projection requires exactly one yielding function in the whole program; generic instance `{}` also declares `yields`",
            other.id.as_str()
        )));
    }
    Ok(())
}

fn plan_identity(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
    yield_expression: &ExpressionId,
) -> Result<ResumablePlanIdentity, Diagnostic> {
    let encoded = crate::cache_codec::encode(program).map_err(|diagnostics| {
        diagnostics
            .into_iter()
            .next()
            .unwrap_or_else(|| invalid("checked-program encoding failed without a diagnostic"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(PLAN_IDENTITY_DOMAIN);
    frame(&mut hasher, &encoded);
    frame(&mut hasher, function.id.as_str().as_bytes());
    frame(&mut hasher, yield_expression.as_str().as_bytes());
    Ok(ResumablePlanIdentity(hasher.finalize().into()))
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_scalar(hasher: &mut Sha256, value: &ResumableScalar) {
    match value {
        ResumableScalar::I64(value) => {
            hasher.update([0u8]);
            hasher.update(value.to_le_bytes());
        }
        ResumableScalar::I32(value) => {
            hasher.update([1u8]);
            hasher.update(value.to_le_bytes());
        }
        ResumableScalar::U8(value) => hasher.update([2u8, *value]),
        ResumableScalar::Usize(value) => {
            hasher.update([3u8]);
            hasher.update(value.to_le_bytes());
        }
        ResumableScalar::Char(value) => {
            hasher.update([4u8]);
            hasher.update(value.to_le_bytes());
        }
        ResumableScalar::F32(bits) => {
            hasher.update([5u8]);
            hasher.update(bits.to_le_bytes());
        }
        ResumableScalar::F64(bits) => {
            hasher.update([6u8]);
            hasher.update(bits.to_le_bytes());
        }
        ResumableScalar::Bool(value) => hasher.update([7u8, u8::from(*value)]),
    }
}

fn reject_incoming_calls(
    program: &ResolvedProgram,
    function_id: &DeclarationId,
) -> Result<(), Diagnostic> {
    for caller in program
        .functions
        .iter()
        .filter(|caller| caller.id != *function_id)
    {
        if function_calls(caller, function_id) {
            return Err(invalid(format!(
                "resumable function `{function_id}` has incoming call from `{}`; isolated projection requires no callers",
                caller.id
            )));
        }
    }
    for instance in &program.function_instances {
        if function_calls(&instance.function, function_id) {
            return Err(invalid(format!(
                "resumable function `{function_id}` has incoming call from generic instance `{}`",
                instance.id.as_str()
            )));
        }
    }
    for template in &program.function_templates {
        if expressions_call(
            template
                .requires
                .iter()
                .chain(std::iter::once(&template.body))
                .chain(&template.ensures),
            function_id,
        ) {
            return Err(invalid(format!(
                "resumable function `{function_id}` has incoming call from generic template `{}`",
                template.id
            )));
        }
    }
    Ok(())
}

fn reject_reachable_resumable_callees(
    program: &ResolvedProgram,
    entry: &ResolvedFunction,
) -> Result<(), Diagnostic> {
    let mut visited = BTreeSet::new();
    let mut pending = vec![entry.id.clone()];
    while let Some(function_id) = pending.pop() {
        if !visited.insert(function_id.clone()) {
            continue;
        }
        let function = program
            .functions
            .iter()
            .find(|function| function.id == function_id)
            .ok_or_else(|| invalid(format!("reachable function `{function_id}` is absent")))?;
        for callee in called_functions(function)? {
            let resolved = program
                .functions
                .iter()
                .find(|candidate| candidate.id == callee)
                .ok_or_else(|| invalid(format!("reachable callee `{callee}` is absent")))?;
            if resolved.yields.is_some() {
                return Err(invalid(format!(
                    "resumable function `{}` reaches yielding callee `{callee}`; yield propagation is not admitted",
                    entry.id
                )));
            }
            pending.push(callee);
        }
    }
    Ok(())
}

fn function_calls(function: &ResolvedFunction, target: &DeclarationId) -> bool {
    expressions_call(
        function
            .requires
            .iter()
            .chain(std::iter::once(&function.body))
            .chain(&function.ensures),
        target,
    )
}

fn expressions_call<'a>(
    expressions: impl Iterator<Item = &'a ResolvedExpr>,
    target: &DeclarationId,
) -> bool {
    let mut pending = expressions.collect::<Vec<_>>();
    while let Some(expression) = pending.pop() {
        if matches!(&expression.kind, ResolvedExprKind::Call { callee, .. } if callee == target)
            || matches!(&expression.kind, ResolvedExprKind::FunctionReference { target: reference } if reference == target)
        {
            return true;
        }
        hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
    }
    false
}

fn called_functions(function: &ResolvedFunction) -> Result<Vec<DeclarationId>, Diagnostic> {
    let mut callees = Vec::new();
    let mut pending = function
        .requires
        .iter()
        .chain(std::iter::once(&function.body))
        .chain(&function.ensures)
        .collect::<Vec<_>>();
    while let Some(expression) = pending.pop() {
        if let ResolvedExprKind::Call {
            callee, instance, ..
        } = &expression.kind
        {
            if instance.is_some() {
                return Err(invalid(format!(
                    "resumable function reaches generic callee `{callee}`; generic call projection is not admitted"
                )));
            }
            callees.push(callee.clone());
        }
        hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
    }
    Ok(callees)
}

fn state(
    function: &DeclarationId,
    kind: ResumableStateKind,
    expression: Option<&ExpressionId>,
) -> ResumableState {
    let function = function.as_str();
    let kind_text = match kind {
        ResumableStateKind::Entry => "entry",
        ResumableStateKind::Suspended => "suspended",
        ResumableStateKind::Complete => "complete",
    };
    let mut identity = format!(
        "semaprax.resumable-state.v1|{}:{}|{}",
        function.len(),
        function,
        kind_text
    );
    if let Some(expression) = expression {
        identity.push('|');
        identity.push_str(&expression.as_str().len().to_string());
        identity.push(':');
        identity.push_str(expression.as_str());
    }
    ResumableState {
        id: ResumableStateId(identity),
        kind,
    }
}

fn locate_single_direct_yield<'a>(
    function: &'a ResolvedFunction,
) -> Result<(&'a ResolvedExpr, &'a ResolvedExpr, ResumableYieldPosition), Diagnostic> {
    let mut all_yields = Vec::new();
    let mut pending = vec![&function.body];
    while let Some(expression) = pending.pop() {
        if let ResolvedExprKind::Yield { .. } = expression.kind {
            all_yields.push(expression);
        }
        hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
    }
    if all_yields.len() != 1 {
        return Err(invalid(format!(
            "resumable lowering requires exactly one yield; found {}",
            all_yields.len()
        )));
    }

    let ResolvedExprKind::Block { statements, tail } = &function.body.kind else {
        return Err(invalid(
            "resumable function body is not its expected top-level block",
        ));
    };
    let mut direct = None;
    for (index, statement) in statements.iter().enumerate() {
        let (value, kind) = match statement {
            ResolvedStatement::Let { value, .. } => (value, ResumableStatementKind::Let),
            ResolvedStatement::Assign { value, .. } => (value, ResumableStatementKind::Assign),
            ResolvedStatement::Unsafe { .. } | ResolvedStatement::While { .. } => continue,
        };
        if let ResolvedExprKind::Yield { request } = &value.kind {
            let index = u32::try_from(index)
                .map_err(|_| invalid("resumable statement index exceeds u32"))?;
            direct = Some((
                value,
                request.as_ref(),
                ResumableYieldPosition::Statement { index, kind },
            ));
        }
    }
    if let ResolvedExprKind::Yield { request } = &tail.kind {
        direct = Some((
            tail.as_ref(),
            request.as_ref(),
            ResumableYieldPosition::Tail,
        ));
    }
    let Some(direct) = direct else {
        return Err(invalid(
            "resumable yield is nested instead of occupying one direct top-level slot",
        ));
    };
    if direct.0.id != all_yields[0].id {
        return Err(invalid(
            "resumable direct yield does not equal the function's sole yield expression",
        ));
    }
    Ok(direct)
}

fn reject_yield_in_contracts(function: &ResolvedFunction) -> Result<(), Diagnostic> {
    for expression in function.requires.iter().chain(function.ensures.iter()) {
        let mut pending = vec![expression];
        while let Some(expression) = pending.pop() {
            if matches!(expression.kind, ResolvedExprKind::Yield { .. }) {
                return Err(invalid(
                    "resumable lowering found `yield` in a contract expression",
                ));
            }
            hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
        }
    }
    Ok(())
}

fn require_scalar_expression_tree(root: &ResolvedExpr) -> Result<(), Diagnostic> {
    let mut pending = vec![root];
    while let Some(expression) = pending.pop() {
        if expression.ty != ResolvedType::Unit && !hir::is_scalar_resolved_type(&expression.ty) {
            return Err(invalid(
                "resumable lowering found a non-scalar intermediate value",
            ));
        }
        hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
    }
    Ok(())
}

/// Move one already-resolved expression to a new canonical path inside the
/// same function. Expression identities are structural, so cloning a request
/// from `yield.request` into the start projection's tail must rederive every
/// nested identity. Locals introduced inside the moved subtree are rederived
/// with the same scope rules; references to parameters and outer-prefix
/// locals deliberately retain their existing identities.
fn relocate_expression(
    expression: &mut ResolvedExpr,
    execution: &FunctionExecutionId,
    path: &str,
    values: &BTreeMap<ValueId, ValueId>,
) -> Result<(), Diagnostic> {
    expression.id = ExpressionId::new(execution, path);
    let expression_id = expression.id.clone();
    match &mut expression.kind {
        ResolvedExprKind::Closure { .. } => {
            return Err(invalid(
                "resumable projection cannot relocate a closure expression",
            ));
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
        | ResolvedExprKind::String(_) => {}
        ResolvedExprKind::Invoke { callable, args } => {
            relocate_expression(callable, execution, &format!("{path}.callable"), values)?;
            relocate_arguments(args, execution, path, "arg", values)?;
        }
        ResolvedExprKind::Place(place) | ResolvedExprKind::BorrowPlace { place, .. } => {
            remap_place(place, values);
        }
        ResolvedExprKind::ByteRange {
            source, start, end, ..
        } => {
            relocate_expression(source, execution, &format!("{path}.arg.0"), values)?;
            relocate_expression(start, execution, &format!("{path}.arg.1"), values)?;
            relocate_expression(end, execution, &format!("{path}.arg.2"), values)?;
        }
        ResolvedExprKind::Call { args, .. } => {
            relocate_arguments(args, execution, path, "arg", values)?;
        }
        ResolvedExprKind::NativeRustImportCall(call) => {
            call.expression = expression_id;
            relocate_arguments(&mut call.args, execution, path, "native-rust-arg", values)?;
        }
        ResolvedExprKind::HostCommandCall(call) => {
            call.expression = expression_id;
            relocate_arguments(&mut call.args, execution, path, "arg", values)?;
        }
        ResolvedExprKind::Unary { value, .. } => {
            relocate_expression(value, execution, &format!("{path}.value"), values)?;
        }
        ResolvedExprKind::Binary { left, right, .. } => {
            relocate_expression(left, execution, &format!("{path}.left"), values)?;
            relocate_expression(right, execution, &format!("{path}.right"), values)?;
        }
        ResolvedExprKind::Block { statements, tail } => {
            let mut block_values = values.clone();
            for (index, statement) in statements.iter_mut().enumerate() {
                let statement_path = format!("{path}.s{index}");
                match statement {
                    ResolvedStatement::Let { binding, value, .. } => {
                        relocate_expression(
                            value,
                            execution,
                            &format!("{statement_path}.value"),
                            &block_values,
                        )?;
                        let previous = binding.id.clone();
                        binding.id = ValueId::local(execution, &statement_path);
                        block_values.insert(previous, binding.id.clone());
                    }
                    ResolvedStatement::Assign { binding, value, .. } => {
                        remap_binding(binding, &block_values);
                        relocate_expression(
                            value,
                            execution,
                            &format!("{statement_path}.value"),
                            &block_values,
                        )?;
                    }
                    ResolvedStatement::Unsafe { body, .. } => relocate_expression(
                        body,
                        execution,
                        &format!("{statement_path}.body"),
                        &block_values,
                    )?,
                    ResolvedStatement::While {
                        condition, body, ..
                    } => {
                        relocate_expression(
                            condition,
                            execution,
                            &format!("{statement_path}.condition"),
                            &block_values,
                        )?;
                        relocate_expression(
                            body,
                            execution,
                            &format!("{statement_path}.body"),
                            &block_values,
                        )?;
                    }
                }
            }
            relocate_expression(tail, execution, &format!("{path}.tail"), &block_values)?;
        }
        ResolvedExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            relocate_expression(condition, execution, &format!("{path}.condition"), values)?;
            relocate_expression(then_branch, execution, &format!("{path}.then"), values)?;
            relocate_expression(else_branch, execution, &format!("{path}.else"), values)?;
        }
        ResolvedExprKind::ConstructRecord { fields, .. }
        | ResolvedExprKind::ConstructVariant { fields, .. } => {
            relocate_fields(fields, execution, path, values)?;
        }
        ResolvedExprKind::Match {
            scrutinee, arms, ..
        } => {
            relocate_expression(scrutinee, execution, &format!("{path}.scrutinee"), values)?;
            for (index, arm) in arms.iter_mut().enumerate() {
                let arm_path = format!("{path}.arm.{index}");
                let mut arm_values = values.clone();
                relocate_pattern(&mut arm.pattern, execution, &arm_path, &mut arm_values);
                if let Some(guard) = &mut arm.guard {
                    relocate_expression(
                        guard,
                        execution,
                        &format!("{arm_path}.guard"),
                        &arm_values,
                    )?;
                }
                relocate_expression(
                    &mut arm.value,
                    execution,
                    &format!("{arm_path}.value"),
                    &arm_values,
                )?;
            }
        }
        ResolvedExprKind::Try { operand, .. } | ResolvedExprKind::TryOption { operand, .. } => {
            relocate_expression(operand, execution, &format!("{path}.operand"), values)?;
        }
        ResolvedExprKind::UpdateRecord { base, fields, .. } => {
            relocate_expression(base, execution, &format!("{path}.base"), values)?;
            relocate_fields(fields, execution, path, values)?;
        }
        ResolvedExprKind::Project { base, .. } => {
            relocate_expression(base, execution, &format!("{path}.base"), values)?;
        }
        ResolvedExprKind::Upcast { source } => {
            relocate_expression(source, execution, &format!("{path}.source"), values)?;
        }
        ResolvedExprKind::Yield { .. } => {
            return Err(invalid(
                "resumable request relocation found a nested yield expression",
            ));
        }
    }
    Ok(())
}

fn relocate_arguments(
    arguments: &mut [ResolvedExpr],
    execution: &FunctionExecutionId,
    path: &str,
    segment: &str,
    values: &BTreeMap<ValueId, ValueId>,
) -> Result<(), Diagnostic> {
    for (index, argument) in arguments.iter_mut().enumerate() {
        relocate_expression(
            argument,
            execution,
            &format!("{path}.{segment}.{index}"),
            values,
        )?;
    }
    Ok(())
}

fn relocate_fields(
    fields: &mut [hir::ResolvedFieldInitializer],
    execution: &FunctionExecutionId,
    path: &str,
    values: &BTreeMap<ValueId, ValueId>,
) -> Result<(), Diagnostic> {
    for (index, field) in fields.iter_mut().enumerate() {
        relocate_expression(
            &mut field.value,
            execution,
            &format!("{path}.field.{index}.value"),
            values,
        )?;
    }
    Ok(())
}

fn remap_place(place: &mut Place, values: &BTreeMap<ValueId, ValueId>) {
    if let Some(mapped) = values.get(&place.root) {
        place.root = mapped.clone();
    }
}

fn remap_binding(binding: &mut hir::ResolvedBinding, values: &BTreeMap<ValueId, ValueId>) {
    if let Some(mapped) = values.get(&binding.id) {
        binding.id = mapped.clone();
    }
}

fn relocate_pattern(
    pattern: &mut hir::ResolvedMatchPattern,
    execution: &FunctionExecutionId,
    path: &str,
    values: &mut BTreeMap<ValueId, ValueId>,
) {
    match pattern {
        hir::ResolvedMatchPattern::Variant { fields, .. } => {
            for (index, field) in fields.iter_mut().enumerate() {
                let previous = field.binding.id.clone();
                field.binding.id = ValueId::local(execution, &format!("{path}.binding.{index}"));
                values.insert(previous, field.binding.id.clone());
            }
        }
        hir::ResolvedMatchPattern::Record { fields, .. } => {
            relocate_record_pattern_fields(fields, execution, &format!("{path}.record"), values);
        }
        hir::ResolvedMatchPattern::Binding(binding) => {
            let previous = binding.id.clone();
            binding.id = ValueId::local(execution, &format!("{path}.binding"));
            values.insert(previous, binding.id.clone());
        }
        hir::ResolvedMatchPattern::Wildcard
        | hir::ResolvedMatchPattern::Literal(_)
        | hir::ResolvedMatchPattern::Or(_) => {}
    }
}

fn relocate_record_pattern_fields(
    fields: &mut [hir::ResolvedRecordMatchPatternField],
    execution: &FunctionExecutionId,
    path: &str,
    values: &mut BTreeMap<ValueId, ValueId>,
) {
    for (index, field) in fields.iter_mut().enumerate() {
        let field_path = format!("{path}.field.{index}");
        match &mut field.pattern {
            hir::ResolvedRecordMatchFieldPattern::Binding(binding) => {
                let previous = binding.id.clone();
                binding.id = ValueId::local(execution, &format!("{field_path}.binding"));
                values.insert(previous, binding.id.clone());
            }
            hir::ResolvedRecordMatchFieldPattern::Record { fields, .. } => {
                relocate_record_pattern_fields(
                    fields,
                    execution,
                    &format!("{field_path}.record"),
                    values,
                );
            }
            hir::ResolvedRecordMatchFieldPattern::Wildcard => {}
        }
    }
}

fn start_projection(
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

fn resume_projection(
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

fn projection_program(
    program: &ResolvedProgram,
    function_id: &DeclarationId,
    function: &ResolvedFunction,
) -> Result<ResolvedProgram, Diagnostic> {
    let mut projected = program.clone();
    let target = projected
        .functions
        .iter_mut()
        .find(|candidate| candidate.id == *function_id)
        .ok_or_else(|| invalid("projection target is absent from the resolved program"))?;
    *target = function.clone();
    hir::validate(&projected)?;
    Ok(projected)
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

fn invalid(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(
        INVALID_RESUMABLE_PLAN,
        format!("invalid resumable HIR plan: {}", message.into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SOURCE: &str = r#"
module test.resumable_lowering;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let before = seed + 1;
    let answer = yield before;
    answer * 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;

    fn program(source: &str) -> ResolvedProgram {
        let ast = crate::parse(source, Path::new("resumable-lowering.spx")).unwrap();
        hir::resolve(&ast).unwrap()
    }

    fn plan(program: &ResolvedProgram) -> ResumablePlan {
        let function = program
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        lower(program, function).unwrap()
    }

    #[test]
    fn lowering_is_deterministic_and_both_projections_are_yield_free() {
        let program = program(SOURCE);
        let first = plan(&program);
        let second = plan(&program);
        assert_eq!(first, second);
        assert_eq!(first.entry.kind, ResumableStateKind::Entry);
        assert_eq!(first.suspension.state.kind, ResumableStateKind::Suspended);
        assert_eq!(first.complete.kind, ResumableStateKind::Complete);
        assert!(first
            .entry
            .id
            .as_str()
            .starts_with("semaprax.resumable-state.v1|"));
        assert_ne!(first.entry.id, first.suspension.state.id);
        assert_ne!(first.suspension.state.id, first.complete.id);
        assert!(matches!(
            first.suspension.position,
            ResumableYieldPosition::Statement {
                index: 1,
                kind: ResumableStatementKind::Let
            }
        ));

        let start = first.start_program(&program).unwrap();
        let resume = first.resume_program(&program).unwrap();
        for projected in [&start, &resume] {
            let function = projected
                .functions
                .iter()
                .find(|function| function.id.as_str() == "app.ask")
                .unwrap();
            assert!(function.yields.is_none());
            let mut pending = vec![&function.body];
            while let Some(expression) = pending.pop() {
                assert!(!matches!(expression.kind, ResolvedExprKind::Yield { .. }));
                hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
            }
        }
        let start = start
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        assert_eq!(start.params.len(), 1);
        assert_eq!(start.return_type, ResolvedType::I64);
        assert!(start.ensures.is_empty());
        let resume = resume
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        assert_eq!(resume.params.len(), 2);
        assert_eq!(resume.params[1].name, "__semaprax_resumable_answer");
        assert!(resume.requires.is_empty());
    }

    #[test]
    fn request_relocation_rederives_nested_block_branch_and_local_identities() {
        let source = r#"
module test.resumable_nested_request;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let answer = yield {
        let local = seed + 1;
        if local > 1 { local } else { seed }
    };
    answer * 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let program = program(source);
        let plan = plan(&program);
        let start = plan.start_program(&program).unwrap();
        let resume = plan.resume_program(&program).unwrap();
        hir::validate(&start).unwrap();
        hir::validate(&resume).unwrap();
    }

    #[test]
    fn projection_validation_and_plan_authentication_reject_identity_or_meaning_mutation() {
        let program = program(SOURCE);
        let plan = plan(&program);

        let mut invalid_identity = plan.start_program(&program).unwrap();
        let function = invalid_identity
            .functions
            .iter_mut()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        let ResolvedExprKind::Block { tail, .. } = &mut function.body.kind else {
            panic!("projection body is a block")
        };
        tail.id = plan.suspension.request_expression.clone();
        let error = hir::validate(&invalid_identity).unwrap_err();
        assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
        assert!(error.message.contains("non-canonical identity"));

        let mut forged_plan = plan.clone();
        let ResolvedExprKind::Block { tail, .. } = &mut forged_plan.start.function.body.kind else {
            panic!("projection body is a block")
        };
        tail.kind = ResolvedExprKind::Int(99);
        let error = forged_plan.start_program(&program).unwrap_err();
        assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
        assert!(error.message.contains("exact deterministic lowering"));
    }

    #[test]
    fn display_renames_preserve_the_compiler_owned_state_identities() {
        let renamed = SOURCE
            .replace("fn ask(seed: i64)", "fn question(input: i64)")
            .replace("let before = seed + 1", "let request = input + 1")
            .replace("let answer = yield before", "let reply = yield request")
            .replace("answer * 2", "reply * 2");
        let before = plan(&program(SOURCE));
        let after = plan(&program(&renamed));
        assert_eq!(before.entry.id, after.entry.id);
        assert_eq!(before.suspension.state.id, after.suspension.state.id);
        assert_eq!(before.complete.id, after.complete.id);
    }

    #[test]
    fn a_forged_second_or_nested_yield_is_rejected_by_lowering_itself() {
        let mut program = program(SOURCE);
        {
            let function = program
                .functions
                .iter_mut()
                .find(|function| function.id.as_str() == "app.ask")
                .unwrap();
            let ResolvedExprKind::Block { statements, tail } = &mut function.body.kind else {
                panic!("fixture body is a block")
            };
            let ResolvedStatement::Let { value, .. } = &statements[1] else {
                panic!("fixture yield is a let value")
            };
            *tail = Box::new(value.clone());
        }
        let function = program
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        let error = lower(&program, function).unwrap_err();
        assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
        assert!(error.message.contains("exactly one yield"));
    }

    #[test]
    fn length_framed_state_ids_do_not_alias_punctuation_in_identifiers() {
        let expression = ExpressionId::new(
            &FunctionExecutionId::Monomorphic(DeclarationId::new("b")),
            "yield",
        );
        let left = state(
            &DeclarationId::new("a|1:b"),
            ResumableStateKind::Suspended,
            Some(&expression),
        );
        let right = state(
            &DeclarationId::new("a"),
            ResumableStateKind::Suspended,
            Some(&expression),
        );
        assert_ne!(left.id, right.id);
    }

    #[test]
    fn reachable_yielding_callees_are_rejected_before_projection() {
        let source = r#"
module test.resumable_yielding_callee;
@id("app.inner")
fn inner(seed: i64) -> i64
    yields i64 -> i64
{
    let answer = yield seed;
    answer
}
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let from_inner = inner(seed);
    let answer = yield from_inner;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
        let program = program(source);
        let function = program
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        let error = lower(&program, function).unwrap_err();
        assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
        assert!(error.message.contains("yielding callee `app.inner`"));
    }

    #[test]
    fn disconnected_second_yielding_function_is_rejected_before_projection() {
        let source = r#"
module test.resumable_disconnected;
@id("app.other")
fn other(seed: i64) -> i64
    yields i64 -> i64
{
    let answer = yield seed;
    answer
}
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
        let program = program(source);
        let function = program
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        let error = lower(&program, function).unwrap_err();
        assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
        assert!(error.message.contains("additional function `app.other`"));
    }

    #[test]
    fn projection_rejects_an_incoming_caller_before_signature_replacement() {
        let source = SOURCE.replace("fn main() -> i64 { 0 }", "fn main() -> i64 { ask(0) }");
        let program = program(&source);
        let function = program
            .functions
            .iter()
            .find(|function| function.id.as_str() == "app.ask")
            .unwrap();
        let error = lower(&program, function).unwrap_err();
        assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
        assert!(error.message.contains("incoming call from `app.main`"));
    }

    #[test]
    fn suspension_binding_commits_program_meaning_site_and_exact_argument_bits() {
        let first_program = program(SOURCE);
        let first = plan(&first_program);
        let changed_program = program(&SOURCE.replace("answer * 2", "answer * 3"));
        let changed = plan(&changed_program);
        assert_eq!(first.suspension.state.id, changed.suspension.state.id);
        assert_ne!(first.identity, changed.identity);

        let one = first.suspension_binding(&[ResumableScalar::I64(1)]);
        let two = first.suspension_binding(&[ResumableScalar::I64(2)]);
        let other_program = changed.suspension_binding(&[ResumableScalar::I64(1)]);
        assert_ne!(one, two);
        assert_ne!(one, other_program);
        let error = first.start_program(&changed_program).unwrap_err();
        assert!(error.message.contains("checked-program identity"));
        assert_ne!(
            first.suspension_binding(&[ResumableScalar::F64((-0.0f64).to_bits())]),
            first.suspension_binding(&[ResumableScalar::F64(0.0f64.to_bits())])
        );
    }
}
