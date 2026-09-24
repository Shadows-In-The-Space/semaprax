use super::*;

pub(super) fn refusal() -> Diagnostic {
    backend_error("authenticated-native-allocating.v1 requires a closed checked Bytes body, bounded direct callees and literal boolean contracts")
}

pub(super) fn check(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
) -> Result<(), Diagnostic> {
    let mut active = BTreeSet::new();
    let mut remaining = 65_536;
    if function_body(
        program,
        function,
        &function.params[0].ty,
        &mut active,
        0,
        &mut remaining,
    ) {
        Ok(())
    } else {
        Err(refusal())
    }
}

fn admitted_type(ty: &ResolvedType, record: &ResolvedType) -> bool {
    ty == record
        || matches!(
            ty,
            ResolvedType::Unit
                | ResolvedType::I64
                | ResolvedType::I32
                | ResolvedType::Char
                | ResolvedType::U8
                | ResolvedType::Usize
                | ResolvedType::F32
                | ResolvedType::F64
                | ResolvedType::Bool
                | ResolvedType::ArrayU8(_)
                | ResolvedType::SliceU8
                | ResolvedType::Bytes
        )
}

fn function_body(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
    record: &ResolvedType,
    active: &mut BTreeSet<DeclarationId>,
    depth: usize,
    remaining: &mut usize,
) -> bool {
    if depth > 64
        || !function.effects.is_empty()
        || function.yields.is_some()
        || !admitted_type(&function.return_type, record)
        || function
            .params
            .iter()
            .any(|param| !admitted_type(&param.ty, record))
        || function
            .requires
            .iter()
            .chain(&function.ensures)
            .any(|guard| !matches!(guard.kind, ResolvedExprKind::Bool(_)))
        || !active.insert(function.id.clone())
    {
        return false;
    }
    let roots = function
        .params
        .iter()
        .map(|param| param.id.clone())
        .collect();
    let valid = expression(
        program,
        &function.body,
        record,
        &roots,
        active,
        depth + 1,
        remaining,
    );
    active.remove(&function.id);
    valid
}

fn expression(
    program: &ResolvedProgram,
    value: &ResolvedExpr,
    record: &ResolvedType,
    roots: &BTreeSet<ValueId>,
    active: &mut BTreeSet<DeclarationId>,
    depth: usize,
    remaining: &mut usize,
) -> bool {
    // Also bound repeated expansion of a shared direct-call DAG; a depth
    // bound alone would still permit exponential admission work.
    if *remaining == 0 || depth > 128 || !admitted_type(&value.ty, record) {
        return false;
    }
    *remaining -= 1;
    let mut child = |value| expression(program, value, record, roots, active, depth + 1, remaining);
    match &value.kind {
        ResolvedExprKind::Place(place) => roots.contains(&place.root),
        ResolvedExprKind::BorrowPlace { operation, place } => {
            matches!(
                operation.as_str(),
                crate::byte_ops::BYTES_AS_SLICE_ID | crate::byte_ops::ARRAY_AS_SLICE_ID
            ) && roots.contains(&place.root)
        }
        ResolvedExprKind::Int(_)
        | ResolvedExprKind::Int32(_)
        | ResolvedExprKind::Char(_)
        | ResolvedExprKind::Uint8(_)
        | ResolvedExprKind::Usize(_)
        | ResolvedExprKind::Bool(_)
        | ResolvedExprKind::Float32(_)
        | ResolvedExprKind::Float64(_)
        | ResolvedExprKind::ArrayU8(_)
        | ResolvedExprKind::RepeatArrayU8 { .. } => true,
        ResolvedExprKind::Unary { value, .. } | ResolvedExprKind::Project { base: value, .. } => {
            child(value)
        }
        ResolvedExprKind::Binary { left, right, .. } => child(left) && child(right),
        ResolvedExprKind::ByteRange {
            source, start, end, ..
        } => child(source) && child(start) && child(end),
        ResolvedExprKind::ConstructRecord { fields, .. } => {
            fields.iter().all(|field| child(&field.value))
        }
        ResolvedExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => child(condition) && child(then_branch) && child(else_branch),
        ResolvedExprKind::Block { statements, tail } => {
            let mut locals = roots.clone();
            for statement in statements {
                let hir::ResolvedStatement::Let {
                    mutable: false,
                    binding,
                    value,
                    ..
                } = statement
                else {
                    return false;
                };
                if !admitted_type(&binding.ty, record)
                    || !expression(
                        program,
                        value,
                        record,
                        &locals,
                        active,
                        depth + 1,
                        remaining,
                    )
                    || !locals.insert(binding.id.clone())
                {
                    return false;
                }
            }
            expression(program, tail, record, &locals, active, depth + 1, remaining)
        }
        ResolvedExprKind::Call {
            callee,
            instance,
            args,
            ..
        } => {
            if !args.iter().all(child) {
                return false;
            }
            // Independent local invariant, even though HIR validation also
            // enforces the literal-capacity language rule.
            if callee.as_str() == crate::byte_ops::ZEROED_ID {
                return matches!(args.as_slice(), [ResolvedExpr { kind: ResolvedExprKind::Usize(count), .. }]
                    if *count <= crate::byte_ops::MAX_OWNED_BYTE_VALUE_BYTES);
            }
            if matches!(
                callee.as_str(),
                crate::byte_ops::LEN_ID | crate::byte_ops::COPY_ID | crate::byte_ops::SET_ID
            ) {
                true
            } else {
                program
                    .resolve_call_target(callee, instance.as_ref())
                    .is_some_and(|function| {
                        function_body(program, function, record, active, depth + 1, remaining)
                    })
            }
        }
        _ => false,
    }
}
