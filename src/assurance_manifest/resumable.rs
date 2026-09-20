//! Source contract ownership in the bounded compiler-generated transition plan.
//! Uses the existing manifest method vocabulary; this is not target evidence.

use std::collections::BTreeMap;
use std::path::Path;

use crate::diagnostic::Diagnostic;
use crate::hir::ResolvedProgram;
use crate::resumable_effects::lowering::lower_sequential;

use super::{obligation_id, AssuranceClass, MethodRecord, Obligation, ObligationKind};

const TOOL: &str = "semaprax-resumable-contract-placement.v1";

fn methods(program: &ResolvedProgram) -> Result<BTreeMap<String, MethodRecord>, Diagnostic> {
    let mut result = BTreeMap::new();
    for function in &program.functions {
        if function.yields.is_none()
            || (function.requires.is_empty() && function.ensures.is_empty())
        {
            continue;
        }
        let plan = lower_sequential(program, function)?;
        // Prove the closed projections can actually be built and validated;
        // a plan's state labels alone do not justify contract placement.
        plan.start_program(program)?;
        for index in 0..plan.suspensions.len() {
            plan.resume_program_at(program, index)?;
        }
        for (kind, prefix, count, role, from, to) in [
            (
                ObligationKind::Precondition,
                "require",
                function.requires.len(),
                "start",
                plan.entry.id.as_str(),
                plan.suspensions[0].state.id.as_str(),
            ),
            (
                ObligationKind::Postcondition,
                "ensure",
                function.ensures.len(),
                "final_resume",
                plan.suspensions.last().unwrap().state.id.as_str(),
                plan.complete.id.as_str(),
            ),
        ] {
            for index in 0..count {
                let mut method = MethodRecord::new(
                    AssuranceClass::RuntimeGuarded,
                    TOOL,
                    env!("CARGO_PKG_VERSION"),
                );
                method.inputs = vec![
                    function.id.as_str().to_owned(),
                    format!(
                        "plan:sha256:{:x}",
                        crate::digest_hex::LowerHex(plan.identity.as_bytes())
                    ),
                    role.to_owned(),
                    from.to_owned(),
                    to.to_owned(),
                ];
                method.bounds = Some(format!(
                    "sequential_copy_scalar_yields:{}",
                    plan.suspensions.len()
                ));
                method.runtime_fallback = true;
                method.target = Some("resumable_yield_free_projection".to_owned());
                method.detail = Some("source clause owned by this checked transition; runtime guard only; no target execution, durable runtime, handler or resume authority".to_owned());
                result.insert(
                    obligation_id(kind, function.id.as_str(), &format!("{prefix}:{index}")),
                    method,
                );
            }
        }
    }
    Ok(result)
}

pub(super) fn attach(
    program: &ResolvedProgram,
    obligations: &mut [Obligation],
) -> Result<(), Diagnostic> {
    for (id, method) in methods(program)? {
        let obligation = obligations
            .iter_mut()
            .find(|obligation| obligation.id == id)
            .ok_or_else(|| drift("resumable source contract obligation is absent"))?;
        obligation.methods.push(method);
    }
    Ok(())
}

fn drift(message: &str) -> Diagnostic {
    Diagnostic::io("SPX-Z104", message.to_owned())
}

pub(super) fn verify_source(envelope: &str, source: &str, path: &Path) -> Result<(), Diagnostic> {
    let parsed = crate::parse(source, path)?;
    let mut expected = if parsed
        .functions
        .iter()
        .any(|function| function.yields.is_some())
    {
        let program = crate::hir::resolve(&parsed)
            .map_err(|_| drift("resumable assurance source no longer resolves"))?;
        methods(&program).map_err(|_| drift("resumable assurance source no longer lowers"))?
    } else {
        BTreeMap::new()
    };
    let source_obligations = super::derive::derive_obligations(&parsed)
        .into_iter()
        .filter(|obligation| expected.contains_key(&obligation.id))
        .map(|obligation| (obligation.id.clone(), obligation))
        .collect::<BTreeMap<_, _>>();
    let value: serde_json::Value = serde_json::from_str(envelope)
        .map_err(|_| drift("resumable assurance envelope is malformed"))?;
    let obligations = value["payload"]["obligations"]
        .as_array()
        .ok_or_else(|| drift("resumable assurance obligations are absent"))?;
    for obligation in obligations {
        let id = obligation["id"].as_str().unwrap_or_default();
        let records = obligation["methods"]
            .as_array()
            .ok_or_else(|| drift("resumable assurance methods are absent"))?;
        let recorded = records
            .iter()
            .enumerate()
            .filter(|(_, method)| method["tool"].as_str() == Some(TOOL))
            .collect::<Vec<_>>();
        match expected.remove(id) {
            Some(method) => {
                let owner = source_obligations
                    .get(id)
                    .ok_or_else(|| drift("resumable source contract obligation is absent"))?;
                if obligation["declaration_id"].as_str() != Some(owner.declaration_id.as_str())
                    || obligation["kind"].as_str() != Some(owner.kind.token())
                {
                    return Err(drift(
                        "resumable contract obligation owner or kind differs from checked source",
                    ));
                }
                let canonical: serde_json::Value =
                    serde_json::from_str(&super::render::render_method(&method))
                        .map_err(|_| drift("resumable assurance method cannot render"))?;
                if recorded.len() != 1 || recorded[0].0 != 1 || recorded[0].1 != &canonical {
                    return Err(drift(
                        "resumable contract transition binding differs from checked source",
                    ));
                }
            }
            None if !recorded.is_empty() => {
                return Err(drift("unexpected resumable contract transition binding"))
            }
            None => {}
        }
    }
    if !expected.is_empty() {
        return Err(drift("resumable contract transition obligation is missing"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
