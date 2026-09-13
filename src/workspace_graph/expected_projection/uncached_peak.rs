//! Final pre-bound for a core that does not retain staged synthetic ASTs.
use std::collections::BTreeMap;

use crate::ast::Program;
use crate::diagnostic::Diagnostic;

use super::{
    active_builder_limit, checked_retention_prebound_with_uncached_peak, checked_usage, cost,
    dependency_identity_max, limit_error, retention_prebound_mode, synthetic_builder_bytes_scoped,
    AuthoredDeclaration,
};

/// Mode six retains a filtered module and compact cross-module proof after
/// each resolution.  Its peak is the already-retained output/proof plus one
/// complete synthetic AST/HIR, never every complete resolved program.
pub(in crate::workspace_graph) fn uncached_output_peak_prebound(
    programs: &[Program],
    authored: &BTreeMap<&str, AuthoredDeclaration<'_>>,
) -> Result<(usize, usize), Vec<Diagnostic>> {
    let mut retained_output = 0usize;
    let mut validation = 0usize;
    let mut peak = 0usize;
    for program in programs {
        let maximum = Some(dependency_identity_max(program, authored, programs)?);
        let full = synthetic_builder_bytes_scoped(program, authored, programs, maximum, 4)?;
        let mut owned = program.clone();
        owned.module_uses.clear();
        let retained = synthetic_builder_bytes_scoped(&owned, authored, programs, maximum, 4)?;
        let live = checked_usage(
            checked_usage(
                retained_output,
                validation,
                "builder_bytes",
                active_builder_limit(),
            )?,
            checked_usage(
                full.retained_hir,
                full.synthetic_ast,
                "builder_bytes",
                active_builder_limit(),
            )?,
            "builder_bytes",
            active_builder_limit(),
        )?;
        peak = peak.max(live);
        // The compact index carries no bodies/contracts.  Its source-shaped
        // carrier is bounded by the full synthetic AST it projects from; the
        // live builder separately reserves each exact output/index entry.
        validation = checked_usage(
            validation,
            full.synthetic_ast,
            "builder_bytes",
            active_builder_limit(),
        )?;
        retained_output = checked_usage(
            retained_output,
            retained.retained_hir,
            "builder_bytes",
            active_builder_limit(),
        )?;
    }
    let total = peak.max(checked_usage(
        retained_output,
        validation,
        "builder_bytes",
        active_builder_limit(),
    )?);
    Ok((total, total))
}

/// Select the only receipt a core without a retained frontend may use.
pub(in crate::workspace_graph) fn initial_core_prebound(
    programs: &[Program],
    authored: &BTreeMap<&str, AuthoredDeclaration<'_>>,
    frontend_is_absent: bool,
) -> Result<(usize, usize, bool), Vec<Diagnostic>> {
    let receipt =
        match checked_retention_prebound_with_uncached_peak(programs, authored, frontend_is_absent)
        {
            Ok(receipt) => receipt,
            Err(errors) if frontend_is_absent && cost::is_builder_refusal(&errors) => {
                uncached_output_peak_prebound(programs, authored)?
            }
            Err(errors) => return Err(errors),
        };
    Ok((receipt.0, receipt.1, frontend_is_absent))
}

// The builder limit scopes the `with_limit_usage` core attempt, after
// `build_owned_inner` has parsed and retained the authored `programs`; that
// pre-existing AST is deliberately outside this phase's receipt. This receipt
// starts at `build_resolved_core`: every uncached synthetic AST is dropped
// after its one HIR resolution, while the resolved HIR remains in
// `synthetic_modules` until filtering completes.
pub(super) fn uncached_peak_prebound(
    programs: &[Program],
    authored: &BTreeMap<&str, AuthoredDeclaration<'_>>,
) -> Result<(usize, usize), Vec<Diagnostic>> {
    let mut retained_hir = 0usize;
    let mut synthetic_ast_peak = 0usize;
    for program in programs {
        let maximum = Some(dependency_identity_max(program, authored, programs)?);
        let costs = synthetic_builder_bytes_scoped(program, authored, programs, maximum, 4)?;
        retained_hir = checked_usage(
            retained_hir,
            costs.retained_hir,
            "builder_bytes",
            active_builder_limit(),
        )?;
        synthetic_ast_peak = synthetic_ast_peak.max(costs.synthetic_ast);
    }
    let total = checked_usage(
        retained_hir,
        synthetic_ast_peak,
        "builder_bytes",
        active_builder_limit(),
    )?;
    Ok((total, total))
}

/// Mode five is an execution-phase peak, never a checked-cache receipt.
/// Callers may select it only when no frontend can retain synthetic programs.
pub(in crate::workspace_graph) fn next_retention_prebound_with_uncached_peak(
    programs: &[Program],
    authored: &BTreeMap<&str, AuthoredDeclaration<'_>>,
    current: usize,
    layout_mode: &mut u8,
    allow_uncached_peak: bool,
) -> Result<(usize, usize), Vec<Diagnostic>> {
    let maximum_mode = if allow_uncached_peak { 5 } else { 4 };
    while *layout_mode < maximum_mode {
        *layout_mode += 1;
        if *layout_mode == 5 {
            match uncached_peak_prebound(programs, authored) {
                Ok((resolve, total)) if resolve < current => return Ok((resolve, total)),
                Ok(_) => continue,
                Err(errors) if cost::is_builder_refusal(&errors) => continue,
                Err(errors) => return Err(errors),
            }
        }
        match retention_prebound_mode(programs, authored, true, *layout_mode) {
            Ok((resolve, total)) if resolve < current => return Ok((resolve, total)),
            Ok(_) => continue,
            Err(errors) if cost::is_builder_refusal(&errors) => continue,
            Err(errors) => return Err(errors),
        }
    }
    Err(vec![limit_error("builder_bytes", active_builder_limit())])
}
