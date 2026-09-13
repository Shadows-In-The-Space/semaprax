//! Output-carrier reservation for the final uncached core retry.

use crate::diagnostic::Diagnostic;

use super::reserve_builder_structure;

fn limit_error() -> Vec<Diagnostic> {
    vec![super::limit_error(
        "builder_bytes",
        super::active_builder_limit(),
    )]
}

fn output_carrier<T>(
    selected: usize,
    fixed_element_bytes: usize,
) -> Result<Vec<T>, Vec<Diagnostic>> {
    let reserved = selected
        .checked_mul(fixed_element_bytes)
        .ok_or_else(limit_error)?;
    reserve_builder_structure(reserved)?;
    let retained = Vec::with_capacity(selected);
    let actual = retained
        .capacity()
        .checked_mul(fixed_element_bytes)
        .ok_or_else(limit_error)?;
    if actual > reserved {
        reserve_builder_structure(actual - reserved)?;
    }
    Ok(retained)
}

/// Move selected entries into a retained output carrier.
///
/// Normal core attempts retain the established full-carrier receipt. The final
/// uncached retry keeps the complete input carrier live and charged until this
/// move finishes, then charges only the new output carrier. `keep` is an `Fn`:
/// the final retry counts and moves the same selection without accepting a
/// stateful predicate as accounting evidence.
pub(super) fn filter_owned_vec<T>(
    items: Vec<T>,
    keep: impl Fn(&T) -> bool,
    retained_output_only: bool,
) -> Result<Vec<T>, Vec<Diagnostic>> {
    if !retained_output_only {
        reserve_builder_structure(
            items
                .len()
                .checked_mul(std::mem::size_of::<T>())
                .ok_or_else(limit_error)?,
        )?;
        return Ok(items.into_iter().filter(|item| keep(item)).collect());
    }

    let selected = items.iter().filter(|item| keep(*item)).count();
    let mut retained = output_carrier::<T>(selected, std::mem::size_of::<T>())?;
    for item in items {
        if keep(&item) {
            retained.push(item);
        }
    }
    debug_assert_eq!(retained.len(), selected);
    Ok(retained)
}

/// Move selected entries and account their loan-plan sidecars.
pub(super) fn filter_owned_vec_accounted<T>(
    items: Vec<T>,
    fixed_element_bytes: usize,
    extra_owned_bytes: impl Fn(&T) -> Result<usize, Vec<Diagnostic>>,
    keep: impl Fn(&T) -> bool,
    retained_output_only: bool,
) -> Result<Vec<T>, Vec<Diagnostic>> {
    if !retained_output_only {
        let fixed = items
            .len()
            .checked_mul(fixed_element_bytes)
            .ok_or_else(limit_error)?;
        let mut bytes = fixed;
        for item in &items {
            bytes = bytes
                .checked_add(extra_owned_bytes(item)?)
                .ok_or_else(limit_error)?;
        }
        reserve_builder_structure(bytes)?;
        return Ok(items.into_iter().filter(|item| keep(item)).collect());
    }

    let mut selected = 0usize;
    let mut sidecars = 0usize;
    for item in &items {
        if keep(item) {
            selected = selected.checked_add(1).ok_or_else(limit_error)?;
            sidecars = sidecars
                .checked_add(extra_owned_bytes(item)?)
                .ok_or_else(limit_error)?;
        }
    }
    reserve_builder_structure(sidecars)?;
    let mut retained = output_carrier::<T>(selected, fixed_element_bytes)?;
    for item in items {
        if keep(&item) {
            retained.push(item);
        }
    }
    debug_assert_eq!(retained.len(), selected);
    Ok(retained)
}
