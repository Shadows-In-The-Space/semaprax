//! Exact declaration-index pruning for compiler-owned resumable projections.

use super::*;

impl DeclarationIndex {
    /// Retain exactly the function bodies carried by one independently
    /// validated resumable projection. Non-function declarations stay intact:
    /// they remain the canonical type/import environment of the retained HIR.
    pub(crate) fn retain_resumable_projection_functions(
        &mut self,
        functions: &[ResolvedFunction],
        templates: &[ResolvedFunctionTemplate],
    ) -> Result<(), Diagnostic> {
        let retained = functions
            .iter()
            .map(|function| function.id.clone())
            .chain(templates.iter().map(|template| template.id.clone()))
            .collect::<BTreeSet<_>>();

        self.declarations.retain(|id, declaration| {
            declaration.kind != DeclarationKind::Function || retained.contains(id)
        });
        self.functions_by_name.retain(|_, id| retained.contains(id));
        let declarations = self.declarations.keys().cloned().collect::<BTreeSet<_>>();
        self.type_parameters
            .retain(|id, _| declarations.contains(id));
        self.byte_slice_roots = super::super::derive_byte_slice_provenance(functions, self)?;
        Ok(())
    }
}
