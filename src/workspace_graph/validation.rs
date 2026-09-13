//! Compact exact evidence retained between sequential workspace HIR resolutions.
//!
//! The uncached final builder path must prove imports against their authored
//! authorities without retaining every complete `ResolvedProgram`.  This
//! module extracts only declaration and signature facts while the owning HIR
//! is live, then performs the same exact comparisons after those programs
//! have been filtered into their workspace carriers.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{ModuleUseKind, Program, TypeDeclarationKind};
use crate::diagnostic::Diagnostic;
use crate::{hir, prelude};

use super::{
    graph_error, owned_generics, prelude_binding, reserve_builder_structure, top_level_declaration,
    WorkspaceDeclarationFact,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct FunctionSignature {
    type_parameters: Vec<hir::ResolvedTypeParameterDeclaration>,
    params: Vec<hir::ResolvedParam>,
    return_type: hir::ResolvedType,
    effects: Vec<String>,
    vec_wrapper: Option<crate::vec_ops::VecOp>,
    box_wrapper: Option<crate::box_ops::BoxOp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypeSignature {
    type_parameters: Vec<hir::ResolvedTypeParameterDeclaration>,
    kind: hir::ResolvedTypeDeclarationKind,
}

#[derive(Default)]
struct ModuleSignatureFacts {
    functions: BTreeMap<String, FunctionSignature>,
    templates: BTreeMap<String, FunctionSignature>,
    types: BTreeMap<String, TypeSignature>,
}

/// Exact cross-module facts that outlive one full resolved module only on the
/// final uncached output-carrier path.
pub(super) struct WorkspaceValidationIndex {
    expected: BTreeMap<String, WorkspaceDeclarationFact>,
    expected_compiler: BTreeMap<String, WorkspaceDeclarationFact>,
    actual: BTreeMap<String, WorkspaceDeclarationFact>,
    modules: BTreeMap<String, ModuleSignatureFacts>,
}

impl WorkspaceValidationIndex {
    pub(super) fn new(programs: &[Program]) -> Result<Self, Vec<Diagnostic>> {
        let expected = expected_declaration_facts(programs)?;
        let expected_compiler = prelude_binding::expected_declaration_facts_for(
            prelude_binding::uses_vec(programs),
            prelude_binding::uses_box(programs),
            prelude_binding::uses_iterator(programs),
        )?;
        reserve_builder_structure(
            expected
                .len()
                .checked_add(expected_compiler.len())
                .and_then(|entries| {
                    entries
                        .checked_mul(std::mem::size_of::<(String, WorkspaceDeclarationFact)>() * 2)
                })
                .ok_or_else(|| {
                    vec![graph_error(
                        "SPX-G171",
                        "workspace validation facts exceed the builder budget",
                    )]
                })?,
        )?;
        Ok(Self {
            expected,
            expected_compiler,
            actual: BTreeMap::new(),
            modules: BTreeMap::new(),
        })
    }

    /// Extract all HIR-dependent proof while `resolved` is still live.  The
    /// copied signatures retain type parameters, effects, and Vec/Box wrapper
    /// identity; bodies, contracts, cleanup plans, and resolver indexes do
    /// not survive this boundary.
    pub(super) fn record_module(
        &mut self,
        module: &str,
        resolved: &hir::ResolvedProgram,
        programs: &[Program],
    ) -> Result<(), Vec<Diagnostic>> {
        let source = programs
            .iter()
            .find(|program| program.module == module)
            .expect("resolved workspace module belongs to authenticated source");
        self.record_declarations(module, resolved, source, programs)?;

        let mut facts = ModuleSignatureFacts::default();
        for function in &resolved.functions {
            reserve_validation_entry::<FunctionSignature>()?;
            facts.functions.insert(
                crate::bounded_output::budgeted_clone(function.id.as_str()),
                FunctionSignature {
                    type_parameters: Vec::new(),
                    params: function.params.clone(),
                    return_type: function.return_type.clone(),
                    effects: function.effects.clone(),
                    vec_wrapper: None,
                    box_wrapper: None,
                },
            );
        }
        for template in &resolved.function_templates {
            reserve_validation_entry::<FunctionSignature>()?;
            facts.templates.insert(
                crate::bounded_output::budgeted_clone(template.id.as_str()),
                FunctionSignature {
                    type_parameters: template.type_parameters.clone(),
                    params: template.params.clone(),
                    return_type: template.return_type.clone(),
                    effects: template.effects.clone(),
                    vec_wrapper: crate::vec_ops::hir_wrapper_in_program(resolved, template),
                    box_wrapper: crate::box_ops::hir_wrapper_in_program(resolved, template),
                },
            );
        }
        for declaration in &resolved.types {
            reserve_validation_entry::<TypeSignature>()?;
            facts.types.insert(
                crate::bounded_output::budgeted_clone(declaration.id.as_str()),
                TypeSignature {
                    type_parameters: declaration.type_parameters.clone(),
                    kind: declaration.kind.clone(),
                },
            );
        }
        reserve_validation_entry::<ModuleSignatureFacts>()?;
        if self
            .modules
            .insert(crate::bounded_output::budgeted_clone(module), facts)
            .is_some()
        {
            return Err(vec![graph_error(
                "SPX-G173",
                "resolved workspace module is retained more than once",
            )]);
        }
        Ok(())
    }

    fn record_declarations(
        &mut self,
        module: &str,
        resolved: &hir::ResolvedProgram,
        source: &Program,
        programs: &[Program],
    ) -> Result<(), Vec<Diagnostic>> {
        let imports_vec_wrapper = owned_generics::program_imports_vec_wrapper(source, programs);
        let imports_box_wrapper = owned_generics::program_imports_box_wrapper(source, programs);
        let expected_module_compiler = prelude_binding::expected_declaration_facts_for(
            prelude::program_uses_vec(source) || imports_vec_wrapper,
            prelude::program_uses_box(source) || imports_box_wrapper,
            crate::iterator_ops::program_uses_iterator(source),
        )?;
        let direct_targets = source
            .module_uses
            .iter()
            .map(|module_use| module_use.persistent_id.as_str())
            .collect::<BTreeSet<_>>();
        let synthetic_main = crate::bounded_output::budgeted_format(format_args!(
            "workspace.synthetic.main.{module}"
        ));
        let synthetic_main_is_allowed = !source
            .functions
            .iter()
            .any(|function| function.name == "main")
            && !self.expected.contains_key(synthetic_main.as_str())
            && !self.expected_compiler.contains_key(synthetic_main.as_str());
        let mut compiler = BTreeMap::new();
        for declaration in resolved.declarations.workspace_declarations() {
            if declaration.identity_origin == hir::IdentityOrigin::CompilerOwned {
                let fact = WorkspaceDeclarationFact {
                    kind: declaration.kind,
                    origin: declaration.identity_origin,
                    owner: declaration
                        .owner
                        .map(|owner| crate::bounded_output::budgeted_clone(owner.as_str())),
                    path: None,
                    module: None,
                };
                if compiler
                    .insert(
                        crate::bounded_output::budgeted_clone(declaration.id.as_str()),
                        fact,
                    )
                    .is_some()
                {
                    return Err(vec![graph_error(
                        "SPX-G173",
                        "compiler-owned workspace declaration identity is duplicated",
                    )]);
                }
                continue;
            }
            let top = top_level_declaration(&resolved.declarations, &declaration);
            let Some(top_fact) = self.expected.get(top.as_str()) else {
                if synthetic_main_is_allowed
                    && declaration.id.as_str() == synthetic_main.as_str()
                    && declaration.kind == hir::DeclarationKind::Function
                    && declaration.identity_origin == hir::IdentityOrigin::Explicit
                    && declaration.owner.is_none()
                {
                    continue;
                }
                return Err(vec![graph_error(
                    "SPX-G173",
                    "resolved workspace declaration has an unauthenticated synthetic or rogue root",
                )]);
            };
            if top_fact.module.as_deref() != Some(module) {
                let expected_foreign = self.expected.get(declaration.id.as_str());
                if direct_targets.contains(top.as_str())
                    && expected_foreign.is_some_and(|fact| {
                        fact.kind == declaration.kind
                            && fact.origin == declaration.identity_origin
                            && fact.owner.as_deref()
                                == declaration.owner.as_ref().map(hir::DeclarationId::as_str)
                            && fact.path == top_fact.path
                            && fact.module == top_fact.module
                    })
                {
                    continue;
                }
                return Err(vec![graph_error(
                    "SPX-G173",
                    "resolved workspace declaration leaks a non-imported foreign authority",
                )]);
            }
            let fact = WorkspaceDeclarationFact {
                kind: declaration.kind,
                origin: declaration.identity_origin,
                owner: declaration
                    .owner
                    .map(|owner| crate::bounded_output::budgeted_clone(owner.as_str())),
                path: top_fact
                    .path
                    .as_deref()
                    .map(crate::bounded_output::budgeted_clone),
                module: top_fact
                    .module
                    .as_deref()
                    .map(crate::bounded_output::budgeted_clone),
            };
            reserve_validation_entry::<WorkspaceDeclarationFact>()?;
            if self
                .actual
                .insert(
                    crate::bounded_output::budgeted_clone(declaration.id.as_str()),
                    fact,
                )
                .is_some()
            {
                return Err(vec![graph_error(
                    "SPX-G173",
                    "workspace declaration identity is retained more than once",
                )]);
            }
        }
        if compiler != expected_module_compiler {
            return Err(vec![graph_error(
                "SPX-G173",
                "compiler-owned prelude declaration facts disagree with the independent prelude map",
            )]);
        }
        Ok(())
    }

    pub(super) fn validate_stub_signatures(
        &self,
        programs: &[Program],
    ) -> Result<(), Vec<Diagnostic>> {
        for caller in programs {
            let caller_facts = self.modules.get(caller.module.as_str()).ok_or_else(|| {
                vec![graph_error(
                    "SPX-G173",
                    "resolved caller module is absent from the workspace HIR",
                )]
            })?;
            for module_use in &caller.module_uses {
                if module_use.kind == ModuleUseKind::Protocol {
                    continue;
                }
                let target_facts = self
                    .modules
                    .get(module_use.target_module.as_str())
                    .ok_or_else(|| {
                        vec![graph_error(
                            "SPX-G173",
                            "resolved target module is absent from the workspace HIR",
                        )]
                    })?;
                match module_use.kind {
                    ModuleUseKind::Function => {
                        let monomorphic_matches = caller_facts
                            .functions
                            .get(module_use.persistent_id.as_str())
                            .zip(
                                target_facts
                                    .functions
                                    .get(module_use.persistent_id.as_str()),
                            )
                            .is_some_and(|(stub, authority)| {
                                stub.params == authority.params
                                    && stub.return_type == authority.return_type
                                    && stub.effects == authority.effects
                            });
                        let generic_matches = caller_facts
                            .templates
                            .get(module_use.persistent_id.as_str())
                            .zip(
                                target_facts
                                    .templates
                                    .get(module_use.persistent_id.as_str()),
                            )
                            .is_some_and(|(stub, authority)| {
                                stub.type_parameters == authority.type_parameters
                                    && stub.params == authority.params
                                    && stub.return_type == authority.return_type
                                    && stub.effects == authority.effects
                                    && ((stub.vec_wrapper.is_some()
                                        && stub.vec_wrapper == authority.vec_wrapper)
                                        || (stub.box_wrapper.is_some()
                                            && stub.box_wrapper == authority.box_wrapper))
                            });
                        if !monomorphic_matches && !generic_matches {
                            return Err(vec![graph_error(
                                "SPX-G173",
                                "workspace function signature stub disagrees with authored HIR authority",
                            )]);
                        }
                    }
                    ModuleUseKind::Type => {
                        let matches = caller_facts
                            .types
                            .get(module_use.persistent_id.as_str())
                            .zip(target_facts.types.get(module_use.persistent_id.as_str()))
                            .is_some_and(|(stub, authority)| {
                                stub.type_parameters == authority.type_parameters
                                    && stub.kind == authority.kind
                            });
                        if !matches {
                            return Err(vec![graph_error(
                                "SPX-G173",
                                "workspace type signature stub disagrees with authored HIR authority",
                            )]);
                        }
                    }
                    ModuleUseKind::Protocol => unreachable!(),
                }
            }
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
        programs: &[Program],
    ) -> Result<BTreeMap<String, WorkspaceDeclarationFact>, Vec<Diagnostic>> {
        if self.actual != self.expected {
            let differing = self
                .actual
                .keys()
                .chain(self.expected.keys())
                .find(|id| self.actual.get(id.as_str()) != self.expected.get(id.as_str()))
                .expect("unequal declaration maps have a differing identity");
            return Err(vec![graph_error(
                "SPX-G173",
                format!(
                    "authored workspace declaration facts disagree with retained HIR at `{differing}`"
                ),
            )]);
        }
        let compiler_ids = self
            .expected_compiler
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if compiler_ids != prelude_binding::ids(programs) {
            return Err(vec![graph_error(
                "SPX-G173",
                "compiler-owned workspace declaration facts disagree with the exact shared prelude",
            )]);
        }
        let mut facts = self.expected;
        for (id, fact) in self.expected_compiler {
            if facts.insert(id, fact).is_some() {
                return Err(vec![graph_error(
                    "SPX-G173",
                    "compiler-owned and authored workspace declaration identities overlap",
                )]);
            }
        }
        Ok(facts)
    }
}

fn reserve_validation_entry<T>() -> Result<(), Vec<Diagnostic>> {
    reserve_builder_structure(
        std::mem::size_of::<(String, T)>()
            .checked_mul(2)
            .ok_or_else(|| {
                vec![graph_error(
                    "SPX-G171",
                    "workspace validation facts exceed the builder budget",
                )]
            })?,
    )
}

pub(super) fn validate_stub_signatures(
    programs: &[Program],
    modules: &[(String, hir::ResolvedProgram)],
) -> Result<(), Vec<Diagnostic>> {
    for caller in programs {
        let caller_hir = modules
            .iter()
            .find(|(module, _)| module == &caller.module)
            .map(|(_, resolved)| resolved)
            .ok_or_else(|| {
                vec![graph_error(
                    "SPX-G173",
                    "resolved caller module is absent from the workspace HIR",
                )]
            })?;
        for module_use in &caller.module_uses {
            if module_use.kind == ModuleUseKind::Protocol {
                continue;
            }
            let target_hir = modules
                .iter()
                .find(|(module, _)| module == &module_use.target_module)
                .map(|(_, resolved)| resolved)
                .ok_or_else(|| {
                    vec![graph_error(
                        "SPX-G173",
                        "resolved target module is absent from the workspace HIR",
                    )]
                })?;
            let id = hir::DeclarationId::new(crate::bounded_output::budgeted_clone(
                &module_use.persistent_id,
            ));
            match module_use.kind {
                ModuleUseKind::Function => {
                    let monomorphic_matches = caller_hir
                        .functions
                        .iter()
                        .find(|item| item.id == id)
                        .zip(target_hir.functions.iter().find(|item| item.id == id))
                        .is_some_and(|(stub, authority)| {
                            stub.params == authority.params
                                && stub.return_type == authority.return_type
                                && stub.effects == authority.effects
                        });
                    let vec_matches = caller_hir
                        .function_templates
                        .iter()
                        .find(|item| item.id == id)
                        .zip(
                            target_hir
                                .function_templates
                                .iter()
                                .find(|item| item.id == id),
                        )
                        .is_some_and(|(stub, authority)| {
                            crate::vec_ops::hir_wrapper_in_program(caller_hir, stub).is_some_and(
                                |operation| {
                                    crate::vec_ops::hir_wrapper_in_program(target_hir, authority)
                                        == Some(operation)
                                },
                            ) && stub.type_parameters == authority.type_parameters
                                && stub.params == authority.params
                                && stub.return_type == authority.return_type
                                && stub.effects == authority.effects
                        });
                    let box_matches = caller_hir
                        .function_templates
                        .iter()
                        .find(|item| item.id == id)
                        .zip(
                            target_hir
                                .function_templates
                                .iter()
                                .find(|item| item.id == id),
                        )
                        .is_some_and(|(stub, authority)| {
                            crate::box_ops::hir_wrapper_in_program(caller_hir, stub).is_some_and(
                                |operation| {
                                    crate::box_ops::hir_wrapper_in_program(target_hir, authority)
                                        == Some(operation)
                                },
                            ) && stub.type_parameters == authority.type_parameters
                                && stub.params == authority.params
                                && stub.return_type == authority.return_type
                                && stub.effects == authority.effects
                        });
                    if !monomorphic_matches && !vec_matches && !box_matches {
                        return Err(vec![graph_error(
                            "SPX-G173",
                            "workspace function signature stub disagrees with authored HIR authority",
                        )]);
                    }
                }
                ModuleUseKind::Type => {
                    if !caller_hir
                        .types
                        .iter()
                        .find(|item| item.id == id)
                        .zip(target_hir.types.iter().find(|item| item.id == id))
                        .is_some_and(|(stub, authority)| {
                            stub.type_parameters == authority.type_parameters
                                && stub.kind == authority.kind
                        })
                    {
                        return Err(vec![graph_error(
                            "SPX-G173",
                            "workspace type signature stub disagrees with authored HIR authority",
                        )]);
                    }
                }
                ModuleUseKind::Protocol => unreachable!(),
            }
        }
    }
    Ok(())
}

pub(super) fn expected_declaration_facts(
    programs: &[Program],
) -> Result<BTreeMap<String, WorkspaceDeclarationFact>, Vec<Diagnostic>> {
    let mut facts = BTreeMap::new();
    for program in programs {
        for declaration in &program.types {
            let kind = match declaration.kind {
                TypeDeclarationKind::Resource { .. } => hir::DeclarationKind::Resource,
                TypeDeclarationKind::Record { .. } => hir::DeclarationKind::Record,
                TypeDeclarationKind::Class { .. } => hir::DeclarationKind::Class,
                TypeDeclarationKind::Variant { .. } => hir::DeclarationKind::Variant,
            };
            insert_expected_declaration(
                &mut facts,
                program,
                &declaration.stable_id,
                kind,
                identity_origin(declaration.explicit_id),
                None,
            )?;
            match &declaration.kind {
                TypeDeclarationKind::Resource { lifecycles } => {
                    let [lifecycle] = lifecycles.as_slice() else {
                        return Err(vec![graph_error(
                            "SPX-G173",
                            "authored workspace resource has no exact lifecycle identity",
                        )]);
                    };
                    let id = lifecycle.stable_id.as_deref().ok_or_else(|| {
                        vec![graph_error(
                            "SPX-G173",
                            "authored workspace resource lifecycle identity is missing",
                        )]
                    })?;
                    insert_expected_declaration(
                        &mut facts,
                        program,
                        id,
                        hir::DeclarationKind::ResourceDrop,
                        hir::IdentityOrigin::Explicit,
                        Some(&declaration.stable_id),
                    )?;
                }
                TypeDeclarationKind::Record { fields }
                | TypeDeclarationKind::Class { fields, .. } => {
                    for field in fields {
                        insert_expected_declaration(
                            &mut facts,
                            program,
                            &field.stable_id,
                            hir::DeclarationKind::Field,
                            identity_origin(field.explicit_id),
                            Some(&declaration.stable_id),
                        )?;
                    }
                    if let TypeDeclarationKind::Class { methods, .. } = &declaration.kind {
                        for method in methods {
                            insert_expected_declaration(
                                &mut facts,
                                program,
                                &method.stable_id,
                                hir::DeclarationKind::Function,
                                identity_origin(method.explicit_id),
                                Some(&declaration.stable_id),
                            )?;
                        }
                    }
                }
                TypeDeclarationKind::Variant { cases } => {
                    for case in cases {
                        insert_expected_declaration(
                            &mut facts,
                            program,
                            &case.stable_id,
                            hir::DeclarationKind::VariantCase,
                            identity_origin(case.explicit_id),
                            Some(&declaration.stable_id),
                        )?;
                        for field in &case.fields {
                            insert_expected_declaration(
                                &mut facts,
                                program,
                                &field.stable_id,
                                hir::DeclarationKind::CaseField,
                                identity_origin(field.explicit_id),
                                Some(&case.stable_id),
                            )?;
                        }
                    }
                }
            }
        }
        for interface in &program.interfaces {
            insert_expected_declaration(
                &mut facts,
                program,
                &interface.stable_id,
                hir::DeclarationKind::Interface,
                identity_origin(interface.explicit_id),
                None,
            )?;
            for import in &interface.imports {
                insert_expected_declaration(
                    &mut facts,
                    program,
                    &import.stable_id,
                    hir::DeclarationKind::Import,
                    identity_origin(import.explicit_id),
                    Some(&interface.stable_id),
                )?;
            }
        }
        for function in &program.functions {
            insert_expected_declaration(
                &mut facts,
                program,
                &function.stable_id,
                hir::DeclarationKind::Function,
                identity_origin(function.explicit_id),
                None,
            )?;
        }
    }
    Ok(facts)
}

fn identity_origin(explicit: bool) -> hir::IdentityOrigin {
    if explicit {
        hir::IdentityOrigin::Explicit
    } else {
        hir::IdentityOrigin::Automatic
    }
}

fn insert_expected_declaration(
    facts: &mut BTreeMap<String, WorkspaceDeclarationFact>,
    program: &Program,
    id: &str,
    kind: hir::DeclarationKind,
    origin: hir::IdentityOrigin,
    owner: Option<&str>,
) -> Result<(), Vec<Diagnostic>> {
    let fact = WorkspaceDeclarationFact {
        kind,
        origin,
        owner: owner.map(crate::bounded_output::budgeted_clone),
        path: Some(crate::bounded_output::budgeted_clone(&program.path)),
        module: Some(crate::bounded_output::budgeted_clone(&program.module)),
    };
    if facts
        .insert(crate::bounded_output::budgeted_clone(id), fact)
        .is_some()
    {
        return Err(vec![graph_error(
            "SPX-G173",
            "independent authored workspace declaration identity is duplicated",
        )]);
    }
    Ok(())
}

pub(super) fn insert_expected_compiler_declaration(
    facts: &mut BTreeMap<String, WorkspaceDeclarationFact>,
    id: &str,
    kind: hir::DeclarationKind,
    owner: Option<&str>,
) -> Result<(), Vec<Diagnostic>> {
    let fact = WorkspaceDeclarationFact {
        kind,
        origin: hir::IdentityOrigin::CompilerOwned,
        owner: owner.map(crate::bounded_output::budgeted_clone),
        path: None,
        module: None,
    };
    if facts
        .insert(crate::bounded_output::budgeted_clone(id), fact)
        .is_some()
    {
        return Err(vec![graph_error(
            "SPX-G173",
            "independent compiler prelude declaration identity is duplicated",
        )]);
    }
    Ok(())
}
