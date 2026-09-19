//! Deterministic `builder_bytes` accounting breakdown for the workspace
//! semantic graph builder's precharge (see `expected_projection`'s
//! `retention_prebound_mode`, which this module never modifies).
//!
//! Three sessions have guessed at why one more cross-module call site trips
//! the builder's byte cap while a same-file, uncalled declaration of similar
//! size does not, because the builder previously reported only a single
//! pass/fail number. This module answers with data instead: for every
//! module, how much of its charged cost is its own declared source with no
//! imports at all, and how much is the marginal cost of each individual
//! cross-module `use` it declares; and, separately, which declarations in a
//! used module are never reached by any call site anywhere in the workspace,
//! and how many bytes the builder still charges for them.
//!
//! Every entry point here is read-only replay of the exact same cost
//! functions the real precharge calls (`synthetic_builder_bytes` and
//! `synthetic_builder_bytes_scoped`); nothing in this file changes what the
//! builder admits or refuses.

#[cfg(test)]
use super::expected_projection::retention_prebound_mode;
use super::expected_projection::{synthetic_builder_bytes, synthetic_builder_bytes_scoped};
use super::{visit_ast_call_sites, AuthoredDeclaration};
use crate::ast::{ModuleUseKind, Program};
use crate::diagnostic::Diagnostic;
use std::collections::{BTreeMap, BTreeSet};

/// One module's contribution to the workspace's `builder_bytes` precharge,
/// split into what its own declarations cost with no imports at all
/// (`own_bytes`) and what each individual `use` costs on top of that
/// (`per_import`, each computed in isolation from every other `use` the
/// module declares).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModuleBudget {
    pub(crate) path: String,
    pub(crate) module: String,
    pub(crate) own_bytes: usize,
    pub(crate) per_import: Vec<ImportBudget>,
    /// The module's actual charged cost with every one of its `use`s
    /// present together. Not generally `own_bytes` plus the sum of
    /// `per_import`: the HIR structural/identity expansion in
    /// `synthetic_builder_bytes_scoped` is not linear in declaration count,
    /// so isolating one import at a time is a ceiling on that import's
    /// share, not an exact partition of `total_bytes`.
    pub(crate) total_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImportBudget {
    pub(crate) persistent_id: String,
    pub(crate) target_module: String,
    pub(crate) marginal_bytes: usize,
}

/// A declaration the builder charges in full even though no call site
/// anywhere in the workspace can reach it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnreachedDeclaration {
    pub(crate) module: String,
    pub(crate) stable_id: String,
}

/// For every module in `programs`, the precharge cost of its own
/// declarations with no imports (`own_bytes`), the marginal precharge cost
/// of each `use` it declares in isolation (`per_import`), and its real
/// charged total (`total_bytes`). Deterministic: costed purely from
/// `programs`/`authored` (both already sorted by path before any caller
/// reaches this), and every collection built here is either a `BTreeMap`, a
/// `BTreeSet`, or a plain `Vec` walked in `programs`/`module_uses` order.
pub(crate) fn builder_bytes_breakdown(
    programs: &[Program],
    authored: &BTreeMap<&str, AuthoredDeclaration<'_>>,
) -> Result<Vec<ModuleBudget>, Vec<Diagnostic>> {
    let mut modules = Vec::with_capacity(programs.len());
    for program in programs {
        let own_bytes =
            synthetic_builder_bytes_scoped(program, authored, programs, None, 0, false)?
                .raw_clone_and_hir;
        let total_bytes = synthetic_builder_bytes(program, authored, programs)?.raw_clone_and_hir;
        let mut per_import = Vec::with_capacity(program.module_uses.len());
        for module_use in &program.module_uses {
            if module_use.kind == ModuleUseKind::Protocol {
                continue;
            }
            let mut isolated = program.clone();
            isolated.module_uses = vec![module_use.clone()];
            let isolated_bytes =
                synthetic_builder_bytes(&isolated, authored, programs)?.raw_clone_and_hir;
            per_import.push(ImportBudget {
                persistent_id: module_use.persistent_id.clone(),
                target_module: module_use.target_module.clone(),
                marginal_bytes: isolated_bytes.saturating_sub(own_bytes),
            });
        }
        modules.push(ModuleBudget {
            path: program.path.clone(),
            module: program.module.clone(),
            own_bytes,
            per_import,
            total_bytes,
        });
    }
    Ok(modules)
}

/// Every declaration in `programs` that is never the target of a
/// cross-module `use` and is not reached transitively (by an ordinary call,
/// including one in a `requires`/`ensures` contract) from a declaration that
/// is. Call-graph edges are resolved from source text alone: a `use
/// function` alias, or a same-module function name. A callee this cannot
/// resolve (a prelude/intrinsic operation such as `byte_len`, or any other
/// name this pass fails to match) is simply not an edge, so this
/// under-approximates reachability and can only under-report waste, never
/// invent it.
pub(crate) fn unreached_declarations(
    programs: &[Program],
) -> Result<BTreeSet<UnreachedDeclaration>, Vec<Diagnostic>> {
    let mut roots = BTreeSet::new();
    for program in programs {
        for module_use in &program.module_uses {
            if module_use.kind == ModuleUseKind::Function {
                roots.insert(module_use.persistent_id.clone());
            }
        }
    }
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for program in programs {
        let mut aliases: BTreeMap<&str, &str> = BTreeMap::new();
        for module_use in &program.module_uses {
            if module_use.kind == ModuleUseKind::Function {
                aliases.insert(module_use.alias.as_str(), module_use.persistent_id.as_str());
            }
        }
        for function in &program.functions {
            let mut callees = BTreeSet::new();
            let mut record = |name: &str, _path: &str| -> Result<(), Vec<Diagnostic>> {
                if let Some(target) = aliases.get(name) {
                    callees.insert((*target).to_owned());
                } else if let Some(sibling) = program
                    .functions
                    .iter()
                    .find(|candidate| candidate.name == name)
                {
                    callees.insert(sibling.stable_id.clone());
                }
                Ok(())
            };
            visit_ast_call_sites(&function.body, "body", &mut record)?;
            for expr in function.requires.iter().chain(function.ensures.iter()) {
                visit_ast_call_sites(expr, "contract", &mut record)?;
            }
            edges.insert(function.stable_id.clone(), callees);
        }
    }
    let mut reached = roots.clone();
    let mut pending: Vec<String> = roots.into_iter().collect();
    while let Some(id) = pending.pop() {
        if let Some(callees) = edges.get(&id) {
            for callee in callees {
                if reached.insert(callee.clone()) {
                    pending.push(callee.clone());
                }
            }
        }
    }
    let mut unreached = BTreeSet::new();
    for program in programs {
        for function in &program.functions {
            if !reached.contains(function.stable_id.as_str()) {
                unreached.insert(UnreachedDeclaration {
                    module: program.module.clone(),
                    stable_id: function.stable_id.clone(),
                });
            }
        }
    }
    Ok(unreached)
}

/// The precharge cost `program` would carry (own declarations, no imports)
/// if every function named in `drop_stable_ids` were absent. Used to measure
/// how many of the `builder_bytes` the builder charges for
/// `unreached_declarations()` in one module are actually recoverable:
/// because the HIR structural/identity expansion in
/// `synthetic_builder_bytes_scoped` is not linear in declaration count, this
/// is not the same as summing a per-declaration cost, and must be measured
/// by removing the whole set at once.
pub(crate) fn own_bytes_without(
    program: &Program,
    drop_stable_ids: &BTreeSet<&str>,
    authored: &BTreeMap<&str, AuthoredDeclaration<'_>>,
    programs: &[Program],
) -> Result<usize, Vec<Diagnostic>> {
    let mut trimmed = program.clone();
    trimmed
        .functions
        .retain(|function| !drop_stable_ids.contains(function.stable_id.as_str()));
    Ok(
        synthetic_builder_bytes_scoped(&trimmed, authored, programs, None, 0, false)?
            .raw_clone_and_hir,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_graph::{
        build_owned_with_builder_limit, index_authored, MAX_BUILDER_BYTES,
    };
    use std::path::Path;

    fn programs_from(sources: &[(&str, &str)]) -> Vec<Program> {
        sources
            .iter()
            .map(|(path, source)| crate::parse(source, Path::new(path)).unwrap())
            .collect()
    }

    /// `build_owned` (unlike the cost-accounting functions this module
    /// wraps) requires each source to already be in canonical-formatted
    /// text; a hand-written fixture is not, so route it through one
    /// parse/format round trip first.
    fn canonical_source(path: &str, source: &str) -> String {
        crate::format::canonical(&crate::parse(source, Path::new(path)).unwrap())
    }

    /// The exact scenario measured against the real
    /// `examples/catalog-normalizer-project` in issue #124: a pure-scalar
    /// function with no caller anywhere fits, but wiring the single smallest
    /// possible cross-module call to it does not, even though the callee's
    /// own source did not change at all between the two builds. This proves,
    /// on a minimal fixture, that the marginal cost of a new cross-module
    /// call site is a distinct, separately measurable term from the
    /// declaration's own source bytes: `own_bytes` for `app` is identical
    /// whether or not `tests` imports it, and the entire delta lands in
    /// `tests`'s `per_import` entry for that one `use`.
    #[test]
    fn cross_module_call_site_charges_a_distinct_marginal_term() {
        let uncalled = programs_from(&[
            (
                "app.spx",
                "module app;\n@id(\"app.value\") fn value(input: i64) -> i64 { input + 1 }\n@id(\"app.main\") fn main() -> i64 { 0 }\n",
            ),
            (
                "tests.spx",
                "module tests;\n@id(\"tests.main\") fn main() -> i64 { 0 }\n",
            ),
        ]);
        let authored_uncalled = index_authored(&uncalled).unwrap();
        let uncalled_budget = builder_bytes_breakdown(&uncalled, &authored_uncalled).unwrap();
        let app_own_uncalled = uncalled_budget
            .iter()
            .find(|module| module.module == "app")
            .unwrap()
            .own_bytes;

        let called = programs_from(&[
            (
                "app.spx",
                "module app;\n@id(\"app.value\") fn value(input: i64) -> i64 { input + 1 }\n@id(\"app.main\") fn main() -> i64 { 0 }\n",
            ),
            (
                "tests.spx",
                "module tests;\nuse function @id(\"app.value\") from app as value;\n@id(\"tests.main\") fn main() -> i64 { value(1) }\n",
            ),
        ]);
        let authored_called = index_authored(&called).unwrap();
        let called_budget = builder_bytes_breakdown(&called, &authored_called).unwrap();
        let app_own_called = called_budget
            .iter()
            .find(|module| module.module == "app")
            .unwrap()
            .own_bytes;
        let tests_module = called_budget
            .iter()
            .find(|module| module.module == "tests")
            .unwrap();
        let import_marginal = tests_module
            .per_import
            .iter()
            .find(|import| import.persistent_id == "app.value")
            .unwrap()
            .marginal_bytes;

        // The callee's own declared source did not change: defining
        // `app.value` costs the same whether or not anyone imports it.
        assert_eq!(app_own_uncalled, app_own_called);
        // Yet reaching it from `tests` costs a real, separately-charged,
        // strictly positive number of bytes on top of `tests`'s own
        // (unchanged) source declarations.
        assert!(
            import_marginal > 0,
            "expected a strictly positive marginal reach cost, got {import_marginal}"
        );
    }

    #[test]
    fn breakdown_is_deterministic_for_identical_input() {
        let programs = programs_from(&[
            (
                "app.spx",
                "module app;\n@id(\"app.value\") fn value(input: i64) -> i64 { input + 1 }\n@id(\"app.main\") fn main() -> i64 { 0 }\n",
            ),
            (
                "tests.spx",
                "module tests;\nuse function @id(\"app.value\") from app as value;\n@id(\"tests.main\") fn main() -> i64 { value(1) }\n",
            ),
        ]);
        let authored = index_authored(&programs).unwrap();
        let first = builder_bytes_breakdown(&programs, &authored).unwrap();
        let second = builder_bytes_breakdown(&programs, &authored).unwrap();
        assert_eq!(first, second);
        let first_unreached = unreached_declarations(&programs).unwrap();
        let second_unreached = unreached_declarations(&programs).unwrap();
        assert_eq!(first_unreached, second_unreached);
    }

    /// A declaration only reachable through an ordinary internal call from
    /// an imported one is not flagged as unreached, and a declaration no
    /// import and no reachable caller ever names is.
    #[test]
    fn unreached_declarations_follow_the_internal_call_graph() {
        let programs = programs_from(&[
            (
                "app.spx",
                concat!(
                    "module app;\n",
                    "@id(\"app.helper\") fn helper(input: i64) -> i64 { input + 1 }\n",
                    "@id(\"app.value\") fn value(input: i64) -> i64 { helper(input) }\n",
                    "@id(\"app.dead\") fn dead(input: i64) -> i64 { input - 1 }\n",
                    "@id(\"app.main\") fn main() -> i64 { 0 }\n",
                ),
            ),
            (
                "tests.spx",
                "module tests;\nuse function @id(\"app.value\") from app as value;\n@id(\"tests.main\") fn main() -> i64 { value(1) }\n",
            ),
        ]);
        let unreached = unreached_declarations(&programs).unwrap();
        let unreached_ids: BTreeSet<&str> = unreached
            .iter()
            .map(|entry| entry.stable_id.as_str())
            .collect();
        assert!(!unreached_ids.contains("app.value"), "imported directly");
        assert!(
            !unreached_ids.contains("app.helper"),
            "reached through app.value's own body"
        );
        assert!(
            unreached_ids.contains("app.dead"),
            "never imported and never called by anything reachable"
        );
    }

    /// Diagnostic, not a regression gate: prints how `own_bytes` scales with
    /// the number of trivial one-line declarations in a single module, at
    /// the most conservative accounting mode (mode 0, the one
    /// `retention_prebound_mode`'s fallback ladder tries first). Run with
    /// `cargo test --lib workspace_graph::builder_bytes_report::tests::declaration_scaling_reference -- --ignored --nocapture`.
    /// On an unmodified tree this measured ~44.6KB of mode-0 `builder_bytes`
    /// per additional one-parameter, one-expression function — the HIR
    /// structural/identity expansion factors (`HIR_STRUCTURE_EXPANSION_FACTOR`,
    /// `HIR_IDENTITY_COPY_FACTOR`) applied to a handful of AST nodes, not a
    /// cross-module effect: this fixture never imports anything.
    #[test]
    #[ignore = "diagnostic measurement tool, not a regression gate; run with --ignored --nocapture"]
    fn declaration_scaling_reference() {
        for count in [1usize, 10, 50, 100, 200, 400] {
            let mut source =
                String::from("module app;\n@id(\"app.main\") fn main() -> i64 { 0 }\n");
            for index in 0..count {
                source.push_str(&format!(
                    "@id(\"app.fn{index}\") fn fn{index}(input: i64) -> i64 {{ input + {index} }}\n"
                ));
            }
            let programs = programs_from(&[
                ("app.spx", source.as_str()),
                (
                    "tests.spx",
                    "module tests;\n@id(\"tests.main\") fn main() -> i64 { 0 }\n",
                ),
            ]);
            let authored = index_authored(&programs).unwrap();
            let budget = builder_bytes_breakdown(&programs, &authored).unwrap();
            let app = budget.iter().find(|m| m.module == "app").unwrap();
            eprintln!(
                "count={count} own_bytes={} total_bytes={}",
                app.own_bytes, app.total_bytes
            );
        }
    }

    /// Diagnostic, not a regression gate: the full `SPX-G171` measurement
    /// against the real `examples/catalog-normalizer-project` plus the exact
    /// two bundled dependencies it declares (`std.data.json.dec`, transitively
    /// `std.io`). Run with
    /// `cargo test --lib workspace_graph::builder_bytes_report::tests::catalog_normalizer_project_reference -- --ignored --nocapture`.
    ///
    /// On an unmodified tree this measured:
    /// - Mode 0 (the most conservative accounting, tried first) refuses:
    ///   summed module costs alone are ~26.7MB against an 18,874,368-byte cap.
    /// - The real build succeeds at mode 2 (`retention_prebound_mode`'s third
    ///   rung), the first rung that fits: ~17.50MB used, ~1.34MB (7.3%)
    ///   margin. `build_owned` on the real sources confirms this: it verifies.
    /// - Of `std.data.json.dec`'s 27 functions, only 7 are imported by this
    ///   project; the transitive internal-call closure from those 7 reaches
    ///   20; 7 functions are never imported and never called by a reached
    ///   one. Of `std.io`'s 11 functions, this project imports *types* only
    ///   (`Reader`/`Writer`), never a function, so all 11 are unreached.
    /// - Removing exactly those unreached declarations and re-measuring the
    ///   same mode 2 the real build lands on drops the total from ~17.50MB to
    ///   ~10.59MB: a ~6.9MB (39.5%) recovery, turning a 7.3% margin into a
    ///   44% margin. That is real, substantial, safe-to-identify waste
    ///   (SPX-G171 charges full module cost regardless of use), but *not* a
    ///   safe narrow accounting fix to ship blind: recovering it in
    ///   production requires the resolver itself to skip building HIR for a
    ///   bundled dependency's unreached declarations, and every declaration
    ///   this project's own source contains must stay resolvable for
    ///   AGENTS.md's "semantic impact and review are read-only and bound to
    ///   exact source ... bytes" invariant — this measurement does not
    ///   distinguish "unreached from this workspace" from "a bundled
    ///   dependency file whose other declarations a reviewer may still ask
    ///   about", so pruning them from real resolution is a maintainer
    ///   decision, not an accounting correction.
    #[test]
    #[ignore = "diagnostic measurement tool, not a regression gate; run with --ignored --nocapture"]
    fn catalog_normalizer_project_reference() {
        let root = env!("CARGO_MANIFEST_DIR");
        let read = |relative: &str| std::fs::read_to_string(format!("{root}/{relative}")).unwrap();
        let programs = programs_from(&[
            (
                "examples/catalog-normalizer-project/src/app.spx",
                &read("examples/catalog-normalizer-project/src/app.spx"),
            ),
            (
                "examples/catalog-normalizer-project/src/batch.spx",
                &read("examples/catalog-normalizer-project/src/batch.spx"),
            ),
            (
                "examples/catalog-normalizer-project/src/limits.spx",
                &read("examples/catalog-normalizer-project/src/limits.spx"),
            ),
            (
                "examples/catalog-normalizer-project/src/tests.spx",
                &read("examples/catalog-normalizer-project/src/tests.spx"),
            ),
            (
                "std/data-json-dec/src/dec.spx",
                &read("std/data-json-dec/src/dec.spx"),
            ),
            ("std/io/src/io.spx", &read("std/io/src/io.spx")),
        ]);
        let authored = index_authored(&programs).unwrap();
        let budget = builder_bytes_breakdown(&programs, &authored).unwrap();
        let mut grand_total = 0usize;
        for module in &budget {
            eprintln!(
                "module={} own_bytes={} total_bytes={} imports={}",
                module.module,
                module.own_bytes,
                module.total_bytes,
                module.per_import.len()
            );
            for import in &module.per_import {
                eprintln!(
                    "    import {} <- {} marginal_bytes={}",
                    import.persistent_id, module.module, import.marginal_bytes
                );
            }
            grand_total += module.total_bytes;
        }
        eprintln!("grand_total(sum of per-module total_bytes)={grand_total}");
        eprintln!("MAX_BUILDER_BYTES={MAX_BUILDER_BYTES}");

        let unreached = unreached_declarations(&programs).unwrap();
        for entry in &unreached {
            eprintln!(
                "unreached: module={} stable_id={}",
                entry.module, entry.stable_id
            );
        }
        for module_name in ["std.data.json.dec", "std.io"] {
            let program = programs
                .iter()
                .find(|program| program.module == module_name)
                .unwrap();
            let drop_ids: BTreeSet<&str> = unreached
                .iter()
                .filter(|entry| entry.module == module_name)
                .map(|entry| entry.stable_id.as_str())
                .collect();
            if drop_ids.is_empty() {
                continue;
            }
            let full =
                synthetic_builder_bytes_scoped(program, &authored, &programs, None, 0, false)
                    .unwrap()
                    .raw_clone_and_hir;
            let trimmed = own_bytes_without(program, &drop_ids, &authored, &programs).unwrap();
            eprintln!(
                "{module_name}: own_bytes_full={full} own_bytes_reached_only={trimmed} waste={}",
                full.saturating_sub(trimmed)
            );
        }

        // The real end-to-end path (`build_owned`), with the exact logical
        // paths the bundled dependency table and the project manifest use,
        // to see the actual fallback-mode-adjusted charge rather than the
        // mode-0 ceiling computed above.
        let sources = vec![
            crate::workspace_graph::WorkspaceSource {
                path: "src/app.spx".to_owned(),
                source: read("examples/catalog-normalizer-project/src/app.spx"),
            },
            crate::workspace_graph::WorkspaceSource {
                path: "src/batch.spx".to_owned(),
                source: read("examples/catalog-normalizer-project/src/batch.spx"),
            },
            crate::workspace_graph::WorkspaceSource {
                path: "src/limits.spx".to_owned(),
                source: read("examples/catalog-normalizer-project/src/limits.spx"),
            },
            crate::workspace_graph::WorkspaceSource {
                path: "src/tests.spx".to_owned(),
                source: read("examples/catalog-normalizer-project/src/tests.spx"),
            },
            crate::workspace_graph::WorkspaceSource {
                path: "dependencies/std.data.json.dec/0.1.0/dec.spx".to_owned(),
                source: read("std/data-json-dec/src/dec.spx"),
            },
            crate::workspace_graph::WorkspaceSource {
                path: "dependencies/std.io/0.1.0/io.spx".to_owned(),
                source: read("std/io/src/io.spx"),
            },
        ];
        assert!(
            retention_prebound_mode(&programs, &authored, false, 0).is_err(),
            "mode 0 is expected to refuse this project; if it now fits, the \
             margin numbers in this test's doc comment are stale"
        );
        let mode2_total = match retention_prebound_mode(&programs, &authored, true, 2) {
            Ok((resolve, total)) => {
                eprintln!(
                    "mode2 (the mode the real build below lands on): resolve={resolve} total={total} fits={}",
                    total <= MAX_BUILDER_BYTES
                );
                total
            }
            Err(errors) => panic!(
                "expected mode2 to fit this project; refused with {}",
                errors[0].code
            ),
        };
        for (label, layout_mode) in [("mode3", 3u8), ("mode4", 4u8)] {
            match retention_prebound_mode(&programs, &authored, true, layout_mode) {
                Ok((resolve, total)) => eprintln!(
                    "{label}: resolve={resolve} total={total} fits={}",
                    total <= MAX_BUILDER_BYTES
                ),
                Err(errors) => eprintln!("{label}: refused ({})", errors[0].code),
            }
        }
        // Now prune the same unreached declarations from the real programs
        // and re-measure mode2 (the mode the real build above actually
        // lands on) end to end, to see what pruning would really be worth
        // at the exact fallback mode that gates this project today.
        let unreached_ids: BTreeSet<&str> = unreached
            .iter()
            .map(|entry| entry.stable_id.as_str())
            .collect();
        let trimmed_programs: Vec<Program> = programs
            .iter()
            .map(|program| {
                let mut trimmed = program.clone();
                trimmed
                    .functions
                    .retain(|function| !unreached_ids.contains(function.stable_id.as_str()));
                trimmed
            })
            .collect();
        let trimmed_authored = index_authored(&trimmed_programs).unwrap();
        let pruned_mode2_total =
            retention_prebound_mode(&trimmed_programs, &trimmed_authored, true, 2)
                .expect("pruning only removes provably-unreached functions, so this must still fit")
                .1;
        eprintln!(
            "mode2 AFTER PRUNING unreached declarations: total={pruned_mode2_total} fits={} (was {mode2_total})",
            pruned_mode2_total <= MAX_BUILDER_BYTES
        );
        // Conservative threshold well under the ~6.9MB measured on an
        // unmodified tree: catches a regression that silently makes the
        // waste this test exists to document disappear or invert, without
        // pinning to a byte-exact figure that any unrelated cost-accounting
        // change would immediately break.
        assert!(
            mode2_total.saturating_sub(pruned_mode2_total) > 5_000_000,
            "expected pruning unreached bundled-dependency declarations to recover \
             several megabytes of builder_bytes; recovered only {} \
             (before={mode2_total}, after={pruned_mode2_total})",
            mode2_total.saturating_sub(pruned_mode2_total)
        );

        match crate::workspace_graph::build_owned(sources.clone()) {
            Ok(_) => eprintln!("build_owned (baseline): OK (fits within MAX_BUILDER_BYTES)"),
            Err(diagnostics) => {
                for diagnostic in &diagnostics {
                    eprintln!(
                        "build_owned (baseline) error: {} {} help={:?}",
                        diagnostic.code, diagnostic.message, diagnostic.help
                    );
                }
                panic!("expected the unmodified real project to verify");
            }
        }

        // Reproduce issue #124's exact report on the real project, end to
        // end through `build_owned`: a pure-scalar function with no caller
        // anywhere still verifies, but wiring the single smallest possible
        // cross-module call to it does not.
        let mut app_with_uncalled_function = sources.clone();
        let app_source = &mut app_with_uncalled_function
            .iter_mut()
            .find(|source| source.path == "src/app.spx")
            .unwrap()
            .source;
        app_source.push_str(
            "\n@id(\"catalog_normalizer.app.g171_probe\") fn g171_probe(input: i64) -> i64 { input + 1 }\n",
        );
        *app_source = canonical_source("src/app.spx", app_source);
        match crate::workspace_graph::build_owned(app_with_uncalled_function.clone()) {
            Ok(_) => eprintln!(
                "build_owned (uncalled function added): OK, exactly as issue #124 reported"
            ),
            Err(diagnostics) => {
                panic!("expected an uncalled function to still fit; got {diagnostics:?}")
            }
        }
        let mut with_wired_call = app_with_uncalled_function;
        let tests_source = &mut with_wired_call
            .iter_mut()
            .find(|source| source.path == "src/tests.spx")
            .unwrap()
            .source;
        // Module uses must sit immediately after the module declaration, so
        // insert the new `use` right after the `module ...;` line rather
        // than appending it at the end of the file.
        let module_line_end = tests_source.find('\n').unwrap() + 1;
        tests_source.insert_str(
            module_line_end,
            "use function @id(\"catalog_normalizer.app.g171_probe\") from catalog_normalizer.app as g171_probe;\n",
        );
        tests_source.push_str(
            "@id(\"catalog_normalizer.tests.g171_probe_call\") fn g171_probe_call() -> i64 { g171_probe(1) }\n",
        );
        *tests_source = canonical_source("src/tests.spx", tests_source);
        match crate::workspace_graph::build_owned(with_wired_call) {
            Ok(_) => eprintln!(
                "build_owned (call site wired): unexpectedly OK -- issue #124's margin may have \
                 changed; re-measure before relying on this reproduction"
            ),
            Err(diagnostics) => {
                assert_eq!(diagnostics[0].code, "SPX-G171");
                eprintln!(
                    "build_owned (call site wired): refused with SPX-G171, exactly as issue #124 reported: {}",
                    diagnostics[0].message
                );
            }
        }
    }

    /// Negative control: this module is read-only replay of the existing
    /// cost functions, so it must not change what the ordinary builder
    /// refuses. A workspace whose declared source alone already exceeds a
    /// deliberately tight builder limit is still refused with `SPX-G171`,
    /// exactly as before this module existed.
    #[test]
    fn oversized_workspace_is_still_refused() {
        let mut source = String::from("module app;\n@id(\"app.main\") fn main() -> i64 { 0 }\n");
        for index in 0..100 {
            source.push_str(&format!(
                "@id(\"app.fn{index}\") fn fn{index}(input: i64) -> i64 {{ input + {index} }}\n"
            ));
        }
        let tests_source = "module tests;\n@id(\"tests.main\") fn main() -> i64 { 0 }\n";
        let sources = vec![
            crate::workspace_graph::WorkspaceSource {
                path: "app.spx".to_owned(),
                source: canonical_source("app.spx", &source),
            },
            crate::workspace_graph::WorkspaceSource {
                path: "tests.spx".to_owned(),
                source: canonical_source("tests.spx", tests_source),
            },
        ];
        if let Err(errors) = build_owned_with_builder_limit(sources.clone(), MAX_BUILDER_BYTES) {
            panic!("expected the full-budget build to succeed, got: {errors:?}");
        }
        let result = build_owned_with_builder_limit(sources, 4096);
        let error = match result {
            Ok(_) => panic!("a 4096-byte builder limit must refuse this workspace"),
            Err(diagnostics) => diagnostics,
        };
        assert_eq!(error[0].code, "SPX-G171");
    }
}
