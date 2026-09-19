//! Deterministic, host-independent measurement of `FrontendPass::lookup`'s
//! real payload on a persistent-semantic-cache warm hit.
//!
//! `lookup` (see `super::lookup`) satisfies a whole-module cache hit with
//! `entry.program.as_ref().clone()`: a full recursive `Program` clone, the
//! same structural walk `Program`'s own iterative `Drop` performs. #85's
//! quiet-host bench found `rebuild-unchanged` at parity with `cold` (no
//! speedup within 1.4% at every tested scale); #131's prior audit named this
//! clone as the confirmed root cause at this exact call site
//! (`src/project/incremental.rs`, `FrontendPass::lookup`) without shipping a
//! fix, because avoiding it needs `Program` (or a borrow of it) threaded
//! through every downstream signature that currently takes it by value --
//! `rg -c 'Vec<Program>|&\[Program\]' src/workspace_graph.rs src/workspace_graph/*.rs
//! src/static_protocol.rs src/project/candidate/*.rs` counts 89 such
//! occurrences today, confirming that audit's blast-radius finding is still
//! current and still outside a single unreviewed lane's safe scope (see
//! AGENTS.md's ownership-path invariants and #131's own "Review checkpoint").
//!
//! This module does not change `lookup`, `build`, or any admitted result.
//! It replays the exact same cache through an ordinary two-build cold/warm
//! sequence and classifies every module in the second build as either a
//! whole-module clone (a cache hit, per the real build's own
//! `invalidated_sources`) or a reparse, then counts AST nodes on each side.
//! AST node count -- not wall-clock time or byte count -- is the metric: it
//! is the exact substructure `Program::clone`'s derived `Clone` impl
//! recursively visits, so it holds identically on a quiet host or a host
//! running fourteen concurrent `cargo` builds. Source byte count is recorded
//! alongside for comparison, since #85 already showed `modules_parsed == 0`
//! does not by itself imply cheap reuse.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::ast::Program;

use super::{ProjectFrontendCache, ProjectFrontendSource, ProjectManifest, Result};

/// One module's contribution to a [`CloneCostReport`]: how many AST nodes
/// and source bytes it carries, on whichever side (`cloned` or `reparsed`)
/// of the report it landed on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModuleCloneCost {
    pub(crate) path: String,
    pub(crate) ast_node_count: usize,
    pub(crate) source_bytes: usize,
}

/// The classification of every module in a warm build's source set, against
/// the cache state left behind by the build immediately before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CloneCostReport {
    /// Modules the warm build satisfied from cache: `lookup` ran a full
    /// `Program::clone` on each of these.
    pub(crate) cloned: Vec<ModuleCloneCost>,
    /// Modules the warm build reparsed instead: new, changed, or caught by
    /// the conservative reverse-import invalidation closure.
    pub(crate) reparsed: Vec<ModuleCloneCost>,
}

impl CloneCostReport {
    pub(crate) fn total_cloned_nodes(&self) -> usize {
        self.cloned.iter().map(|module| module.ast_node_count).sum()
    }
    pub(crate) fn total_cloned_source_bytes(&self) -> usize {
        self.cloned.iter().map(|module| module.source_bytes).sum()
    }
    pub(crate) fn total_reparsed_nodes(&self) -> usize {
        self.reparsed
            .iter()
            .map(|module| module.ast_node_count)
            .sum()
    }
}

/// Deterministic count of every expression node reachable from `program`'s
/// functions (parameters carry no expressions; bodies, `requires`, and
/// `ensures` do), plus one unit per top-level declaration. This is not a
/// byte-for-byte allocator accounting -- the `String`/`Vec`/`Box` allocations
/// inside each node are not weighed individually -- but every unit counted
/// here is one heap-allocated struct node `#[derive(Clone)]` on `Program`
/// recursively visits, so it is a stable, host-independent proxy for clone
/// (and parse, and iterative-`Drop`) work. Types, interfaces, protocols, and
/// protocol implementations carry no embedded expression bodies in this
/// language's grammar, so they are counted once each as declarations and not
/// walked further; agent operation bodies are likewise not walked (no fixture
/// in this report's tests declares an agent, and undercounting here only
/// makes the reported clone cost a floor, never an inflated one).
pub(crate) fn program_ast_node_count(program: &Program) -> usize {
    let mut count = program.types.len()
        + program.interfaces.len()
        + program.protocols.len()
        + program.implementations.len()
        + program.agents.len();
    for function in &program.functions {
        count += 1; // the function declaration itself
        function.body.visit_all_nodes(&mut |_| count += 1);
        for clause in function.requires.iter().chain(function.ensures.iter()) {
            clause.visit_all_nodes(&mut |_| count += 1);
        }
    }
    count
}

/// Cold-build `initial`, then warm-build `next` against the same cache, and
/// classify every module in `next` as cloned or reparsed using the exact
/// `invalidated_sources` the real build already computes. This function
/// reads that field; it never recomputes invalidation itself, so it cannot
/// disagree with -- or bypass -- the real admission it replays.
pub(crate) fn measure_warm_open(
    manifest: &ProjectManifest,
    initial: &[ProjectFrontendSource],
    next: &[ProjectFrontendSource],
) -> Result<CloneCostReport> {
    let mut cache = ProjectFrontendCache::new_with_semantic_cache();
    cache.build(manifest, initial)?;
    // Snapshot what the cache holds before the second build: these are the
    // exact `Arc<Program>` values `lookup` clones if their path's source is
    // unchanged and the path is not invalidated.
    let baseline: BTreeMap<String, (usize, usize)> = cache
        .entries
        .iter()
        .map(|(path, entry)| {
            (
                path.clone(),
                (program_ast_node_count(&entry.program), entry.source.len()),
            )
        })
        .collect();
    let built = cache.build(manifest, next)?;
    let report = super::work_value(&built)?;
    let reset = report["manifest_context_reset"]
        .as_bool()
        .ok_or_else(|| super::invalid("frontend work report is missing manifest_context_reset"))?;
    let invalidated: BTreeSet<String> = report["invalidated_sources"]
        .as_array()
        .ok_or_else(|| super::invalid("frontend work report is missing invalidated_sources"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| super::invalid("invalidated_sources entry is not a path string"))
        })
        .collect::<Result<BTreeSet<String>>>()?;
    let mut cloned = Vec::new();
    let mut reparsed = Vec::new();
    for source in next {
        let path = source.path().to_owned();
        let hit = !reset && !invalidated.contains(&path) && baseline.contains_key(&path);
        if hit {
            let (ast_node_count, source_bytes) = baseline[&path];
            cloned.push(ModuleCloneCost {
                path,
                ast_node_count,
                source_bytes,
            });
        } else {
            let (program, _comments) =
                crate::parse_with_comments(source.source(), Path::new(&path))
                    .map_err(|error| vec![error])?;
            reparsed.push(ModuleCloneCost {
                ast_node_count: program_ast_node_count(&program),
                source_bytes: source.source().len(),
                path,
            });
        }
    }
    Ok(CloneCostReport { cloned, reparsed })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calculator_project() -> (ProjectManifest, Vec<ProjectFrontendSource>) {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/calculator-project");
        let manifest = ProjectManifest::parse(
            &std::fs::read_to_string(root.join("semaprax.toml")).unwrap(),
        )
        .unwrap();
        let sources = manifest
            .sources()
            .iter()
            .map(|path| {
                ProjectFrontendSource::new(
                    path.as_str(),
                    &std::fs::read_to_string(root.join(path.as_str())).unwrap(),
                )
                .unwrap()
            })
            .collect();
        (manifest, sources)
    }

    fn with_replacement(
        sources: &[ProjectFrontendSource],
        path: &str,
        from: &str,
        to: &str,
    ) -> Vec<ProjectFrontendSource> {
        sources
            .iter()
            .map(|source| {
                if source.path() == path {
                    let changed = source.source().replace(from, to);
                    let canonical = crate::format::canonical(
                        &crate::parse(&changed, path).unwrap_or_else(|error| {
                            panic!("fixture edit must stay parseable: {error:?}")
                        }),
                    );
                    ProjectFrontendSource::new(path, &canonical).unwrap()
                } else {
                    ProjectFrontendSource::new(source.path(), source.source()).unwrap()
                }
            })
            .collect()
    }

    /// The measurement is a pure function of its inputs: running it twice on
    /// identical sources produces an identical report, down to per-module
    /// node counts and classification order. This is the "byte-identical
    /// for identical input" invariant, checked both structurally and via a
    /// stable text rendering, so a future change that makes classification
    /// order depend on hash-map iteration would fail this test rather than
    /// only showing up as flaky CI.
    #[test]
    fn measurement_is_deterministic_across_repeated_runs() {
        let (manifest, sources) = calculator_project();
        let first = measure_warm_open(&manifest, &sources, &sources).unwrap();
        let second = measure_warm_open(&manifest, &sources, &sources).unwrap();
        assert_eq!(first, second);
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
    }

    /// Unchanged rebuild: every module in `next` is a whole-module cache
    /// hit, so `reparsed` is empty and `total_cloned_nodes` is exactly the
    /// AST size of the whole retained project -- not a token, a real,
    /// nonzero clone volume, quantifying #85's "warm hits coexist with
    /// substantial total work" finding in units that don't need a quiet
    /// host to be trustworthy.
    #[test]
    fn unchanged_rebuild_clones_every_module_and_reparses_none() {
        let (manifest, sources) = calculator_project();
        let report = measure_warm_open(&manifest, &sources, &sources).unwrap();
        assert!(report.reparsed.is_empty());
        assert_eq!(report.cloned.len(), sources.len());
        assert!(
            report.total_cloned_nodes() > 0,
            "an unchanged warm build must still walk real AST structure per hit"
        );
        eprintln!(
            "unchanged rebuild: {} modules cloned, {} AST nodes, {} source bytes",
            report.cloned.len(),
            report.total_cloned_nodes(),
            report.total_cloned_source_bytes()
        );
    }

    /// A body-only edit to a module nothing else imports invalidates exactly
    /// that module (matching
    /// `warm_open_after_local_body_edit_reuses_unaffected_modules` in the
    /// cross-process CLI harness); its siblings remain whole-module clone
    /// hits. This is the scenario where the clone genuinely buys something:
    /// most of the project's AST volume is still cloned, not reparsed.
    #[test]
    fn local_body_edit_reparses_one_module_and_clones_the_rest() {
        let (manifest, sources) = calculator_project();
        let edited = with_replacement(&sources, "src/app.spx", "multiply(6, 7)", "multiply(7, 6)");
        let report = measure_warm_open(&manifest, &sources, &edited).unwrap();
        let reparsed_paths: BTreeSet<&str> = report
            .reparsed
            .iter()
            .map(|module| module.path.as_str())
            .collect();
        assert_eq!(reparsed_paths, BTreeSet::from(["src/app.spx"]));
        assert_eq!(report.cloned.len(), sources.len() - 1);
        assert!(report.total_cloned_nodes() > 0);
        assert!(report.total_reparsed_nodes() > 0);
        eprintln!(
            "local body edit: {} modules cloned ({} AST nodes), {} module reparsed ({} AST nodes)",
            report.cloned.len(),
            report.total_cloned_nodes(),
            report.reparsed.len(),
            report.total_reparsed_nodes()
        );
    }

    /// Editing the shared provider seeds the conservative reverse-import
    /// inventory (matching
    /// `warm_open_after_provider_edit_invalidates_the_reverse_import_closure`):
    /// every consumer is invalidated even though only the provider's body
    /// changed. Here the clone buys nothing at all for this build: 0 modules
    /// cloned, the full project reparsed, exactly the opposite side of the
    /// same tradeoff from the body-edit case above.
    #[test]
    fn provider_edit_reparses_the_whole_reverse_import_closure() {
        let (manifest, sources) = calculator_project();
        let edited = with_replacement(&sources, "src/core.spx", "left + right", "right + left");
        let report = measure_warm_open(&manifest, &sources, &edited).unwrap();
        assert!(report.cloned.is_empty());
        assert_eq!(report.reparsed.len(), sources.len());
        eprintln!(
            "provider edit: {} modules cloned, {} modules reparsed ({} AST nodes)",
            report.cloned.len(),
            report.reparsed.len(),
            report.total_reparsed_nodes()
        );
    }

    /// Negative control: this module is read-only replay of the real
    /// `ProjectFrontendCache::build`, so a genuinely invalid warm-build input
    /// must still be refused by that same admission path, not silently
    /// absorbed into a (wrong) report. A duplicate source path is refused by
    /// `build` itself (`"frontend sources contain duplicate paths"`); this
    /// proves the measurement wrapper propagates that refusal unchanged
    /// rather than swallowing or working around it.
    #[test]
    fn measurement_does_not_bypass_frontend_admission_on_invalid_input() {
        let (manifest, sources) = calculator_project();
        let mut duplicated: Vec<ProjectFrontendSource> = sources
            .iter()
            .map(|source| ProjectFrontendSource::new(source.path(), source.source()).unwrap())
            .collect();
        duplicated.push(ProjectFrontendSource::new(sources[0].path(), sources[0].source()).unwrap());
        let result = measure_warm_open(&manifest, &sources, &duplicated);
        let error = match result {
            Ok(report) => panic!("expected duplicate-path input to be refused, got {report:?}"),
            Err(error) => error,
        };
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.message.contains("duplicate paths")),
            "expected the real frontend admission's duplicate-path diagnostic, got {error:?}"
        );
    }
}
