use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::corpus::{adversarial_structure_corpus, generated_corpus};
use super::*;

static NEXT_LEAN_FIXTURE: AtomicUsize = AtomicUsize::new(0);

const SOURCE: &str = r#"module test.graph;
@id("math.pair")
fn pair(left: i64, right: i64) -> i64 { left - right }
@id("math.adjust")
fn adjust(value: i64) -> i64 { -value }
@id("app.main")
fn main() -> i64 {
    let answer = pair(adjust(1), adjust(2));
    if true && answer == 1 { answer } else { pair(1, 0) }
}
"#;

fn lean_lake() -> Option<PathBuf> {
    let candidate = std::env::var_os("SEMAPRAX_KERNEL0_LAKE").unwrap_or_else(|| "lake".into());
    let candidate = PathBuf::from(candidate);
    if candidate.components().count() > 1 {
        return candidate.is_file().then_some(candidate);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(&candidate))
            .find(|path| path.is_file())
    })
}

fn proof_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("proofs/kernel0-lean")
}

fn lean_string(value: &str) -> String {
    // The fixed real fixture contains ASCII IDs, and Rust debug quoting is
    // Lean string-literal syntax for that bounded set. Refuse an expansion
    // rather than silently generating a different witness language.
    assert!(value.is_ascii());
    format!("{value:?}")
}

fn lean_list(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(", "))
}

fn lean_fact(fact: &FunctionFact) -> String {
    format!(
        "⟨{}, {}⟩",
        lean_string(&fact.id),
        lean_list(fact.call_occurrences.iter().map(|id| lean_string(id)))
    )
}

fn lean_fixture_source(facts: &ProjectionFacts) -> String {
    let inventory = lean_list(facts.functions.iter().map(|fact| lean_string(&fact.id)));
    let facts = lean_list(facts.functions.iter().map(lean_fact));
    format!(
        r#"import GraphProjection

open Kernel0.GraphProjection

namespace SemapraxGraphProjectionWitness

def actualInventory : List String := {inventory}
def actualFacts : List StableFact := {facts}

-- Both equalities are derived from compiler output in Rust. The first
-- pins actual stable-ID order; the second pins exact call occurrences.
theorem actual_inventory_is_modeled : actualInventory = compilerFixtureInventory := by rfl
theorem actual_facts_are_modeled :
    project actualInventory compilerFixture = some actualFacts := by
  exact compiler_fixture_projection_exact
theorem actual_ids_preserved :
    actualFacts.map StableFact.stableId = actualInventory := by
  exact project_preserves_exact_inventory actual_facts_are_modeled

end SemapraxGraphProjectionWitness
"#
    )
}

#[test]
fn real_graph_projection_replays_exact_source_identity_and_bytes() {
    let entry = DeclarationId::new("app.main");
    let bound = BoundProjection::derive(SOURCE, &entry).unwrap();
    assert_eq!(bound, BoundProjection::derive(SOURCE, &entry).unwrap());
    assert_eq!(
        bound.replay(SOURCE, &entry, &bound.graph_bytes),
        Ok(&bound.facts)
    );
    assert_eq!(
        bound.facts.functions[0].call_occurrences,
        ["math.pair", "math.adjust", "math.adjust", "math.pair"]
    );
    assert_eq!(
        bound.replay(SOURCE, &entry, &(bound.graph_bytes.clone() + "\n")),
        Err(ProjectionError::Binding)
    );
    assert_eq!(
        bound.replay(&(SOURCE.to_owned() + "\n"), &entry, &bound.graph_bytes),
        Err(ProjectionError::Binding)
    );
    assert_eq!(
        bound.replay(SOURCE, &DeclarationId::new("math.pair"), &bound.graph_bytes),
        Err(ProjectionError::Binding)
    );
    let mut forged = bound.clone();
    forged.graph_bytes.push('\n');
    forged.graph_digest = graph_digest(forged.graph_bytes.as_bytes());
    assert_eq!(
        forged.replay(SOURCE, &entry, &forged.graph_bytes),
        Err(ProjectionError::Binding)
    );
    let mut forged = bound.clone();
    forged.facts.functions[0].call_occurrences.swap(0, 1);
    assert_eq!(
        forged.replay(SOURCE, &entry, &forged.graph_bytes),
        Err(ProjectionError::Binding)
    );
}

#[test]
fn real_graph_projection_stable_ids_and_calls_match_the_lean_fixture() {
    let entry = DeclarationId::new("app.main");
    let bound = BoundProjection::derive(SOURCE, &entry).unwrap();
    let source = lean_fixture_source(&bound.facts);
    assert!(source.contains("theorem actual_ids_preserved"));
    let Some(lake) = lean_lake() else {
        eprintln!(
            "Kernel-0 graph-projection fixture generation passed; Lean NOT RUN \
             (set SEMAPRAX_KERNEL0_LAKE to require the pinned checker)"
        );
        return;
    };
    let directory = proof_directory();
    assert!(directory.join("lakefile.toml").is_file());
    let fixture = directory.join(format!(
        ".semaprax-graph-projection-witness-{}-{}.lean",
        std::process::id(),
        NEXT_LEAN_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&fixture, &source).expect("write deterministic graph projection witness");
    let result = Command::new(lake)
        .args(["env", "lean"])
        .arg(&fixture)
        .current_dir(&directory)
        .output();
    fs::remove_file(&fixture).ok();
    let result = result.expect("run pinned Lean against graph projection witness");
    assert!(
        result.status.success(),
        "Lean rejected the compiler-derived stable-ID graph fixture:\nsource:\n{source}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn explicit_identity_survives_display_rename_declaration_reorder_and_module_move() {
    let entry = DeclarationId::new("app.main");
    let original = BoundProjection::derive(SOURCE, &entry).unwrap();
    let renamed = SOURCE
        .replace("fn pair(", "fn difference(")
        .replace("= pair(", "= difference(")
        .replace("{ pair(", "{ difference(");
    let moved = renamed.replace("module test.graph;", "module relocated.graph;");
    let pair = "@id(\"math.pair\")\nfn difference(left: i64, right: i64) -> i64 { left - right }\n";
    let reordered = moved.replace(pair, "") + pair;
    for changed in [renamed, moved, reordered] {
        let new = BoundProjection::derive(&changed, &entry).unwrap();
        assert_eq!(original.facts, new.facts);
        assert_ne!(original.graph_digest, new.graph_digest);
        assert_ne!(original.graph_bytes, new.graph_bytes);
        assert_eq!(
            original.replay(&changed, &entry, &original.graph_bytes),
            Err(ProjectionError::Binding)
        );
    }
    let unstable = SOURCE.replace("@id(\"math.pair\")\n", "");
    assert_eq!(
        BoundProjection::derive(&unstable, &entry),
        Err(ProjectionError::UnstableIdentity)
    );
}

#[test]
fn real_generated_and_structural_corpus_graphs_correspond_to_reification() {
    let corpus = generated_corpus()
        .into_iter()
        .chain(adversarial_structure_corpus())
        .collect::<Vec<_>>();
    assert!(!corpus.is_empty());
    for case in corpus {
        let entry = DeclarationId::new(case.entry_id);
        let bound = BoundProjection::derive(&case.source, &entry).unwrap_or_else(|error| {
            panic!(
                "real corpus graph must correspond exactly: {error:?}\n{}",
                case.source
            )
        });
        assert_eq!(
            bound.replay(&case.source, &entry, &bound.graph_bytes),
            Ok(&bound.facts)
        );
    }
}
