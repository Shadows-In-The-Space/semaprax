use super::super::corpus::{adversarial_structure_corpus, generated_corpus};
use super::*;

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
