use super::*;
use crate::project::{
    with_authenticated_project, ProjectCandidate, SemanticChange, SemanticTransactionAddContract,
    SemanticTransactionRenameDisplayName, SemanticTransactionReplaceBlock,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SERIAL: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "semaprax-kernel-transaction-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        // create_dir refuses a preexisting fixture instead of adopting it.
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/calculator-project");
        for path in [
            "semaprax.toml",
            "src/app.spx",
            "src/core.spx",
            "src/tests.spx",
        ] {
            std::fs::copy(example.join(path), root.join(path)).unwrap();
        }
        Self(root.canonicalize().unwrap())
    }

    fn revision(&self) -> Arc<ProjectRevision> {
        with_authenticated_project(&self.0.join("semaprax.toml"), |snapshot| {
            Ok(snapshot.retain_revision())
        })
        .unwrap()
    }

    fn inventory(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let bytes = if entry.file_type().unwrap().is_dir() {
                    visit(root, &path, result);
                    Vec::new()
                } else {
                    std::fs::read(&path).unwrap()
                };
                result.insert(path.strip_prefix(root).unwrap().to_owned(), bytes);
            }
        }
        let mut result = BTreeMap::new();
        visit(&self.0, &self.0, &mut result);
        result
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn rename(base: &ProjectRevision, old: &str, new: &str) -> SemanticTransaction {
    SemanticTransaction::rename_display_name(
        base.canonical_workspace_revision()
            .unwrap()
            .workspace_revision(),
        SemanticTransactionRenameDisplayName::new("calculator.add", old, new),
    )
    .unwrap()
}

fn replacement(op: &str) -> serde_json::Value {
    json!({"kind":"binary", "op":op,
        "left":{"kind":"place","name":"left"},
        "right":{"kind":"place","name":"right"}})
}

fn block(base: &ProjectRevision, old: &str, body: serde_json::Value) -> SemanticTransaction {
    SemanticTransaction::replace_block(
        base.canonical_workspace_revision()
            .unwrap()
            .workspace_revision(),
        SemanticTransactionReplaceBlock::new("calculator.add", old, body),
    )
    .unwrap()
}

fn assert_code(result: Result<BoundTransaction, Refusal>, code: &str) {
    let Err(Refusal::Compiler(codes)) = result else {
        panic!("expected compiler diagnostic {code}, got {result:?}");
    };
    assert!(codes.iter().any(|actual| actual == code), "{codes:?}");
}

#[test]
fn finite_rename_and_block_witnesses_correspond_to_direct_candidates() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let before = SourceBinding::capture(&base).unwrap();
    let disk = fixture.inventory();
    for (transaction, intention) in [
        (
            rename(&base, "add", "sum"),
            json!({"kind":"rename_declaration",
            "target":"calculator.add","name":"sum"}),
        ),
        (
            rename(&base, "add", "total"),
            json!({"kind":"rename_declaration",
            "target":"calculator.add","name":"total"}),
        ),
        (
            block(&base, "{\n    left + right\n}", replacement("-")),
            json!({"kind":"replace_function_body","target":"calculator.add",
                "body":replacement("-")}),
        ),
        (
            block(
                &base,
                "{\n    left + right\n}",
                json!({"kind":"i64","value":7}),
            ),
            json!({"kind":"replace_function_body","target":"calculator.add",
                "body":{"kind":"i64","value":7}}),
        ),
    ] {
        let bytes = transaction.to_json().as_bytes();
        let witness = BoundTransaction::derive(Arc::clone(&base), bytes).unwrap();
        let repeated = BoundTransaction::derive(Arc::clone(&base), bytes).unwrap();
        assert_eq!(witness, repeated);
        let result: serde_json::Value = serde_json::from_str(&witness.output.result).unwrap();
        assert_eq!(
            result["authority"],
            json!({"commit_performed":false,"granted":false})
        );
        assert_eq!(result["source_review"]["source_authority"], false);
        witness
            .replay(Arc::clone(&base), bytes, witness.output.evidence.as_bytes())
            .unwrap();
        let open = ProjectCandidate::open(Arc::clone(&base), base.project_revision()).unwrap();
        let change = SemanticChange::new(base.project_revision(), &intention).unwrap();
        let direct = open.apply(open.candidate_digest(), &change).unwrap();
        assert_eq!(witness.output.candidate, direct.to_json());
        assert_eq!(
            witness.output.sources,
            SourceBinding::capture(direct.revision()).unwrap()
        );
        assert_eq!(witness.output.graph, direct.revision().semantic_graph());
        assert_eq!(before, SourceBinding::capture(&base).unwrap());
    }
    assert_eq!(
        disk,
        fixture.inventory(),
        "no files, locks or candidates published"
    );
}

#[test]
fn public_old_value_and_workspace_preconditions_remain_decisive() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let disk = fixture.inventory();
    for transaction in [
        rename(&base, "obsolete", "sum"),
        block(&base, "{\n    left - right\n}", replacement("-")),
        SemanticTransaction::rename_display_name(
            &format!("sha256:{}", "0".repeat(64)),
            SemanticTransactionRenameDisplayName::new("calculator.add", "add", "sum"),
        )
        .unwrap(),
    ] {
        assert_code(
            BoundTransaction::derive(Arc::clone(&base), transaction.to_json().as_bytes()),
            "SPX-G527",
        );
    }
    let malformed = format!("{}\n", rename(&base, "add", "sum").to_json());
    assert_code(
        BoundTransaction::derive(Arc::clone(&base), malformed.as_bytes()),
        "SPX-G525",
    );
    let unsupported = SemanticTransaction::add_contract(
        base.canonical_workspace_revision()
            .unwrap()
            .workspace_revision(),
        SemanticTransactionAddContract::new(
            "calculator.add",
            json!({"requires":[],"ensures":[]}),
            "requires",
            json!({"kind":"bool","value":true}),
        ),
    )
    .unwrap();
    assert_eq!(
        BoundTransaction::derive(Arc::clone(&base), unsupported.to_json().as_bytes()),
        Err(Refusal::UnsupportedOperation)
    );
    assert_eq!(
        BoundTransaction::derive(base, &vec![0; MAX_TRANSACTION_BYTES + 1]),
        Err(Refusal::Capacity)
    );
    assert_eq!(disk, fixture.inventory());
}

#[test]
fn every_fixture_source_and_transaction_byte_is_bound_without_hash_assumptions() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let transaction = rename(&base, "add", "sum");
    let witness = BoundTransaction::derive(base, transaction.to_json().as_bytes()).unwrap();
    let evidence = witness.output.evidence.as_bytes();
    for index in 0..witness.transaction.len() {
        let mut changed = witness.transaction.clone();
        changed[index] ^= 1;
        assert_eq!(
            witness.admit_inputs(&witness.base, &changed, evidence),
            Err(Refusal::TransactionDrift)
        );
    }
    for file in 0..witness.base.sources.len() {
        for byte in 0..witness.base.sources[file].1.len() {
            let mut changed = witness.base.clone();
            let mut source = changed.sources[file].1.as_bytes().to_owned();
            source[byte] ^= 1;
            changed.sources[file].1 = String::from_utf8(source).unwrap();
            // Existing selectors are deliberately left unchanged: actual bytes,
            // not an asserted source digest or semantic normalization, decide.
            assert_eq!(
                witness.admit_inputs(&changed, &witness.transaction, evidence),
                Err(Refusal::BaseDrift)
            );
        }
    }
    let mut variants = Vec::new();
    let mut changed = witness.base.clone();
    changed.sources.pop();
    variants.push(changed);
    let mut changed = witness.base.clone();
    changed.sources.push(changed.sources[0].clone());
    variants.push(changed);
    let mut changed = witness.base.clone();
    changed.sources.swap(0, 1);
    variants.push(changed);
    let mut changed = witness.base.clone();
    changed.sources[0].0.push('x');
    variants.push(changed);
    let mut changed = witness.base.clone();
    changed.workspace_manifest.push('\n');
    variants.push(changed);
    let mut changed = witness.base.clone();
    changed.project_revision.push('x');
    variants.push(changed);
    let mut changed = witness.base.clone();
    changed.workspace_revision.push('x');
    variants.push(changed);
    for changed in variants {
        assert_eq!(
            witness.admit_inputs(&changed, &witness.transaction, evidence),
            Err(Refusal::BaseDrift)
        );
    }
}

#[test]
fn stale_bytes_never_reach_replay_or_candidate_work() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let transaction = rename(&base, "add", "sum");
    let bytes = transaction.to_json().as_bytes();
    let witness = BoundTransaction::derive(Arc::clone(&base), bytes).unwrap();
    let evidence = witness.output.evidence.as_bytes();
    let forbidden = |_, _: &[u8], _: &[u8]| panic!("stale inputs crossed the replay boundary");
    assert_eq!(
        witness.replay_with(Arc::clone(&base), b"{}", evidence, forbidden),
        Err(Refusal::TransactionDrift)
    );
    assert_eq!(
        witness.replay_with(Arc::clone(&base), bytes, b"{}", forbidden),
        Err(Refusal::EvidenceDrift)
    );
    assert_eq!(
        witness.replay_with(
            Arc::clone(&base),
            &vec![0; MAX_TRANSACTION_BYTES + 1],
            evidence,
            forbidden
        ),
        Err(Refusal::Capacity)
    );
    // Re-admit real source-only drift. This is a new retained revision, not a
    // claim that an already retained revision observes live filesystem changes.
    let path = fixture.0.join("src/tests.spx");
    let source = format!(
        "// source-only drift\n{}",
        std::fs::read_to_string(&path).unwrap()
    );
    std::fs::write(path, source).unwrap();
    let drifted = fixture.revision();
    let disk = fixture.inventory();
    assert_eq!(
        witness.replay_with(drifted, bytes, evidence, forbidden),
        Err(Refusal::BaseDrift)
    );
    assert_eq!(disk, fixture.inventory());
    witness.replay(base, bytes, evidence).unwrap();
}

#[test]
fn self_consistent_input_remint_cannot_bypass_existing_evidence_replay() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let transaction = rename(&base, "add", "sum");
    let mut witness =
        BoundTransaction::derive(Arc::clone(&base), transaction.to_json().as_bytes()).unwrap();
    witness.output.evidence = witness.output.evidence.replace("sum", "different");
    let error = witness.replay(
        Arc::clone(&base),
        &witness.transaction,
        witness.output.evidence.as_bytes(),
    );
    assert_eq!(error, Err(Refusal::Compiler(vec!["SPX-G527".to_owned()])));
    let mut witness =
        BoundTransaction::derive(Arc::clone(&base), transaction.to_json().as_bytes()).unwrap();
    witness.transaction = rename(&base, "add", "total")
        .to_json()
        .as_bytes()
        .to_owned();
    assert_eq!(
        witness.replay(
            base,
            &witness.transaction,
            witness.output.evidence.as_bytes()
        ),
        Err(Refusal::Compiler(vec!["SPX-G527".to_owned()]))
    );
}

#[test]
fn fresh_engine_replay_checks_every_recorded_output() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let transaction = rename(&base, "add", "sum");
    let witness =
        BoundTransaction::derive(Arc::clone(&base), transaction.to_json().as_bytes()).unwrap();
    for field in 0..16 {
        let mut forged = witness.clone();
        match field {
            0 => forged.output.sources.sources[0].1.push('\n'),
            1 => forged.output.candidate.push(' '),
            2 => forged.output.graph.push(' '),
            3 => forged.output.base_program_root.push(' '),
            4 => forged.output.candidate_program_root.push(' '),
            5 => forged.output.base_program_root_v2 = Some("forged".into()),
            6 => forged.output.base_program_root_v3 = Some("forged".into()),
            7 => forged.output.impact.push(' '),
            8 => forged.output.impact_digest.push('x'),
            9 => forged.output.review.push(' '),
            10 => forged.output.review_digest.push('x'),
            11 => forged.output.result.push(' '),
            12 => forged.output.result_digest.push('x'),
            13 => forged.output.sources.project_revision.push('x'),
            14 => forged.output.sources.workspace_revision.push('x'),
            15 => forged.output.sources.workspace_manifest.push('\n'),
            _ => unreachable!(),
        }
        assert_eq!(
            forged.replay(
                Arc::clone(&base),
                &witness.transaction,
                witness.output.evidence.as_bytes()
            ),
            Err(Refusal::OutputDrift)
        );
    }
}

#[test]
fn source_and_evidence_capacity_refuse_before_replay() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let transaction = rename(&base, "add", "sum");
    let bytes = transaction.to_json().as_bytes();
    let witness = BoundTransaction::derive(Arc::clone(&base), bytes).unwrap();
    let forbidden = |_, _: &[u8], _: &[u8]| panic!("capacity failure reached replay");
    assert_eq!(
        witness.replay_with(base, bytes, &vec![0; MAX_OUTPUT_BYTES + 1], forbidden),
        Err(Refusal::Capacity)
    );
    let path = fixture.0.join("src/tests.spx");
    let source = format!(
        "// {}\n{}",
        "x".repeat(MAX_SOURCE_BYTES),
        std::fs::read_to_string(&path).unwrap()
    );
    std::fs::write(path, source).unwrap();
    let large = fixture.revision();
    assert_eq!(
        BoundTransaction::derive(Arc::clone(&large), bytes),
        Err(Refusal::Capacity)
    );
    assert_eq!(
        witness.replay_with(large, bytes, witness.output.evidence.as_bytes(), forbidden),
        Err(Refusal::Capacity)
    );
}

#[test]
fn malformed_authority_and_ill_typed_replacements_never_mint_witnesses() {
    let fixture = Fixture::new();
    let base = fixture.revision();
    let transaction = rename(&base, "add", "sum");
    for mutation in [
        transaction.to_json().replace(
            "\"requested_authority\":\"none\"",
            "\"requested_authority\":\"commit\"",
        ),
        transaction
            .to_json()
            .replace("\"rename_display_name\"", "\"invented_operation\""),
        transaction
            .to_json()
            .replace("\"schema\":", "\"schema\":\"duplicate\",\"schema\":"),
    ] {
        assert_ne!(mutation, transaction.to_json());
        assert_code(
            BoundTransaction::derive(Arc::clone(&base), mutation.as_bytes()),
            "SPX-G525",
        );
    }
    let ill_typed = block(
        &base,
        "{\n    left + right\n}",
        json!({"kind":"bool","value":true}),
    );
    assert!(matches!(
        BoundTransaction::derive(base, ill_typed.to_json().as_bytes()),
        Err(Refusal::Compiler(_))
    ));
}
