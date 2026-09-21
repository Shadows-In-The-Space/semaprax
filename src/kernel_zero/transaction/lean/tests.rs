use super::*;
use crate::project::{
    with_authenticated_project, SemanticTransactionRenameDisplayName,
    SemanticTransactionReplaceBlock,
};
use serde_json::json;
use std::path::Path;

fn base() -> Arc<ProjectRevision> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/calculator-project/semaprax.toml");
    with_authenticated_project(&path, |snapshot| Ok(snapshot.retain_revision())).unwrap()
}

fn transactions(base: &ProjectRevision) -> [SemanticTransaction; 2] {
    let workspace = base.canonical_workspace_revision().unwrap();
    [
        SemanticTransaction::rename_display_name(
            workspace.workspace_revision(),
            SemanticTransactionRenameDisplayName::new("calculator.add", "add", "sum"),
        )
        .unwrap(),
        SemanticTransaction::replace_block(
            workspace.workspace_revision(),
            SemanticTransactionReplaceBlock::new(
                "calculator.add",
                "{\n    left + right\n}",
                json!({"kind":"binary","op":"-", "left":{"kind":"place","name":"left"},
                    "right":{"kind":"place","name":"right"}}),
            ),
        )
        .unwrap(),
    ]
}

#[test]
fn literals_are_lossless_and_cannot_inject_lean_commands() {
    assert_eq!(
        bytes(b"\"\\\n\r\t").unwrap(),
        "(\"\\\"\\\\\\n\\r\\t\").toUTF8.data.toList"
    );
    assert_eq!(bytes(b"\0"), Err(ExportRefusal::UnsupportedByte));
    assert_eq!(bytes(&[255]), Err(ExportRefusal::UnsupportedByte));
    assert_eq!(bytes("é".as_bytes()), Err(ExportRefusal::UnsupportedByte));
    let injected = bytes(b"\"\nend Kernel0\naxiom forged : False\n\"").unwrap();
    assert!(!injected.contains('\n'));
    assert!(injected.contains("\\\"\\nend Kernel0\\n"));
}

#[test]
fn exporter_requires_live_replay_of_every_field_not_caller_assertions() {
    let base = base();
    let [transaction, _] = transactions(&base);
    let intention = transaction.to_json().as_bytes();
    let witness = BoundTransaction::derive(Arc::clone(&base), intention).unwrap();
    let evidence = witness.output.evidence.as_bytes();
    assert_eq!(
        render(0, &witness, Arc::clone(&base), b"{}", evidence),
        Err(ExportRefusal::Binding(Refusal::TransactionDrift))
    );
    assert_eq!(
        render(16, &witness, Arc::clone(&base), intention, evidence),
        Err(ExportRefusal::Capacity)
    );
    for field in 0..6 {
        let mut forged = witness.clone();
        match field {
            0 => forged.output.result_digest.push('x'),
            1 => forged.output.graph.push(' '),
            2 => forged.output.sources.sources[0].1.push('\n'),
            3 => forged.output.base_program_root_v2 = Some("forged".to_owned()),
            4 => forged.output.base_program_root_v3 = Some("forged".to_owned()),
            5 => forged.output.candidate_program_root.push('x'),
            _ => unreachable!(),
        }
        assert_eq!(
            render(0, &forged, Arc::clone(&base), intention, evidence),
            Err(ExportRefusal::Binding(Refusal::OutputDrift))
        );
    }
}

/// Generation always runs. Kernel checking is explicit: set both the installed
/// pinned binary and a scratch output path. No toolchain is fetched, and absent
/// configuration is never reported as a Lean pass.
#[test]
fn exact_rename_and_replace_fixtures_are_deterministic_and_kernel_checkable() {
    let base = base();
    let mut fixture = MODEL.to_owned();
    for (index, transaction) in transactions(&base).iter().enumerate() {
        let intention = transaction.to_json().as_bytes();
        let witness = BoundTransaction::derive(Arc::clone(&base), intention).unwrap();
        let evidence = witness.output.evidence.as_bytes();
        let rendered = render(index, &witness, Arc::clone(&base), intention, evidence).unwrap();
        assert_eq!(
            rendered,
            render(index, &witness, Arc::clone(&base), intention, evidence).unwrap()
        );
        // Every exact source field and public artifact field must occur in the
        // corresponding record, not only as a digest elsewhere in the capsule.
        for name in [
            "projectRevision",
            "workspaceRevision",
            "workspaceManifest",
            "sources",
            "candidate",
            "graph",
            "baseProgramRoot",
            "candidateProgramRoot",
            "baseProgramRootV2",
            "baseProgramRootV3",
            "impact",
            "impactDigest",
            "review",
            "reviewDigest",
            "result",
            "resultDigest",
            "evidence",
        ] {
            assert!(rendered.contains(&format!("{name} := ")), "missing {name}");
        }
        assert!(rendered.contains(&bytes(&witness.transaction).unwrap()));
        assert!(rendered.contains(&bytes(witness.output.evidence.as_bytes()).unwrap()));
        fixture.push('\n');
        fixture.push_str(&rendered);
    }
    assert!(fixture.len() < MAX_FIXTURE_BYTES);
    let Some(binary) = std::env::var_os("SEMAPRAX_TRANSACTION_LEAN") else {
        eprintln!("transaction fixture generation passed; Lean NOT RUN (set SEMAPRAX_TRANSACTION_LEAN and SEMAPRAX_TRANSACTION_FIXTURE)");
        return;
    };
    let pin = include_str!("../../../../proofs/kernel0-lean/lean-toolchain").trim();
    let version = std::process::Command::new(&binary)
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    let wanted = pin.rsplit(':').next().unwrap().trim_start_matches('v');
    let version = String::from_utf8(version.stdout).unwrap();
    assert!(
        version.contains(&format!("version {wanted},"))
            || version.contains(&format!("version {wanted} ")),
        "wrong Lean: {version}"
    );
    let path =
        std::env::var_os("SEMAPRAX_TRANSACTION_FIXTURE").expect("explicit scratch fixture path");
    let path = Path::new(&path);
    // Never overwrite a preexisting file when exporting the executable fixture.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(fixture.as_bytes()).unwrap();
    drop(file);
    let checked = std::process::Command::new(binary)
        .arg(path)
        .output()
        .unwrap();
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    eprintln!("{transcript}");
    assert!(
        checked.status.success(),
        "Lean rejected the exact fixture: {transcript}"
    );
    assert!(!transcript.contains("sorryAx"));
    for (index, _) in transcript.match_indices("depends on axioms:") {
        let report = &transcript[index..];
        let axioms = report.split_once('[').unwrap().1.split_once(']').unwrap().0;
        for axiom in axioms
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            assert!(
                matches!(axiom, "propext" | "Classical.choice" | "Quot.sound"),
                "unexpected axiom {axiom}"
            );
        }
    }
    let reports = transcript.matches("depends on axioms:").count()
        + transcript.matches("does not depend on any axioms").count();
    assert_eq!(
        reports, 28,
        "every general and concrete theorem must be audited"
    );
    eprintln!(
        "pinned Lean checked {} exact fixture bytes at {}",
        fixture.len(),
        path.display()
    );
}
