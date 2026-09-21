//! Exact, private finite bridge to TransactionReplay.lean. ASCII-only fixtures
//! are a deliberate bounded export profile; unsupported bytes fail closed.
//! Rust/compiler/exporter correctness is not established by these theorems.

use super::*;

const MODEL: &str = include_str!("../../../proofs/kernel0-lean/TransactionReplay.lean");
const MAX_FIXTURE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
enum ExportRefusal {
    Binding(Refusal),
    UnsupportedByte,
    Capacity,
}

/// Encode bytes as Lean's own UTF-8 conversion of a lossless ASCII literal.
/// Caller text never becomes Lean syntax, a theorem name, or a proof tactic.
fn bytes(value: &[u8]) -> Result<String, ExportRefusal> {
    let mut result = String::from("(\"");
    for byte in value {
        match byte {
            b'"' => result.push_str("\\\""),
            b'\\' => result.push_str("\\\\"),
            b'\n' => result.push_str("\\n"),
            b'\r' => result.push_str("\\r"),
            b'\t' => result.push_str("\\t"),
            32..=126 => result.push(char::from(*byte)),
            _ => return Err(ExportRefusal::UnsupportedByte),
        }
    }
    result.push_str("\").toUTF8.data.toList");
    Ok(result)
}

fn source(binding: &SourceBinding) -> Result<String, ExportRefusal> {
    let files = binding
        .sources
        .iter()
        .map(|(path, contents)| {
            Ok(format!(
                "({}, {})",
                bytes(path.as_bytes())?,
                bytes(contents.as_bytes())?
            ))
        })
        .collect::<Result<Vec<_>, ExportRefusal>>()?;
    Ok(format!("{{ projectRevision := {}, workspaceRevision := {}, workspaceManifest := {}, sources := [{}] }}",
        bytes(binding.project_revision.as_bytes())?, bytes(binding.workspace_revision.as_bytes())?,
        bytes(binding.workspace_manifest.as_bytes())?, files.join(", ")))
}

fn optional(value: &Option<String>) -> Result<String, ExportRefusal> {
    match value {
        None => Ok("none".to_owned()),
        Some(value) => Ok(format!("some ({})", bytes(value.as_bytes())?)),
    }
}

fn output(binding: &OutputBinding) -> Result<String, ExportRefusal> {
    let mut fields = vec![format!("sources := {}", source(&binding.sources)?)];
    for (name, value) in [
        ("candidate", &binding.candidate),
        ("graph", &binding.graph),
        ("baseProgramRoot", &binding.base_program_root),
        ("candidateProgramRoot", &binding.candidate_program_root),
        ("impact", &binding.impact),
        ("impactDigest", &binding.impact_digest),
        ("review", &binding.review),
        ("reviewDigest", &binding.review_digest),
        ("result", &binding.result),
        ("resultDigest", &binding.result_digest),
        ("evidence", &binding.evidence),
    ] {
        fields.push(format!("{name} := {}", bytes(value.as_bytes())?));
    }
    fields.push(format!(
        "baseProgramRootV2 := {}",
        optional(&binding.base_program_root_v2)?
    ));
    fields.push(format!(
        "baseProgramRootV3 := {}",
        optional(&binding.base_program_root_v3)?
    ));
    Ok(format!("{{ {} }}", fields.join(", ")))
}

/// The caller cannot mint a fixture by supplying a digest or asserted result:
/// first replay the witness, then independently capture fresh engine outputs.
fn render(
    ordinal: usize,
    witness: &BoundTransaction,
    base: Arc<ProjectRevision>,
    transaction: &[u8],
    evidence: &[u8],
) -> Result<String, ExportRefusal> {
    if ordinal >= 16 {
        return Err(ExportRefusal::Capacity);
    }
    witness
        .replay(Arc::clone(&base), transaction, evidence)
        .map_err(ExportRefusal::Binding)?;
    let current = SourceBinding::capture(&base).map_err(ExportRefusal::Binding)?;
    let fresh = SemanticTransaction::replay(base, transaction, evidence)
        .map_err(compiler)
        .map_err(ExportRefusal::Binding)?;
    let fresh = OutputBinding::capture(&fresh).map_err(ExportRefusal::Binding)?;
    let mut result = format!("namespace Kernel0.TransactionReplay.Fixture{ordinal}\n");
    result.push_str("set_option maxRecDepth 4096\nset_option maxHeartbeats 2000000\n");
    for (name, binding, intention, capsule) in [
        (
            "expected",
            &witness.base,
            witness.transaction.as_slice(),
            witness.output.evidence.as_bytes(),
        ),
        ("current", &current, transaction, evidence),
    ] {
        result.push_str(&format!(
            "def {name} : Request := {{ base := {}, transaction := {}, evidence := {} }}\n",
            source(binding)?,
            bytes(intention)?,
            bytes(capsule)?
        ));
    }
    result.push_str(&format!(
        "def expectedOutput : OutputBinding := {}\n",
        output(&witness.output)?
    ));
    result.push_str(&format!(
        "def freshOutput : OutputBinding := {}\n",
        output(&fresh)?
    ));
    result.push_str("def witness : Witness := ⟨expected, expectedOutput⟩\n");
    result.push_str("theorem exact_inputs : current = expected := by rfl\n");
    result.push_str("theorem exact_outputs : freshOutput = expectedOutput := by rfl\n");
    result.push_str("theorem real_fixture_accepted : replay witness current (fun _ => some freshOutput) = .accepted := by\n  apply (replay_accepted_iff witness current _).mpr\n  exact ⟨exact_inputs, congrArg some exact_outputs⟩\n");
    result.push_str("theorem changed_input_refused (changed : Request) (engine : Request → Option OutputBinding) (h : changed ≠ expected) : replay witness changed engine = .stale := stale_refused witness changed engine h\n");
    result.push_str(&format!("end Kernel0.TransactionReplay.Fixture{ordinal}\n"));
    for theorem in [
        "delegates_iff",
        "stale_never_delegates",
        "stale_refused",
        "stale_engine_independent",
        "source_drift_refused",
        "transaction_drift_refused",
        "evidence_drift_refused",
        "replay_accepted_iff",
        "reminted_output_refused",
        "accepted_preserves_all_fields",
        "Fixture.exact_inputs",
        "Fixture.exact_outputs",
        "Fixture.real_fixture_accepted",
        "Fixture.changed_input_refused",
    ] {
        let theorem = theorem.replace("Fixture.", &format!("Fixture{ordinal}."));
        result.push_str(&format!(
            "#print axioms Kernel0.TransactionReplay.{theorem}\n"
        ));
    }
    if result.len() > MAX_FIXTURE_BYTES {
        return Err(ExportRefusal::Capacity);
    }
    Ok(result)
}

#[path = "lean/tests.rs"]
mod tests;
