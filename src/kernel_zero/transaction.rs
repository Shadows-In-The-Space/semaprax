//! Private finite transaction correspondence harness, not a transaction API.
//!
//! The public engine owns canonical decoding, old-value preconditions, complete
//! Project rebuilding and replay. This harness records a bounded exact-byte
//! relation around that engine; it neither interprets intentions independently
//! nor serializes a new evidence format. Only rename and block replacement are
//! admitted. Success is executable local evidence, not a universal theorem.
//!
//! A retained revision is immutable and authority-free. Its source inventory is
//! not a live filesystem snapshot: this module does not authenticate disk drift,
//! original manifest spelling, external facts or any commit/publication route.

use std::sync::Arc;

use crate::diagnostic::Diagnostic;
use crate::project::{
    ProjectRevision, SemanticTransaction, SemanticTransactionArtifacts,
    SemanticTransactionOperation,
};

const MAX_SOURCES: usize = 16;
const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Refusal {
    Capacity,
    UnsupportedOperation,
    BaseDrift,
    TransactionDrift,
    EvidenceDrift,
    OutputDrift,
    // Preserve the existing public diagnostic codes; invent no public code.
    Compiler(Vec<String>),
}

fn compiler(errors: Vec<Diagnostic>) -> Refusal {
    Refusal::Compiler(errors.iter().map(|error| error.code.to_owned()).collect())
}

/// Ordered, complete exact source inventory and its existing retained selectors.
/// No sorting, source normalization, hashing-only comparison or omitted files.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceBinding {
    project_revision: String,
    workspace_revision: String,
    workspace_manifest: String,
    sources: Vec<(String, String)>,
}

impl SourceBinding {
    fn capture(base: &ProjectRevision) -> Result<Self, Refusal> {
        let mut bytes = base.workspace_manifest().len();
        if base.sources().is_empty() || base.sources().len() > MAX_SOURCES {
            return Err(Refusal::Capacity);
        }
        for (index, source) in base.sources().iter().enumerate() {
            bytes = bytes
                .checked_add(source.path().len())
                .and_then(|n| n.checked_add(source.source().len()))
                .ok_or(Refusal::Capacity)?;
            if bytes > MAX_SOURCE_BYTES {
                return Err(Refusal::Capacity);
            }
            if base.sources()[..index]
                .iter()
                .any(|other| other.path() == source.path())
            {
                return Err(Refusal::BaseDrift);
            }
        }
        Ok(Self {
            project_revision: base.project_revision().to_owned(),
            workspace_revision: base.workspace_revision().to_owned(),
            workspace_manifest: base.workspace_manifest().to_owned(),
            sources: base
                .sources()
                .iter()
                .map(|source| (source.path().to_owned(), source.source().to_owned()))
                .collect(),
        })
    }
}

/// Complete outputs, not just a digest or a caller's asserted success bit.
/// The actual candidate is deliberately not retained or returned.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OutputBinding {
    sources: SourceBinding,
    candidate: String,
    graph: String,
    base_program_root: String,
    candidate_program_root: String,
    base_program_root_v2: Option<String>,
    base_program_root_v3: Option<String>,
    impact: String,
    impact_digest: String,
    review: String,
    review_digest: String,
    result: String,
    result_digest: String,
    evidence: String,
}

impl OutputBinding {
    fn capture(artifacts: &SemanticTransactionArtifacts) -> Result<Self, Refusal> {
        let candidate = artifacts.candidate();
        let payloads = [
            candidate.to_json(),
            candidate.revision().semantic_graph(),
            artifacts.base_program_root().to_json(),
            artifacts.candidate_program_root().to_json(),
            artifacts.impact(),
            artifacts.impact_digest(),
            artifacts.review(),
            artifacts.review_digest(),
            artifacts.result(),
            artifacts.result_digest(),
            artifacts.evidence(),
        ];
        let mut bytes = 0usize;
        for payload in payloads {
            bytes = bytes.checked_add(payload.len()).ok_or(Refusal::Capacity)?;
            if bytes > MAX_OUTPUT_BYTES {
                return Err(Refusal::Capacity);
            }
        }
        for payload in [
            artifacts.base_program_root_v2().map(|root| root.to_json()),
            artifacts.base_program_root_v3().map(|root| root.to_json()),
        ]
        .into_iter()
        .flatten()
        {
            bytes = bytes.checked_add(payload.len()).ok_or(Refusal::Capacity)?;
            if bytes > MAX_OUTPUT_BYTES {
                return Err(Refusal::Capacity);
            }
        }
        Ok(Self {
            sources: SourceBinding::capture(candidate.revision())?,
            candidate: candidate.to_json().to_owned(),
            graph: candidate.revision().semantic_graph().to_owned(),
            base_program_root: artifacts.base_program_root().to_json().to_owned(),
            candidate_program_root: artifacts.candidate_program_root().to_json().to_owned(),
            base_program_root_v2: artifacts
                .base_program_root_v2()
                .map(|root| root.to_json().to_owned()),
            base_program_root_v3: artifacts
                .base_program_root_v3()
                .map(|root| root.to_json().to_owned()),
            impact: artifacts.impact().to_owned(),
            impact_digest: artifacts.impact_digest().to_owned(),
            review: artifacts.review().to_owned(),
            review_digest: artifacts.review_digest().to_owned(),
            result: artifacts.result().to_owned(),
            result_digest: artifacts.result_digest().to_owned(),
            evidence: artifacts.evidence().to_owned(),
        })
    }
}

/// An unexported executable witness relating one retained base and exact
/// canonical transaction to the complete outputs of existing validation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundTransaction {
    base: SourceBinding,
    transaction: Vec<u8>,
    output: OutputBinding,
}

impl BoundTransaction {
    fn derive(base: Arc<ProjectRevision>, bytes: &[u8]) -> Result<Self, Refusal> {
        // All harness bounds and closed-profile admission precede validation.
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(Refusal::Capacity);
        }
        let binding = SourceBinding::capture(&base)?;
        let transaction = SemanticTransaction::from_json(bytes).map_err(compiler)?;
        match transaction.operation() {
            SemanticTransactionOperation::RenameDisplayName(_)
            | SemanticTransactionOperation::ReplaceBlock(_) => {}
            _ => return Err(Refusal::UnsupportedOperation),
        }
        let artifacts = transaction.validate(base).map_err(compiler)?;
        Ok(Self {
            base: binding,
            transaction: bytes.to_owned(),
            output: OutputBinding::capture(&artifacts)?,
        })
    }

    /// The exact-byte barrier is independent of the expensive replay. Comparing
    /// evidence here does NOT accept it: success still requires fresh engine
    /// replay and equality of every recorded output below.
    fn admit_inputs(
        &self,
        base: &SourceBinding,
        transaction: &[u8],
        evidence: &[u8],
    ) -> Result<(), Refusal> {
        if &self.base != base {
            return Err(Refusal::BaseDrift);
        }
        if self.transaction != transaction {
            return Err(Refusal::TransactionDrift);
        }
        if self.output.evidence.as_bytes() != evidence {
            return Err(Refusal::EvidenceDrift);
        }
        Ok(())
    }

    fn replay(
        &self,
        base: Arc<ProjectRevision>,
        transaction: &[u8],
        evidence: &[u8],
    ) -> Result<(), Refusal> {
        self.replay_with(base, transaction, evidence, SemanticTransaction::replay)
    }

    /// A private test seam proves the replay boundary is never crossed by stale
    /// inputs. The ordinary path above always uses the existing public engine.
    fn replay_with(
        &self,
        base: Arc<ProjectRevision>,
        transaction: &[u8],
        evidence: &[u8],
        replay: impl FnOnce(
            Arc<ProjectRevision>,
            &[u8],
            &[u8],
        ) -> Result<SemanticTransactionArtifacts, Vec<Diagnostic>>,
    ) -> Result<(), Refusal> {
        if transaction.len() > MAX_TRANSACTION_BYTES || evidence.len() > MAX_OUTPUT_BYTES {
            return Err(Refusal::Capacity);
        }
        self.admit_inputs(&SourceBinding::capture(&base)?, transaction, evidence)?;
        let artifacts = replay(base, transaction, evidence).map_err(compiler)?;
        if OutputBinding::capture(&artifacts)? != self.output {
            return Err(Refusal::OutputDrift);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "transaction/tests.rs"]
mod tests;
